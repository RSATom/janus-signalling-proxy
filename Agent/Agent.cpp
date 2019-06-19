#include "Agent.h"

#include <string>
#include <deque>

#include <libwebsockets.h>

#include "CxxPtr/libwebsocketsPtr.h"

#include "Common/MessageBuffer.h"
#include "Common/ConfigHelpers.h"

#include "AgentConfig.h"


enum {
    RX_BUFFER_SIZE = 512,
    RECONNECT_TIMEOUT = 5,
};

enum {
    SERVICE_PROTOCOL_ID = 1,
    PROXY_PROTOCOL_ID,
};

#if LWS_LIBRARY_VERSION_MAJOR < 3
enum {
    LWS_CALLBACK_CLIENT_CLOSED = LWS_CALLBACK_CLOSED
};
#endif

namespace {

struct ContextData
{
    AgentConfig config;

    lws* serviceConnection;
    lws* proxyConnection;
};

struct SessionData
{
    MessageBuffer incomingMessage;
    std::deque<MessageBuffer> sendMessages;
};

// Should contain only POD types,
// since created inside libwebsockets on session create.
struct SessionContextData
{
    SessionData* data;
};

}

static bool IsServiceConnection(lws* wsi)
{
    const lws_protocols* protocol = lws_get_protocol(wsi);
    return protocol ? SERVICE_PROTOCOL_ID == protocol->id : false;
}

static void ServiceConnect(struct lws_context* context)
{
    ContextData* cd = static_cast<ContextData*>(lws_context_user(context));

    if(cd->serviceConnection)
        return;

    if(cd->config.serviceHost.empty() || !cd->config.servicePort) {
        lwsl_err("Missing required connect parameter.\n");
        return;
    }

    char host_and_port[cd->config.serviceHost.size() + 1 + 5 + 1];
    snprintf(host_and_port, sizeof(host_and_port), "%s:%u",
        cd->config.serviceHost.c_str(), cd->config.servicePort);

    lwsl_notice("Connecting to service %s... \n", host_and_port);

    struct lws_client_connect_info connectInfo = {};
    connectInfo.context = context;
    connectInfo.address = cd->config.serviceHost.c_str();
    connectInfo.port = cd->config.servicePort;
    connectInfo.path = "/";
    connectInfo.protocol = "janus-protocol";
    connectInfo.host = host_and_port;

    cd->serviceConnection = lws_client_connect_via_info(&connectInfo);
}

static void ProxyConnect(struct lws_context* context)
{
    ContextData* cd = static_cast<ContextData*>(lws_context_user(context));

    if(cd->proxyConnection)
        return;

    if(cd->config.proxyHost.empty() || !cd->config.proxyPort) {
        lwsl_err("Missing required connect parameter.\n");
        return;
    }

    char host_and_port[cd->config.proxyHost.size() + 1 + 5 + 1];
    snprintf(host_and_port, sizeof(host_and_port), "%s:%u",
        cd->config.proxyHost.c_str(), cd->config.proxyPort);

    lwsl_notice("Connecting to proxy %s... \n", host_and_port);

    struct lws_client_connect_info connectInfo = {};
    connectInfo.context = context;
    connectInfo.address = cd->config.proxyHost.c_str();
    connectInfo.port = cd->config.proxyPort;
    connectInfo.path = "/";
    connectInfo.protocol = "janus-agent-protocol";
    connectInfo.host = host_and_port;
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
    connectInfo.ssl_connection = LCCSCF_USE_SSL;
#ifndef NDEBUG
    connectInfo.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
    connectInfo.ssl_connection |= LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    connectInfo.ssl_connection |= LCCSCF_ALLOW_EXPIRED;
#endif
#else
    connectInfo.ssl_connection = 1;
#endif

    cd->proxyConnection = lws_client_connect_via_info(&connectInfo);
}

static bool RouteMessage(lws* wsi, MessageBuffer* message)
{
    lws_context* context = lws_get_context(wsi);
    ContextData* cd = static_cast<ContextData*>(lws_context_user(context));

    if(IsServiceConnection(wsi)) {
        SessionData* proxySessionData =
            static_cast<SessionContextData*>(lws_wsi_user(cd->proxyConnection))->data;
        proxySessionData->sendMessages.emplace_back(std::move(*message));

        lws_callback_on_writable(cd->proxyConnection);
    } else {
        SessionData* serviceSessionData =
            static_cast<SessionContextData*>(lws_wsi_user(cd->serviceConnection))->data;

        serviceSessionData->sendMessages.emplace_back(std::move(*message));

        lws_callback_on_writable(cd->serviceConnection);
    }

    return true;
}

static int WsCallback(
    lws* wsi,
    lws_callback_reasons reason,
    void* user,
    void* in, size_t len)
{
    lws_context* context = lws_get_context(wsi);
    ContextData* cd = static_cast<ContextData*>(lws_context_user(context));
    SessionContextData* sd = static_cast<SessionContextData*>(user);
    const bool isServiceConnection = IsServiceConnection(wsi);

    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            if(isServiceConnection)
                lwsl_notice("Service connection established\n");
            else
                lwsl_notice("Proxy connection established\n");

            sd->data = new SessionData;

            if(isServiceConnection)
                ProxyConnect(lws_get_context(wsi));
            break;
        case LWS_CALLBACK_CLIENT_RECEIVE:
            if(isServiceConnection && !cd->proxyConnection)
                return -1;
            else if(!isServiceConnection && !cd->serviceConnection)
                return -1;

            if(sd->data->incomingMessage.onReceive(wsi, in, len)) {
                lwsl_notice("%.*s\n", static_cast<int>(sd->data->incomingMessage.size()), sd->data->incomingMessage.data());

                if(!RouteMessage(wsi, &(sd->data->incomingMessage))) {
                    if(isServiceConnection)
                        lwsl_err("Fail route message client\n");
                    else
                        lwsl_err("Fail route message service\n");

                    return -1;
                }

                sd->data->incomingMessage.clear();
            }

            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            if(isServiceConnection && !cd->proxyConnection)
                return -1;
            else if(!isServiceConnection && !cd->serviceConnection)
                return -1;

            if(!sd->data->sendMessages.empty()) {
                MessageBuffer& buffer = sd->data->sendMessages.front();
                if(!buffer.writeAsText(wsi)) {
                    lwsl_err("Write failed\n");
                    return -1;
                }

                sd->data->sendMessages.pop_front();

                if(!sd->data->sendMessages.empty())
                    lws_callback_on_writable(wsi);
            }

            break;
        case LWS_CALLBACK_CLIENT_CLOSED:
            if(isServiceConnection && cd->proxyConnection) {
                lwsl_notice("Service connection closed\n");
                lws_callback_on_writable(cd->proxyConnection);
            } else if(!isServiceConnection && cd->serviceConnection) {
                lwsl_notice("Proxy connection closed\n");
                lws_callback_on_writable(cd->serviceConnection);
            }

            delete sd->data;
            sd = nullptr;

            if(isServiceConnection)
                cd->serviceConnection = nullptr;
            else
                cd->proxyConnection = nullptr;

            break;
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            if(isServiceConnection && cd->proxyConnection) {
                if(in)
                    lwsl_notice("Service connection failed. %s\n", in);
                else
                    lwsl_notice("Service connection failed\n");

                lws_callback_on_writable(cd->proxyConnection);
            } else if(!isServiceConnection && cd->serviceConnection) {
                if(in)
                    lwsl_notice("Proxy connection failed. %s\n", in);
                else
                    lwsl_notice("Proxy connection failed\n");

                lws_callback_on_writable(cd->serviceConnection);
            }

            if(sd) {
                delete sd->data;
                sd = nullptr;
            }

            if(isServiceConnection)
                cd->serviceConnection = nullptr;
            else
                cd->proxyConnection = nullptr;

            break;
        default:
            break;
    }

    return 0;
}

void Agent()
{
    const lws_protocols protocols[] = {
        {
            "janus-protocol",
            WsCallback,
            sizeof(SessionContextData),
            RX_BUFFER_SIZE,
            SERVICE_PROTOCOL_ID,
            nullptr
        },
        {
            "janus-agent-protocol",
            WsCallback,
            sizeof(SessionContextData),
            RX_BUFFER_SIZE,
            PROXY_PROTOCOL_ID,
            nullptr
        },
        { nullptr, nullptr, 0, 0, 0, nullptr } /* terminator */
    };

    ContextData contextData {};

    if(!LoadConfig(&contextData.config))
        return;

    lws_context_creation_info wsInfo {};
    wsInfo.gid = -1;
    wsInfo.uid = -1;
    wsInfo.protocols = protocols;
    wsInfo.port = CONTEXT_PORT_NO_LISTEN;
    wsInfo.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    wsInfo.ssl_cert_filepath = contextData.config.authCertificate.c_str();
    wsInfo.ssl_private_key_filepath = contextData.config.authKey.c_str();
    wsInfo.user = &contextData;

    LwsContextPtr contextPtr(lws_create_context(&wsInfo));
    lws_context* context = contextPtr.get();
    if(!context)
        return;

    time_t wsDisconnectedTime = 1; // =1 to emulate timeout on startup

    while(lws_service(context, 50) >= 0) {
        if(!contextData.serviceConnection && !contextData.proxyConnection) {
            struct timespec now;
            if(0 == clock_gettime(CLOCK_MONOTONIC, &now)) {
                if(!wsDisconnectedTime) {
                    wsDisconnectedTime = now.tv_sec;
                } else if(now.tv_sec - wsDisconnectedTime > RECONNECT_TIMEOUT) {
                    ServiceConnect(context);
                    wsDisconnectedTime = 0;
                }
            }
        }
    }
}
