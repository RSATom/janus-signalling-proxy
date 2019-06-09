#include "Proxy.h"

#include <cassert>
#include <thread>
#include <vector>
#include <deque>
#include <set>
#include <map>

#include <libwebsockets.h>
#include <jansson.h>

#include <CxxPtr/libwebsocketsPtr.h>
#include <CxxPtr/JanssonPtr.h>

#include "MessageBuffer.h"
#include "Base62.h"


enum {
    RX_BUFFER_SIZE = 512,

    DEFAULT_PORT = 8188,
    DEFAULT_SECURE_PORT = 8989,
};

enum {
    CLIENT_PROTOCOL_ID,
    SECURE_CLIENT_PROTOCOL_ID,
    SERVICE_PROTOCOL_ID,
    SECURE_SERVICE_PROTOCOL_ID,
};

struct SenderTransaction
{
    std::string transaction;
    lws* sender;
};

typedef std::map<std::string, SenderTransaction> Transactions;

struct ContextData
{
    lws* service;
    std::set<lws*> clients;

    Base62Number serviceTransactionCounter;
    Transactions transactions;

    std::map<json_int_t, lws*> sessions;
};

struct SessionData
{
    MessageBuffer incomingMessage;
    std::deque<MessageBuffer> sendMessages;
};

struct ClientSessionData : public SessionData
{
    std::set<std::string> serviceTransactions;
    std::string createSessionTransaction;
    json_int_t sessionId = 0;
};

// Should contain only POD types,
// since created inside libwebsockets on session create.
struct SessionContextData
{
    SessionData* data;
};

static int HTTPCallback(
    lws* wsi,
    lws_callback_reasons reason,
    void* /*user*/,
    void* /*in*/, size_t /*len*/)
{
    switch(reason) {
        case LWS_CALLBACK_HTTP:
            lws_return_http_status(wsi, 418, nullptr);
            return -1;
        default:
            break;
    }

    return 0;
}

static bool IsServiceConnection(lws* wsi)
{
    const lws_protocols* protocol = lws_get_protocol(wsi);
    return SERVICE_PROTOCOL_ID == protocol->id;
}

static std::string&& ExtractJanus(const JsonPtr& jsonMessagePtr)
{
    json_t* jsonMessage = jsonMessagePtr.get();

    const char* janus = nullptr;
    if(json_t* jsonJanus = json_object_get(jsonMessage, "janus"))
        janus = json_string_value(jsonJanus);

    if(!janus)
        return std::move(std::string());

    return std::move(std::string(janus));
}

static std::string&& ExtractTransaction(const JsonPtr& jsonMessagePtr)
{
    json_t* jsonMessage = jsonMessagePtr.get();

    const char* transaction = nullptr;
    if(json_t* jsonTransaction = json_object_get(jsonMessage, "transaction"))
        transaction = json_string_value(jsonTransaction);

    if(!transaction)
        return std::move(std::string());

    return std::move(std::string(transaction));
}

static json_int_t ExtractSessionId(const JsonPtr& jsonMessagePtr)
{
    json_t* jsonMessage = jsonMessagePtr.get();

    if(json_t* jsonSessionId = json_object_get(jsonMessage, "session_id"))
        return json_integer_value(jsonSessionId);
    else
        return json_int_t();
}

static json_int_t ExtractNewSessionId(const JsonPtr& jsonMessagePtr)
{
    json_t* jsonMessage = jsonMessagePtr.get();

    const std::string janus = ExtractJanus(jsonMessagePtr);
    if(janus != "success")
        return json_int_t();

    json_t* jsonData = json_object_get(jsonMessage, "data");
    if(!jsonData || !json_is_object(jsonData))
        return json_int_t();

    if(json_t* jsonId = json_object_get(jsonData, "id"))
        return json_integer_value(jsonId);
    else
        return json_int_t();
}

void OnClientSessionEnd(ContextData* cd, ClientSessionData* clientSessionData)
{
    for(auto& t: clientSessionData->serviceTransactions) {
        cd->transactions.erase(t);
    }
    clientSessionData->serviceTransactions.clear();
    if(clientSessionData->sessionId) {
        cd->sessions.erase(clientSessionData->sessionId);
        clientSessionData->sessionId = json_int_t();
    }
}

static bool RouteMessageToService(lws* wsi, MessageBuffer* message)
{
    lws_context* context = lws_get_context(wsi);
    SessionContextData* clientSessionContextData =
        static_cast<SessionContextData*>(lws_wsi_user(wsi));
    ClientSessionData* clientSessionData =
        static_cast<ClientSessionData*>(clientSessionContextData->data);
    ContextData* cd = static_cast<ContextData*>(lws_context_user(context));
    SessionData* serviceSessionData =
        static_cast<SessionContextData*>(lws_wsi_user(cd->service))->data;

    JsonPtr jsonMessagePtr(
        json_loadb(
            reinterpret_cast<const char*>(message->data()), message->size(),
            JSON_REJECT_DUPLICATES, nullptr));

    if(!jsonMessagePtr)
        return false;

    json_t* jsonMessage = jsonMessagePtr.get();

    const std::string messageTransaction =
        ExtractTransaction(jsonMessagePtr);
    if(messageTransaction.empty())
        return false;

    // it should be session create message
    if(!clientSessionData->sessionId) {
        const std::string messageJanus =
            ExtractJanus(jsonMessagePtr);
        if(messageJanus.empty() || messageJanus != "create") {
            lwsl_err("First client message should be about session create. Disconnecting...\n");
            return false;
        }

        clientSessionData->createSessionTransaction =
            messageTransaction;
    } else {
        const std::string messageJanus =
            ExtractJanus(jsonMessagePtr);
        if(messageJanus.empty()) {
            lwsl_err("Missing janus command. Disconnecting...\n");
            return false;
        }

        if(messageJanus == "destroy" ) {
            OnClientSessionEnd(cd, clientSessionData);
        }
    }

    const std::string serviceTransaction = cd->serviceTransactionCounter.str();
    ++cd->serviceTransactionCounter;

    SenderTransaction& clientTransaction = cd->transactions[serviceTransaction];
    clientTransaction.sender = wsi;
    clientTransaction.transaction = messageTransaction;
    clientSessionData->serviceTransactions.insert(serviceTransaction);

    JsonPtr jsonTransaction(json_string(serviceTransaction.c_str()));
    json_object_set(jsonMessage, "transaction", jsonTransaction.get());

    message->clear();

    auto jsonCallback =
        [] (const char* buffer, size_t size, void* data) -> int {
            MessageBuffer* message = static_cast<MessageBuffer*>(data);
            message->append(buffer, size);
            return 0;
        };
    json_dump_callback(jsonMessage, jsonCallback, message, JSON_COMPACT);

    serviceSessionData->sendMessages.emplace_back(std::move(*message));

    lws_callback_on_writable(cd->service);

    return true;
}

static bool RouteMessageToClient(lws* wsi, MessageBuffer* message)
{
    lws_context* context = lws_get_context(wsi);
    ContextData* cd = static_cast<ContextData*>(lws_context_user(context));

    JsonPtr jsonMessagePtr(
        json_loadb(
            reinterpret_cast<const char*>(message->data()), message->size(),
            JSON_REJECT_DUPLICATES, nullptr));

    if(!jsonMessagePtr)
        return false;

    json_t* jsonMessage = jsonMessagePtr.get();

    const std::string messageTransaction =
        ExtractTransaction(jsonMessagePtr);
    const json_int_t sessionId =
        ExtractSessionId(jsonMessagePtr);

    auto it =
        !messageTransaction.empty() ?
            cd->transactions.find(messageTransaction) :
            cd->transactions.end();

    if(it != cd->transactions.end()) {
        // FIXME! add sessionId check

        SenderTransaction& clientTransaction = it->second;

        SessionContextData* clientSessionContextData =
            static_cast<SessionContextData*>(lws_wsi_user(clientTransaction.sender));
        ClientSessionData* clientSessionData =
            static_cast<ClientSessionData*>(clientSessionContextData->data);
        if(!clientSessionData->createSessionTransaction.empty()) {
            if(clientSessionData->createSessionTransaction == clientTransaction.transaction) {
                json_int_t newSessionId = ExtractNewSessionId(jsonMessagePtr);
                lwsl_notice("Client session id received: %I64u\n, ", newSessionId);
                clientSessionData->createSessionTransaction.clear();
                clientSessionData->sessionId = newSessionId;

                cd->sessions.emplace(clientSessionData->sessionId, clientTransaction.sender);
            } else {
                // it should be create session reply, but it seems it's not
                assert(false);
            }
        }

        JsonPtr jsonTransaction(json_string(clientTransaction.transaction.c_str()));
        json_object_set(jsonMessage, "transaction", jsonTransaction.get());

        message->clear();

        auto jsonCallback =
            [] (const char* buffer, size_t size, void* data) -> int {
                MessageBuffer* message = static_cast<MessageBuffer*>(data);
                message->append(buffer, size);
                return 0;
            };
        json_dump_callback(jsonMessage, jsonCallback, message, JSON_COMPACT);

        clientSessionData->sendMessages.emplace_back(std::move(*message));

        lws_callback_on_writable(clientTransaction.sender);

        // transaction should be one-time usable
        cd->transactions.erase(it);
        clientSessionData->serviceTransactions.erase(messageTransaction);
    } else if(sessionId) {
        lwsl_warn("Fail find client by transaction. Trying to find by session_id...\n");

        auto it = cd->sessions.find(sessionId);
        if(it != cd->sessions.end()) {
            lwsl_warn("Found client by session_id.\n");
            SessionData* clientSessionData =
                static_cast<SessionContextData*>(lws_wsi_user(it->second))->data;

            clientSessionData->sendMessages.emplace_back(std::move(*message));

            lws_callback_on_writable(it->second);
        } else
            lwsl_err("Fail find client by transaction and session_id.\n");
    } else
        lwsl_err("Fail find client by transaction or session_id.\n");

    return true;
}

static bool RouteMessage(lws* wsi, MessageBuffer* message)
{
    if(IsServiceConnection(wsi))
        return RouteMessageToClient(wsi, message);
    else
        return RouteMessageToService(wsi, message);
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
    const bool serviceConnection = IsServiceConnection(wsi);

    switch (reason) {
        case LWS_CALLBACK_PROTOCOL_INIT:
            lwsl_notice("LWS_CALLBACK_PROTOCOL_INIT\n");
            break;
        case LWS_CALLBACK_ESTABLISHED:
            lwsl_notice("LWS_CALLBACK_ESTABLISHED\n");

            assert(!sd->data);

            char ip[20];
#ifdef HAVE_LIBWEBSOCKETS_PEER_SIMPLE
            lws_get_peer_simple(wsi, ip, sizeof(ip));
#else
            char host[100];
            lws_get_peer_addresses(wsi, lws_get_socket_fd(wsi), host, sizeof(host), ip, sizeof(ip));
#endif

            if(serviceConnection) {
                sd->data = new SessionData;
                if(cd->service) {
#ifdef HAVE_LIBWEBSOCKETS_PEER_SIMPLE
                    lwsl_err("Second service trying connect from %s. Disconnecting...\n", ip);
#else
                    lwsl_err("Second service trying connect from %s by %s. Disconnecting...\n", ip, host);
#endif
                    return -1;
                } else {
#ifdef HAVE_LIBWEBSOCKETS_PEER_SIMPLE
                    lwsl_notice("Service connected from %s.\n", ip);
#else
                    lwsl_notice("Service connected from %s by %s.\n", ip, host);
#endif
                    cd->service = wsi;
                }
            } else {
                sd->data = new ClientSessionData;
#ifdef HAVE_LIBWEBSOCKETS_PEER_SIMPLE
                lwsl_notice("Client connected from %s.\n", ip);
#else
                lwsl_notice("Client connected from %s by %s.\n", ip, host);
#endif
                cd->clients.insert(wsi);
            }

            break;
        case LWS_CALLBACK_RECEIVE:
            lwsl_notice("LWS_CALLBACK_RECEIVE\n");

            if(!serviceConnection && !cd->service) { // service disconnected
                lwsl_err("no service connection\n");
                return -1;
            }

            if(sd->data->incomingMessage.onReceive(wsi, in, len)) {
                lwsl_notice("%.*s\n", sd->data->incomingMessage.size(), sd->data->incomingMessage.data());
                if(!RouteMessage(wsi, &(sd->data->incomingMessage))) {
                    if(serviceConnection)
                        lwsl_err("fail route message client\n");
                    else
                        lwsl_err("fail route message service\n");

                    return -1;
                }

                sd->data->incomingMessage.clear();
            }

            break;
        case LWS_CALLBACK_SERVER_WRITEABLE:
            lwsl_notice("LWS_CALLBACK_SERVER_WRITEABLE\n");

            if(!serviceConnection && !cd->service) { // service disconnected
                lwsl_err("no service connection\n");
                return -1;
            }

            if(!sd->data->sendMessages.empty()) {
                MessageBuffer& buffer = sd->data->sendMessages.front();
                if(!buffer.writeAsText(wsi)) {
                    lwsl_err("write failed\n");
                    return -1;
                }

                sd->data->sendMessages.pop_front();

                if(!sd->data->sendMessages.empty())
                    lws_callback_on_writable(wsi);
            }

            break;
        case LWS_CALLBACK_CLOSED:
            lwsl_notice("LWS_CALLBACK_CLOSED\n");

            if(serviceConnection) {
                cd->service = nullptr;
                cd->transactions.clear();
                cd->sessions.clear();

                // client will disconnect when will know about service disconnect on wakeup
                for(lws* wsi: cd->clients)
                    lws_callback_on_writable(wsi);
            } else {
                ClientSessionData* clientSessionData =
                    static_cast<ClientSessionData*>(sd->data);
                OnClientSessionEnd(cd, clientSessionData);

                cd->clients.erase(wsi);
            }

            delete sd->data;
            sd->data = nullptr;

            break;
        default:
            break;
    }

    return 0;
}

void Proxy()
{
    const lws_protocols protocols[] = {
        { "http", HTTPCallback, 0, 0 },
        {
            "janus-protocol",
            WsCallback,
            sizeof(SessionContextData),
            RX_BUFFER_SIZE,
            CLIENT_PROTOCOL_ID,
            nullptr
        },
        {
            "janus-client-protocol",
            WsCallback,
            sizeof(SessionContextData),
            RX_BUFFER_SIZE,
            SERVICE_PROTOCOL_ID,
            nullptr
        },
        { nullptr, nullptr, 0, 0 } /* terminator */
    };

    const lws_protocols secureProtocols[] = {
        { "http", HTTPCallback, 0, 0 },
        {
            "janus-protocol",
            WsCallback,
            sizeof(SessionContextData),
            RX_BUFFER_SIZE,
            SECURE_CLIENT_PROTOCOL_ID,
            nullptr
        },
        {
            "janus-client-protocol",
            WsCallback,
            sizeof(SessionContextData),
            RX_BUFFER_SIZE,
            SECURE_SERVICE_PROTOCOL_ID,
            nullptr
        },
        { nullptr, nullptr, 0, 0 } /* terminator */
    };

    ContextData contextData {};
    contextData.serviceTransactionCounter = 1;

    lws_context_creation_info wsInfo {};
    wsInfo.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
    wsInfo.user = &contextData;

    LwsContextPtr contextPtr(lws_create_context(&wsInfo));
    lws_context* context = contextPtr.get();
    if(!context)
        return;

    lws_context_creation_info vhostInfo {};
    vhostInfo.port = DEFAULT_PORT;
    vhostInfo.protocols = protocols;

    lws_vhost* vhost = lws_create_vhost(context, &vhostInfo);
    if(!vhost)
         return;

    lws_context_creation_info secureVhostInfo {};
    secureVhostInfo.port = DEFAULT_SECURE_PORT;
    secureVhostInfo.protocols = secureProtocols;
    vhostInfo.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    vhostInfo.options |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;

    lws_vhost* secureVhost = lws_create_vhost(context, &secureVhostInfo);
    if(!secureVhost)
         return;

    while(lws_service(context, 50) >= 0);
}
