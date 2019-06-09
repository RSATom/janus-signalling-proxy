#include <thread>

#include <libwebsockets.h>

#include <Proxy/Proxy.h>

enum {
    RX_BUFFER_SIZE = 512,
    PROTOCOL_ID = 0,
    SERVER_PORT = 8188,
};

#if LWS_LIBRARY_VERSION_MAJOR < 3
enum {
    LWS_CALLBACK_CLIENT_CLOSED = LWS_CALLBACK_CLOSED
};
#endif

static const char* server_host = "localhost";
static const char* server_path = "/";
static const char* server_protocol = "janus-protocol";

struct wsClientSessionData
{
};

static void wsConnect(lws* wsi)
{
    char hostAndPort[strlen(server_host) + 1 + 5 + 1];
    snprintf(hostAndPort, sizeof(hostAndPort), "%s:%u",
        server_host, SERVER_PORT);

    lws_client_connect_info connectInfo = {};
    connectInfo.context = lws_get_context(wsi);
    connectInfo.address = server_host;
    connectInfo.port = SERVER_PORT;
    connectInfo.path = server_path;
    connectInfo.protocol = server_protocol;
    connectInfo.host = hostAndPort;

    lws* lws = lws_client_connect_via_info(&connectInfo);
    if(!lws)
        return;
}

static int wsClientCallback(
    lws* wsi,
    lws_callback_reasons reason,
    void* user,
    void* opt, size_t len)
{
    wsClientSessionData* sd = static_cast<wsClientSessionData*>(user);

    switch (reason) {
        case LWS_CALLBACK_PROTOCOL_INIT:
            lwsl_notice("LWS_CALLBACK_PROTOCOL_INIT\n");
            wsConnect(wsi);
            break;
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            lwsl_notice("LWS_CALLBACK_CLIENT_ESTABLISHED\n");
            break;
        case LWS_CALLBACK_CLIENT_RECEIVE:
            lwsl_notice("LWS_CALLBACK_CLIENT_RECEIVE\n");
            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            lwsl_notice("LWS_CALLBACK_CLIENT_WRITEABLE\n");
            break;
        case LWS_CALLBACK_CLIENT_CLOSED:
            lwsl_notice("LWS_CALLBACK_CLIENT_CLOSED\n");
            break;
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            lwsl_notice("LWS_CALLBACK_CLIENT_CONNECTION_ERROR\n");
            break;
        default:
            break;
    }

    return 0;
}

void TestClient()
{
    const lws_protocols wsClientProtocols[] = {
        {
            server_protocol,
            wsClientCallback,
            sizeof(struct wsClientSessionData),
            RX_BUFFER_SIZE,
            PROTOCOL_ID,
            nullptr
        },
        { nullptr, nullptr, 0, 0, 0, nullptr } /* terminator */
    };

    lws_context_creation_info wsInfo {};
    wsInfo.protocols = wsClientProtocols;
    wsInfo.port = CONTEXT_PORT_NO_LISTEN;

    lws_context* context = lws_create_context(&wsInfo);
    if(!context)
        return;

    while(lws_service(context, 50) >= 0);

    lws_context_destroy(context);
}

int main(int , char*[])
{
#if 0
    std::thread serverThread(
        [] () {
            Proxy();
        }
    );

    std::this_thread::sleep_for(std::chrono::seconds(1));

    lwsl_notice("------ TestClient ------\n");
    TestClient();
#else
    Proxy();
#endif

    return 0;
}
