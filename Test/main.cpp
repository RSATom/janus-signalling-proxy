#include <thread>

#include <glib.h>
#include <libwebsockets.h>

#include <Proxy/Proxy.h>
#include <Agent/Agent.h>

enum {
    RX_BUFFER_SIZE = 512,
    PROTOCOL_ID = 0,
    SERVER_PORT = 8989,
};

#if LWS_LIBRARY_VERSION_MAJOR < 3
enum {
    LWS_CALLBACK_CLIENT_CLOSED = LWS_CALLBACK_CLOSED
};
#endif

static const char* server_host = "localhost";
static const char* server_path = "/";
static const char* server_protocol = "janus-agent-protocol";

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
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
    connectInfo.ssl_connection = LCCSCF_USE_SSL;
#ifndef NDEBUG
    connectInfo.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
    connectInfo.ssl_connection |= LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    connectInfo.ssl_connection |= LCCSCF_ALLOW_EXPIRED;
#endif
#else
    connectInfo.ssl_connection = TRUE;
#endif

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

static std::string ConfigDir()
{
    const gchar* configDir = g_get_user_config_dir();
    if(!configDir) {
        return std::string();
    }

    return configDir;
}

static std::string FullPath(const std::string& configDir, const std::string& path)
{
    std::string fullPath;
    if(!g_path_is_absolute(path.c_str())) {
        gchar* tmpPath =
            g_build_filename(configDir.c_str(), path.c_str(), NULL);
        fullPath = tmpPath;
        g_free(tmpPath);
    } else
        fullPath = path;

    return fullPath;
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

    const std::string configDir = ::ConfigDir();
    if(configDir.empty())
        return;

    const std::string certificatePath =
        FullPath(configDir, "janus-signalling-agent.certificate");
    const std::string privateKeyPath =
        FullPath(configDir, "janus-signalling-agent.key");
    if(certificatePath.empty() || privateKeyPath.empty())
        return;

    lws_context_creation_info wsInfo {};
    wsInfo.protocols = wsClientProtocols;
    wsInfo.port = CONTEXT_PORT_NO_LISTEN;
    wsInfo.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    wsInfo.ssl_cert_filepath = certificatePath.c_str();
    wsInfo.ssl_private_key_filepath = privateKeyPath.c_str();

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

    if(serverThread.joinable())
        serverThread.join();
#else
    std::thread serverThread(
        [] () {
            Proxy();
        }
    );

    std::this_thread::sleep_for(std::chrono::seconds(1));

    lwsl_notice("------ Agent ------\n");
    Agent();

    if(serverThread.joinable())
        serverThread.join();
#endif

    return 0;
}
