#include "ProxyConfig.h"

#include <libwebsockets.h>

#include <CxxPtr/GlibPtr.h>
#include <CxxPtr/libconfigDestroy.h>

#include "Common/ConfigHelpers.h"


bool LoadConfig(ProxyConfig* outConfig)
{
    const std::deque<std::string> configDirs = ::ConfigDirs();
    if(configDirs.empty())
        return false;

    ProxyConfig loadedConfig {};

    for(const std::string& configDir: configDirs) {
        lwsl_notice("Looking for config in: %s\n", configDir.c_str());

        const std::string configFile = configDir + "/janus-signalling-proxy.conf";
        if(!g_file_test(configFile.c_str(),  G_FILE_TEST_IS_REGULAR))
            continue;

        config_t config;
        config_init(&config);
        ConfigDestroy ConfigDestroy(&config);

        lwsl_notice("Loading config: %s\n", configFile.c_str());
        if(!config_read_file(&config, configFile.c_str())) {
            lwsl_err("Fail load config. %s. %s:%d\n",
                config_error_text(&config),
                configFile.c_str(),
                config_error_line(&config));
            return false;
        }

        config_setting_t* serverConfig = config_lookup(&config, "server");
        if(serverConfig && CONFIG_TRUE == config_setting_is_group(serverConfig)) {
            const char* serverName = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(serverConfig, "name", &serverName)) {
                loadedConfig.serverName = serverName;
            }
            const char* certificate = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(serverConfig, "certificate", &certificate)) {
                loadedConfig.certificate = FullPath(configDir, certificate);
            }
            const char* key = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(serverConfig, "key", &key)) {
                loadedConfig.key = FullPath(configDir, key);
            }
        }

        config_setting_t* httpConfig = config_lookup(&config, "http");
        if(serverConfig && CONFIG_TRUE == config_setting_is_group(httpConfig)) {
            int httpPort = 0;
            if(CONFIG_TRUE == config_setting_lookup_int(httpConfig, "port", &httpPort)) {
                loadedConfig.httpPort = static_cast<unsigned short>(httpPort);
            }
            int httpsPort = 0;
            if(CONFIG_TRUE == config_setting_lookup_int(httpConfig, "secure_port", &httpsPort)) {
                loadedConfig.httpsPort = static_cast<unsigned short>(httpsPort);
            }
            const char* root = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(httpConfig, "root", &root)) {
                loadedConfig.httpRoot = FullPath(configDir, root);
            }
            const char* index = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(httpConfig, "index", &index)) {
                loadedConfig.httpIndex = index;
            }
        }

        config_setting_t* proxyConfig = config_lookup(&config, "proxy");
        if(proxyConfig && CONFIG_TRUE == config_setting_is_group(proxyConfig)) {
            int wsPort = 0;
            if(CONFIG_TRUE == config_setting_lookup_int(proxyConfig, "ws_port", &wsPort)) {
                loadedConfig.port = static_cast<unsigned short>(wsPort);
            }
            int wssPort = 0;
            if(CONFIG_TRUE == config_setting_lookup_int(proxyConfig, "wss_port", &wssPort)) {
                loadedConfig.securePort = static_cast<unsigned short>(wssPort);
            }
        }

        config_setting_t* agentConfig = config_lookup(&config, "agent");
        if(agentConfig && CONFIG_TRUE == config_setting_is_group(agentConfig)) {
            const char* agentCert = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(agentConfig, "certificate", &agentCert)) {
                loadedConfig.agentCertificate  = FullPath(configDir, agentCert);
            }
        }
    }

    bool success = true;

    if(loadedConfig.serverName.empty()) {
        lwsl_err("Missing server name\n");
        success = false;
    }

    if(!loadedConfig.httpRoot.empty() || !loadedConfig.httpIndex.empty() ||
       0 != loadedConfig.httpPort || 0 != loadedConfig.httpsPort)
    {
        if(loadedConfig.httpRoot.empty()) {
            lwsl_err("Missing http root dir\n");
            success = false;
        }
        if(loadedConfig.httpIndex.empty()) {
            lwsl_err("Missing http index file name\n");
            success = false;
        }
        if(0 == loadedConfig.httpPort && 0 == loadedConfig.httpsPort) {
            lwsl_err("Missing http or https port\n");
            success = false;
        }
    }

    if(!loadedConfig.port) {
        lwsl_err("Missing port\n");
        success = false;
    }

    if(!loadedConfig.securePort) {
        lwsl_err("Missing secure port\n");
        success = false;
    }

    if(loadedConfig.certificate.empty()) {
        lwsl_err("Missing certificate\n");
        success = false;
    }

    if(loadedConfig.key.empty()) {
        lwsl_err("Missing key\n");
        success = false;
    }

    if(loadedConfig.agentCertificate.empty()) {
        lwsl_err("Missing agent certificate\n");
        success = false;
    }

    if(success)
        *outConfig = loadedConfig;

    return success;
}
