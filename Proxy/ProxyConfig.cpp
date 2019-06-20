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

        lwsl_notice("Trying load config: %s\n", configFile.c_str());
        if(!config_read_file(&config, configFile.c_str())) {
            lwsl_err("Fail load config. %s. %s:%d\n",
                config_error_text(&config),
                configFile.c_str(),
                config_error_line(&config));
            return false;
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
            const char* certificate = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(proxyConfig, "certificate", &certificate)) {
                loadedConfig.certificate = FullPath(configDir, certificate);
            }
            const char* key = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(proxyConfig, "key", &key)) {
                loadedConfig.key = FullPath(configDir, key);
            }
        }

        config_setting_t* agentConfig = config_lookup(&config, "agent");
        if(agentConfig && CONFIG_TRUE == config_setting_is_group(agentConfig)) {
            const char* agentCert = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(proxyConfig, "certificate", &agentCert)) {
                loadedConfig.agentCertificate  = FullPath(configDir, agentCert);
            }
        }
    }

    bool success = true;

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
