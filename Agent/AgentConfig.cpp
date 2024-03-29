#include "AgentConfig.h"

#include <libwebsockets.h>

#include <CxxPtr/GlibPtr.h>
#include <CxxPtr/libconfigDestroy.h>

#include "Common/ConfigHelpers.h"


bool LoadConfig(AgentConfig* agentConfig)
{
    const std::deque<std::string> configDirs = ::ConfigDirs();
    if(configDirs.empty())
        return false;

    AgentConfig loadedConfig {};

    for(const std::string& configDir: configDirs) {
        lwsl_notice("Looking for config in: %s\n", configDir.c_str());

        const std::string configFile = configDir + "/janus-signalling-agent.conf";
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
            const char* host = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(proxyConfig, "host", &host)) {
                loadedConfig.proxyHost = host;
            }
            int port = 0;
            if(CONFIG_TRUE == config_setting_lookup_int(proxyConfig, "port", &port)) {
                loadedConfig.proxyPort = static_cast<unsigned short>(port);
            }
            const char* authCert = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(proxyConfig, "certificate", &authCert)) {
                loadedConfig.authCertificate = FullPath(configDir, authCert);
            }
            const char* authKey = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(proxyConfig, "key", &authKey)) {
                loadedConfig.authKey = FullPath(configDir, authKey);
            }
        }

        config_setting_t* serviceConfig = config_lookup(&config, "janus");
        if(serviceConfig && CONFIG_TRUE == config_setting_is_group(serviceConfig)) {
            const char* host = nullptr;
            if(CONFIG_TRUE == config_setting_lookup_string(serviceConfig, "host", &host)) {
                loadedConfig.serviceHost = host;
            }
            int port = 0;
            if(CONFIG_TRUE == config_setting_lookup_int(serviceConfig, "port", &port)) {
                loadedConfig.servicePort = static_cast<unsigned short>(port);
            }
        }
    }

    bool success = true;

    if(loadedConfig.proxyHost.empty()) {
        lwsl_err("Missing proxy host\n");
        success = false;
    }

    if(!loadedConfig.proxyPort) {
        lwsl_err("Missing proxy port\n");
        success = false;
    }

    if(loadedConfig.authCertificate.empty()) {
        lwsl_err("Missing auth certificate\n");
        success = false;
    }

    if(loadedConfig.authKey.empty()) {
        lwsl_err("Missing auth key\n");
        success = false;
    }

    if(loadedConfig.serviceHost.empty()) {
        lwsl_err("Missing Janus Server host\n");
        success = false;
    }

    if(!loadedConfig.servicePort) {
        lwsl_err("Missing Janus Server port\n");
        success = false;
    }

    if(success)
        *agentConfig = loadedConfig;

    return success;
}
