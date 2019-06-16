#include "AgentConfig.h"

#include <libwebsockets.h>

#include <CxxPtr/GlibPtr.h>
#include <CxxPtr/libconfigDestroy.h>

#include "Common/ConfigHelpers.h"


bool LoadConfig(AgentConfig* agentConfig)
{
    const std::string configDir = ::ConfigDir();
    if(configDir.empty())
        return false;

    config_t config;
    config_init(&config);
    ConfigDestroy ConfigDestroy(&config);

    const std::string configFile = configDir + "/janus-signalling-agent.conf";

    if(!config_read_file(&config, configFile.c_str())) {
        lwsl_err("Fail load config. %s. %s:%d\n",
            config_error_text(&config),
            configFile.c_str(),
            config_error_line(&config));
        return false;
    }

    AgentConfig loadedConfig {};

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

    if(loadedConfig.proxyHost.empty() || !loadedConfig.proxyPort)
        return false;

    if(loadedConfig.authCertificate.empty() || loadedConfig.authKey.empty())
        return false;

    if(loadedConfig.serviceHost.empty() || !loadedConfig.servicePort)
        return false;

    *agentConfig = loadedConfig;

    return true;
}
