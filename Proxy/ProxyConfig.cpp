#include "ProxyConfig.h"

#include <libwebsockets.h>

#include <CxxPtr/GlibPtr.h>
#include <CxxPtr/libconfigDestroy.h>

#include "Common/ConfigHelpers.h"


bool LoadConfig(ProxyConfig* outConfig)
{
    const std::string configDir = ::ConfigDir();
    if(configDir.empty())
        return false;

    config_t config;
    config_init(&config);
    ConfigDestroy ConfigDestroy(&config);

    const std::string configFile = configDir + "/janus-signalling-proxy.conf";
    lwsl_notice("Trying load config: %s\n", configFile.c_str());
    if(!config_read_file(&config, configFile.c_str())) {
        lwsl_err("Fail load config. %s. %s:%d\n",
            config_error_text(&config),
            configFile.c_str(),
            config_error_line(&config));
        return false;
    }

    ProxyConfig loadedConfig {};

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

    if(!loadedConfig.port)
        return false;

    if(!loadedConfig.securePort || loadedConfig.certificate.empty() || loadedConfig.key.empty())
        return false;

    if(loadedConfig.agentCertificate.empty())
        return false;

    *outConfig = loadedConfig;

    return true;
}
