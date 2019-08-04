#pragma once

#include <string>


struct ProxyConfig
{
    std::string serverName;
    std::string certificate;
    std::string key;

    unsigned short httpPort;
    unsigned short httpsPort;
    std::string httpRoot;
    std::string httpIndex;

    unsigned short port;
    unsigned short securePort;

    std::string agentCertificate;
};

bool LoadConfig(ProxyConfig*);
