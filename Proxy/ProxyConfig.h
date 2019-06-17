#pragma once

#include <string>


struct ProxyConfig
{
    unsigned short port;

    unsigned short securePort;
    std::string certificate;
    std::string key;

    std::string agentCertificate;
};

bool LoadConfig(ProxyConfig*);
