#pragma once

#include <string>


struct AgentConfig
{
    std::string proxyHost;
    unsigned short proxyPort;
    std::string authCertificate;
    std::string authKey;

    std::string serviceHost;
    unsigned short servicePort;
};

bool LoadConfig(AgentConfig*);
