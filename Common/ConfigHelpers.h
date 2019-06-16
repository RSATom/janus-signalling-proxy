#pragma once

#include <string>


std::string ConfigDir();
std::string FullPath(const std::string& configDir, const std::string& path);
