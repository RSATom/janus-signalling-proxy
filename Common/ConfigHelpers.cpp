#include "ConfigHelpers.h"

#include <glib.h>


std::string ConfigDir()
{
    const gchar* configDir = g_get_user_config_dir();
    if(!configDir) {
        return std::string();
    }

    return configDir;
}

std::string FullPath(const std::string& configDir, const std::string& path)
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
