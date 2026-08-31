#include "../include/agent.h"

#define OMINULL_MSI_UNINSTALL_KEY "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OminullAgent"

static void SetUnknownProvenance(AGENT_CONFIG* config) {
    snprintf(config->install_type, sizeof(config->install_type), "unknown");
    config->package_identifier[0] = '\0';
    config->registered_package_version[0] = '\0';
    snprintf(config->provenance_status, sizeof(config->provenance_status), "unknown");
}

void Agent_DetectInstallProvenance(AGENT_CONFIG* config) {
    if (!config) return;
    SetUnknownProvenance(config);

    char executable[MAX_PATH] = {0};
    if (!GetModuleFileNameA(NULL, executable, sizeof(executable)) ||
        _stricmp(executable, "C:\\Program Files\\Ominull\\ominulld.exe") != 0) {
        return;
    }

    HKEY key = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, OMINULL_MSI_UNINSTALL_KEY, 0,
                      KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        snprintf(config->install_type, sizeof(config->install_type), "manual");
        snprintf(config->package_identifier, sizeof(config->package_identifier), "legacy-archive");
        snprintf(config->provenance_status, sizeof(config->provenance_status), "manual");
        return;
    }

    char name[128] = {0}, version[64] = {0};
    DWORD nameSize = sizeof(name), versionSize = sizeof(version);
    LONG nameResult = RegGetValueA(key, NULL, "DisplayName", RRF_RT_REG_SZ, NULL, name, &nameSize);
    LONG versionResult = RegGetValueA(key, NULL, "DisplayVersion", RRF_RT_REG_SZ, NULL, version, &versionSize);
    RegCloseKey(key);
    if (nameResult != ERROR_SUCCESS || versionResult != ERROR_SUCCESS ||
        strcmp(name, "Ominull Agent") != 0 || version[0] == '\0') return;

    snprintf(config->install_type, sizeof(config->install_type), "msi");
    snprintf(config->package_identifier, sizeof(config->package_identifier), "OminullAgent");
    snprintf(config->registered_package_version, sizeof(config->registered_package_version), "%s", version);
    snprintf(config->provenance_status, sizeof(config->provenance_status),
             strcmp(version, OMINULL_AGENT_VERSION) == 0 ? "native" : "mismatch");
}
