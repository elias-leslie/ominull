#include "../include/agent.h"

static void PrintUsage(const char* prog) {
    printf("Ominull Endpoint Agent (v%s)\n", OMINULL_AGENT_VERSION);
    printf("Usage:\n");
    printf("  %s --console --hub <url> --key <api_key>   Run in foreground (interactive)\n", prog);
    printf("  %s --service --hub <url> --key <api_key>   Run under Service Control Manager\n", prog);
    printf("  %s --install --hub <url> --key <api_key>   Install Windows Service\n", prog);
    printf("  %s --uninstall                             Uninstall Windows Service\n", prog);
}

int main(int argc, char* argv[]) {
    AGENT_CONFIG config;
    ZeroMemory(&config, sizeof(config));
    strcpy(config.hub_url, "http://10.0.0.58:9999");
    strcpy(config.api_key, "<provision-via-bootstrap>");
    strcpy(config.role_tag, "workstation");
    strcpy(config.location_id, "loc-home");

    DWORD hostLen = sizeof(config.hostname);
    if (!GetComputerNameA(config.hostname, &hostLen)) {
        strcpy(config.hostname, "win11-target-01");
    }
    snprintf(config.endpoint_id, sizeof(config.endpoint_id), "win11-%s", config.hostname);

    /* Observe the address, hardware address and OS once, before either the
       console or the service path takes the config. */
    Agent_DetectHostIdentity(&config);

    bool doInstall = false;
    bool doUninstall = false;
    bool doConsole = false;
    bool doService = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--install") == 0) {
            doInstall = true;
        } else if (strcmp(argv[i], "--uninstall") == 0) {
            doUninstall = true;
        } else if (strcmp(argv[i], "--console") == 0) {
            doConsole = true;
        } else if (strcmp(argv[i], "--service") == 0) {
            doService = true;
        } else if (strcmp(argv[i], "--hub") == 0 && i + 1 < argc) {
            strncpy(config.hub_url, argv[++i], sizeof(config.hub_url) - 1);
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            strncpy(config.api_key, argv[++i], sizeof(config.api_key) - 1);
        } else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            strncpy(config.endpoint_id, argv[++i], sizeof(config.endpoint_id) - 1);
        } else if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            strncpy(config.role_tag, argv[++i], sizeof(config.role_tag) - 1);
        } else if (strcmp(argv[i], "--location") == 0 && i + 1 < argc) {
            strncpy(config.location_id, argv[++i], sizeof(config.location_id) - 1);
        } else if (strcmp(argv[i], "--cf-id") == 0 && i + 1 < argc) {
            strncpy(config.cf_client_id, argv[++i], sizeof(config.cf_client_id) - 1);
        } else if (strcmp(argv[i], "--cf-secret") == 0 && i + 1 < argc) {
            strncpy(config.cf_client_secret, argv[++i], sizeof(config.cf_client_secret) - 1);
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            config.verbose = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    if (doInstall) {
        return Service_Install(config.hub_url, config.api_key) ? 0 : 1;
    }

    if (doUninstall) {
        return Service_Uninstall() ? 0 : 1;
    }

    if (doConsole) {
        printf("[*] Starting Ominull Agent in Console Mode (PID: %lu)...\n", GetCurrentProcessId());
        printf("[*] Connecting to Hub at: %s (Key: %s)\n", config.hub_url, config.api_key);
        RunAgentLoop(&config);
        return 0;
    }

    if (doService) {
        Service_SetConfig(&config);
        Service_Run();
        return 0;
    }

    PrintUsage(argv[0]);
    return 1;
}
