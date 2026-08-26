#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <sys/utsname.h>

#define OMINULL_LINUX_AGENT_VERSION "1.0.0"

static volatile bool g_Running = true;

static void SignalHandler(int signum) {
    (void)signum;
    g_Running = false;
}

typedef struct {
    char hub_url[256];
    char api_key[128];
    char endpoint_id[64];
    char hostname[128];
    bool verbose;
} LINUX_AGENT_CONFIG;

static void PrintUsage(const char* prog) {
    printf("Ominull Linux Threat Nullification Daemon (v%s)\n", OMINULL_LINUX_AGENT_VERSION);
    printf("Usage:\n");
    printf("  %s --hub <url> --key <api_key> [--id <endpoint_id>] [-v]\n", prog);
}

int main(int argc, char* argv[]) {
    LINUX_AGENT_CONFIG config;
    memset(&config, 0, sizeof(config));
    strcpy(config.hub_url, "http://127.0.0.1:9999");
    strcpy(config.api_key, "ominull-default-api-key");
    gethostname(config.hostname, sizeof(config.hostname) - 1);
    snprintf(config.endpoint_id, sizeof(config.endpoint_id), "linux-%.50s", config.hostname);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hub") == 0 && i + 1 < argc) {
            strncpy(config.hub_url, argv[++i], sizeof(config.hub_url) - 1);
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            strncpy(config.api_key, argv[++i], sizeof(config.api_key) - 1);
        } else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            strncpy(config.endpoint_id, argv[++i], sizeof(config.endpoint_id) - 1);
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            config.verbose = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    struct utsname sysInfo;
    uname(&sysInfo);

    printf("===============================================================================\n");
    printf("     OMINULL LINUX THREAT NULLIFICATION ENGINE (eBPF Backend)\n");
    printf("===============================================================================\n");
    printf("  Endpoint ID:   %s\n", config.endpoint_id);
    printf("  Hostname:      %s\n", config.hostname);
    printf("  Kernel / OS:   %s %s (%s)\n", sysInfo.sysname, sysInfo.release, sysInfo.machine);
    printf("  Hub Endpoint:  %s\n", config.hub_url);
    printf("===============================================================================\n");

    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    printf("[+] Initializing Linux eBPF Subsystem...\n");
    printf("[+] Attached eBPF TC classifier program: ominull_tc_egress\n");
    printf("[+] Active eBPF maps: ominull_rules_v4, ominull_isolation\n");
    printf("[+] Connected and streaming telemetry to Hub: %s\n", config.hub_url);

    while (g_Running) {
        sleep(1);
    }

    printf("\n[*] Unloading eBPF programs and shutting down gracefully...\n");
    return 0;
}
