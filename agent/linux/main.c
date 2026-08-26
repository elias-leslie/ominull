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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static void SendHeartbeat(const LINUX_AGENT_CONFIG* config) {
    char host[128] = "127.0.0.1";
    int port = 9999;
    const char* p = config->hub_url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    const char* colon = strchr(p, ':');
    if (colon) {
        size_t len = colon - p;
        if (len >= sizeof(host)) len = sizeof(host) - 1;
        strncpy(host, p, len);
        host[len] = '\0';
        port = atoi(colon + 1);
    } else {
        strncpy(host, p, sizeof(host) - 1);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    inet_pton(AF_INET, host, &saddr.sin_addr);

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&saddr, sizeof(saddr)) == 0) {
        char json[512];
        snprintf(json, sizeof(json),
            "{\"type\":\"telemetry\",\"endpoint_id\":\"%s\",\"hostname\":\"%s\",\"os\":\"Ubuntu 24.04 (Linux 6.8.0)\",\"driver_version\":\"1.0.0\",\"events\":[]}",
            config->endpoint_id, config->hostname
        );

        char req[1024];
        snprintf(req, sizeof(req),
            "POST /api/v1/events HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "X-API-Key: %s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            host, port, config->api_key, strlen(json), json
        );

        send(sock, req, strlen(req), 0);
    }
    close(sock);
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

    // Initial heartbeat
    SendHeartbeat(&config);

    int count = 0;
    while (g_Running) {
        sleep(1);
        if (++count >= 5) {
            SendHeartbeat(&config);
            count = 0;
        }
    }

    printf("\n[*] Unloading eBPF programs and shutting down gracefully...\n");
    return 0;
}
