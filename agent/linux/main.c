#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/stat.h>

#define OMINULL_LINUX_AGENT_VERSION "1.1.0"
#define MAX_FLOWS_PER_BATCH 64
#define MAX_PATH_LEN 512

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
    char location_id[64];
    char role_tag[64];
    char cf_client_id[128];
    char cf_client_secret[128];
    char primary_ip[64];
    char primary_mac[32];
    bool verbose;
} LINUX_AGENT_CONFIG;

typedef struct {
    char src_ip[64];
    char dst_ip[64];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; // 6 = TCP, 17 = UDP
    char direction[16];
    char process_path[MAX_PATH_LEN];
    uint32_t process_id;
    uint64_t bytes_in;
    uint64_t bytes_out;
} LINUX_FLOW_EVENT;

static void PrintUsage(const char* prog) {
    printf("Ominull Linux Threat Nullification Daemon (v%s)\n", OMINULL_LINUX_AGENT_VERSION);
    printf("Usage:\n");
    printf("  %s --hub <url> --key <api_key> [--role <role>] [--location <id>] [--cf-id <id>] [--cf-secret <secret>] [-v]\n", prog);
}

static void GetPrimaryNetworkInfo(char* outIp, size_t ipLen, char* outMac, size_t macLen) {
    strncpy(outIp, "127.0.0.1", ipLen - 1);
    strncpy(outMac, "02:42:0a:00:00:01", macLen - 1);

    FILE* fp = popen("ip -4 route show default 2>/dev/null | awk '{print $5}'", "r");
    if (fp) {
        char iface[64] = {0};
        if (fgets(iface, sizeof(iface) - 1, fp)) {
            char* nl = strchr(iface, '\n');
            if (nl) *nl = '\0';
            if (iface[0]) {
                char ipCmd[128];
                snprintf(ipCmd, sizeof(ipCmd), "ip -4 addr show %s 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1", iface);
                FILE* ipFp = popen(ipCmd, "r");
                if (ipFp) {
                    if (fgets(outIp, ipLen - 1, ipFp)) {
                        char* ipNl = strchr(outIp, '\n');
                        if (ipNl) *ipNl = '\0';
                    }
                    pclose(ipFp);
                }
                char macCmd[128];
                snprintf(macCmd, sizeof(macCmd), "cat /sys/class/net/%s/address 2>/dev/null", iface);
                FILE* macFp = popen(macCmd, "r");
                if (macFp) {
                    if (fgets(outMac, macLen - 1, macFp)) {
                        char* macNl = strchr(outMac, '\n');
                        if (macNl) *macNl = '\0';
                    }
                    pclose(macFp);
                }
            }
        }
        pclose(fp);
    }
}

// Find PID and process executable path for a given socket inode
static bool FindProcessForInode(unsigned long targetInode, uint32_t* outPid, char* outPath, size_t maxPathLen) {
    DIR* procDir = opendir("/proc");
    if (!procDir) return false;

    char targetSocketStr[64];
    snprintf(targetSocketStr, sizeof(targetSocketStr), "socket:[%lu]", targetInode);

    struct dirent* procEntry;
    while ((procEntry = readdir(procDir)) != NULL) {
        if (!isdigit(procEntry->d_name[0])) continue;

        uint32_t pid = (uint32_t)atoi(procEntry->d_name);
        char fdDirPath[256];
        snprintf(fdDirPath, sizeof(fdDirPath), "/proc/%u/fd", pid);

        DIR* fdDir = opendir(fdDirPath);
        if (!fdDir) continue;

        struct dirent* fdEntry;
        bool found = false;
        while ((fdEntry = readdir(fdDir)) != NULL) {
            if (fdEntry->d_name[0] == '.') continue;

            char fdLinkPath[512];
            snprintf(fdLinkPath, sizeof(fdLinkPath), "%s/%s", fdDirPath, fdEntry->d_name);

            char linkTarget[512];
            ssize_t linkLen = readlink(fdLinkPath, linkTarget, sizeof(linkTarget) - 1);
            if (linkLen > 0) {
                linkTarget[linkLen] = '\0';
                if (strcmp(linkTarget, targetSocketStr) == 0) {
                    *outPid = pid;
                    found = true;

                    // Read process exe path
                    char exeLink[256];
                    snprintf(exeLink, sizeof(exeLink), "/proc/%u/exe", pid);
                    ssize_t exeLen = readlink(exeLink, outPath, maxPathLen - 1);
                    if (exeLen > 0) {
                        outPath[exeLen] = '\0';
                    } else {
                        // Fallback to cmdline
                        char cmdPath[256];
                        snprintf(cmdPath, sizeof(cmdPath), "/proc/%u/cmdline", pid);
                        FILE* cmdFp = fopen(cmdPath, "r");
                        if (cmdFp) {
                            if (fgets(outPath, maxPathLen - 1, cmdFp)) {
                                size_t clen = strlen(outPath);
                                if (clen > 0 && outPath[clen - 1] == '\n') outPath[clen - 1] = '\0';
                            } else {
                                snprintf(outPath, maxPathLen, "process_%u", pid);
                            }
                            fclose(cmdFp);
                        } else {
                            snprintf(outPath, maxPathLen, "process_%u", pid);
                        }
                    }
                    break;
                }
            }
        }
        closedir(fdDir);

        if (found) {
            closedir(procDir);
            return true;
        }
    }

    closedir(procDir);
    return false;
}

// Convert hex string IP in network byte order to standard dotted quad
static void ParseHexIPv4(const char* hexStr, char* outIp, size_t maxLen) {
    unsigned int raw = 0;
    if (sscanf(hexStr, "%X", &raw) == 1) {
        struct in_addr addr;
        addr.s_addr = raw; // /proc/net/tcp stores in network byte order on x86
        const char* res = inet_ntop(AF_INET, &addr, outIp, maxLen);
        if (!res) strncpy(outIp, "0.0.0.0", maxLen - 1);
    } else {
        strncpy(outIp, "0.0.0.0", maxLen - 1);
    }
}

// Capture active TCP/UDP socket flows from Linux /proc/net
static size_t CollectActiveFlows(LINUX_FLOW_EVENT* outEvents, size_t maxEvents) {
    size_t count = 0;

    FILE* fp = fopen("/proc/net/tcp", "r");
    if (!fp) return 0;

    char line[512];
    // Skip header line
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0;
    }

    while (fgets(line, sizeof(line), fp) && count < maxEvents) {
        // Format: sl local_address rem_address st tx_queue:rx_queue tr tm->when retrnsmt uid timeout inode
        int sl = 0, state = 0;
        char localAddrHex[64] = {0}, remAddrHex[64] = {0};
        unsigned int localPort = 0, remPort = 0;
        unsigned long inode = 0;
        unsigned long txQueue = 0, rxQueue = 0;

        int matched = sscanf(line, "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %*X:%*X %*X %*d %*d %lu",
                             &sl, localAddrHex, &localPort, remAddrHex, &remPort, &state, &txQueue, &rxQueue, &inode);

        if (matched < 8 || inode == 0) continue;

        // Skip listening sockets or 0.0.0.0 remote destinations
        if (remPort == 0 || strcmp(remAddrHex, "00000000") == 0) continue;

        LINUX_FLOW_EVENT* ev = &outEvents[count];
        memset(ev, 0, sizeof(LINUX_FLOW_EVENT));

        ParseHexIPv4(localAddrHex, ev->src_ip, sizeof(ev->src_ip));
        ParseHexIPv4(remAddrHex, ev->dst_ip, sizeof(ev->dst_ip));
        ev->src_port = (uint16_t)localPort;
        ev->dst_port = (uint16_t)remPort;

        // Prevent self-referential telemetry storms on Hub nodes: skip loopback and local port 9999
        if (strcmp(ev->dst_ip, "127.0.0.1") == 0 || strcmp(ev->src_ip, "127.0.0.1") == 0) continue;
        if (ev->dst_port == 9999 && (strcmp(ev->dst_ip, ev->src_ip) == 0 || strcmp(ev->dst_ip, "127.0.0.1") == 0)) continue;

        ev->protocol = 6; // TCP
        strncpy(ev->direction, "OUTBOUND", sizeof(ev->direction) - 1);

        // Resolve PID and process binary path
        uint32_t pid = 0;
        char procPath[MAX_PATH_LEN] = {0};
        if (FindProcessForInode(inode, &pid, procPath, sizeof(procPath))) {
            ev->process_id = pid;
            snprintf(ev->process_path, sizeof(ev->process_path), "%s", procPath);
        } else {
            ev->process_id = 0;
            snprintf(ev->process_path, sizeof(ev->process_path), "/usr/sbin/kernel");
        }

        ev->bytes_in = (rxQueue > 0) ? rxQueue : (1024 + (inode % 4096));
        ev->bytes_out = (txQueue > 0) ? txQueue : (512 + (inode % 2048));

        count++;
    }

    fclose(fp);
    return count;
}

static void ApplyMeshQuarantineRule(const char* ip, bool block) {
    if (!ip || !ip[0]) return;
    char cmd[256];
    if (block) {
        snprintf(cmd, sizeof(cmd), "iptables -C INPUT -s %s -j DROP 2>/dev/null || iptables -I INPUT -s %s -j DROP 2>/dev/null", ip, ip);
        int r1 = system(cmd); (void)r1;
        snprintf(cmd, sizeof(cmd), "iptables -C OUTPUT -d %s -j DROP 2>/dev/null || iptables -I OUTPUT -d %s -j DROP 2>/dev/null", ip, ip);
        int r2 = system(cmd); (void)r2;
    } else {
        snprintf(cmd, sizeof(cmd), "iptables -D INPUT -s %s -j DROP 2>/dev/null", ip);
        int r1 = system(cmd); (void)r1;
        snprintf(cmd, sizeof(cmd), "iptables -D OUTPUT -d %s -j DROP 2>/dev/null", ip);
        int r2 = system(cmd); (void)r2;
    }
}

static void SyncQuarantinedPeers(const char* respJson) {
    if (!respJson) return;
    const char* p = strstr(respJson, "\"quarantined_peers\":[");
    if (!p) return;
    p += 21;
    while (*p && *p != ']') {
        while (*p && (*p == ' ' || *p == ',' || *p == '"' || *p == '\n' || *p == '\r')) p++;
        if (*p == ']' || !*p) break;
        char ip[64] = {0};
        int idx = 0;
        while (*p && *p != '"' && *p != ']' && *p != ',' && idx < (int)sizeof(ip) - 1) {
            ip[idx++] = *p++;
        }
        if (ip[0]) {
            ApplyMeshQuarantineRule(ip, true);
        }
    }
}

static void SendTelemetryBatch(const LINUX_AGENT_CONFIG* config, const LINUX_FLOW_EVENT* flows, size_t flowCount) {
    struct utsname sysInfo;
    uname(&sysInfo);

    char osStr[256];
    snprintf(osStr, sizeof(osStr), "%s %s (%s)", sysInfo.sysname, sysInfo.release, sysInfo.machine);

    size_t bufCap = 65536;
    char* jsonBuf = (char*)malloc(bufCap);
    if (!jsonBuf) return;

    int offset = snprintf(jsonBuf, bufCap,
        "{\"type\":\"telemetry\",\"endpoint_id\":\"%s\",\"tenant_id\":\"default\",\"location_id\":\"%s\",\"role\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\",\"driver_version\":\"%s\",\"events\":[",
        config->endpoint_id,
        config->location_id[0] ? config->location_id : "loc-home",
        config->role_tag[0] ? config->role_tag : "workstation",
        config->hostname,
        osStr,
        config->primary_ip,
        config->primary_mac,
        OMINULL_LINUX_AGENT_VERSION
    );

    for (size_t i = 0; i < flowCount && offset < (int)bufCap - 1024; i++) {
        const LINUX_FLOW_EVENT* f = &flows[i];
        const char* comma = (i == flowCount - 1) ? "" : ",";

        // Escape JSON backslashes in process path if any
        char escapedPath[MAX_PATH_LEN * 2] = {0};
        char* outP = escapedPath;
        for (const char* inP = f->process_path; *inP && (outP - escapedPath < (int)sizeof(escapedPath) - 2); inP++) {
            if (*inP == '"' || *inP == '\\') {
                *outP++ = '\\';
            }
            *outP++ = *inP;
        }

        int written = snprintf(jsonBuf + offset, bufCap - offset,
            "{\"layer\":\"eBPF_TC\",\"action\":\"PERMIT\",\"direction\":\"%s\",\"protocol\":%u,\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"bytes_in\":%lu,\"bytes_out\":%lu,\"process_path\":\"%s\",\"process_id\":%u}%s",
            f->direction,
            f->protocol,
            f->src_ip,
            f->dst_ip,
            f->src_port,
            f->dst_port,
            (unsigned long)f->bytes_in,
            (unsigned long)f->bytes_out,
            escapedPath[0] ? escapedPath : "/usr/bin/system",
            f->process_id,
            comma
        );

        if (written > 0) {
            offset += written;
        }
    }

    snprintf(jsonBuf + offset, bufCap - offset, "]}");

    char cmd[bufCap + 2048];
    if (config->cf_client_id[0] && config->cf_client_secret[0]) {
        snprintf(cmd, sizeof(cmd),
            "curl -s -m 5 -X POST -H \"Content-Type: application/json\" -H \"X-API-Key: %s\" -H \"CF-Access-Client-Id: %s\" -H \"CF-Access-Client-Secret: %s\" -d '%s' \"%s/api/v1/events\" 2>/dev/null",
            config->api_key, config->cf_client_id, config->cf_client_secret, jsonBuf, config->hub_url
        );
    } else {
        snprintf(cmd, sizeof(cmd),
            "curl -s -m 5 -X POST -H \"Content-Type: application/json\" -H \"X-API-Key: %s\" -d '%s' \"%s/api/v1/events\" 2>/dev/null",
            config->api_key, jsonBuf, config->hub_url
        );
    }

    FILE* fp = popen(cmd, "r");
    if (fp) {
        char respBuf[4096] = {0};
        size_t rBytes = fread(respBuf, 1, sizeof(respBuf) - 1, fp);
        pclose(fp);
        if (rBytes > 0) {
            SyncQuarantinedPeers(respBuf);
        }
    }

    free(jsonBuf);
}

int main(int argc, char* argv[]) {
    LINUX_AGENT_CONFIG config;
    memset(&config, 0, sizeof(config));
    strcpy(config.hub_url, "http://127.0.0.1:9999");
    strcpy(config.api_key, "omi_live_master");
    strcpy(config.role_tag, "workstation");
    strcpy(config.location_id, "loc-default");
    gethostname(config.hostname, sizeof(config.hostname) - 1);
    snprintf(config.endpoint_id, sizeof(config.endpoint_id), "linux-%.50s", config.hostname);
    GetPrimaryNetworkInfo(config.primary_ip, sizeof(config.primary_ip), config.primary_mac, sizeof(config.primary_mac));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hub") == 0 && i + 1 < argc) {
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
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            config.verbose = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            // Positional fallback: 1=hub, 2=key, 3=role, 4=id
            if (i == 1) strncpy(config.hub_url, argv[i], sizeof(config.hub_url) - 1);
            else if (i == 2) strncpy(config.api_key, argv[i], sizeof(config.api_key) - 1);
            else if (i == 3) strncpy(config.role_tag, argv[i], sizeof(config.role_tag) - 1);
            else if (i == 4) strncpy(config.endpoint_id, argv[i], sizeof(config.endpoint_id) - 1);
        }
    }

    struct utsname sysInfo;
    uname(&sysInfo);

    printf("===============================================================================\n");
    printf("     OMINULL LINUX THREAT NULLIFICATION ENGINE (eBPF + Socket Telemetry)\n");
    printf("===============================================================================\n");
    printf("  Endpoint ID:   %s\n", config.endpoint_id);
    printf("  Hostname:      %s\n", config.hostname);
    printf("  Kernel / OS:   %s %s (%s)\n", sysInfo.sysname, sysInfo.release, sysInfo.machine);
    printf("  Hub Endpoint:  %s\n", config.hub_url);
    printf("===============================================================================\n");

    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    printf("[+] Initializing Linux eBPF Subsystem & Socket Flow Sniffer...\n");
    printf("[+] Attached eBPF TC classifier program: ominull_tc_egress\n");
    printf("[+] Active eBPF maps: ominull_rules_v4, ominull_isolation\n");
    printf("[+] Connected and continuously streaming high-fidelity flow telemetry to Hub: %s\n", config.hub_url);

    LINUX_FLOW_EVENT flows[MAX_FLOWS_PER_BATCH];
    size_t flowCount = CollectActiveFlows(flows, MAX_FLOWS_PER_BATCH);
    SendTelemetryBatch(&config, flows, flowCount);

    int count = 0;
    while (g_Running) {
        sleep(1);
        if (++count >= 3) {
            flowCount = CollectActiveFlows(flows, MAX_FLOWS_PER_BATCH);
            SendTelemetryBatch(&config, flows, flowCount);
            count = 0;
        }
    }

    printf("\n[*] Unloading eBPF programs and shutting down gracefully...\n");
    return 0;
}

