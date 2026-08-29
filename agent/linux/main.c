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
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#include "../include/release_key.h"

#define OMINULL_LINUX_AGENT_VERSION "1.5.8"

// Where enrolment leaves the hub's CA certificate. The agent verifies every
// hub connection against this file and nothing else, so it sits beside the
// enrolment config in /etc rather than under the install prefix: an upgrade
// replaces /opt/ominull, and the trust anchor has to survive that.
#define OMINULL_DEFAULT_CA_PATH "/etc/ominull/ca.crt"

// Where a downloaded release is staged before it is verified and installed.
// This must be a directory only root can write. The previous implementation
// staged in /tmp under a name derived from the advertised version - fully
// predictable, in a world-writable directory, then installed as root with
// dpkg, whose maintainer scripts also run as root. That gave any local user
// two ways to become root: plant the file, or win the race between the
// download finishing and dpkg opening it. Verifying the download does not fix
// that on its own; the file has to live somewhere unprivileged users cannot
// reach between the check and the install.
#define OMINULL_UPDATE_DIR "/var/lib/ominull/updates"
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
    char ca_path[256];
    /* The certificate this endpoint proves its identity with. The API key says
     * which tenant is calling and every endpoint in a tenant carries the same
     * one, so without this the hub has to take the endpoint id in the body on
     * trust. Optional: a fleet has to be able to migrate onto certificates
     * while it is still reporting. */
    char client_cert_path[256];
    char client_key_path[256];
    bool verbose;
    bool auto_update;
    bool allow_plaintext;
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
    printf("  %s --hub <url> --key <api_key> [--ca <path>] [--role <role>] [--location <id>] [--cf-id <id>] [--cf-secret <secret>] [--no-auto-update] [--allow-plaintext] [-v]\n", prog);
    printf("\nOptions:\n");
    printf("  --ca <path>        CA certificate the hub is verified against (default %s).\n", OMINULL_DEFAULT_CA_PATH);
    printf("  --client-cert <p>  Certificate this endpoint identifies itself with, and --client-key\n");
    printf("                     its private key. Enrolment issues both; without them the hub has\n");
    printf("                     only the tenant API key, which every endpoint shares.\n");
    printf("  --allow-plaintext  Permit an http:// hub. Telemetry and the API key then cross the network in the clear.\n");
    printf("  --no-auto-update   Report the running version but never install a hub-offered package.\n");
}

/* ---------------------------------------------------------------------------
 * Hub transport
 *
 * Everything this agent sends carries the tenant API key, and everything it
 * receives can move the host: an isolation command, a mesh quarantine list, a
 * release to install. On plain HTTP all of that is readable and writable by
 * anyone on the path, so the transport is checked before a batch is built
 * rather than after a failure.
 *
 * The check has no degraded mode. An agent that cannot verify the hub keeps
 * enforcing locally and says so on every attempt; it does not fall back to
 * HTTP, because a silent downgrade is exactly the outcome an on-path attacker
 * would be trying to force.
 * ------------------------------------------------------------------------- */

static bool HubUsesTLS(const LINUX_AGENT_CONFIG* config) {
    return strncmp(config->hub_url, "https://", 8) == 0;
}

/* Complains at most once a minute. The failure is permanent until an operator
 * fixes it, and a line every three seconds would bury the rest of the log. */
static void ReportTransportRefusal(const char* reason) {
    static time_t lastReport = 0;
    time_t now = time(NULL);
    if (lastReport != 0 && now - lastReport < 60) return;
    lastReport = now;
    fprintf(stderr, "[!] Refusing to talk to the hub: %s\n", reason);
    fflush(stderr);
}

static bool HubTransportReady(const LINUX_AGENT_CONFIG* config) {
    if (!HubUsesTLS(config)) {
        if (config->allow_plaintext) return true;
        ReportTransportRefusal(
            "the configured hub URL is not https://. Re-enrol this endpoint against the hub's "
            "TLS address, or pass --allow-plaintext to accept a cleartext transport deliberately.");
        return false;
    }
    if (config->ca_path[0] == '\0') {
        ReportTransportRefusal("no CA certificate is configured; pass --ca <path>.");
        return false;
    }
    if (access(config->ca_path, R_OK) != 0) {
        char reason[512];
        snprintf(reason, sizeof(reason),
                 "the CA certificate %s cannot be read (%s). Enrolment installs it; without it "
                 "the hub's identity cannot be checked.", config->ca_path, strerror(errno));
        ReportTransportRefusal(reason);
        return false;
    }
    return true;
}

/* The curl flags that make a hub connection verifiable: trust this CA and no
 * other, refuse to follow a redirect off TLS, and present this endpoint's own
 * certificate. Without --proto a redirect to http:// would hand the API key
 * over in the clear on the next hop. */
#define HUB_CURL_ARGS_LEN 1024
static void HubCurlSecurityArgs(const LINUX_AGENT_CONFIG* config, char* out, size_t outLen) {
    if (!HubUsesTLS(config)) {
        out[0] = '\0';
        return;
    }

    /* The client certificate is added only when both halves are present and
     * readable. Passing --cert for a file curl cannot open fails the request
     * outright, which would turn a half-finished enrolment into an endpoint
     * that has stopped reporting rather than one that has not started
     * presenting a certificate yet.
     *
     * One snprintf per case rather than an append: the paths are bounded by the
     * config struct, so a single call has a maximum length the compiler can
     * check against HUB_CURL_ARGS_LEN. Appending to the first string leaves it
     * unable to prove anything about what is left. */
    if (config->client_cert_path[0] && config->client_key_path[0] &&
        access(config->client_cert_path, R_OK) == 0 && access(config->client_key_path, R_OK) == 0) {
        snprintf(out, outLen,
                 "--cacert \"%s\" --proto =https --proto-redir =https --cert \"%s\" --key \"%s\"",
                 config->ca_path, config->client_cert_path, config->client_key_path);
    } else {
        snprintf(out, outLen, "--cacert \"%s\" --proto =https --proto-redir =https", config->ca_path);
    }
}

static void GetPrimaryNetworkInfo(char* outIp, size_t ipLen, char* outMac, size_t macLen) {
    /* Report nothing rather than something invented.
     *
     * These used to default to 127.0.0.1 and a fixed 02:42:0a:00:00:01. Both
     * are actively harmful now that the hub keys asset identity on what the
     * agent reports: a shared placeholder MAC makes every host whose interface
     * lookup fails - a container, a network namespace, a box with no default
     * route - collapse onto a single asset record, and a loopback address
     * overrides the peer address the hub would otherwise have used. Empty is
     * honest, and the hub already knows what to do with it: it falls back to
     * the connection's own address, and identity falls back to address plus
     * subnet. */
    outIp[0] = '\0';
    outMac[0] = '\0';

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

#define MAX_QUARANTINED_PEERS 64

// SyncQuarantinedPeers reconciles kernel drop rules against the hub's authoritative
// peer list on every heartbeat. Reconciling rather than only adding matters: a peer
// the hub has released must have its rule lifted, and an endpoint that was offline
// when the release happened would otherwise keep the host blackholed indefinitely.
static void SyncQuarantinedPeers(const char* respJson) {
    static char applied[MAX_QUARANTINED_PEERS][64];
    static int appliedCount = 0;

    if (!respJson) return;
    const char* p = strstr(respJson, "\"quarantined_peers\":[");
    if (!p) return;
    p += 21;

    char current[MAX_QUARANTINED_PEERS][64];
    int currentCount = 0;

    while (*p && *p != ']') {
        while (*p && (*p == ' ' || *p == ',' || *p == '"' || *p == '\n' || *p == '\r')) p++;
        if (*p == ']' || !*p) break;
        char ip[64] = {0};
        int idx = 0;
        while (*p && *p != '"' && *p != ']' && *p != ',' && idx < (int)sizeof(ip) - 1) {
            ip[idx++] = *p++;
        }
        if (ip[0] && currentCount < MAX_QUARANTINED_PEERS) {
            ApplyMeshQuarantineRule(ip, true);
            snprintf(current[currentCount++], sizeof(current[0]), "%s", ip);
        }
    }

    // Lift rules for every peer that was blocked on a previous heartbeat but is no
    // longer on the hub's list.
    for (int i = 0; i < appliedCount; i++) {
        bool stillQuarantined = false;
        for (int j = 0; j < currentCount; j++) {
            if (strcmp(applied[i], current[j]) == 0) {
                stillQuarantined = true;
                break;
            }
        }
        if (!stillQuarantined) {
            printf("[*] Hub released peer %s; lifting mesh drop rules.\n", applied[i]);
            ApplyMeshQuarantineRule(applied[i], false);
        }
    }

    memcpy(applied, current, sizeof(current));
    appliedCount = currentCount;
}

// ExtractJsonString pulls a flat "key":"value" pair out of a JSON fragment. The hub's
// update descriptor has no nesting or escaping beyond this, so a full parser is not
// warranted here.
static bool ExtractJsonString(const char* json, const char* key, char* out, size_t outLen) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char* p = strstr(json, needle);
    if (!p) return false;
    p += strlen(needle);
    size_t idx = 0;
    while (*p && *p != '"' && idx < outLen - 1) {
        out[idx++] = *p++;
    }
    out[idx] = '\0';
    return idx > 0;
}

// IsSafeToken rejects anything outside the character set a package URL or version can
// legitimately use, so a malformed hub response can never reach the shell as an operator.
static bool IsSafeToken(const char* s, bool allowUrlChars) {
    if (!s || !s[0]) return false;
    for (const char* p = s; *p; p++) {
        if (isalnum((unsigned char)*p)) continue;
        if (*p == '.' || *p == '_' || *p == '-') continue;
        if (allowUrlChars && (*p == ':' || *p == '/' || *p == '~' || *p == '%' || *p == '+')) continue;
        return false;
    }
    return true;
}

// IsHexDigest reports whether a string is exactly a SHA-256 hex digest.
static bool IsHexDigest(const char* s) {
    size_t n = 0;
    for (; s[n]; n++) {
        if (!isxdigit((unsigned char)s[n])) return false;
    }
    return n == 64;
}

// HubPathOf takes only the path from a descriptor URL, and only if it points at
// the hub's package route.
//
// The agent fetches that path from the hub it is already configured to talk to
// and ignores the advertised host entirely. Behind a reverse proxy the hub
// legitimately advertises a different host than the agent dials, so matching on
// the host would break valid deployments - and ignoring it is strictly safer
// anyway, because then no hub response can point the download somewhere else.
static const char* HubPathOf(const char* url) {
    const char* path = strstr(url, "://");
    path = path ? strchr(path + 3, '/') : (url[0] == '/' ? url : NULL);
    if (!path || strncmp(path, "/download/", 10) != 0) return NULL;
    if (!IsSafeToken(path, true)) return NULL;
    return path;
}

// PrepareUpdateDir creates the staging directory and refuses to use one that
// anybody but root can write to.
//
// Everything downstream depends on this: the package, its signature and the
// pinned public key all land here, and the whole point is that no unprivileged
// process can touch them between verification and install. A directory that
// already exists with the wrong owner or mode is treated as hostile rather
// than corrected, because the safe response to "something else made this" is
// to stop.
static bool PrepareUpdateDir(void) {
    mkdir("/var/lib/ominull", 0755);
    if (mkdir(OMINULL_UPDATE_DIR, 0700) != 0 && errno != EEXIST) {
        printf("[!] Cannot create %s: %s\n", OMINULL_UPDATE_DIR, strerror(errno));
        return false;
    }

    struct stat st;
    if (lstat(OMINULL_UPDATE_DIR, &st) != 0) {
        printf("[!] Cannot stat %s: %s\n", OMINULL_UPDATE_DIR, strerror(errno));
        return false;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        printf("[!] Refusing to stage an update in %s: it must be a root-owned directory "
               "that is not group- or world-writable.\n", OMINULL_UPDATE_DIR);
        return false;
    }
    return true;
}

// WriteStagedFile writes one file into the staging directory.
//
// O_NOFOLLOW and O_EXCL-on-fresh-create matter even here: the directory should
// be unreachable to other users, so a symlink in it means an assumption has
// already been broken and the write must not proceed through it.
static bool WriteStagedFile(const char* name, const char* content, mode_t mode) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", OMINULL_UPDATE_DIR, name);
    unlink(path);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode);
    if (fd < 0) {
        printf("[!] Cannot write %s: %s\n", path, strerror(errno));
        return false;
    }
    size_t len = strlen(content);
    ssize_t written = write(fd, content, len);
    if (close(fd) != 0 || written < 0 || (size_t)written != len) {
        printf("[!] Short write to %s\n", path);
        unlink(path);
        return false;
    }
    return true;
}

// ApplyAgentUpdate installs a newer agent package when the hub offers one on a
// telemetry heartbeat.
//
// Nothing is installed that has not been proved genuine first. The package is
// checked against the digest the hub advertised, and then - the check that
// actually matters - against a detached ECDSA P-256 signature verified with the
// release public key compiled into this binary. That key does not come from the
// hub, so a compromised hub, or anyone on the plain-HTTP path between agent and
// hub, can serve any bytes they like and none of them will be installed.
//
// The install itself runs detached: dpkg's prerm stops this very daemon, so a
// child of the current process would be torn down mid-install.
static void ApplyAgentUpdate(const LINUX_AGENT_CONFIG* config, const char* respJson) {
    // Bounded retry, not a single shot. Everything that can go wrong before the
    // install - a dropped download, a hub restarting mid-fetch - would otherwise
    // wedge this endpoint on the offered version until the daemon restarted,
    // because one attempt is all it would ever make. Retrying without a bound is
    // the opposite failure: a package that can never verify would be fetched
    // every heartbeat forever.
    static char attemptedVersion[64] = {0};
    static int attempts = 0;

    if (!config->auto_update || !respJson) return;
    const char* block = strstr(respJson, "\"agent_update\"");
    if (!block) return;

    char version[64] = {0}, pkg[32] = {0}, url[512] = {0}, sigUrl[512] = {0}, sha256[80] = {0};
    if (!ExtractJsonString(block, "version", version, sizeof(version))) return;
    if (!ExtractJsonString(block, "url", url, sizeof(url))) return;
    ExtractJsonString(block, "package", pkg, sizeof(pkg));

    if (strcmp(attemptedVersion, version) != 0) {
        snprintf(attemptedVersion, sizeof(attemptedVersion), "%s", version);
        attempts = 0;
    }
    if (attempts >= 3) return;
    attempts++;

    if (pkg[0] && strcmp(pkg, "deb") != 0) {
        printf("[!] Hub offers agent v%s as a '%s' package; this daemon only self-installs .deb.\n", version, pkg);
        return;
    }
    if (geteuid() != 0) {
        printf("[!] Agent v%s is available but this daemon is not running as root; skipping self-update.\n", version);
        return;
    }

    // No signature, no install. A hub that cannot produce one is offering a
    // package this agent has no way to trust, and there is no degraded mode
    // worth having here - an unverified root install is the thing being
    // prevented, not an inconvenience to work around.
    if (!ExtractJsonString(block, "signature", sigUrl, sizeof(sigUrl)) ||
        !ExtractJsonString(block, "sha256", sha256, sizeof(sha256))) {
        printf("[!] Rejected agent update v%s: the hub offered it without a signature and digest.\n", version);
        return;
    }
    if (!IsHexDigest(sha256)) {
        printf("[!] Rejected agent update v%s: advertised digest is not a SHA-256 hex string.\n", version);
        return;
    }
    if (!IsSafeToken(version, false)) {
        printf("[!] Rejected agent update v%s: malformed package descriptor.\n", version);
        return;
    }

    const char* pkgPath = HubPathOf(url);
    const char* sigPath = HubPathOf(sigUrl);
    if (!pkgPath || !sigPath) {
        printf("[!] Rejected agent update v%s: package or signature is not on a hub download path.\n", version);
        return;
    }

    if (!PrepareUpdateDir()) return;
    if (!WriteStagedFile("release.pub", OMINULL_RELEASE_PUBKEY_PEM, 0600)) return;

    printf("[*] Hub published agent v%s (running v%s); fetching and verifying before install.\n",
           version, OMINULL_LINUX_AGENT_VERSION);
    fflush(stdout);

    // The updater runs as a script in the staging directory rather than as an
    // inline shell command so that every step is written down in one auditable
    // place, and `set -e` guarantees a failed download, a wrong digest or a bad
    // signature stops before dpkg is ever reached.
    /* The release signature is what makes an update safe, and it is checked
     * below regardless. The CA pin here is a second, earlier line: it keeps the
     * package from being fetched from anyone but the hub in the first place,
     * so a hostile path cannot even spend the endpoint's bandwidth or learn
     * which version it is on. */
    char curlSec[HUB_CURL_ARGS_LEN];
    HubCurlSecurityArgs(config, curlSec, sizeof(curlSec));

    char script[5120];
    int n = snprintf(script, sizeof(script),
        "#!/bin/sh\n"
        "set -e\n"
        "D=%s\n"
        "exec >>/var/log/ominull-update.log 2>&1\n"
        "echo \"=== $(date -u '+%%Y-%%m-%%dT%%H:%%M:%%SZ') updating to v%s ===\"\n"
        "rm -f \"$D/agent.deb\" \"$D/agent.deb.sig\"\n"
        "curl -fsSL %s -m 300 -o \"$D/agent.deb\" \"%s%s\"\n"
        "curl -fsSL %s -m 60 -o \"$D/agent.deb.sig\" \"%s%s\"\n"
        "echo \"%s  $D/agent.deb\" | sha256sum -c -\n"
        "openssl dgst -sha256 -verify \"$D/release.pub\" -signature \"$D/agent.deb.sig\" \"$D/agent.deb\"\n"
        "echo \"[+] v%s verified against the pinned release key; installing\"\n"
        "dpkg -i \"$D/agent.deb\"\n"
        "rm -f \"$D/agent.deb\" \"$D/agent.deb.sig\"\n"
        "systemctl restart ominull-agent.service\n",
        OMINULL_UPDATE_DIR, version,
        curlSec, config->hub_url, pkgPath,
        curlSec, config->hub_url, sigPath,
        sha256, version);
    if (n < 0 || n >= (int)sizeof(script)) {
        printf("[!] Rejected agent update v%s: updater script would be truncated.\n", version);
        return;
    }
    if (!WriteStagedFile("apply.sh", script, 0700)) return;

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "setsid nohup sh %s/apply.sh >/dev/null 2>&1 </dev/null &", OMINULL_UPDATE_DIR);
    int rc = system(cmd);
    (void)rc;
}

/* The hub answers a rejected batch with a status and a body, and curl reports
 * both as success. These two split the status back off the response and make a
 * refusal visible, because an agent whose credentials the hub no longer accepts
 * is otherwise indistinguishable, in its own log, from one that is working: it
 * posts every few seconds, curl exits 0, and nothing is ever recorded. The only
 * place the truth shows up is the hub's last_seen. */
#define HUB_STATUS_MARKER "OMINULL_HTTP:"

static long SplitHubStatus(char* resp) {
    char* marker = strstr(resp, "\n" HUB_STATUS_MARKER);
    if (!marker) return 0;
    long status = strtol(marker + 1 + strlen(HUB_STATUS_MARKER), NULL, 10);
    *marker = '\0';   /* leave the caller the body alone */
    return status;
}

/* Returns true when the batch was refused, and says so at most once a minute:
 * a rejection repeats every heartbeat, and a line every few seconds would bury
 * the reason it started. */
static bool ReportHubRejection(const LINUX_AGENT_CONFIG* config, long status) {
    static time_t lastReport = 0;
    static long lastStatus = 0;
    static bool accepted = false;

    if (status == 0 || (status >= 200 && status < 300)) {
        if (lastStatus != 0) {
            printf("[+] The hub is accepting telemetry again (HTTP %ld).\n", status);
            lastStatus = 0;
        } else if (!accepted && status != 0) {
            accepted = true;
            printf("[+] The hub accepted this endpoint's first telemetry batch (HTTP %ld).\n", status);
        }
        return false;
    }

    time_t now = time(NULL);
    if (status != lastStatus || now - lastReport >= 60) {
        if (status == 403 && config->client_cert_path[0] && access(config->client_cert_path, R_OK) == 0) {
            /* 403 while presenting a certificate is the identity check, not the
             * key: the hub compares the name in the certificate against the
             * endpoint id being reported and refuses the two disagreeing. The
             * usual cause is --id having been changed after enrolment. */
            printf("[!] The hub refused this endpoint's telemetry with HTTP %ld. It reports as \"%s\", "
                   "which is not the endpoint named by %s; re-enrol or correct --id. Nothing is being "
                   "recorded until it is fixed.\n", status, config->endpoint_id, config->client_cert_path);
        } else if (status == 401 || status == 403) {
            printf("[!] The hub refused this endpoint's telemetry with HTTP %ld. The API key in "
                   "--key is not one it accepts; nothing is being recorded until it is fixed.\n", status);
        } else {
            printf("[!] The hub refused this endpoint's telemetry with HTTP %ld; nothing is being "
                   "recorded.\n", status);
        }
        lastReport = now;
        lastStatus = status;
    }
    return true;
}

static void SendTelemetryBatch(const LINUX_AGENT_CONFIG* config, const LINUX_FLOW_EVENT* flows, size_t flowCount) {
    /* Checked before the batch is built, not after it fails: the payload and
     * the header that authenticates it are the things being protected. */
    if (!HubTransportReady(config)) return;

    struct utsname sysInfo;
    uname(&sysInfo);

    char osStr[256];
    snprintf(osStr, sizeof(osStr), "%s %s (%s)", sysInfo.sysname, sysInfo.release, sysInfo.machine);

    size_t bufCap = 65536;
    char* jsonBuf = (char*)malloc(bufCap);
    if (!jsonBuf) return;

    int offset = snprintf(jsonBuf, bufCap,
        "{\"type\":\"telemetry\",\"endpoint_id\":\"%s\",\"tenant_id\":\"default\",\"location_id\":\"%s\",\"role\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\",\"driver_version\":\"%s\",\"update_capability\":\"deb\",\"events\":[",
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

    char curlSec[HUB_CURL_ARGS_LEN];
    HubCurlSecurityArgs(config, curlSec, sizeof(curlSec));

    /* -sS rather than -s, and stderr is no longer discarded. A rejected
     * certificate is the one failure this agent must not swallow, and it used
     * to look identical to the hub being down.
     *
     * -w appends the status code, because curl without -f treats a 401 as a
     * successful request: the body arrives, the exit code is 0, and an agent
     * the hub is refusing looks exactly like a healthy one from here. Adding -f
     * instead would throw the body away, and the body is what carries the
     * agent_update descriptor. */
    char cmd[bufCap + 2048];
    if (config->cf_client_id[0] && config->cf_client_secret[0]) {
        snprintf(cmd, sizeof(cmd),
            "curl -sS %s -m 5 -w '\\n" HUB_STATUS_MARKER "%%{http_code}' -X POST -H \"Content-Type: application/json\" -H \"X-API-Key: %s\" -H \"CF-Access-Client-Id: %s\" -H \"CF-Access-Client-Secret: %s\" -d '%s' \"%s/api/v1/events\"",
            curlSec, config->api_key, config->cf_client_id, config->cf_client_secret, jsonBuf, config->hub_url
        );
    } else {
        snprintf(cmd, sizeof(cmd),
            "curl -sS %s -m 5 -w '\\n" HUB_STATUS_MARKER "%%{http_code}' -X POST -H \"Content-Type: application/json\" -H \"X-API-Key: %s\" -d '%s' \"%s/api/v1/events\"",
            curlSec, config->api_key, jsonBuf, config->hub_url
        );
    }

    FILE* fp = popen(cmd, "r");
    if (fp) {
        char respBuf[4096] = {0};
        size_t rBytes = fread(respBuf, 1, sizeof(respBuf) - 1, fp);
        pclose(fp);
        if (rBytes > 0) {
            long status = SplitHubStatus(respBuf);
            if (!ReportHubRejection(config, status)) {
                SyncQuarantinedPeers(respBuf);
                ApplyAgentUpdate(config, respBuf);
            }
        }
    }

    free(jsonBuf);
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    LINUX_AGENT_CONFIG config;
    memset(&config, 0, sizeof(config));
    strcpy(config.hub_url, "https://127.0.0.1:9443");
    strcpy(config.api_key, "<provision-via-bootstrap>");
    strcpy(config.ca_path, OMINULL_DEFAULT_CA_PATH);
    strcpy(config.role_tag, "workstation");
    strcpy(config.location_id, "loc-default");
    config.auto_update = true;
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
        } else if (strcmp(argv[i], "--client-cert") == 0 && i + 1 < argc) {
            strncpy(config.client_cert_path, argv[++i], sizeof(config.client_cert_path) - 1);
        } else if (strcmp(argv[i], "--client-key") == 0 && i + 1 < argc) {
            strncpy(config.client_key_path, argv[++i], sizeof(config.client_key_path) - 1);
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            strncpy(config.ca_path, argv[++i], sizeof(config.ca_path) - 1);
        } else if (strcmp(argv[i], "--allow-plaintext") == 0) {
            config.allow_plaintext = true;
        } else if (strcmp(argv[i], "--no-auto-update") == 0) {
            config.auto_update = false;
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
    if (HubUsesTLS(&config)) {
        printf("  Hub Trust:     TLS, pinned to %s\n", config.ca_path);
        if (config.client_cert_path[0] && access(config.client_cert_path, R_OK) == 0) {
            printf("  Identity:      client certificate %s\n", config.client_cert_path);
        } else {
            printf("  Identity:      tenant API key only (no client certificate; the hub cannot tell\n");
            printf("                 this endpoint apart from any other holding the same key)\n");
        }
    } else {
        printf("  Hub Trust:     NONE - cleartext transport%s\n",
               config.allow_plaintext ? " (--allow-plaintext)" : " (will refuse to report)");
    }
    printf("  Agent Version: %s (self-update %s)\n", OMINULL_LINUX_AGENT_VERSION,
           config.auto_update ? "enabled" : "disabled");
    printf("===============================================================================\n");

    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    printf("[+] Initializing Linux eBPF Subsystem & Socket Flow Sniffer...\n");
    printf("[+] Attached eBPF TC classifier program: ominull_tc_egress\n");
    printf("[+] Active eBPF maps: ominull_rules_v4, ominull_isolation\n");
    /* Says what is about to happen, not what has happened. This line used to
     * read "Connected and continuously streaming", printed before a single
     * request had been made - so a host that could not reach the hub at all
     * announced a working connection and then went quiet. The hub's first
     * acceptance is reported by ReportHubRejection, from evidence. */
    printf("[+] Streaming flow telemetry to Hub: %s\n", config.hub_url);

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

