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
#include <netdb.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>

#include "../include/release_key.h"

#define OMINULL_LINUX_AGENT_VERSION "1.7.11"

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
    /* Where api_key was read from, when it came from a file rather than an
     * argument. Every argument of every process is world-readable through
     * /proc/<pid>/cmdline, so a key passed with --key is a key any account on
     * this host can lift out of `ps` - and it is the tenant key, shared by the
     * whole fleet. --key stays for the installer, which has no other channel;
     * the daemon that runs afterwards should be given a path. */
    char key_path[256];
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

/* ReadKeyFile takes the first line of a file as the API key. A file is the only
 * channel that keeps the credential off the command line, and the mode is
 * checked because a 0644 key file would give back exactly the exposure the
 * file was introduced to remove. */
static bool ReadKeyFile(const char* path, char* out, size_t cap) {
    struct stat st;
    if (stat(path, &st) != 0) {
        printf("[!] Cannot read the API key file %s: %s\n", path, strerror(errno));
        return false;
    }
    if (st.st_mode & (S_IRGRP | S_IROTH)) {
        printf("[!] API key file %s is readable beyond its owner; tighten it to 0600.\n", path);
    }
    FILE* f = fopen(path, "r");
    if (!f) {
        printf("[!] Cannot open the API key file %s: %s\n", path, strerror(errno));
        return false;
    }
    char line[512] = {0};
    char* got = fgets(line, sizeof(line), f);
    fclose(f);
    if (!got) {
        printf("[!] API key file %s is empty.\n", path);
        return false;
    }
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r' ||
                     line[n - 1] == ' ' || line[n - 1] == '\t')) {
        line[--n] = '\0';
    }
    if (!line[0]) {
        printf("[!] API key file %s holds no key on its first line.\n", path);
        return false;
    }
    snprintf(out, cap, "%s", line);
    return true;
}

static void PrintUsage(const char* prog) {
    printf("Ominull Linux Threat Nullification Daemon (v%s)\n", OMINULL_LINUX_AGENT_VERSION);
    printf("Usage:\n");
    printf("  %s --hub <url> --key-file <path> [--ca <path>] [--role <role>] [--location <id>] [--cf-id <id>] [--cf-secret <secret>] [--no-auto-update] [--allow-plaintext] [-v]\n", prog);
    printf("\nOptions:\n");
    printf("  --key-file <path>  Read the tenant API key from a file instead of --key. Prefer this:\n");
    printf("                     an argument is world-readable through /proc/<pid>/cmdline.\n");
    printf("  --ca <path>        CA certificate the hub is verified against (default %s).\n", OMINULL_DEFAULT_CA_PATH);
    printf("  --client-cert <p>  Certificate this endpoint identifies itself with, and --client-key\n");
    printf("                     its private key. Enrolment issues both; without them the hub has\n");
    printf("                     only the tenant API key, which every endpoint shares.\n");
    printf("  --allow-plaintext  Permit an http:// hub. Telemetry and the API key then cross the network in the clear.\n");
    printf("  --no-auto-update   Report the running version but never install a hub-offered package.\n");
    printf("  --version          Print the version and exit.\n");
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
#define OMINULL_STR_(x) #x
#define OMINULL_STR(x) OMINULL_STR_(x)

/* The hub answers a rejected batch with a status and a body, and curl reports
 * both as success. The marker splits the status back off the response and
 * makes a refusal visible, because an agent whose credentials the hub no
 * longer accepts is otherwise indistinguishable, in its own log, from one
 * that is working. */
#define HUB_STATUS_MARKER "OMINULL_HTTP:"
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

        /* The queue depths from /proc/net/tcp, and zero when there are none.
         *
         * The fallback here used to be 1024 + (inode % 4096) in and
         * 512 + (inode % 2048) out - a hash of the socket inode, reported as a
         * measurement and totalled on the console as bandwidth. Zero is the
         * honest answer for a flow this path cannot measure; the hub no longer
         * substitutes anything for it either.
         *
         * What is reported when they are non-zero is a point-in-time queue
         * depth, not a cumulative byte count for the flow. It is a real
         * reading, which is why it is kept, but it is not the same quantity. */
        ev->bytes_in = rxQueue;
        ev->bytes_out = txQueue;

        count++;
    }

    fclose(fp);
    return count;
}

/* IsIPLiteral accepts only a bare IPv4 or IPv6 address.
 *
 * Every peer in the hub's quarantine list is a string the hub was given by an
 * API caller, and it ends up naming a host in a firewall rule this daemon
 * applies as root. There is exactly one thing it can legitimately be. */
static bool IsIPLiteral(const char* s) {
    struct in_addr v4;
    struct in6_addr v6;
    if (!s || !s[0]) return false;
    return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1;
}

/* RunTool executes one command with an explicit argument vector and waits for
 * it, returning its exit status or -1.
 *
 * No shell is involved, which is the point. The mesh rules were applied by
 * building an iptables command line as a string and handing it to system(),
 * so a peer address containing a semicolon, a pipe or a $( ) was not an
 * address at all - it was a command, run as root, on every Linux endpoint the
 * hub broadcasts its quarantine list to. Nothing in the string reaches a
 * shell here, so nothing in it can be interpreted as anything but an
 * argument. */
static int RunTool(const char* const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* iptables -C writes to stderr for a rule that is simply not there,
         * which is the ordinary case on every heartbeat. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            dup2(devnull, STDOUT_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        execvp(argv[0], (char* const*)argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* HubCurlSecurityArgv is the argument-vector form of HubCurlSecurityArgs. The
 * string form still builds the updater's shell script, where the paths come
 * from this endpoint's own config file and a shell is genuinely wanted; the
 * heartbeat has neither property and takes this one. */
static void HubCurlSecurityArgv(const LINUX_AGENT_CONFIG* config,
                                const char* argv[], int* n, int cap) {
    if (!HubUsesTLS(config)) return;
    if (*n + 6 > cap) return;
    argv[(*n)++] = "--cacert";
    argv[(*n)++] = config->ca_path;
    argv[(*n)++] = "--proto";
    argv[(*n)++] = "=https";
    argv[(*n)++] = "--proto-redir";
    argv[(*n)++] = "=https";
    if (config->client_cert_path[0] && config->client_key_path[0] &&
        access(config->client_cert_path, R_OK) == 0 && access(config->client_key_path, R_OK) == 0) {
        if (*n + 4 > cap) return;
        argv[(*n)++] = "--cert";
        argv[(*n)++] = config->client_cert_path;
        argv[(*n)++] = "--key";
        argv[(*n)++] = config->client_key_path;
    }
}

/* AppendCurlConfigHeader writes one `header = "..."` line in curl's own
 * configuration syntax, escaping the two characters that syntax reserves. */
static void AppendCurlConfigHeader(char* out, size_t cap, size_t* len,
                                   const char* name, const char* value) {
    if (!value || !value[0]) return;
    size_t o = *len;
    const char* prefix = "header = \"";
    for (const char* q = prefix; *q && o + 2 < cap; q++) out[o++] = *q;
    for (const char* q = name; *q && o + 2 < cap; q++) out[o++] = *q;
    if (o + 3 < cap) { out[o++] = ':'; out[o++] = ' '; }
    for (const char* q = value; *q && o + 3 < cap; q++) {
        if (*q == '"' || *q == '\\') out[o++] = '\\';
        out[o++] = *q;
    }
    if (o + 3 < cap) { out[o++] = '"'; out[o++] = '\n'; }
    out[o] = '\0';
    *len = o;
}

/* HUB_CURL_CONFIG_FD is where the child finds the credential file curl reads
 * with -K. It is a pipe, not a file: the key is written into the child and is
 * never on the filesystem and never in an argument vector. */
#define HUB_CURL_CONFIG_FD 3

/* RunHubCurl posts one JSON body to the hub and returns the response.
 *
 * Two things are deliberate here and both were wrong before.
 *
 * There is no shell. The body was interpolated into a command line inside
 * single quotes and handed to popen(), and the body carries process paths
 * observed on this host. Any local user could name a directory
 * `x'; command; #`, run something from it that opened a socket, and have this
 * daemon run `command` as root on the next heartbeat. The path is escaped for
 * JSON - which does not escape an apostrophe, because JSON has no reason to.
 *
 * The credentials are not arguments. `X-API-Key` was on the curl command line,
 * so the tenant key - the credential the whole fleet shares - was readable out
 * of /proc/<pid>/cmdline by every account on the box for as long as the request
 * lasted. It goes down a pipe the child reads with -K instead.
 *
 * stderr is left alone: a refused certificate has to stay visible in the
 * journal, and that is the one failure this agent must not swallow. */
static bool RunHubCurl(const LINUX_AGENT_CONFIG* config, const char* url,
                       const char* body, char* out, size_t outCap) {
    if (out && outCap) out[0] = '\0';

    char cfg[1024];
    size_t cfgLen = 0;
    cfg[0] = '\0';
    AppendCurlConfigHeader(cfg, sizeof(cfg), &cfgLen, "Content-Type", "application/json");
    AppendCurlConfigHeader(cfg, sizeof(cfg), &cfgLen, "X-API-Key", config->api_key);
    if (config->cf_client_id[0] && config->cf_client_secret[0]) {
        AppendCurlConfigHeader(cfg, sizeof(cfg), &cfgLen, "CF-Access-Client-Id", config->cf_client_id);
        AppendCurlConfigHeader(cfg, sizeof(cfg), &cfgLen, "CF-Access-Client-Secret", config->cf_client_secret);
    }

    const char* argv[32];
    int n = 0;
    argv[n++] = "curl";
    argv[n++] = "-sS";
    HubCurlSecurityArgv(config, argv, &n, 28);
    argv[n++] = "-m";
    argv[n++] = "5";
    argv[n++] = "-w";
    argv[n++] = "\n" HUB_STATUS_MARKER "%{http_code}";
    argv[n++] = "-X";
    argv[n++] = "POST";
    argv[n++] = "-K";
    argv[n++] = "/dev/fd/" OMINULL_STR(HUB_CURL_CONFIG_FD);
    argv[n++] = "--data-binary";
    argv[n++] = "@-";
    argv[n++] = url;
    argv[n] = NULL;

    int cfgPipe[2], bodyPipe[2], outPipe[2];
    if (pipe(cfgPipe) < 0) return false;
    if (pipe(bodyPipe) < 0) { close(cfgPipe[0]); close(cfgPipe[1]); return false; }
    if (pipe(outPipe) < 0) {
        close(cfgPipe[0]); close(cfgPipe[1]);
        close(bodyPipe[0]); close(bodyPipe[1]);
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(cfgPipe[0]); close(cfgPipe[1]);
        close(bodyPipe[0]); close(bodyPipe[1]);
        close(outPipe[0]); close(outPipe[1]);
        return false;
    }
    if (pid == 0) {
        close(cfgPipe[1]); close(bodyPipe[1]); close(outPipe[0]);
        if (dup2(bodyPipe[0], STDIN_FILENO) < 0) _exit(127);
        if (dup2(outPipe[1], STDOUT_FILENO) < 0) _exit(127);
        if (cfgPipe[0] != HUB_CURL_CONFIG_FD) {
            if (dup2(cfgPipe[0], HUB_CURL_CONFIG_FD) < 0) _exit(127);
            close(cfgPipe[0]);
        }
        if (bodyPipe[0] > HUB_CURL_CONFIG_FD) close(bodyPipe[0]);
        if (outPipe[1] > HUB_CURL_CONFIG_FD) close(outPipe[1]);
        execvp(argv[0], (char* const*)argv);
        _exit(127);
    }

    close(cfgPipe[0]); close(bodyPipe[0]); close(outPipe[1]);

    /* SIGPIPE is ignored process-wide, so a curl that dies before reading the
     * body is a short write here rather than a dead daemon. */
    (void)!write(cfgPipe[1], cfg, cfgLen);
    close(cfgPipe[1]);

    size_t bodyLen = body ? strlen(body) : 0;
    size_t written = 0;
    while (written < bodyLen) {
        ssize_t w = write(bodyPipe[1], body + written, bodyLen - written);
        if (w <= 0) break;
        written += (size_t)w;
    }
    close(bodyPipe[1]);

    size_t got = 0;
    if (out && outCap > 1) {
        while (got < outCap - 1) {
            ssize_t r = read(outPipe[0], out + got, outCap - 1 - got);
            if (r <= 0) break;
            got += (size_t)r;
        }
        out[got] = '\0';
    }
    close(outPipe[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { }
    return got > 0;
}

/* ---------------------------------------------------------------------------
 * Host isolation.
 *
 * The hub used to deliver this as a WebSocket command, and the WebSocket route
 * was never registered on its mux - so the command had no transport, the hub
 * answered 200 "isolated", and this daemon was never told. An endpoint that the
 * console showed as cut off went on talking to the whole network. It arrives on
 * the heartbeat reply now, alongside the quarantined-peer list that has always
 * come that way, and is reconciled on every beat for the same reason that list
 * is: a host that was down when it was released must still come back.
 * ------------------------------------------------------------------------- */

#define OMINULL_CHAIN_IN  "OMINULL_ISO_IN"
#define OMINULL_CHAIN_OUT "OMINULL_ISO_OUT"
#define MAX_ISOLATION_ALLOW 32
#define MAX_QUARANTINED_PEERS 64

/* HubAddressLiteral reduces the configured hub URL to an address literal.
 *
 * Isolation has to leave a hole for the hub or it can never be lifted, and the
 * hole is written as an address, so the name in the URL is resolved here while
 * the host can still resolve names. */
static bool HubAddressLiteral(const LINUX_AGENT_CONFIG* config, char* out, size_t cap) {
    const char* p = strstr(config->hub_url, "://");
    p = p ? p + 3 : config->hub_url;

    char host[256] = {0};
    size_t i = 0;
    if (*p == '[') {                       /* [2001:db8::1]:9443 */
        p++;
        while (*p && *p != ']' && i < sizeof(host) - 1) host[i++] = *p++;
    } else {
        while (*p && *p != ':' && *p != '/' && i < sizeof(host) - 1) host[i++] = *p++;
    }
    host[i] = '\0';
    if (!host[0]) return false;

    if (IsIPLiteral(host)) {
        snprintf(out, cap, "%s", host);
        return true;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return false;

    bool ok = false;
    if (res->ai_family == AF_INET) {
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf))) {
            snprintf(out, cap, "%s", buf);
            ok = true;
        }
    } else if (res->ai_family == AF_INET6) {
        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &((struct sockaddr_in6*)res->ai_addr)->sin6_addr, buf, sizeof(buf))) {
            snprintf(out, cap, "%s", buf);
            ok = true;
        }
    }
    freeaddrinfo(res);
    return ok;
}

/* The baseline isolation policy, as this agent receives it.
 *
 * The floor used to carry two permits written into the agent: DNS to any
 * resolver and DHCP to any server. Both were holes with a justification
 * attached, and neither was visible to the person clicking Isolate. The hub now
 * sends the exact set instead - service, destination, protocol and remote port,
 * already expanded - and this agent enforces that and nothing more.
 *
 * baselineKnown is the compatibility hinge. A hub too old to send the key at all
 * leaves this false, and the legacy blanket permits are kept: tightening the
 * floor under a fleet whose hub never asked for it would cut hosts off during a
 * hub upgrade. A hub that sends an empty array is saying "hub and loopback
 * only", which is a policy, and is obeyed. */
#define MAX_BASELINE_RULES 64

/* Defined further down with the update descriptor it was written for; the
 * baseline rules have the same flat shape and reuse it. */
static bool ExtractJsonString(const char* json, const char* key, char* out, size_t outLen);


typedef struct {
    char service[16];
    char destination[64];
    char protocol[8];
    int  port;
} BASELINE_RULE;

/* ParseBaselineRules reads the flat object array the hub sends. Returns the
 * number of usable rules, or -1 when the key is absent entirely - the caller
 * has to tell "this hub has no baseline" from "this hub's baseline is empty",
 * because those two mean opposite things for what gets enforced. */
static int ParseBaselineRules(const char* respJson, BASELINE_RULE* out, int cap) {
    const char* p = strstr(respJson, "\"isolation_baseline\":[");
    if (!p) return -1;
    p += strlen("\"isolation_baseline\":[");

    int count = 0;
    while (*p && *p != ']') {
        const char* obj = strchr(p, '{');
        if (!obj) break;
        const char* end = strchr(obj, '}');
        if (!end) break;

        char frag[256];
        size_t len = (size_t)(end - obj) + 1;
        if (len >= sizeof(frag)) len = sizeof(frag) - 1;
        memcpy(frag, obj, len);
        frag[len] = '\0';

        BASELINE_RULE r;
        memset(&r, 0, sizeof(r));
        ExtractJsonString(frag, "service", r.service, sizeof(r.service));
        ExtractJsonString(frag, "destination", r.destination, sizeof(r.destination));
        ExtractJsonString(frag, "protocol", r.protocol, sizeof(r.protocol));
        const char* portKey = strstr(frag, "\"port\":");
        if (portKey) r.port = atoi(portKey + strlen("\"port\":"));

        p = end + 1;

        /* Everything here becomes an argument to iptables. A hub that sends
         * something else is either running a build that does not validate its
         * own policy or is not the hub; the value is never echoed, because this
         * log is read by people and by journald. */
        if (!IsIPLiteral(r.destination)) {
            printf("[!] Hub sent a baseline rule whose destination is not an IP address; ignoring it.\n");
            fflush(stdout);
            continue;
        }
        if (strcmp(r.protocol, "udp") != 0 && strcmp(r.protocol, "tcp") != 0) {
            printf("[!] Hub sent a baseline rule for an unsupported protocol; ignoring it.\n");
            fflush(stdout);
            continue;
        }
        if (r.port < 1 || r.port > 65535) {
            printf("[!] Hub sent a baseline rule with an out-of-range port; ignoring it.\n");
            fflush(stdout);
            continue;
        }
        if (count < cap) out[count++] = r;
    }
    return count;
}

/* BaselinePermit writes one permit into both chains for one rule.
 *
 * Both directions, because a reply is a new flow rather than part of the
 * request: this is the same mistake that cost the Windows agent its DHCP lease
 * when the floor was permitted outbound only. The remote port is the server's
 * port in both directions, so it is --dport going out and --sport coming back. */
static void BaselinePermit(const char* tool, const BASELINE_RULE* r) {
    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%d", r->port);

    const char* out[] = { tool, "-A", OMINULL_CHAIN_OUT, "-p", r->protocol,
                          "-d", r->destination, "--dport", portStr, "-j", "RETURN", NULL };
    const char* in[]  = { tool, "-A", OMINULL_CHAIN_IN,  "-p", r->protocol,
                          "-s", r->destination, "--sport", portStr, "-j", "RETURN", NULL };
    (void)RunTool(out);
    (void)RunTool(in);
}

/* EnforcementTeardown removes the chains from one table. The unhook is repeated
 * a bounded number of times because a crash loop can leave the jump inserted
 * more than once, and one -D removes one copy. */
static void EnforcementTeardown(const char* tool) {
    const char* unhookIn[]  = { tool, "-D", "INPUT",  "-j", OMINULL_CHAIN_IN,  NULL };
    const char* unhookOut[] = { tool, "-D", "OUTPUT", "-j", OMINULL_CHAIN_OUT, NULL };
    for (int i = 0; i < 8 && RunTool(unhookIn) == 0; i++) { }
    for (int i = 0; i < 8 && RunTool(unhookOut) == 0; i++) { }

    const char* flushIn[]  = { tool, "-F", OMINULL_CHAIN_IN,  NULL };
    const char* flushOut[] = { tool, "-F", OMINULL_CHAIN_OUT, NULL };
    const char* dropIn[]   = { tool, "-X", OMINULL_CHAIN_IN,  NULL };
    const char* dropOut[]  = { tool, "-X", OMINULL_CHAIN_OUT, NULL };
    (void)RunTool(flushIn);
    (void)RunTool(flushOut);
    (void)RunTool(dropIn);
    (void)RunTool(dropOut);
}

/* EnforcementBuild writes this host's whole enforcement state into one ordered
 * chain per direction, for one address family, and hooks them in front of INPUT
 * and OUTPUT.
 *
 * One chain, in one order, is the point. Isolation used to live in
 * OMINULL_ISO_IN/OUT while a mesh quarantine was inserted straight into INPUT
 * and OUTPUT with -I, and both inserted at position 1 - so which of the two
 * came first depended on which had been written most recently. A peer block
 * that named the hub could therefore land in front of the hub pinhole and take
 * away the only path by which the host could ever be released. The Windows
 * agent gets this right by giving every filter an explicit weight; this is the
 * same ladder, written as chain order:
 *
 *   hub pinhole  >  loopback  >  DHCP  >  peer quarantine  >  DNS  >  allow list  >  deny
 *
 * The hub pinhole is above the peer blocks and is written whenever there is
 * anything to enforce, not only while isolated: quarantining the controller
 * from an endpoint is not an operation with a way back.
 *
 * Built before hooked, so there is no moment where traffic is evaluated against
 * a chain that has no DROP in it yet. Both families are always built: leaving
 * ip6tables alone would isolate a host that then carried on over IPv6. */
static void EnforcementBuild(const char* tool, bool isolated, const char* hubIP,
                             char allow[][64], int allowCount,
                             char peers[][64], int peerCount,
                             const BASELINE_RULE* baseline, int baselineCount,
                             bool baselineKnown) {
    bool v6 = strcmp(tool, "ip6tables") == 0;

    const char* newIn[]  = { tool, "-N", OMINULL_CHAIN_IN,  NULL };
    const char* newOut[] = { tool, "-N", OMINULL_CHAIN_OUT, NULL };
    (void)RunTool(newIn);           /* fails when it already exists; ordinary */
    (void)RunTool(newOut);
    const char* flushIn[]  = { tool, "-F", OMINULL_CHAIN_IN,  NULL };
    const char* flushOut[] = { tool, "-F", OMINULL_CHAIN_OUT, NULL };
    (void)RunTool(flushIn);
    (void)RunTool(flushOut);

    /* 1. The hub, ahead of every block below it. */
    if (hubIP && hubIP[0] && ((strchr(hubIP, ':') != NULL) == v6)) {
        const char* hubIn[]  = { tool, "-A", OMINULL_CHAIN_IN,  "-s", hubIP, "-j", "RETURN", NULL };
        const char* hubOut[] = { tool, "-A", OMINULL_CHAIN_OUT, "-d", hubIP, "-j", "RETURN", NULL };
        (void)RunTool(hubIn);
        (void)RunTool(hubOut);
    }

    /* 2. Loopback. */
    const char* loIn[]  = { tool, "-A", OMINULL_CHAIN_IN,  "-i", "lo", "-j", "RETURN", NULL };
    const char* loOut[] = { tool, "-A", OMINULL_CHAIN_OUT, "-o", "lo", "-j", "RETURN", NULL };
    (void)RunTool(loIn);
    (void)RunTool(loOut);

    /* 3. DHCP, above the peer blocks: a lease that expires because a quarantine
     *    named the DHCP server costs this host the address the hub reaches it
     *    on, and there is no way back from that either.
     *
     *    Which servers, though, is the baseline policy's business rather than
     *    this agent's. Only the DHCP rules are placed here - the rest of the
     *    baseline sits below the peer blocks with DNS, so that quarantining a
     *    rogue resolver still beats the rule that lets this host resolve names,
     *    while quarantining something cannot cost it its lease. */
    if (baselineKnown) {
        for (int i = 0; i < baselineCount; i++) {
            if (strcmp(baseline[i].service, "dhcp") != 0) continue;
            if ((strchr(baseline[i].destination, ':') != NULL) != v6) continue;
            BaselinePermit(tool, &baseline[i]);
        }
    } else {
        /* No policy from this hub: keep the permit that has always been here.
         * DHCPv6 is a different pair of ports rather than the same two. */
        const char* dhcpPorts = v6 ? "546:547" : "67:68";
        const char* dhcpIn[]  = { tool, "-A", OMINULL_CHAIN_IN,  "-p", "udp", "--sport", dhcpPorts, "-j", "RETURN", NULL };
        const char* dhcpOut[] = { tool, "-A", OMINULL_CHAIN_OUT, "-p", "udp", "--dport", dhcpPorts, "-j", "RETURN", NULL };
        (void)RunTool(dhcpIn);
        (void)RunTool(dhcpOut);
    }

    /* 4. Mesh quarantine. Applies whether or not this host is isolated. */
    for (int i = 0; i < peerCount; i++) {
        if ((strchr(peers[i], ':') != NULL) != v6) continue;
        const char* pIn[]  = { tool, "-A", OMINULL_CHAIN_IN,  "-s", peers[i], "-j", "DROP", NULL };
        const char* pOut[] = { tool, "-A", OMINULL_CHAIN_OUT, "-d", peers[i], "-j", "DROP", NULL };
        (void)RunTool(pIn);
        (void)RunTool(pOut);
    }

    if (isolated) {
        /* 5. The rest of the baseline - DNS, NTP, whatever else the policy
         *    names - below the peer block on purpose: quarantining a rogue
         *    resolver has to beat the rule that lets this host resolve names. */
        if (baselineKnown) {
            for (int i = 0; i < baselineCount; i++) {
                if (strcmp(baseline[i].service, "dhcp") == 0) continue;  /* already placed */
                if ((strchr(baseline[i].destination, ':') != NULL) != v6) continue;
                BaselinePermit(tool, &baseline[i]);
            }
        } else {
            /* No policy from this hub: the resolver permit that has always been
             * here. UDP only - TCP/53 to any host is a general-purpose tunnel
             * rather than a name lookup. */
            const char* dnsIn[]  = { tool, "-A", OMINULL_CHAIN_IN,  "-p", "udp", "--sport", "53", "-j", "RETURN", NULL };
            const char* dnsOut[] = { tool, "-A", OMINULL_CHAIN_OUT, "-p", "udp", "--dport", "53", "-j", "RETURN", NULL };
            (void)RunTool(dnsIn);
            (void)RunTool(dnsOut);
        }

        /* 6. The hub's allow list - a scoped trust rule, below a peer block so
         *    a quarantine still wins over standing trust that named the peer. */
        for (int i = 0; i < allowCount; i++) {
            if ((strchr(allow[i], ':') != NULL) != v6) continue;
            const char* aIn[]  = { tool, "-A", OMINULL_CHAIN_IN,  "-s", allow[i], "-j", "RETURN", NULL };
            const char* aOut[] = { tool, "-A", OMINULL_CHAIN_OUT, "-d", allow[i], "-j", "RETURN", NULL };
            (void)RunTool(aIn);
            (void)RunTool(aOut);
        }

        /* 7. Default deny. */
        const char* denyIn[]  = { tool, "-A", OMINULL_CHAIN_IN,  "-j", "DROP", NULL };
        const char* denyOut[] = { tool, "-A", OMINULL_CHAIN_OUT, "-j", "DROP", NULL };
        (void)RunTool(denyIn);
        (void)RunTool(denyOut);
    }

    const char* chkIn[]  = { tool, "-C", "INPUT",  "-j", OMINULL_CHAIN_IN,  NULL };
    const char* hookIn[] = { tool, "-I", "INPUT",  "-j", OMINULL_CHAIN_IN,  NULL };
    const char* chkOut[]  = { tool, "-C", "OUTPUT", "-j", OMINULL_CHAIN_OUT, NULL };
    const char* hookOut[] = { tool, "-I", "OUTPUT", "-j", OMINULL_CHAIN_OUT, NULL };
    if (RunTool(chkIn) != 0)  (void)RunTool(hookIn);
    if (RunTool(chkOut) != 0) (void)RunTool(hookOut);
}

/* ParseAddressList pulls a flat JSON array of address literals out of the
 * heartbeat reply. Anything that is not an address is reported and dropped: a
 * hub sending something else is either running a build that does not validate
 * it or is not the hub, and both are worth a line in the log. The value itself
 * is never echoed - it is attacker-controlled text and this log is read by
 * people and by journald. */
static int ParseAddressList(const char* respJson, const char* key,
                            char out[][64], int cap) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":[", key);
    const char* p = strstr(respJson, needle);
    if (!p) return 0;
    p += strlen(needle);

    int count = 0;
    while (*p && *p != ']') {
        while (*p && (*p == ' ' || *p == ',' || *p == '"' || *p == '\n' || *p == '\r')) p++;
        if (*p == ']' || !*p) break;
        char ip[64] = {0};
        int idx = 0;
        while (*p && *p != '"' && *p != ']' && *p != ',' && idx < (int)sizeof(ip) - 1) {
            ip[idx++] = *p++;
        }
        if (!ip[0]) continue;
        if (!IsIPLiteral(ip)) {
            printf("[!] Hub sent a %s entry that is not an IP address; ignoring it.\n", key);
            fflush(stdout);
            continue;
        }
        if (count < cap) snprintf(out[count++], 64, "%s", ip);
    }
    return count;
}

/* What this agent has actually put in the kernel. At file scope rather than
 * inside SyncEnforcement because the dead-man timer below has to be able to
 * rebuild from it - specifically, to lift this host's isolation while leaving
 * the mesh quarantine it was also holding in place. */
static bool known = false;              /* nothing reconciled yet this run */
static bool appliedIsolated = false;
static char appliedAllow[MAX_ISOLATION_ALLOW][64];
static int appliedAllowCount = 0;
static char appliedPeers[MAX_QUARANTINED_PEERS][64];
static int appliedPeerCount = 0;
static BASELINE_RULE appliedBaseline[MAX_BASELINE_RULES];
static int appliedBaselineCount = 0;
static bool appliedBaselineKnown = false;
static bool g_ForgetApplied = false;
static bool g_DeadmanReleased = false;

/* OMINULL_DEADMAN_BEATS is how many consecutive heartbeats may fail while this
 * host is isolated before it releases itself.
 *
 * The readiness gate is a prediction; this is the backstop, and it is what makes
 * the whole arrangement safe to use. Without it, a defect in the floor means a
 * host is gone until somebody reaches it out of band. With it, the same defect
 * means the host comes back after a few minutes and says why - a containment
 * that did not hold, which is recoverable and loud, rather than an endpoint that
 * is lost.
 *
 * Not 1: a hub restart, a brief network event or a rolling release must not lift
 * every isolation in the fleet. Beats are three seconds apart, so 100 is five
 * minutes - long enough to outlast all three, short enough that a person who has
 * just isolated a host is still watching when it comes back. */
#define OMINULL_DEADMAN_BEATS 100

/* SyncEnforcement reconciles this host's whole link state - isolation, the
 * mesh peer list and the isolation allow list - against the hub's answer on
 * every heartbeat.
 *
 * The three used to be reconciled by two functions that did not know about each
 * other, which is what made their relative order in the kernel accidental.
 * Reconciling rather than only adding matters for the same reason it always
 * did: a peer the hub has released must have its rule lifted, and an endpoint
 * that was offline when the release happened would otherwise stay blackholed. */
static void SyncEnforcement(const LINUX_AGENT_CONFIG* config, const char* respJson) {
    if (!respJson) return;

    /* The dead-man timer released this host's isolation without the hub's
     * agreement. Forget what was applied so the next answer is treated as new
     * and the isolation is re-applied if the hub still wants it. */
    if (g_ForgetApplied) {
        known = false;
        g_ForgetApplied = false;
    }

    const char* p = strstr(respJson, "\"is_isolated\":");
    if (!p) return;                         /* an older hub; nothing to obey */
    p += strlen("\"is_isolated\":");
    while (*p == ' ') p++;
    bool wantIsolated = (strncmp(p, "true", 4) == 0);

    char allow[MAX_ISOLATION_ALLOW][64];
    int allowCount = ParseAddressList(respJson, "isolation_allow_ips", allow, MAX_ISOLATION_ALLOW);
    char peers[MAX_QUARANTINED_PEERS][64];
    int peerCount = ParseAddressList(respJson, "quarantined_peers", peers, MAX_QUARANTINED_PEERS);

    BASELINE_RULE baseline[MAX_BASELINE_RULES];
    int baselineCount = ParseBaselineRules(respJson, baseline, MAX_BASELINE_RULES);
    bool baselineKnown = baselineCount >= 0;
    if (!baselineKnown) baselineCount = 0;

    bool changed = !known || wantIsolated != appliedIsolated
                   || allowCount != appliedAllowCount || peerCount != appliedPeerCount
                   || baselineKnown != appliedBaselineKnown || baselineCount != appliedBaselineCount;
    for (int i = 0; !changed && i < allowCount; i++) {
        if (strcmp(allow[i], appliedAllow[i]) != 0) changed = true;
    }
    for (int i = 0; !changed && i < peerCount; i++) {
        if (strcmp(peers[i], appliedPeers[i]) != 0) changed = true;
    }
    for (int i = 0; !changed && i < baselineCount; i++) {
        if (strcmp(baseline[i].destination, appliedBaseline[i].destination) != 0
            || strcmp(baseline[i].protocol, appliedBaseline[i].protocol) != 0
            || strcmp(baseline[i].service, appliedBaseline[i].service) != 0
            || baseline[i].port != appliedBaseline[i].port) changed = true;
    }
    if (!changed) return;

    char hubIP[64] = {0};
    bool haveHub = HubAddressLiteral(config, hubIP, sizeof(hubIP));
    if (wantIsolated && !haveHub) {
        /* Refused, deliberately. An isolation with no hole for the hub can
         * never be lifted by the hub, so it is not a quarantine - it is a
         * host taken off the network permanently by a name lookup that
         * happened to fail. The order stands and is retried next beat. */
        printf("[-] Isolation ordered, but the hub address could not be resolved from %s. "
               "Refusing to isolate: this host could not be released afterwards.\n", config->hub_url);
        fflush(stdout);
        return;
    }

    if (wantIsolated) {
        if (baselineKnown) {
            printf("[!] Threat Nullification: isolating this host. Permitted: hub %s, loopback, "
                   "%d baseline rule(s) and %d allow-listed address(es). %d peer(s) quarantined.\n",
                   hubIP, baselineCount, allowCount, peerCount);
        } else {
            printf("[!] Threat Nullification: isolating this host. This hub sends no baseline policy, "
                   "so the built-in floor applies: hub %s, DHCP and DNS to any destination, loopback, "
                   "%d allow-listed address(es). %d peer(s) quarantined.\n",
                   hubIP, allowCount, peerCount);
        }
    } else if (known && appliedIsolated) {
        printf("[+] Threat neutralized: lifting host isolation. %d peer(s) still quarantined.\n", peerCount);
    } else if (peerCount == 0 && appliedPeerCount > 0) {
        printf("[+] Mesh quarantine cleared; no enforcement rules remain on this host.\n");
    } else if (peerCount != appliedPeerCount) {
        printf("[*] Mesh quarantine updated: %d peer(s).\n", peerCount);
    }
    fflush(stdout);

    if (!wantIsolated && peerCount == 0) {
        EnforcementTeardown("iptables");
        EnforcementTeardown("ip6tables");
    } else {
        EnforcementBuild("iptables", wantIsolated, hubIP, allow, allowCount, peers, peerCount,
                         baseline, baselineCount, baselineKnown);
        EnforcementBuild("ip6tables", wantIsolated, hubIP, allow, allowCount, peers, peerCount,
                         baseline, baselineCount, baselineKnown);
    }

    appliedIsolated = wantIsolated;
    memcpy(appliedAllow, allow, sizeof(allow));
    appliedAllowCount = allowCount;
    memcpy(appliedPeers, peers, sizeof(peers));
    appliedPeerCount = peerCount;
    memcpy(appliedBaseline, baseline, sizeof(baseline));
    appliedBaselineCount = baselineCount;
    appliedBaselineKnown = baselineKnown;
    known = true;
}

/* HubContact drives the dead-man timer. Every beat reports whether the hub
 * answered and accepted; a run of failures while this host is isolated releases
 * the isolation.
 *
 * The release rebuilds rather than tears down: the mesh quarantine this host was
 * also holding is not this timer's to lift. Only the default-deny that made the
 * host unreachable goes. */
static void HubContact(bool accepted) {
    static int missed = 0;

    if (accepted) {
        if (g_DeadmanReleased) {
            printf("[+] The hub is reachable again after a dead-man release. "
                   "Its current answer decides what this host enforces from here.\n");
            fflush(stdout);
            g_DeadmanReleased = false;
        }
        missed = 0;
        return;
    }
    if (!appliedIsolated) {
        missed = 0;                          /* nothing to roll back */
        return;
    }
    if (++missed < OMINULL_DEADMAN_BEATS) return;

    printf("[!] Isolated, and the hub has not answered for %d consecutive heartbeats. "
           "Releasing this host's isolation: an isolation the hub cannot lift is not a "
           "containment, it is a lost endpoint. %d quarantined peer(s) stay blocked.\n",
           missed, appliedPeerCount);
    fflush(stdout);

    EnforcementBuild("iptables", false, NULL, appliedAllow, 0,
                     appliedPeers, appliedPeerCount,
                     appliedBaseline, appliedBaselineCount, appliedBaselineKnown);
    EnforcementBuild("ip6tables", false, NULL, appliedAllow, 0,
                     appliedPeers, appliedPeerCount,
                     appliedBaseline, appliedBaselineCount, appliedBaselineKnown);

    appliedIsolated = false;
    g_DeadmanReleased = true;
    g_ForgetApplied = true;
    missed = 0;
}

/* What this host actually uses the network for at the infrastructure layer.
 *
 * The hub checks these against the baseline policy before it will let anyone
 * isolate this endpoint. The agent reports; it never authors. A host that turns
 * out to resolve against a server nobody put in the policy is a question for a
 * person, not a rule this agent may write for itself - and this host may be the
 * compromised one. */

/* CollectAddressesFromFile scans a config file for a keyword followed by
 * addresses on the same line, which is the shape of resolv.conf, ntp.conf and
 * chrony.conf alike. Hostnames are skipped rather than resolved: an address is
 * the only thing that can be compared against a rule, and resolving one here
 * would mean asking DNS what DNS is. */
static int CollectAddressesFromFile(const char* path, const char* keyword,
                                    char out[][64], int cap, int count) {
    FILE* f = fopen(path, "r");
    if (!f) return count;

    char line[512];
    size_t klen = strlen(keyword);
    while (count < cap && fgets(line, sizeof(line), f)) {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';') continue;
        if (strncasecmp(p, keyword, klen) != 0) continue;
        p += klen;
        if (*p != ' ' && *p != '\t' && *p != '=') continue;

        /* One line can carry several servers - NTP= in timesyncd.conf does. */
        while (count < cap) {
            while (*p == ' ' || *p == '\t' || *p == '=' || *p == ',') p++;
            if (*p == '\0' || *p == '\n' || *p == '#') break;
            char tok[64];
            int i = 0;
            while (*p && *p != ' ' && *p != '\t' && *p != ',' && *p != '\n' && *p != '\r'
                   && i < (int)sizeof(tok) - 1) {
                tok[i++] = *p++;
            }
            tok[i] = '\0';
            if (!tok[0]) break;
            if (!IsIPLiteral(tok)) continue;
            bool dup = false;
            for (int j = 0; j < count; j++) {
                if (strcmp(out[j], tok) == 0) dup = true;
            }
            if (!dup) snprintf(out[count++], 64, "%s", tok);
        }
    }
    fclose(f);
    return count;
}

/* DHCPServerAddress finds the server this host holds its lease from. Which file
 * holds it depends on what manages the interface, so all three known layouts
 * are tried; a host with a static address has none of them and says so. */
static bool DHCPServerAddress(char* out, size_t cap) {
    static const char* leaseFiles[] = {
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/dhclient/dhclient.leases",
        NULL
    };
    for (int i = 0; leaseFiles[i]; i++) {
        FILE* f = fopen(leaseFiles[i], "r");
        if (!f) continue;
        char line[512];
        char last[64] = {0};
        while (fgets(line, sizeof(line), f)) {
            const char* p = strstr(line, "dhcp-server-identifier");
            if (!p) continue;
            p += strlen("dhcp-server-identifier");
            while (*p == ' ' || *p == '\t') p++;
            int j = 0;
            while (*p && *p != ';' && *p != '\n' && j < (int)sizeof(last) - 1) last[j++] = *p++;
            last[j] = '\0';
        }
        fclose(f);
        /* The last lease in the file is the current one. */
        if (last[0] && IsIPLiteral(last)) {
            snprintf(out, cap, "%s", last);
            return true;
        }
    }

    /* systemd-networkd keeps one lease file per interface index. */
    DIR* d = opendir("/run/systemd/netif/leases");
    if (d) {
        struct dirent* e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char path[512];
            snprintf(path, sizeof(path), "/run/systemd/netif/leases/%s", e->d_name);
            FILE* f = fopen(path, "r");
            if (!f) continue;
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "SERVER_ADDRESS=", 15) != 0) continue;
                char addr[64] = {0};
                int j = 0;
                const char* p = line + 15;
                while (*p && *p != '\n' && *p != '\r' && j < (int)sizeof(addr) - 1) addr[j++] = *p++;
                addr[j] = '\0';
                if (IsIPLiteral(addr)) {
                    snprintf(out, cap, "%s", addr);
                    fclose(f);
                    closedir(d);
                    return true;
                }
            }
            fclose(f);
        }
        closedir(d);
    }
    return false;
}

/* EnforcementEngineStatus answers "can this agent apply rules at all", which is
 * the check that decides whether an isolation would be a containment or a host
 * taken off the network with nothing underneath it.
 *
 * Probed once. Running it every heartbeat would fork two processes a second for
 * an answer that changes when a package is installed, and the failure it is
 * looking for - no iptables, or no privilege to use it - does not come and go. */
static const char* EnforcementEngineStatus(void) {
    static char status[128] = {0};
    if (status[0]) return status;

    const char* v4[] = { "iptables", "-n", "-L", "OUTPUT", NULL };
    const char* v6[] = { "ip6tables", "-n", "-L", "OUTPUT", NULL };
    int r4 = RunTool(v4);
    int r6 = RunTool(v6);

    if (r4 == 127) {
        snprintf(status, sizeof(status), "iptables is not installed on this host");
    } else if (r4 != 0) {
        snprintf(status, sizeof(status), "iptables would not list the OUTPUT chain (exit %d)", r4);
    } else if (r6 == 127) {
        snprintf(status, sizeof(status), "ip6tables is not installed, so IPv6 could not be isolated");
    } else if (r6 != 0) {
        snprintf(status, sizeof(status), "ip6tables would not list the OUTPUT chain (exit %d)", r6);
    } else {
        snprintf(status, sizeof(status), "ok");
    }
    return status;
}

/* AppendObservations writes the observed-services array and the readiness object
 * into the telemetry payload. Both are appended to the object the hub already
 * receives rather than sent separately: an agent that can heartbeat can report
 * this, and a second request would be a second thing to fail. */
static int AppendObservations(const LINUX_AGENT_CONFIG* config, char* buf, size_t cap,
                              bool rolledBack) {
    char resolvers[8][64];
    int resolverCount = CollectAddressesFromFile("/etc/resolv.conf", "nameserver", resolvers, 8, 0);

    char ntp[8][64];
    int ntpCount = 0;
    ntpCount = CollectAddressesFromFile("/etc/systemd/timesyncd.conf", "NTP", ntp, 8, ntpCount);
    ntpCount = CollectAddressesFromFile("/etc/ntp.conf", "server", ntp, 8, ntpCount);
    ntpCount = CollectAddressesFromFile("/etc/chrony/chrony.conf", "server", ntp, 8, ntpCount);

    char dhcp[64] = {0};
    bool haveDHCP = DHCPServerAddress(dhcp, sizeof(dhcp));

    int off = snprintf(buf, cap, ",\"observed_services\":[");
    const char* sep = "";
    for (int i = 0; i < resolverCount && off < (int)cap - 256; i++) {
        off += snprintf(buf + off, cap - off,
                        "%s{\"service\":\"dns\",\"destination\":\"%s\",\"source\":\"resolv.conf\"}",
                        sep, resolvers[i]);
        sep = ",";
    }
    for (int i = 0; i < ntpCount && off < (int)cap - 256; i++) {
        off += snprintf(buf + off, cap - off,
                        "%s{\"service\":\"ntp\",\"destination\":\"%s\",\"source\":\"time daemon config\"}",
                        sep, ntp[i]);
        sep = ",";
    }
    if (haveDHCP && off < (int)cap - 256) {
        off += snprintf(buf + off, cap - off,
                        "%s{\"service\":\"dhcp\",\"destination\":\"%s\",\"source\":\"dhcp lease\"}",
                        sep, dhcp);
    }

    char hubIP[64] = {0};
    bool haveHub = HubAddressLiteral(config, hubIP, sizeof(hubIP));

    off += snprintf(buf + off, cap - off,
                    "],\"isolation_readiness\":{\"enforcement_engine\":\"%s\",\"hub_literal\":\"%s\","
                    "\"address_origin\":\"%s\",\"last_applied\":\"%s\"}",
                    EnforcementEngineStatus(),
                    haveHub ? hubIP : "",
                    haveDHCP ? "dhcp" : "static",
                    rolledBack ? "released by the dead-man timer after losing contact with the hub" : "");
    return off;
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

    offset += snprintf(jsonBuf + offset, bufCap - offset, "]");

    /* What this host uses the network for, and whether it believes it could
     * still be released after an isolation. Both ride on the heartbeat that is
     * already going out: an agent that can report telemetry can report this,
     * and a second request would be a second thing to fail. */
    char observations[2048];
    if (AppendObservations(config, observations, sizeof(observations), g_DeadmanReleased) > 0) {
        offset += snprintf(jsonBuf + offset, bufCap - offset, "%s", observations);
    }
    snprintf(jsonBuf + offset, bufCap - offset, "}");

    char url[sizeof(config->hub_url) + 32];
    snprintf(url, sizeof(url), "%s/api/v1/events", config->hub_url);

    /* The reply now carries the resolved baseline as well as the peer list and
     * the allow list. Four kilobytes truncated it once the policy had a handful
     * of rules in it, and a truncated reply is not a parse error - it is a
     * silently shorter enforcement state. */
    char respBuf[16384] = {0};
    bool accepted = false;
    if (RunHubCurl(config, url, jsonBuf, respBuf, sizeof(respBuf))) {
        long status = SplitHubStatus(respBuf);
        if (!ReportHubRejection(config, status)) {
            accepted = true;
            SyncEnforcement(config, respBuf);
            ApplyAgentUpdate(config, respBuf);
        }
    }
    HubContact(accepted);

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
        } else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) {
            strncpy(config.key_path, argv[++i], sizeof(config.key_path) - 1);
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
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("%s\n", OMINULL_LINUX_AGENT_VERSION);
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-' && i <= 4) {
            // Positional fallback: 1=hub, 2=key, 3=role, 4=id
            if (i == 1) strncpy(config.hub_url, argv[i], sizeof(config.hub_url) - 1);
            else if (i == 2) strncpy(config.api_key, argv[i], sizeof(config.api_key) - 1);
            else if (i == 3) strncpy(config.role_tag, argv[i], sizeof(config.role_tag) - 1);
            else if (i == 4) strncpy(config.endpoint_id, argv[i], sizeof(config.endpoint_id) - 1);
        } else {
            /* An argument this daemon does not understand stops it.
             *
             * It used to be ignored, and ignoring one starts a full agent under
             * whatever the defaults are. Running `ominulld --version` - which
             * was not an option either - did exactly that: no version printed,
             * and a second daemon reporting from the endpoint under a default
             * configuration, which is how an agent ends up alive for hours with
             * nothing supervising it. An option missing its value lands here
             * too, so `--key-file` with nothing after it stops rather than
             * silently keeping the placeholder key. */
            fprintf(stderr, "[-] %s: unrecognised argument, or an option missing its value.\n", argv[i]);
            fprintf(stderr, "    Nothing was started. Run with --help for the accepted options.\n");
            return 2;
        }
    }

    /* A key file wins over --key: a unit that carries both is one mid-migration,
     * and the file is the channel being migrated to. */
    if (config.key_path[0] && !ReadKeyFile(config.key_path, config.api_key, sizeof(config.api_key))) {
        fprintf(stderr, "[-] --key-file %s could not be read; refusing to start without a credential.\n",
                config.key_path);
        return 1;
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
    printf("  Credential:    %s\n", config.key_path[0] ? config.key_path
                                                       : "--key (visible in /proc/<pid>/cmdline; prefer --key-file)");
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
    /* The heartbeat writes its body into a child's stdin. A child that exits
     * first would otherwise take the daemon down with a SIGPIPE. */
    signal(SIGPIPE, SIG_IGN);

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

