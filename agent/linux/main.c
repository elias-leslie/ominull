/* Several agent headers need GNU extensions (pipe2, SCHED_IDLE, close_range);
 * defining it before the first libc header is the only place it takes effect. */
#define _GNU_SOURCE
/* The agent runs on glibc 2.36 (Debian 12). With _GNU_SOURCE, glibc 2.38+
 * headers redirect strtol/sscanf and friends to __isoc23_* symbols that only
 * exist in 2.38, so a build on a newer host would not start there. Keep the
 * classic symbols; scripts/check-agent-glibc.sh gates the result. */
#include <features.h>
#undef __GLIBC_USE_C2X_STRTOL
#define __GLIBC_USE_C2X_STRTOL 0
/* glibc 2.40+ names the same switch C23_STRTOL. */
#undef __GLIBC_USE_C23_STRTOL
#define __GLIBC_USE_C23_STRTOL 0
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
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
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/tcp.h>
#include <curl/curl.h>

#include "../include/release_key.h"
#include "../include/hub_address.h"
#include "../include/hub_reply.h"
#include "../include/response_dispatcher.h"
#include "../include/agent_trust.h"
#include "../include/hub_scrape.h"
#include "../include/release_verify_posix.h"
#include "../include/terminal_linux.h"
#include "../include/forensics_linux.h"
#include "../include/script_exec_linux.h"
#include "../include/process_lineage_linux.h"
#include "../include/software_inventory_linux.h"
#include "../include/data_inventory_linux.h"
#include "../include/gzip_encode.h"
#include "../include/upload_queue.h"
#include "../include/cert_renewal.h"

#ifndef OMINULL_PROC_ROOT
#define OMINULL_PROC_ROOT "/proc"
#endif

#define OMINULL_LINUX_AGENT_VERSION "1.8.120"

// Where enrolment leaves the hub's CA certificate. The agent verifies every
// hub connection against this file and nothing else, so it sits beside the
// enrolment config in /etc rather than under the install prefix: an upgrade
// replaces /opt/ominull, and the trust anchor has to survive that.
#define OMINULL_DEFAULT_CA_PATH "/etc/ominull/ca.crt"

#define MAX_FLOWS_PER_BATCH 64
#define MAX_PATH_LEN 512

/* What both agents send when no process can be attributed to a socket. It is
 * deliberately not a path: a path is a claim, and this is the absence of one. */
#define OMINULL_UNATTRIBUTED_PROCESS "unknown"

static volatile bool g_Running = true;
static unsigned long g_ProcDescriptorWalks = 0;

static void ProcPath(char* out, size_t outLen, const char* suffix) {
    snprintf(out, outLen, "%s/%s", OMINULL_PROC_ROOT, suffix);
}

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
    char primary_ip[64];
    char primary_mac[32];
    char ca_path[256];
    /* The certificate this endpoint proves its identity with. It is an
     * additional matching proof alongside the unique device credential. */
    char client_cert_path[256];
    char client_key_path[256];
    char config_path[256];
    char install_type[16];
    char package_identifier[64];
    char registered_package_version[64];
    char provenance_status[16];
    /* Where the device credential was read from. New package services use a
     * protected file; --key remains only as a compatibility migration input. */
    char key_path[256];
    bool verbose;
    /* Direct self-issued hubs use a pinned Ominull CA. Public ACME or
     * Cloudflare endpoints use the operating system trust store instead. */
    bool pin_hub_ca;
    bool allow_plaintext;
    char evidence_pubkey_hex[65];
} LINUX_AGENT_CONFIG;

static bool EnforcementTeardown(const char* tool);

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
    bool bytes_measured;
    uint64_t socket_identity;
    uint64_t observation_count;
    uint64_t first_observed_ns;
    uint64_t last_observed_ns;
    PROCESS_ENRICHMENT enrichment;
} LINUX_FLOW_EVENT;

#include "udp_collector.h"
#include "response_capabilities.h"

/* What this host is authorized to enforce, and the keys and manifest that
 * decide it (agent_trust.h). Loaded once at start, moved only by verified
 * grants. */
static TrustContext g_Trust;

typedef struct {
    unsigned long inode;
    uint32_t cookie0;
    uint32_t cookie1;
    uint64_t bytes_in;
    uint64_t bytes_out;
    bool found;
} SOCKET_DIAG_RESULT;

typedef struct {
    unsigned long inode;
    uint32_t cookie0;
    uint32_t cookie1;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t first_sample_ns, last_sample_ns;
    bool valid;
} SOCKET_COUNTER;

#define SOCKET_COUNTER_CAP 1024
static SOCKET_COUNTER g_SocketCounters[SOCKET_COUNTER_CAP];
static uint64_t g_TCPUnmeasured, g_TCPDeferred;
static bool g_TCPQueryActive;

static size_t SocketCounterSlot(unsigned long inode, uint32_t cookie0, uint32_t cookie1) {
    uint64_t h = (uint64_t)inode * 11400714819323198485ull;
    h ^= (uint64_t)cookie0 << 17;
    h ^= (uint64_t)cookie1 * 0x9e3779b97f4a7c15ull;
    return (size_t)(h & (SOCKET_COUNTER_CAP - 1));
}

/* SOCK_DIAG returns cumulative TCP counters. Keep the last reading per socket
 * cookie and report only the interval delta, so a connection that remains open
 * across several heartbeats is not counted once per heartbeat. A bounded open
 * addressing table is enough for the 64-flow wire cap and refuses to alias a
 * reused inode into an unrelated connection. */
static uint64_t SocketCounterDelta(unsigned long inode, uint32_t cookie0, uint32_t cookie1,
                                    uint64_t bytesIn, uint64_t bytesOut, uint64_t* outIn,
                                    uint64_t* outOut) {
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    uint64_t sample = (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
    size_t start = SocketCounterSlot(inode, cookie0, cookie1);
    SOCKET_COUNTER *available = NULL;
    for (size_t probe = 0; probe < SOCKET_COUNTER_CAP; probe++) {
        SOCKET_COUNTER *slot = &g_SocketCounters[(start + probe) & (SOCKET_COUNTER_CAP - 1)];
        if (slot->valid && slot->inode == inode && slot->cookie0 == cookie0 && slot->cookie1 == cookie1) {
            *outIn = bytesIn >= slot->bytes_in ? bytesIn - slot->bytes_in : 0;
            *outOut = bytesOut >= slot->bytes_out ? bytesOut - slot->bytes_out : 0;
            slot->first_sample_ns = slot->last_sample_ns;
            slot->last_sample_ns = sample;
            slot->bytes_in = bytesIn;
            slot->bytes_out = bytesOut;
            return 1;
        }
        if (!slot->valid || sample - slot->last_sample_ns > 300000000000ULL) {
            if (!available)
                available = slot;
        }
    }
    *outIn = 0;
    *outOut = 0;
    if (!available)
        return 0;
    *available = (SOCKET_COUNTER){.inode = inode,
                                  .cookie0 = cookie0,
                                  .cookie1 = cookie1,
                                  .bytes_in = bytesIn,
                                  .bytes_out = bytesOut,
                                  .first_sample_ns = sample,
                                  .last_sample_ns = sample,
                                  .valid = true};
    return 1;
}
static const SOCKET_COUNTER *SocketCounterWindow(const SOCKET_DIAG_RESULT *stats) {
    size_t start = SocketCounterSlot(stats->inode, stats->cookie0, stats->cookie1);
    for (size_t probe = 0; probe < SOCKET_COUNTER_CAP; probe++) {
        const SOCKET_COUNTER *slot = &g_SocketCounters[(start + probe) & (SOCKET_COUNTER_CAP - 1)];
        if (slot->valid && slot->inode == stats->inode && slot->cookie0 == stats->cookie0 &&
            slot->cookie1 == stats->cookie1)
            return slot;
    }
    return NULL;
}

static bool SocketDiagResultFor(const unsigned long* inodes, size_t count,
                                SOCKET_DIAG_RESULT* results, uint32_t inode,
                                uint32_t cookie0, uint32_t cookie1,
                                const struct tcp_info* info, size_t infoLen) {
    if (infoLen < offsetof(struct tcp_info, tcpi_bytes_received) + sizeof(info->tcpi_bytes_received) ||
        infoLen < offsetof(struct tcp_info, tcpi_bytes_sent) + sizeof(info->tcpi_bytes_sent)) {
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        if (inodes[i] != (unsigned long)inode) continue;
        results[i].inode = inodes[i];
        results[i].cookie0 = cookie0;
        results[i].cookie1 = cookie1;
        results[i].bytes_in = info->tcpi_bytes_received;
        results[i].bytes_out = info->tcpi_bytes_sent;
        results[i].found = true;
        return true;
    }
    return false;
}

/* Query one address family of TCP sockets once and join the result to the
 * already parsed /proc/net rows by inode. One netlink dump replaces one
 * per-socket ioctl or helper process and gives real cumulative byte counters
 * when the kernel exposes them. Unsupported kernels leave the fields
 * unmeasured (zero). */
static bool QuerySocketDiagFamily(const unsigned long* inodes, size_t count,
                                  SOCKET_DIAG_RESULT* results, int family) {
    if (count == 0) return true;

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_INET_DIAG);
    if (fd < 0) return false;

    struct {
        struct nlmsghdr header;
        struct inet_diag_req_v2 request;
    } query;
    memset(&query, 0, sizeof(query));
    query.header.nlmsg_len = NLMSG_LENGTH(sizeof(query.request));
    query.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    query.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    query.header.nlmsg_seq = 1;
    query.request.sdiag_family = (uint8_t)family;
    query.request.sdiag_protocol = IPPROTO_TCP;
    query.request.idiag_ext = (uint8_t)(1U << (INET_DIAG_INFO - 1));
    query.request.idiag_states = UINT32_MAX;

    bool ok = send(fd, &query, query.header.nlmsg_len, 0) == (ssize_t)query.header.nlmsg_len;
    if (!ok) {
        close(fd);
        return false;
    }

    unsigned char buffer[65536];
    bool done = false;
    while (!done) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        if (received == 0) {
            ok = false;
            break;
        }
        for (struct nlmsghdr* header = (struct nlmsghdr*)buffer;
             NLMSG_OK(header, (unsigned int)received);
             header = NLMSG_NEXT(header, received)) {
            if (header->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (header->nlmsg_type == NLMSG_ERROR) {
                ok = false;
                done = true;
                break;
            }
            if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
                NLMSG_PAYLOAD(header, 0) < sizeof(struct inet_diag_msg)) continue;

            const struct inet_diag_msg* message = NLMSG_DATA(header);
            size_t attrLen = NLMSG_PAYLOAD(header, 0) - sizeof(*message);
            struct rtattr* attr = (struct rtattr*)((unsigned char*)message + sizeof(*message));
            const struct tcp_info* info = NULL;
            size_t infoLen = 0;
            for (; RTA_OK(attr, (int)attrLen); attr = RTA_NEXT(attr, attrLen)) {
                if ((attr->rta_type & NLA_F_NESTED) == 0 && attr->rta_type == INET_DIAG_INFO) {
                    info = RTA_DATA(attr);
                    infoLen = RTA_PAYLOAD(attr);
                    break;
                }
            }
            if (info) {
                SocketDiagResultFor(inodes, count, results, message->idiag_inode,
                                    message->id.idiag_cookie[0], message->id.idiag_cookie[1],
                                    info, infoLen);
            }
        }
    }
    close(fd);
    return ok;
}

static bool QuerySocketDiag(const unsigned long* inodes, size_t count,
                            SOCKET_DIAG_RESULT* results) {
    bool ipv4 = QuerySocketDiagFamily(inodes, count, results, AF_INET);
    bool ipv6 = QuerySocketDiagFamily(inodes, count, results, AF_INET6);
    return ipv4 && ipv6;
}

static bool ParsePackageQuery(const char* output, char* version, size_t versionCap) {
    char state[24] = {0};
    if (sscanf(output, "%23s %63s", state, version) != 2 || state[0] == '\0' || version[0] == '\0') {
        return false;
    }
    return strcmp(state, "installed") == 0 && strlen(version) < versionCap;
}

static void DetectPackageProvenance(LINUX_AGENT_CONFIG* config) {
    snprintf(config->install_type, sizeof(config->install_type), "unknown");
    config->package_identifier[0] = '\0';
    config->registered_package_version[0] = '\0';
    snprintf(config->provenance_status, sizeof(config->provenance_status), "unknown");

    char executable[sizeof(config->client_cert_path)] = {0};
    ssize_t executable_len = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (executable_len <= 0) return;
    executable[executable_len] = '\0';
    if (strcmp(executable, "/opt/ominull/bin/ominulld") != 0) return;

    FILE* query = popen("dpkg-query -W -f='${db:Status-Status}\\t${Version}\\n' ominull-agent 2>/dev/null", "r");
    if (!query) return;
	char queryOutput[128] = {0}, version[64] = {0};
	bool read = fgets(queryOutput, sizeof(queryOutput), query) != NULL;
	int exit_code = pclose(query);
	if (exit_code != 0 || !read || !ParsePackageQuery(queryOutput, version, sizeof(version))) return;

    snprintf(config->install_type, sizeof(config->install_type), "deb");
    snprintf(config->package_identifier, sizeof(config->package_identifier), "ominull-agent");
    snprintf(config->registered_package_version, sizeof(config->registered_package_version), "%s", version);
    snprintf(config->provenance_status, sizeof(config->provenance_status),
             strcmp(version, OMINULL_LINUX_AGENT_VERSION) == 0 ? "native" : "mismatch");
}

/* ReadKeyFile takes the first line of a file as the device credential. A file is the only
 * channel that keeps the credential off the command line, and the mode is
 * checked because a 0644 key file would give back exactly the exposure the
 * file was introduced to remove. */
static bool ReadKeyFile(const char* path, char* out, size_t cap) {
    /* Validate the opened object, never a pathname checked before fopen. */
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        printf("[!] Cannot open the device credential file: %s\n", strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_uid != 0 && st.st_uid != geteuid()) ||
        (st.st_mode & (S_IRWXG | S_IRWXO))) {
        printf("[!] Device credential requires an owner-only regular file.\n");
        close(fd);
        return false;
    }
    FILE* f = fdopen(fd, "r");
    if (!f) { close(fd); return false; }
    char line[512] = {0};
    char* got = fgets(line, sizeof(line), f);
    fclose(f);
    if (!got) {
        printf("[!] Device credential file %s is empty.\n", path);
        return false;
    }
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r' ||
                     line[n - 1] == ' ' || line[n - 1] == '\t')) {
        line[--n] = '\0';
    }
    if (!line[0]) {
        printf("[!] Device credential file %s holds no credential on its first line.\n", path);
        return false;
    }
    snprintf(out, cap, "%s", line);
    return true;
}

static bool IsDeviceCredentialValue(const char* value) {
    if (!value || strncmp(value, "omd_", 4) != 0 || strlen(value) != 68) return false;
    for (size_t i = 4; i < 68; i++) {
        if (!isxdigit((unsigned char)value[i])) return false;
    }
    return true;
}

static void SetConfigValue(LINUX_AGENT_CONFIG* config, const char* key, const char* value) {
    if (strcmp(key, "hub_url") == 0) snprintf(config->hub_url, sizeof(config->hub_url), "%s", value);
	    else if (strcmp(key, "key_path") == 0 || strcmp(key, "device_credential_path") == 0) snprintf(config->key_path, sizeof(config->key_path), "%s", value);
    else if (strcmp(key, "endpoint_id") == 0) snprintf(config->endpoint_id, sizeof(config->endpoint_id), "%s", value);
    else if (strcmp(key, "role_tag") == 0) snprintf(config->role_tag, sizeof(config->role_tag), "%s", value);
    else if (strcmp(key, "location_id") == 0) snprintf(config->location_id, sizeof(config->location_id), "%s", value);
    else if (strcmp(key, "ca_path") == 0) snprintf(config->ca_path, sizeof(config->ca_path), "%s", value);
    else if (strcmp(key, "client_cert_path") == 0) snprintf(config->client_cert_path, sizeof(config->client_cert_path), "%s", value);
    else if (strcmp(key, "client_key_path") == 0) snprintf(config->client_key_path, sizeof(config->client_key_path), "%s", value);
	    else if (strcmp(key, "device_credential") == 0 || strcmp(key, "api_key") == 0) snprintf(config->api_key, sizeof(config->api_key), "%s", value);
	else if (strcmp(key, "pin_hub_ca") == 0) config->pin_hub_ca = strcmp(value, "0") != 0;
    else if (strcmp(key, "allow_plaintext") == 0) config->allow_plaintext = strcmp(value, "1") == 0;
}

/* Releases before the native package wrote one shell-style OMINULL_ARGS line
 * and put it in the systemd environment. The package-owned unit deliberately
 * does not evaluate that line, but a package upgrade must still be able to
 * start an enrolled endpoint. Parse the bounded, whitespace-delimited options
 * emitted by that bootstrap without invoking a shell or placing the key in a
 * process argument vector. New installs use the key/value format above. */
static void LoadLegacyArguments(LINUX_AGENT_CONFIG* config, const char* raw) {
    char args[2048];
    int written = snprintf(args, sizeof(args), "%s", raw);
    if (written < 0 || (size_t)written >= sizeof(args)) return;

    char* save = NULL;
    char* option = strtok_r(args, " \t", &save);
    while (option) {
        if (strcmp(option, "--allow-plaintext") == 0) {
            config->allow_plaintext = true;
            option = strtok_r(NULL, " \t", &save);
            continue;
        }
        if (strcmp(option, "--no-auto-update") == 0) { /* retired: this agent never updates itself */
            option = strtok_r(NULL, " \t", &save);
            continue;
        }

        char* value = strtok_r(NULL, " \t", &save);
        if (!value) break;
        if (strcmp(option, "--hub") == 0) SetConfigValue(config, "hub_url", value);
        else if (strcmp(option, "--key") == 0) snprintf(config->api_key, sizeof(config->api_key), "%s", value);
        else if (strcmp(option, "--key-file") == 0) SetConfigValue(config, "key_path", value);
        else if (strcmp(option, "--id") == 0) SetConfigValue(config, "endpoint_id", value);
        else if (strcmp(option, "--role") == 0) SetConfigValue(config, "role_tag", value);
        else if (strcmp(option, "--location") == 0) SetConfigValue(config, "location_id", value);
        else if (strcmp(option, "--ca") == 0) SetConfigValue(config, "ca_path", value);
        else if (strcmp(option, "--client-cert") == 0) SetConfigValue(config, "client_cert_path", value);
        else if (strcmp(option, "--client-key") == 0) SetConfigValue(config, "client_key_path", value);
		/* Cloudflare service-token options are deliberately not accepted by new
		 * steady-state agents. */
        option = strtok_r(NULL, " \t", &save);
    }
}

static bool LoadConfigFile(LINUX_AGENT_CONFIG* config, const char* path) {
    FILE* file = fopen(path, "rb");
    if (!file) return false;
    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        char* value = strchr(line, '=');
        if (!value) continue;
        *value++ = '\0';
        value[strcspn(value, "\r\n")] = '\0';
        if (line[0] == '#') continue;
        if (strcmp(line, "OMINULL_ARGS") == 0) LoadLegacyArguments(config, value);
        else SetConfigValue(config, line, value);
    }
    fclose(file);
    return true;
}

static bool WritePrivateFile(const char* path, const char* data, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, mode);
    if (fd < 0) return false;
    size_t len = strlen(data), written = 0;
    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);
        if (n <= 0) {
            close(fd);
            unlink(path);
            return false;
        }
        written += (size_t)n;
    }
    fchmod(fd, mode);
    /* Callers rename these files over live credentials; what is renamed has
     * to be on disk first, or a power cut leaves an empty key behind. */
    if (fsync(fd) != 0) {
        close(fd);
        unlink(path);
        return false;
    }
    return close(fd) == 0;
}

static bool CopyPrivateFile(const char* source, const char* destination, mode_t mode) {
    int input = open(source, O_RDONLY | O_NOFOLLOW);
    if (input < 0) return false;
    int output = open(destination, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, mode);
    if (output < 0) {
        close(input);
        return false;
    }
    char buffer[16384];
    bool ok = true;
    for (;;) {
        ssize_t n = read(input, buffer, sizeof(buffer));
        if (n == 0) break;
        if (n < 0) { ok = false; break; }
        ssize_t offset = 0;
        while (offset < n) {
            ssize_t wrote = write(output, buffer + offset, (size_t)(n - offset));
            if (wrote <= 0) { ok = false; break; }
            offset += wrote;
        }
        if (!ok) break;
    }
    fchmod(output, mode);
    close(input);
    if (close(output) != 0) ok = false;
    if (!ok) unlink(destination);
    return ok;
}

/* Package-owned enrollment writer. It receives the credential and staged
 * certificate paths on stdin, so bootstrap never writes a daemon or unit and
 * never places the device credential in a privileged process argument. */
static bool ConfigureFromStdin(void) {
    char hub[256] = {0}, key[128] = {0}, endpoint[64] = {0};
    char role[64] = "workstation", location[64] = "loc-home";
    char caSource[256] = {0}, certSource[256] = {0}, keySource[256] = {0};
	bool pinHubCA = true, allowPlaintext = false;
    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        char* value = strchr(line, '=');
        if (!value) continue;
        *value++ = '\0';
        value[strcspn(value, "\r\n")] = '\0';
        if (strchr(value, '\r') || strchr(value, '\n')) return false;
        if (strcmp(line, "hub_url") == 0) snprintf(hub, sizeof(hub), "%s", value);
		else if (strcmp(line, "device_credential") == 0 || strcmp(line, "api_key") == 0) snprintf(key, sizeof(key), "%s", value);
        else if (strcmp(line, "endpoint_id") == 0) snprintf(endpoint, sizeof(endpoint), "%s", value);
        else if (strcmp(line, "role_tag") == 0) snprintf(role, sizeof(role), "%s", value);
        else if (strcmp(line, "location_id") == 0) snprintf(location, sizeof(location), "%s", value);
        else if (strcmp(line, "ca_source") == 0) snprintf(caSource, sizeof(caSource), "%s", value);
        else if (strcmp(line, "client_cert_source") == 0) snprintf(certSource, sizeof(certSource), "%s", value);
        else if (strcmp(line, "client_key_source") == 0) snprintf(keySource, sizeof(keySource), "%s", value);
		else if (strcmp(line, "pin_hub_ca") == 0) pinHubCA = strcmp(value, "0") != 0;
        else if (strcmp(line, "allow_plaintext") == 0) allowPlaintext = strcmp(value, "1") == 0;
    }
    if (!hub[0] || !key[0] || !endpoint[0] || (pinHubCA && !caSource[0])) return false;
    if (!allowPlaintext && strncmp(hub, "https://", 8) != 0) return false;
    if (mkdir("/etc/ominull", 0755) != 0 && errno != EEXIST) return false;
    if (mkdir("/var/lib/ominull", 0755) != 0 && errno != EEXIST) return false;
    if (!WritePrivateFile("/etc/ominull/agent.key", key, 0600)) return false;
	if (pinHubCA && !CopyPrivateFile(caSource, "/etc/ominull/ca.crt", 0644)) return false;
    if (certSource[0] && !CopyPrivateFile(certSource, "/etc/ominull/client.crt", 0600)) return false;
    if (keySource[0] && !CopyPrivateFile(keySource, "/etc/ominull/client.key", 0600)) return false;
    /* The response authority's keys are not taken from the enrollment bundle:
     * the agent pins them on first contact, only from a trust bundle the
     * release key signed (agent_trust.h, Trust_PinKeys). */

    char config[2048];
    int n = snprintf(config, sizeof(config),
                     "hub_url=%s\nkey_path=/etc/ominull/agent.key\nendpoint_id=%s\nrole_tag=%s\n"
	                 "location_id=%s\nca_path=%s\npin_hub_ca=%d\nclient_cert_path=/etc/ominull/client.crt\n"
	                     "client_key_path=/etc/ominull/client.key\n"
	                     "allow_plaintext=%d\n",
	                     hub, endpoint, role, location, pinHubCA ? "/etc/ominull/ca.crt" : "",
	                     pinHubCA ? 1 : 0, allowPlaintext ? 1 : 0);
    if (n < 0 || (size_t)n >= sizeof(config) || !WritePrivateFile("/etc/ominull/agent.conf", config, 0600)) {
        unlink("/etc/ominull/agent.key");
        return false;
    }
    printf("[+] Package-owned agent configuration installed.\n");
    return true;
}

static void PrintUsage(const char* prog) {
    printf("Ominull Linux Threat Nullification Daemon (v%s)\n", OMINULL_LINUX_AGENT_VERSION);
    printf("Usage:\n");
	printf("  %s --hub <url> --key-file <path> [--ca <path>] [--role <role>] [--location <id>] [--allow-plaintext] [-v]\n", prog);
    printf("\nOptions:\n");
	printf("  --key-file <path>  Read the unique device credential from a file. Prefer this:\n");
    printf("                     an argument is world-readable through /proc/<pid>/cmdline.\n");
    printf("  --ca <path>        CA certificate the hub is verified against (default %s).\n", OMINULL_DEFAULT_CA_PATH);
    printf("  --client-cert <p>  Certificate this endpoint identifies itself with, and --client-key\n");
    printf("                     its private key. Enrolment issues both; without them the hub has\n");
	printf("                     direct native mTLS adds a second matching proof.\n");
	printf("  --allow-plaintext  Permit an http:// hub. Credentials then cross the network in the clear.\n");
    printf("  --version          Print the version and exit.\n");
    printf("  --config <path>    Read package-owned runtime configuration.\n");
    printf("  --configure-stdin  Install enrollment material from stdin.\n");
    printf("  --cleanup          Remove Ominull-owned host enforcement state (local recovery: also\n");
    printf("                     records that isolation and quarantines were lifted here).\n");
    printf("  --capability-ceiling P  Cap what any manifest grants this host (monitor, isolate,\n");
    printf("                     signed-scripts, monitor-signed-scripts, respond, engagement; none removes it).\n");
    printf("                     Set at the host, never by the hub. The two signed-scripts levels run scripts\n");
    printf("                     only with a host authority key; monitor-signed-scripts never isolates.\n");
    printf("  --repin-trust      Forget the pinned response authority keys; the next contact with\n");
    printf("                     the hub pins the keys it offers with a release-key-signed bundle (rotation).\n");
}

/* ---------------------------------------------------------------------------
 * Hub transport
 *
 * Everything this agent sends carries its unique device credential, and everything it
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
	if (!config->pin_hub_ca) return true;
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
 * certificate. Without --proto a redirect to http:// would hand the device credential
 * over in the clear on the next hop. */
#define HUB_CURL_ARGS_LEN 1024
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
	bool pin = config->pin_hub_ca && config->ca_path[0];
	if (config->client_cert_path[0] && config->client_key_path[0] &&
        access(config->client_cert_path, R_OK) == 0 && access(config->client_key_path, R_OK) == 0) {
		if (pin) {
			snprintf(out, outLen,
					 "--cacert \"%s\" --proto =https --proto-redir =https --cert \"%s\" --key \"%s\"",
					 config->ca_path, config->client_cert_path, config->client_key_path);
		} else {
			snprintf(out, outLen,
					 "--proto =https --proto-redir =https --cert \"%s\" --key \"%s\"",
					 config->client_cert_path, config->client_key_path);
		}
    } else {
		if (pin) {
			snprintf(out, outLen, "--cacert \"%s\" --proto =https --proto-redir =https", config->ca_path);
		} else {
			snprintf(out, outLen, "--proto =https --proto-redir =https");
		}
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

typedef struct {
    unsigned long inode;
    uint32_t pid;
    char path[MAX_PATH_LEN];
} PROC_SOCKET_OWNER;

typedef struct {
    uint32_t pid;
    unsigned long long start_time;
    char path[MAX_PATH_LEN];
    bool valid;
} PROCESS_PATH_CACHE_ENTRY;

#define PROCESS_PATH_CACHE_CAP 256
static PROCESS_PATH_CACHE_ENTRY g_ProcessPathCache[PROCESS_PATH_CACHE_CAP];

static bool ReadProcessStartTime(uint32_t pid, unsigned long long* outStart) {
    char statSuffix[64];
    char statPath[256];
    snprintf(statSuffix, sizeof(statSuffix), "%u/stat", pid);
    ProcPath(statPath, sizeof(statPath), statSuffix);

    FILE* fp = fopen(statPath, "r");
    if (!fp) return false;
    char line[1024];
    bool ok = fgets(line, sizeof(line), fp) != NULL;
    fclose(fp);
    if (!ok) return false;

    /* The comm field may contain spaces and ')' characters. The last ')' is
     * the stable delimiter; field 22 is the twentieth token after state. */
    char* fields = strrchr(line, ')');
    if (!fields) return false;
    fields++;
    char* save = NULL;
    char* token = strtok_r(fields, " ", &save);
    int field = 3;
    while (token) {
        if (field == 22) {
            char* end = NULL;
            unsigned long long value = strtoull(token, &end, 10);
            if (end == token) return false;
            *outStart = value;
            return true;
        }
        field++;
        token = strtok_r(NULL, " ", &save);
    }
    return false;
}

static bool ReadProcessPath(uint32_t pid, char* outPath, size_t maxPathLen) {
    char suffix[64];
    char path[256];
    snprintf(suffix, sizeof(suffix), "%u/exe", pid);
    ProcPath(path, sizeof(path), suffix);
    ssize_t length = readlink(path, outPath, maxPathLen - 1);
    if (length > 0) {
        outPath[length] = '\0';
        return true;
    }

    snprintf(suffix, sizeof(suffix), "%u/cmdline", pid);
    ProcPath(path, sizeof(path), suffix);
    FILE* fp = fopen(path, "r");
    if (fp) {
        if (fgets(outPath, (int)maxPathLen, fp)) {
            outPath[strcspn(outPath, "\r\n\0")] = '\0';
            fclose(fp);
            return outPath[0] != '\0';
        }
        fclose(fp);
    }
    snprintf(outPath, maxPathLen, "process_%u", pid);
    return false;
}

static const char* CachedProcessPath(uint32_t pid, char* fallback, size_t fallbackLen) {
    unsigned long long startTime = 0;
    bool hasStartTime = ReadProcessStartTime(pid, &startTime);
    size_t slot = (size_t)pid % PROCESS_PATH_CACHE_CAP;
    PROCESS_PATH_CACHE_ENTRY* entry = &g_ProcessPathCache[slot];
    if (entry->valid && entry->pid == pid &&
        ((!hasStartTime && entry->start_time == 0) ||
         (hasStartTime && entry->start_time == startTime))) {
        return entry->path;
    }

    ReadProcessPath(pid, fallback, fallbackLen);
    if (hasStartTime) {
        entry->pid = pid;
        entry->start_time = startTime;
        snprintf(entry->path, sizeof(entry->path), "%s", fallback);
        entry->valid = true;
        return entry->path;
    }
    return fallback;
}

static bool ParseSocketLink(const char* linkTarget, unsigned long* outInode) {
    unsigned long inode = 0;
    char extra = '\0';
    if (sscanf(linkTarget, "socket:[%lu]%c", &inode, &extra) != 1 || inode == 0) {
        return false;
    }
    *outInode = inode;
    return true;
}

static void IndexSocketOwners(const unsigned long* targetInodes, size_t targetCount,
                              PROC_SOCKET_OWNER* owners) {
    DIR* procDir = opendir(OMINULL_PROC_ROOT);
    if (!procDir) return;

    struct dirent* procEntry;
    while ((procEntry = readdir(procDir)) != NULL) {
        if (!isdigit((unsigned char)procEntry->d_name[0])) continue;

        char* end = NULL;
        unsigned long parsedPid = strtoul(procEntry->d_name, &end, 10);
        if (end == procEntry->d_name || *end != '\0' || parsedPid > UINT32_MAX) continue;
        uint32_t pid = (uint32_t)parsedPid;

        char fdSuffix[64];
        char fdDirPath[256];
        snprintf(fdSuffix, sizeof(fdSuffix), "%u/fd", pid);
        ProcPath(fdDirPath, sizeof(fdDirPath), fdSuffix);
        DIR* fdDir = opendir(fdDirPath);
        if (!fdDir) continue;

        struct dirent* fdEntry;
        char pathFallback[MAX_PATH_LEN] = {0};
        const char* processPath = NULL;
        while ((fdEntry = readdir(fdDir)) != NULL) {
            if (fdEntry->d_name[0] == '.') continue;

            char fdLinkPath[512];
            snprintf(fdLinkPath, sizeof(fdLinkPath), "%s/%s", fdDirPath, fdEntry->d_name);
            char linkTarget[512];
            g_ProcDescriptorWalks++;
            ssize_t linkLen = readlink(fdLinkPath, linkTarget, sizeof(linkTarget) - 1);
            if (linkLen <= 0) continue;
            linkTarget[linkLen] = '\0';

            unsigned long inode = 0;
            if (!ParseSocketLink(linkTarget, &inode)) continue;
            for (size_t i = 0; i < targetCount; i++) {
                if (owners[i].pid != 0 || targetInodes[i] != inode) continue;
                if (!processPath) processPath = CachedProcessPath(pid, pathFallback, sizeof(pathFallback));
                owners[i].inode = inode;
                owners[i].pid = pid;
                snprintf(owners[i].path, sizeof(owners[i].path), "%s", processPath);
                break;
            }
        }
        closedir(fdDir);
    }
    closedir(procDir);
}

// Convert a /proc/net/tcp IPv4 address to standard dotted quad.
static void ParseHexIPv4(const char* hexStr, char* outIp, size_t maxLen) {
    unsigned int raw = 0;
    if (sscanf(hexStr, "%X", &raw) == 1) {
        struct in_addr addr;
        addr.s_addr = raw; // /proc/net/tcp stores in network byte order on x86
        const char* res = inet_ntop(AF_INET, &addr, outIp, maxLen);
        if (!res) {
            strncpy(outIp, "0.0.0.0", maxLen - 1);
            outIp[maxLen - 1] = '\0';
        }
    } else {
        strncpy(outIp, "0.0.0.0", maxLen - 1);
        outIp[maxLen - 1] = '\0';
    }
}

// /proc/net/tcp6 prints each 32-bit word in host byte order. Decode the words
// rather than reversing the complete address: reversing all 16 bytes would
// make the first and last halves change places and corrupt non-loopback peers.
static bool ParseHexIPv6(const char* hexStr, char* outIp, size_t maxLen) {
    if (strlen(hexStr) != 32) return false;

    unsigned char encoded[16];
    for (size_t i = 0; i < sizeof(encoded); i++) {
        char byte[3] = {hexStr[i * 2], hexStr[i * 2 + 1], '\0'};
        char* end = NULL;
        unsigned long value = strtoul(byte, &end, 16);
        if (end != byte + 2 || value > 0xff) return false;
        encoded[i] = (unsigned char)value;
    }

    unsigned char address[16];
    for (size_t word = 0; word < 4; word++) {
        for (size_t byte = 0; byte < 4; byte++) {
            address[word * 4 + byte] = encoded[word * 4 + (3 - byte)];
        }
    }
    if (!inet_ntop(AF_INET6, address, outIp, maxLen)) {
        if (maxLen > 0) {
            strncpy(outIp, "::", maxLen - 1);
            outIp[maxLen - 1] = '\0';
        }
        return false;
    }
    return true;
}

static bool IsZeroAddress(const char* hexStr) {
    for (const char* p = hexStr; *p; p++) {
        if (*p != '0') return false;
    }
    return true;
}

static bool IsLoopbackAddress(const char* address) {
    return strcmp(address, "127.0.0.1") == 0 || strcmp(address, "::1") == 0;
}

/* TCP states as /proc/net/tcp prints them, from include/net/tcp_states.h.
 * Only the states in which a connection can still carry data are worth
 * reporting as a flow. */
#define TCP_STATE_ESTABLISHED 0x01
#define TCP_STATE_SYN_SENT    0x02
#define TCP_STATE_FIN_WAIT1   0x04
#define TCP_STATE_FIN_WAIT2   0x05

/* One socket the collector may report, before any process enrichment. The
 * expensive half of a flow - the command line, the user identity and the
 * executable hash behind it - is spent only on the sockets that win a wire
 * slot, so candidates stay cheap enough to hold several times the wire cap. */
typedef struct {
    char src_ip[64];
    char dst_ip[64];
    uint16_t src_port;
    uint16_t dst_port;
    unsigned long inode;
    uint64_t bytes_in;
    uint64_t bytes_out;
} FLOW_CANDIDATE;

#define MAX_FLOW_CANDIDATES 256

/* IsReportableSocketState answers whether a socket in this state is a
 * conversation or a corpse.
 *
 * This filter is the difference between telemetry and noise. /proc/net/tcp
 * lists every socket the kernel still remembers, including ones that have
 * finished. A leaked descriptor sits in CLOSE_WAIT indefinitely and can never
 * move another byte, so it reported a zero-byte delta on every pass, and the
 * idle rollup released it again every thirty seconds - a zero-byte record on
 * a fixed timer, which is exactly the shape of a beacon. Ten sockets a worker
 * had leaked to three market-data APIs produced hours of metronomic
 * command-and-control findings against traffic that did not exist.
 *
 * TIME_WAIT never reached here: the kernel prints those rows with no inode,
 * and the inode check above has always dropped them. Nothing is lost by
 * naming the state anyway - what a finished connection did was already
 * reported while it was established.
 *
 * SYN_SENT is deliberately kept: a connection attempt that never completes is
 * a real signal, and it is one of the few places a dead command-and-control
 * address shows itself. LISTEN never had a peer to talk to; the remote-port
 * check already drops it, and naming it here says so on purpose. */
static bool IsReportableSocketState(int state) {
    switch (state) {
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_SYN_SENT:
        case TCP_STATE_FIN_WAIT1:
        case TCP_STATE_FIN_WAIT2:
            return true;
        default:
            return false;
    }
}

// Read one TCP address-family table from /proc/net into the candidate set.
// The table is read first, then process descriptors are walked once and joined
// by inode. That keeps descriptor reads proportional to the proc tree, not to
// socket count.
static void CollectSocketTable(const char* tableName, bool ipv6,
                               FLOW_CANDIDATE* candidates, size_t maxCandidates,
                               size_t* count) {
    char tablePath[256];
    ProcPath(tablePath, sizeof(tablePath), tableName);
    FILE* fp = fopen(tablePath, "r");
    if (!fp) return;

    char line[512];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return;
    }

    static size_t cursor[2];
    size_t start = cursor[ipv6 ? 1 : 0], eligible = 0, before = *count;
    for (int pass = 0; pass < 2; pass++) {
        while (fgets(line, sizeof(line), fp)) {
            // Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout
            // inode
            int sl = 0, state = 0;
            char localAddrHex[64] = {0}, remAddrHex[64] = {0};
            unsigned int localPort = 0, remPort = 0;
            unsigned long inode = 0;
            int matched =
                sscanf(line, "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %*X:%*X %*X:%*X %*X %*d %*d %lu",
                       &sl, localAddrHex, &localPort, remAddrHex, &remPort, &state, &inode);
            if (matched < 7 || inode == 0 || remPort == 0 || IsZeroAddress(remAddrHex))
                continue;
            if (!IsReportableSocketState(state))
                continue;

            FLOW_CANDIDATE parsed;
            FLOW_CANDIDATE *candidate = &parsed;
            memset(candidate, 0, sizeof(*candidate));
            if (ipv6) {
                if (!ParseHexIPv6(localAddrHex, candidate->src_ip, sizeof(candidate->src_ip)) ||
                    !ParseHexIPv6(remAddrHex, candidate->dst_ip, sizeof(candidate->dst_ip))) {
                    continue;
                }
            } else {
                ParseHexIPv4(localAddrHex, candidate->src_ip, sizeof(candidate->src_ip));
                ParseHexIPv4(remAddrHex, candidate->dst_ip, sizeof(candidate->dst_ip));
            }
            candidate->src_port = (uint16_t)localPort;
            candidate->dst_port = (uint16_t)remPort;
            if (IsLoopbackAddress(candidate->dst_ip) || IsLoopbackAddress(candidate->src_ip))
                continue;
            if (candidate->dst_port == 9999 && strcmp(candidate->dst_ip, candidate->src_ip) == 0)
                continue;

            candidate->inode = inode;
            if (eligible++ < start || *count >= maxCandidates)
                continue;
            candidates[(*count)++] = *candidate;
        }
        if (*count > before || start == 0)
            break;
        rewind(fp);
        if (!fgets(line, sizeof(line), fp))
            break;
        start = 0;
        eligible = 0;
    }
    size_t selected = *count - before;
    cursor[ipv6 ? 1 : 0] = eligible ? (start + selected) % eligible : 0;
    g_TCPDeferred += eligible > selected ? eligible - selected : 0;
    fclose(fp);
}

typedef struct {
    char dst_ip[64];
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t process_id;
    uint64_t last_reported;
    bool valid;
} FLOW_DEDUP_SLOT;

#define FLOW_DEDUP_CAP 2048
static FLOW_DEDUP_SLOT g_FlowDedup[FLOW_DEDUP_CAP];

static bool ShouldReportFlow(const char* dst_ip, uint16_t dst_port, uint8_t proto, uint32_t pid, uint64_t bytesIn, uint64_t bytesOut) {
    if (strcmp(dst_ip, "127.0.0.1") == 0 || strcmp(dst_ip, "::1") == 0) return false;
    
    // Always report if there is active byte movement
    if (bytesIn > 0 || bytesOut > 0) return true;

    time_t now = time(NULL);
    uint64_t hash = (uint64_t)dst_port * 2654435761u ^ (uint64_t)pid ^ (uint64_t)proto;
    for (const char* p = dst_ip; *p; p++) hash = (hash * 33) ^ (unsigned char)*p;
    
    size_t start = (size_t)(hash & (FLOW_DEDUP_CAP - 1));
    for (size_t probe = 0; probe < FLOW_DEDUP_CAP; probe++) {
        FLOW_DEDUP_SLOT* slot = &g_FlowDedup[(start + probe) & (FLOW_DEDUP_CAP - 1)];
        if (!slot->valid) {
            slot->valid = true;
            snprintf(slot->dst_ip, sizeof(slot->dst_ip), "%s", dst_ip);
            slot->dst_port = dst_port;
            slot->protocol = proto;
            slot->process_id = pid;
            slot->last_reported = (uint64_t)now;
            return true; // Novel flow on first seen
        }
        if (slot->dst_port == dst_port && slot->protocol == proto && slot->process_id == pid && strcmp(slot->dst_ip, dst_ip) == 0) {
            if ((uint64_t)now >= slot->last_reported + 30) {
                slot->last_reported = (uint64_t)now;
                return true; // 30s rollup summary
            }
            return false; // Suppress duplicate idle keepalive
        }
    }
    return true;
}

static const char* LookupDnsDomain(const char* ip) {
    (void)ip;
    return NULL;
}

/* The agent's own connection to the hub, so it is not reported back to the
 * hub as telemetry.
 *
 * A flow record exists to tell the hub something it does not already know.
 * The hub receiving a heartbeat is complete evidence that the heartbeat
 * happened, so re-describing that same socket as a flow says nothing and, on
 * an idle host, made this agent the single largest talker in its own
 * telemetry. Only the exact configured hub endpoint is dropped, and only for
 * this process: if this binary ever connects anywhere else, that is precisely
 * the thing worth seeing. */
static char g_HubPeerAddr[64] = {0};
static uint16_t g_HubPeerPort = 0;
static uint32_t g_SelfPid = 0;

static bool HubAddressLiteral(const LINUX_AGENT_CONFIG* config, char* out, size_t cap);

static void SetSelfHubPeer(const LINUX_AGENT_CONFIG* config) {
    g_SelfPid = (uint32_t)getpid();
    g_HubPeerPort = 0;
    g_HubPeerAddr[0] = '\0';
    if (!HubAddressLiteral(config, g_HubPeerAddr, sizeof(g_HubPeerAddr))) return;

    bool tls = strncmp(config->hub_url, "https://", 8) == 0;
    const char* p = strstr(config->hub_url, "://");
    p = p ? p + 3 : config->hub_url;
    const char* port = NULL;
    if (*p == '[') {
        const char* close = strchr(p, ']');
        if (close && close[1] == ':') port = close + 2;
    } else {
        const char* colon = strchr(p, ':');
        const char* slash = strchr(p, '/');
        if (colon && (!slash || colon < slash)) port = colon + 1;
    }
    unsigned long parsed = port ? strtoul(port, NULL, 10) : (tls ? 443UL : 80UL);
    g_HubPeerPort = parsed > 0 && parsed <= UINT16_MAX ? (uint16_t)parsed : 0;
}

static bool IsOwnHubFlow(const FLOW_CANDIDATE* candidate, uint32_t pid) {
    return g_HubPeerPort != 0 && pid != 0 && pid == g_SelfPid &&
           candidate->dst_port == g_HubPeerPort &&
           strcmp(candidate->dst_ip, g_HubPeerAddr) == 0;
}

/* SelectFlowCandidates chooses which sockets get the batch's wire slots.
 *
 * There are more sockets on a busy host than a batch can carry, and the
 * previous selection was "whatever /proc listed first". /proc lists sockets in
 * hash order, which has nothing to do with importance, so a host holding
 * hundreds of idle connections could spend its whole batch on them and never
 * report the transfer that mattered. Sockets that moved bytes this interval go
 * first; the rest fill what is left, still subject to the idle rollup.
 *
 * The rollup is consulted only while a slot is actually free, because
 * ShouldReportFlow records that it released a flow. Asking it about a socket
 * that could not be sent anyway would silence that socket for the next thirty
 * seconds without anything having been reported. */
static size_t SelectFlowCandidates(const FLOW_CANDIDATE* candidates,
                                   const PROC_SOCKET_OWNER* owners, size_t count,
                                   size_t maxEvents, size_t* order) {
    static size_t cursor;
    size_t selected = 0, next = cursor;
    for (int pass = 0; pass < 2 && selected < maxEvents; pass++) {
        for (size_t visited = 0; visited < count && selected < maxEvents; visited++) {
            size_t i = (cursor + visited) % count;
            bool active = candidates[i].bytes_in > 0 || candidates[i].bytes_out > 0;
            if ((pass == 0) != active) continue;
            if (IsOwnHubFlow(&candidates[i], owners[i].pid)) continue;
            if (!ShouldReportFlow(candidates[i].dst_ip, candidates[i].dst_port, IPPROTO_TCP,
                                  owners[i].pid, candidates[i].bytes_in, candidates[i].bytes_out)) {
                continue;
            }
            order[selected++] = i;
            next = (i + 1) % count;
        }
    }
    cursor = next;
    return selected;
}

// Capture active TCP socket flows from both Linux address families.
static size_t CollectTCPObservations(LINUX_FLOW_EVENT *outEvents, size_t maxEvents) {
    /* Held across calls rather than on the stack: the candidate set is several
     * times the wire cap, and this daemon runs with a modest thread stack. */
    static FLOW_CANDIDATE candidates[MAX_FLOW_CANDIDATES];
    static unsigned long targetInodes[MAX_FLOW_CANDIDATES];
    static PROC_SOCKET_OWNER owners[MAX_FLOW_CANDIDATES];
    static SOCKET_DIAG_RESULT socketStats[MAX_FLOW_CANDIDATES];
    static size_t order[MAX_FLOW_CANDIDATES];

    size_t count = 0;
    memset(candidates, 0, sizeof(candidates));
    memset(targetInodes, 0, sizeof(targetInodes));
    memset(owners, 0, sizeof(owners));
    memset(socketStats, 0, sizeof(socketStats));
    memset(outEvents, 0, sizeof(LINUX_FLOW_EVENT) * maxEvents);
    if (maxEvents == 0) return 0;

    g_TCPDeferred = 0;
    CollectSocketTable("net/tcp", false, candidates, MAX_FLOW_CANDIDATES / 2, &count);
    CollectSocketTable("net/tcp6", true, candidates, MAX_FLOW_CANDIDATES, &count);
    for (size_t i = 0; i < count; i++) {
        targetInodes[i] = candidates[i].inode;
    }

    g_TCPQueryActive = QuerySocketDiag(targetInodes, count, socketStats);
    for (size_t i = 0; i < count; i++) {
        if (!socketStats[i].found) {
            g_TCPUnmeasured++;
            continue;
        }
        uint64_t bytesIn = 0, bytesOut = 0;
        if (SocketCounterDelta(socketStats[i].inode, socketStats[i].cookie0,
                                socketStats[i].cookie1, socketStats[i].bytes_in,
                                socketStats[i].bytes_out, &bytesIn, &bytesOut)) {
            candidates[i].bytes_in = bytesIn;
            candidates[i].bytes_out = bytesOut;
        } else {
            g_TCPUnmeasured++;
        }
    }

    IndexSocketOwners(targetInodes, count, owners);

    size_t selected = SelectFlowCandidates(candidates, owners, count, maxEvents, order);
    for (size_t s = 0; s < selected; s++) {
        const FLOW_CANDIDATE* candidate = &candidates[order[s]];
        const PROC_SOCKET_OWNER* owner = &owners[order[s]];
        LINUX_FLOW_EVENT* ev = &outEvents[s];

        snprintf(ev->src_ip, sizeof(ev->src_ip), "%s", candidate->src_ip);
        snprintf(ev->dst_ip, sizeof(ev->dst_ip), "%s", candidate->dst_ip);
        ev->src_port = candidate->src_port;
        ev->dst_port = candidate->dst_port;
        ev->protocol = IPPROTO_TCP;
        strncpy(ev->direction, "OUTBOUND", sizeof(ev->direction) - 1);
        ev->bytes_in = candidate->bytes_in;
        ev->bytes_out = candidate->bytes_out;
        const SOCKET_DIAG_RESULT *stats = &socketStats[order[s]];
        ev->socket_identity =
            stats->found ? ((uint64_t)stats->cookie0 << 32) | stats->cookie1 : candidate->inode;
        struct timespec observed;
        clock_gettime(CLOCK_BOOTTIME, &observed);
        ev->last_observed_ns = (uint64_t)observed.tv_sec * 1000000000ULL + observed.tv_nsec;
        ev->first_observed_ns = ev->last_observed_ns;
        const SOCKET_COUNTER *window = stats->found ? SocketCounterWindow(stats) : NULL;
        if (window) {
            ev->first_observed_ns = window->first_sample_ns;
            ev->last_observed_ns = window->last_sample_ns;
            ev->bytes_measured = window->last_sample_ns > window->first_sample_ns;
        }
        ev->observation_count = 1;

        if (owner->pid != 0) {
            ev->process_id = owner->pid;
            snprintf(ev->process_path, sizeof(ev->process_path), "%s", owner->path);
        } else {
            /* Nothing owns this socket that this agent can see. Saying so is
             * the honest answer; naming a system binary that is not running
             * invents an attribution and, worse, one that sits on the quiet
             * list, so the destination was silently excused as well. */
            ev->process_id = 0;
            snprintf(ev->process_path, sizeof(ev->process_path), "%s", OMINULL_UNATTRIBUTED_PROCESS);
        }

        bool foundInBatch = false;
        for (size_t j = 0; j < s; j++) {
            if (outEvents[j].process_id == ev->process_id) {
                ev->enrichment = outEvents[j].enrichment;
                foundInBatch = true;
                break;
            }
        }
        if (!foundInBatch) {
            ProcessLineage_InspectProcess(ev->process_id, &ev->enrichment);
        }
    }
    return selected;
}

#include "tcp_pending.h"
static size_t CollectTCPFlows(LINUX_FLOW_EVENT *outEvents, size_t maxEvents) {
    static LINUX_FLOW_EVENT observed[MAX_FLOW_CANDIDATES];
    size_t count = CollectTCPObservations(observed, MAX_FLOW_CANDIDATES);
    for (size_t i = 0; i < count; i++)
        TCPPendingAdd(&observed[i]);
    return TCPPendingDrain(outEvents, maxEvents);
}

/* Reserve half the wire slots for pending UDP, then lend unused capacity to
 * either protocol. UDP keys rotate independently of packet volume. */
static size_t CollectActiveFlows(LINUX_FLOW_EVENT *outEvents, size_t maxEvents) {
    if (!maxEvents)
        return 0;
    UDPCollectorPoll();
    static bool singleTCP;
    size_t udpBudget = (maxEvents + 1) / 2;
    if (maxEvents == 1) {
        singleTCP = !singleTCP;
        if (singleTCP)
            udpBudget = 0;
    }
    size_t udp = UDPCollectorDrain(outEvents, udpBudget);
    size_t tcp = CollectTCPFlows(outEvents + udp, maxEvents - udp);
    return udp + tcp + UDPCollectorDrain(outEvents + udp + tcp, maxEvents - udp - tcp);
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
 * The credential is loaded from a protected file and sent only in the
 * device-authentication header.
 *
 * stderr is left alone: a refused certificate has to stay visible in the
 * journal, and that is the one failure this agent must not swallow. */
typedef struct {
    char* data;
    size_t cap;
    size_t len;
    bool overflow;
} HUB_RESPONSE_BUFFER;

static size_t HubResponseWrite(char* ptr, size_t size, size_t nmemb, void* userdata) {
    HUB_RESPONSE_BUFFER* response = (HUB_RESPONSE_BUFFER*)userdata;
    size_t incoming = size * nmemb;
    if (!response || !response->data || response->cap == 0) return incoming;
    if (response->len + incoming >= response->cap) {
        size_t available = response->cap - response->len - 1;
        if (available > 0) memcpy(response->data + response->len, ptr, available);
        response->len += available;
        response->data[response->len] = '\0';
        response->overflow = true;
        return incoming;
    }
    memcpy(response->data + response->len, ptr, incoming);
    response->len += incoming;
    response->data[response->len] = '\0';
    return incoming;
}

/* RunHubCurl posts one JSON body without forking. libcurl keeps its connection
 * cache on this easy handle, so a three-second heartbeat reuses the TLS
 * connection while each request still gets fresh headers and a bounded body. */
/* Sets every option of one hub POST on curl (headers, TLS, timeouts) and
 * returns the header list the caller frees after the transfer; NULL on error. */
static struct curl_slist* SetupHubCurl(CURL* curl, const LINUX_AGENT_CONFIG* config, const char* url,
                                       const char* body, size_t bodyLength, const char* const* extraHeaders,
                                       HUB_RESPONSE_BUFFER* response, long timeoutMs) {
	char apiHeader[256];
	const char* headerName = IsDeviceCredentialValue(config->api_key)
	    ? "X-Ominull-Device-Credential" : "X-API-Key";
	if (snprintf(apiHeader, sizeof(apiHeader), "%s: %s", headerName, config->api_key) >= (int)sizeof(apiHeader)) {
		return NULL;
	}
	struct curl_slist* headers = curl_slist_append(NULL, "Content-Type: application/json");
	headers = curl_slist_append(headers, apiHeader);
	for (size_t i = 0; headers && extraHeaders && extraHeaders[i]; i++)
		headers = curl_slist_append(headers, extraHeaders[i]);
	if (!headers) return NULL;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)(body ? bodyLength : 0));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HubResponseWrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OminullAgent/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMs);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 3000L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, HubUsesTLS(config) ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, HubUsesTLS(config) ? 2L : 0L);
    if (HubUsesTLS(config)) {
		curl_easy_setopt(curl, CURLOPT_CAINFO,
					 config->pin_hub_ca && config->ca_path[0] ? config->ca_path : NULL);
        if (config->client_cert_path[0] && config->client_key_path[0] &&
            access(config->client_cert_path, R_OK) == 0 && access(config->client_key_path, R_OK) == 0) {
            curl_easy_setopt(curl, CURLOPT_SSLCERT, config->client_cert_path);
            curl_easy_setopt(curl, CURLOPT_SSLKEY, config->client_key_path);
        } else {
            curl_easy_setopt(curl, CURLOPT_SSLCERT, NULL);
            curl_easy_setopt(curl, CURLOPT_SSLKEY, NULL);
        }
    } else {
        curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);
        curl_easy_setopt(curl, CURLOPT_SSLCERT, NULL);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, NULL);
    }
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    return headers;
}

/* Set once the client certificate files have been replaced. The heartbeat
 * handle keeps its connection and TLS session for as long as the hub keeps it
 * open, so without a reset it would go on presenting the old certificate for
 * as long as the connection lived. */
static bool g_HubTlsReset = false;

static bool RunHubCurlBody(const LINUX_AGENT_CONFIG* config, const char* url, const char* body,
                           size_t bodyLength, const char* const* extraHeaders, char* out, size_t outCap,
                           long timeoutMs) {
    if (out && outCap) out[0] = '\0';
    static CURL* curl = NULL;
    if (curl && g_HubTlsReset) {
        curl_easy_cleanup(curl);
        curl = NULL;
    }
    g_HubTlsReset = false;
    if (!curl) {
        curl = curl_easy_init();
        if (!curl) return false;
    }
    HUB_RESPONSE_BUFFER response = {
        .data = out, .cap = outCap, .len = 0, .overflow = false
    };
    struct curl_slist* headers = SetupHubCurl(curl, config, url, body, bodyLength, extraHeaders, &response, timeoutMs);
    if (!headers) return false;

    CURLcode result = curl_easy_perform(curl);
    long status = 0;
    if (result == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (out && outCap > 1 && response.len + 1 < outCap) {
        snprintf(out + response.len, outCap - response.len, "\n" HUB_STATUS_MARKER "%ld", status);
    } else if (out && outCap > 0) {
        out[outCap - 1] = '\0';
    }
    curl_slist_free_all(headers);
    return result == CURLE_OK && !response.overflow;
}

static bool RunHubCurlTimeout(const LINUX_AGENT_CONFIG* config, const char* url,
                              const char* body, char* out, size_t outCap, long timeoutMs) {
    return RunHubCurlBody(config, url, body, body ? strlen(body) : 0, NULL, out, outCap, timeoutMs);
}

static bool RunHubCurl(const LINUX_AGENT_CONFIG* config, const char* url,
                       const char* body, char* out, size_t outCap) {
    return RunHubCurlTimeout(config, url, body, out, outCap, 5000L);
}
/* ---------------------------------------------------------------------------
 * Host isolation.
 *
 * Isolation arrives on the authenticated heartbeat reply, alongside the
 * quarantined-peer list, and is reconciled on every beat: a host that was down
 * when it was released must still come back.
 * ------------------------------------------------------------------------- */

#define OMINULL_CHAIN_IN  "OMINULL_ISO_IN"
#define OMINULL_CHAIN_OUT "OMINULL_ISO_OUT"
/* Where a rebuild writes before it swaps in; never holds policy for long. */
#define OMINULL_NEXT_IN  "OMINULL_ISO_IN_N"
#define OMINULL_NEXT_OUT "OMINULL_ISO_OUT_N"
#define MAX_ISOLATION_ALLOW 32
#define MAX_QUARANTINED_PEERS 64

/* HubAddressLiteral reduces the configured hub URL to an address literal.
 *
 * Isolation has to leave a hole for the hub or it can never be lifted, and the
 * hole is written as an address, so the name in the URL is resolved here while
 * the host can still resolve names. */
static bool HubAddressLiteral(const LINUX_AGENT_CONFIG* config, char* out, size_t cap) {
    OMINULL_HUB_TARGETS targets;
    if (!cap || !OminullResolveHub(config->hub_url, &targets) || strlen(targets.addresses[0]) >= cap) return false;
    strcpy(out, targets.addresses[0]);
    return true;
}

/* The baseline isolation policy, as this agent receives it.
 *
 * The floor used to carry two permits written into the agent: DNS to any
 * resolver and DHCP to any server. Both were holes with a justification
 * attached, and neither was visible to the person clicking Isolate. The hub now
 * sends the exact set instead - service, destination, protocol and remote port,
 * already expanded - and this agent enforces that and nothing more.
 *
 * A hub that sends an empty array is saying "hub and loopback only", which is a
 * policy, and is obeyed. */
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

/* RunFw is RunTool for the firewall tools: it waits for the xtables lock rather
 * than failing because Docker or fail2ban happened to be holding it. */
static int RunFw(const char* const argv[]) {
    const char* full[32] = { argv[0], "-w", "5" };
    size_t n = 3;
    for (size_t i = 1; argv[i] && n < sizeof(full) / sizeof(full[0]) - 1; i++) full[n++] = argv[i];
    full[n] = NULL;
    return RunTool(full);
}

/* BaselinePermit writes one permit into both chains for one rule.
 *
 * Both directions, because a reply is a new flow rather than part of the
 * request: this is the same mistake that cost the Windows agent its DHCP lease
 * when the floor was permitted outbound only. The remote port is the server's
 * port in both directions, so it is --dport going out and --sport coming back. */
static int BaselinePermit(const char* tool, const BASELINE_RULE* r) {
    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%d", r->port);
    /* A DHCPv6 request goes to the multicast address; the reply comes from the
     * server's own link-local one. */
    const char* source = strcmp(r->destination, "ff02::1:2") == 0 ? "fe80::/10" : r->destination;

    const char* out[] = { tool, "-A", OMINULL_NEXT_OUT, "-p", r->protocol,
                          "-d", r->destination, "--dport", portStr, "-j", "RETURN", NULL };
    const char* in[]  = { tool, "-A", OMINULL_NEXT_IN,  "-p", r->protocol,
                          "-s", source, "--sport", portStr, "-j", "RETURN", NULL };
    int rc = RunFw(out);
    int rcIn = RunFw(in);
    return rc != 0 ? rc : rcIn;
}

/* What iptables exit codes mean for "is it there": 0 yes; 1 or 2 no such rule or
 * chain; 3 and 127 no such table or tool. Anything else, a held lock (4) above
 * all, says nothing, and nothing may be flushed on the strength of it. */
static bool FwSaysAbsent(int rc) {
    return rc == 1 || rc == 2 || rc == 3 || rc == 127;
}

/* HookState: 1 the chain is in force, 0 it is not, -1 we could not find out. */
static int HookState(const char* tool, const char* hook, const char* chain) {
    const char* check[] = { tool, "-C", hook, "-j", chain, NULL };
    int rc = RunFw(check);
    return rc == 0 ? 1 : FwSaysAbsent(rc) ? 0 : -1;
}

/* DropChain unhooks and removes one chain and says whether it is gone. The
 * unhook is repeated a bounded number of times because a crash loop can leave
 * the jump inserted more than once, and one -D removes one copy. A chain that
 * may still be hooked keeps its rules: emptying it would open the host. */
static bool DropChain(const char* tool, const char* hook, const char* chain) {
    const char* unhook[] = { tool, "-D", hook, "-j", chain, NULL };
    for (int i = 0; i < 8 && RunFw(unhook) == 0; i++) { }
    if (HookState(tool, hook, chain) != 0) return false;
    const char* flush[] = { tool, "-F", chain, NULL };
    const char* drop[]  = { tool, "-X", chain, NULL };
    const char* list[]  = { tool, "-S", chain, NULL };
    (void)RunFw(flush);
    (void)RunFw(drop);
    return FwSaysAbsent(RunFw(list));
}

/* NoIPv6Here: a host with IPv6 turned off has no IPv6 rules to keep, and its
 * ip6tables can answer anything at all, a lock-style exit 4 included. */
static bool NoIPv6Here(const char* tool) {
    return strcmp(tool, "ip6tables") == 0 && access("/proc/net/if_inet6", F_OK) != 0;
}

/* EnforcementTeardown removes the chains from one table, including what a
 * rebuild that died part-way left behind. It reports whether they are gone. */
static bool EnforcementTeardown(const char* tool) {
    if (NoIPv6Here(tool)) return true;
    bool gone = DropChain(tool, "INPUT", OMINULL_CHAIN_IN);
    gone = DropChain(tool, "OUTPUT", OMINULL_CHAIN_OUT) && gone;
    gone = DropChain(tool, "INPUT", OMINULL_NEXT_IN) && gone;
    return DropChain(tool, "OUTPUT", OMINULL_NEXT_OUT) && gone;
}

/* RecoverSwap finishes a swap that died after unhooking the old chain, which
 * left the second chain as the only policy in force. False means that chain may
 * still be the only policy, or we could not tell, so it must not be dropped. */
static bool RecoverSwap(const char* tool, const char* hook, const char* chain, const char* next) {
    int nextHooked = HookState(tool, hook, next);
    int chainHooked = HookState(tool, hook, chain);
    if (nextHooked < 0 || chainHooked < 0) return false;
    if (nextHooked == 0 || chainHooked == 1) return true;
    const char* flush[] = { tool, "-F", chain, NULL };
    const char* drop[]  = { tool, "-X", chain, NULL };
    const char* rename[] = { tool, "-E", next, chain, NULL };
    (void)RunFw(flush);
    (void)RunFw(drop);
    return RunFw(rename) == 0;
}

/* LiftDefaultDeny removes only the rule that makes a host isolated. It is the
 * unconditional DROP: peer and threat DROPs always name an address, so they stay,
 * and everything left below them is a RETURN that changes nothing. It needs no
 * knowledge of what the rules hold, so the dead-man timer can use it after a
 * restart too. */
static bool LiftDefaultDeny(const char* tool) {
    if (NoIPv6Here(tool)) return true;
    const char* chains[] = { OMINULL_CHAIN_IN, OMINULL_CHAIN_OUT, OMINULL_NEXT_IN, OMINULL_NEXT_OUT };
    bool lifted = true;
    for (int i = 0; i < 4; i++) {
        const char* remove[] = { tool, "-D", chains[i], "-j", "DROP", NULL };
        const char* check[]  = { tool, "-C", chains[i], "-j", "DROP", NULL };
        for (int n = 0; n < 8 && RunFw(remove) == 0; n++) { }
        if (!FwSaysAbsent(RunFw(check))) lifted = false;
    }
    return lifted;
}

/* Set by EnforcementBuild when a destination the policy permits did not make it
 * into the rules, and whether trying again could help. */
static bool g_PermitsMissing = false;
static bool g_PermitsRetry = false;

static void NotePermit(int rc) {
    if (rc == 0) return;
    g_PermitsMissing = true;
    if (!FwSaysAbsent(rc)) g_PermitsRetry = true;
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
 * Both families are built; nftables migration remains separate work. */
static bool EnforcementBuild(const char* tool, bool isolated, const OMINULL_HUB_TARGETS *hub,
                             char allow[][64], int allowCount,
                             char peers[][64], int peerCount,
                             char threats[][64], int threatCount,
                             const BASELINE_RULE* baseline, int baselineCount) {
    bool v6 = strcmp(tool, "ip6tables") == 0;
    if (NoIPv6Here(tool)) return true;

    /* A rebuild never touches the rules in force until the new set is whole:
     * rules are written to a second chain, and that chain is hooked in before
     * the old one is unhooked. Flushing in place opened the host until the
     * final DROP went back on, and every change to the allow list, the peers or
     * the threat list, and every agent restart, rebuilds. */
    if (!RecoverSwap(tool, "INPUT", OMINULL_CHAIN_IN, OMINULL_NEXT_IN) ||
        !RecoverSwap(tool, "OUTPUT", OMINULL_CHAIN_OUT, OMINULL_NEXT_OUT)) return false;
    bool cleared = DropChain(tool, "INPUT", OMINULL_NEXT_IN);
    if (!DropChain(tool, "OUTPUT", OMINULL_NEXT_OUT) || !cleared) return false;
    const char* newIn[]  = { tool, "-N", OMINULL_NEXT_IN,  NULL };
    const char* newOut[] = { tool, "-N", OMINULL_NEXT_OUT, NULL };
    if (RunFw(newIn) != 0 || RunFw(newOut) != 0) {
        /* A host with no IPv6, or no IPv6 firewall tool or table, has no IPv6
         * rules to keep. A held lock (exit 4) is none of those. */
        const char* probe[] = { tool, "-S", NULL };
        int rc = RunFw(probe);
        DropChain(tool, "INPUT", OMINULL_NEXT_IN);
        DropChain(tool, "OUTPUT", OMINULL_NEXT_OUT);
        return v6 && (rc == 127 || rc == 3 || access("/proc/net/if_inet6", F_OK) != 0);
    }
    /* What the swap cannot go ahead without: the way back to the hub, loopback,
     * DHCP, every block and, when isolating, the default deny. Any other permit
     * that fails only closes more, so containment goes ahead and it is reported. */
    bool whole = true;

    /* 1. Complete A/AAAA pinholes, ahead of peer blocks, TCP port only. */
    if (hub && hub->port) {
        char port[6]; snprintf(port, sizeof(port), "%u", hub->port);
        for (size_t i = 0; i < hub->count; i++) {
            const char *address = hub->addresses[i];
            if ((strchr(address, ':') != NULL) != v6) continue;
            const char *hubIn[] = {tool, "-A", OMINULL_NEXT_IN, "-s", address,
                "-p", "tcp", "--sport", port, "-j", "RETURN", NULL};
            const char *hubOut[] = {tool, "-A", OMINULL_NEXT_OUT, "-d", address,
                "-p", "tcp", "--dport", port, "-j", "RETURN", NULL};
            if (RunFw(hubIn) != 0 || RunFw(hubOut) != 0) whole = false;
        }
    }

    /* 2. Loopback. */
    const char* loIn[]  = { tool, "-A", OMINULL_NEXT_IN,  "-i", "lo", "-j", "RETURN", NULL };
    const char* loOut[] = { tool, "-A", OMINULL_NEXT_OUT, "-o", "lo", "-j", "RETURN", NULL };
    if (RunFw(loIn) != 0 || RunFw(loOut) != 0) whole = false;

    /* IPv6 neighbor/router discovery is the link control plane, like ARP
     * for IPv4. Blocking it strands even an explicitly permitted hub after
     * neighbor entries expire. Hop-limit 255 confines NDP to this link. */
    if (v6) {
        const char *types[] = {"133", "134", "135", "136"};
        for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
            const char *ndIn[] = {tool, "-A", OMINULL_NEXT_IN, "-p", "ipv6-icmp",
                "--icmpv6-type", types[i], "-m", "hl", "--hl-eq", "255", "-j", "RETURN", NULL};
            const char *ndOut[] = {tool, "-A", OMINULL_NEXT_OUT, "-p", "ipv6-icmp",
                "--icmpv6-type", types[i], "-m", "hl", "--hl-eq", "255", "-j", "RETURN", NULL};
            NotePermit(RunFw(ndIn));
            NotePermit(RunFw(ndOut));
        }
    }

    /* Preserve path-MTU/error feedback for existing flows, not arbitrary ICMP
     * requests that could bypass peer quarantine. It comes from routers on no
     * allow list, and an allowed connection through a smaller link stalls
     * without it (scripts/test-linux-icmp-errors.sh). */
    const char *icmp = v6 ? "ipv6-icmp" : "icmp";
    const char *errorIn[] = {tool, "-A", OMINULL_NEXT_IN, "-p", icmp,
        "-m", "conntrack", "--ctstate", "RELATED", "-j", "RETURN", NULL};
    const char *errorOut[] = {tool, "-A", OMINULL_NEXT_OUT, "-p", icmp,
        "-m", "conntrack", "--ctstate", "RELATED", "-j", "RETURN", NULL};
    NotePermit(RunFw(errorIn));
    NotePermit(RunFw(errorOut));

    /* 3. DHCP, above the peer blocks. */
    for (int i = 0; i < baselineCount; i++) {
        if (strcmp(baseline[i].service, "dhcp") != 0) continue;
        if ((strchr(baseline[i].destination, ':') != NULL) != v6) continue;
        if (BaselinePermit(tool, &baseline[i]) != 0) whole = false;
    }

    /* 4. Mesh quarantine. Applies whether or not this host is isolated. */
    for (int i = 0; i < peerCount; i++) {
        if ((strchr(peers[i], ':') != NULL) != v6) continue;
        const char* pIn[]  = { tool, "-A", OMINULL_NEXT_IN,  "-s", peers[i], "-j", "DROP", NULL };
        const char* pOut[] = { tool, "-A", OMINULL_NEXT_OUT, "-d", peers[i], "-j", "DROP", NULL };
        if (RunFw(pIn) != 0 || RunFw(pOut) != 0) whole = false;
    }

    /* 4b. In-Line Threat Intelligence indicators drop. */
    for (int i = 0; i < threatCount; i++) {
        if ((strchr(threats[i], ':') != NULL) != v6) continue;
        const char* tIn[]  = { tool, "-A", OMINULL_NEXT_IN,  "-s", threats[i], "-j", "DROP", NULL };
        const char* tOut[] = { tool, "-A", OMINULL_NEXT_OUT, "-d", threats[i], "-j", "DROP", NULL };
        if (RunFw(tIn) != 0 || RunFw(tOut) != 0) whole = false;
    }

    if (isolated) {
        /* 5. The rest of the baseline - DNS, NTP, whatever else the policy
         *    names - below the peer block on purpose: quarantining a rogue
         *    resolver has to beat the rule that lets this host resolve names. */
        for (int i = 0; i < baselineCount; i++) {
            if (strcmp(baseline[i].service, "dhcp") == 0) continue;  /* already placed */
            if ((strchr(baseline[i].destination, ':') != NULL) != v6) continue;
            NotePermit(BaselinePermit(tool, &baseline[i]));
        }

        /* 6. The hub's allow list - a scoped trust rule, below a peer block so
         *    a quarantine still wins over standing trust that named the peer. */
        for (int i = 0; i < allowCount; i++) {
            if ((strchr(allow[i], ':') != NULL) != v6) continue;
            const char* aIn[]  = { tool, "-A", OMINULL_NEXT_IN,  "-s", allow[i], "-j", "RETURN", NULL };
            const char* aOut[] = { tool, "-A", OMINULL_NEXT_OUT, "-d", allow[i], "-j", "RETURN", NULL };
            NotePermit(RunFw(aIn));
            NotePermit(RunFw(aOut));
        }

        /* 7. Default deny. */
        const char* denyIn[]  = { tool, "-A", OMINULL_NEXT_IN,  "-j", "DROP", NULL };
        const char* denyOut[] = { tool, "-A", OMINULL_NEXT_OUT, "-j", "DROP", NULL };
        if (RunFw(denyIn) != 0 || RunFw(denyOut) != 0) whole = false;
    }

    /* Hook the new set in front, then take the old one out, then give the new
     * one the usual name. No moment between these has neither set in force, and
     * anything short of a whole new set leaves the old one alone. */
    const char* hookIn[]  = { tool, "-I", "INPUT",  "-j", OMINULL_NEXT_IN,  NULL };
    const char* hookOut[] = { tool, "-I", "OUTPUT", "-j", OMINULL_NEXT_OUT, NULL };
    if (!whole || RunFw(hookIn) != 0 || RunFw(hookOut) != 0) {
        DropChain(tool, "INPUT", OMINULL_NEXT_IN);
        DropChain(tool, "OUTPUT", OMINULL_NEXT_OUT);
        return false;
    }
    /* The old set must really be gone: on a release its DROP would still sit
     * behind the new chain, with the host cut off. */
    cleared = DropChain(tool, "INPUT", OMINULL_CHAIN_IN);
    if (!DropChain(tool, "OUTPUT", OMINULL_CHAIN_OUT) || !cleared) return false;
    const char* promoteIn[]  = { tool, "-E", OMINULL_NEXT_IN,  OMINULL_CHAIN_IN,  NULL };
    const char* promoteOut[] = { tool, "-E", OMINULL_NEXT_OUT, OMINULL_CHAIN_OUT, NULL };
    (void)RunFw(promoteIn);         /* a failure leaves the rules in force under the other name */
    (void)RunFw(promoteOut);
    return true;
}

/* ParseAddressList pulls a flat JSON array of address literals out of the
 * heartbeat reply. Anything that is not an address is reported and dropped: a
 * hub sending something else is either running a build that does not validate
 * it or is not the hub, and both are worth a line in the log. The value itself
 * is never echoed - it is attacker-controlled text and this log is read by
 * people and by journald. */
typedef struct {
    const char* key;
    char (*out)[64];
    int cap;
    int count;
} AddressListCtx;

static void TakeAddress(const char* ip, void* ctx) {
    AddressListCtx* c = (AddressListCtx*)ctx;
    if (!IsIPLiteral(ip)) {
        printf("[!] Hub sent a %s entry that is not an IP address; ignoring it.\n", c->key);
        fflush(stdout);
        return;
    }
    if (c->count < c->cap) snprintf(c->out[c->count++], 64, "%s", ip);
}

static int ParseAddressList(const char* respJson, const char* key,
                            char out[][64], int cap) {
    AddressListCtx c = {key, out, cap, 0};
    Scrape_AddressList(respJson, key, TakeAddress, &c);
    return c.count;
}

/* What this agent has actually put in the kernel. At file scope rather than
 * inside SyncEnforcement because the dead-man timer below has to be able to
 * rebuild from it - specifically, to lift this host's isolation while leaving
 * the mesh quarantine it was also holding in place. */
static bool known = false;              /* nothing reconciled yet this run */
static bool appliedIsolated = false;
static bool g_ApplyRefused = false;
static const char* g_ApplyNote = "";    /* what last_applied reports */
static OMINULL_HUB_TARGETS appliedHubTargets;

/* AdoptRulesInForce: chains outlive the agent, so a host restarted while isolated
 * is still isolated, and if the hub never answers again the dead-man timer has to
 * know that. Asked until there is a definite answer: a held lock isn't one. */
static bool g_RulesAdopted = false;
static void AdoptRulesInForce(void) {
    if (g_RulesAdopted) return;
    const char* tools[] = { "iptables", "ip6tables" };
    const char* chains[] = { OMINULL_CHAIN_OUT, OMINULL_NEXT_OUT };
    bool settled = true;
    for (int i = 0; i < 2; i++) {
        if (NoIPv6Here(tools[i])) continue;
        (void)RecoverSwap(tools[i], "INPUT", OMINULL_CHAIN_IN, OMINULL_NEXT_IN);
        (void)RecoverSwap(tools[i], "OUTPUT", OMINULL_CHAIN_OUT, OMINULL_NEXT_OUT);
        for (int c = 0; c < 2; c++) {
            const char* deny[] = { tools[i], "-C", chains[c], "-j", "DROP", NULL };
            int rc = RunFw(deny);
            if (rc == 0) appliedIsolated = true;
            else if (!FwSaysAbsent(rc)) settled = false;
        }
    }
    g_RulesAdopted = settled;
}

/* SameAddress compares two address literals as addresses (family and bytes),
 * so "2001:4860::8888" and its expanded form are one address. */
static bool SameAddress(const char* a, const char* b) {
    unsigned char x[16], y[16];
    if (inet_pton(AF_INET, a, x) == 1) return inet_pton(AF_INET, b, y) == 1 && memcmp(x, y, 4) == 0;
    if (inet_pton(AF_INET6, a, x) == 1) return inet_pton(AF_INET6, b, y) == 1 && memcmp(x, y, 16) == 0;
    return false;
}

/* LocalResolvers lists the nameservers in /etc/resolv.conf. */
static int LocalResolvers(char out[][64], int cap) {
    FILE* f = fopen("/etc/resolv.conf", "r");
    if (!f) return 0;
    char line[256];
    int n = 0;
    while (n < cap && fgets(line, sizeof(line), f)) {
        char addr[64];
        if (sscanf(line, " nameserver %63s", addr) == 1) snprintf(out[n++], 64, "%s", addr);
    }
    fclose(f);
    return n;
}
static char appliedAllow[MAX_ISOLATION_ALLOW][64];
static int appliedAllowCount = 0;
static char appliedPeers[MAX_QUARANTINED_PEERS][64];
static int appliedPeerCount = 0;
static char appliedThreats[MAX_QUARANTINED_PEERS][64];
static int appliedThreatCount = 0;
static BASELINE_RULE appliedBaseline[MAX_BASELINE_RULES];
static int appliedBaselineCount = 0;
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
/* The count itself comes from Trust_DeadmanBeats (agent_trust.h): 100 beats
 * for an isolation nobody supervised, twelve hours for an owner's. */

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
    (void)p;
    /* Isolation, its allow list and the mesh peers come from the authorized
     * state (verified grants, agent_trust.h), never from the hub's say-so. */
    bool wantIsolated = Trust_EffectiveIsolated(&g_Trust);

    char allow[MAX_ISOLATION_ALLOW][64];
    int allowCount = 0;
    for (int i = 0; wantIsolated && i < g_Trust.state.allowCount && i < MAX_ISOLATION_ALLOW; i++)
        snprintf(allow[allowCount++], 64, "%s", g_Trust.state.allow[i]);
    char peers[MAX_QUARANTINED_PEERS][64];
    int peerCount = Trust_EffectivePeers(&g_Trust, peers, MAX_QUARANTINED_PEERS);
    char threats[MAX_QUARANTINED_PEERS][64];
    int threatCount = ParseAddressList(respJson, "threat_indicators", threats, MAX_QUARANTINED_PEERS);
    {
        /* Unsigned indicators: public addresses only, never a local resolver
         * (the hub's own addresses are permitted ahead of any drop). */
        char resolvers[8][64];
        int nres = LocalResolvers(resolvers, 8);
        int kept = 0;
        for (int i = 0; i < threatCount; i++) {
            bool skip = !Trust_PublicAddress(threats[i]);
            for (int j = 0; !skip && j < nres; j++) skip = SameAddress(threats[i], resolvers[j]);
            if (!skip && kept != i) memcpy(threats[kept], threats[i], sizeof(threats[0]));
            if (!skip) kept++;
        }
        threatCount = kept;
    }

    if (allowCount > 1) qsort(allow, allowCount, sizeof(allow[0]), (int (*)(const void*, const void*))strcmp);
    if (peerCount > 1) qsort(peers, peerCount, sizeof(peers[0]), (int (*)(const void*, const void*))strcmp);
    if (threatCount > 1) qsort(threats, threatCount, sizeof(threats[0]), (int (*)(const void*, const void*))strcmp);

    /* An isolation's exceptions are the ones bound into it: the owner
     * approved them with the isolation (signed payload), and they are kept in
     * the authorized state. The heartbeat's baseline never opens a hole. */
    BASELINE_RULE baseline[MAX_BASELINE_RULES];
    int baselineCount = 0;
    memset(baseline, 0, sizeof(baseline));
    for (int i = 0; wantIsolated && i < g_Trust.state.ruleCount && i < MAX_BASELINE_RULES; i++) {
        const TrustRule* r = &g_Trust.state.rules[i];
        snprintf(baseline[baselineCount].service, sizeof(baseline[0].service), "%s", r->service);
        snprintf(baseline[baselineCount].destination, sizeof(baseline[0].destination), "%s", r->destination);
        snprintf(baseline[baselineCount].protocol, sizeof(baseline[0].protocol), "%s", r->protocol);
        baseline[baselineCount++].port = r->port;
    }

    bool changed = !known || wantIsolated != appliedIsolated
                   || allowCount != appliedAllowCount || peerCount != appliedPeerCount
                   || threatCount != appliedThreatCount
                   || baselineCount != appliedBaselineCount;
    for (int i = 0; !changed && i < allowCount; i++) {
        if (strcmp(allow[i], appliedAllow[i]) != 0) changed = true;
    }
    for (int i = 0; !changed && i < peerCount; i++) {
        if (strcmp(peers[i], appliedPeers[i]) != 0) changed = true;
    }
    for (int i = 0; !changed && i < threatCount; i++) {
        if (strcmp(threats[i], appliedThreats[i]) != 0) changed = true;
    }
    for (int i = 0; !changed && i < baselineCount; i++) {
        if (strcmp(baseline[i].destination, appliedBaseline[i].destination) != 0
            || strcmp(baseline[i].protocol, appliedBaseline[i].protocol) != 0
            || strcmp(baseline[i].service, appliedBaseline[i].service) != 0
            || baseline[i].port != appliedBaseline[i].port) changed = true;
    }
    if (!changed) {
        g_ApplyRefused = false;
        if (!g_PermitsMissing) g_ApplyNote = "";
        return;
    }

    OMINULL_HUB_TARGETS hubTargets = {0};
    bool haveHub = OminullResolveHub(config->hub_url, &hubTargets);
    if (!haveHub && appliedHubTargets.count > 0 && (appliedIsolated || appliedPeerCount || appliedThreatCount)) {
        /* The lookup may be failing because of the isolation itself. The hole in
         * force is good enough to change the rules, including to lift them. */
        hubTargets = appliedHubTargets;
        haveHub = true;
    }
    const char *hubIP = haveHub ? hubTargets.addresses[0] : "";
    if ((wantIsolated || peerCount || threatCount) && !haveHub) {
        /* Refused, deliberately. An isolation with no hole for the hub can
         * never be lifted by the hub, so it is not a quarantine - it is a
         * host taken off the network permanently by a name lookup that
         * happened to fail. The order stands and is retried next beat. */
        if (!g_ApplyRefused) {
            printf("[-] Isolation ordered, but the hub address could not be resolved from %s. "
                   "Refusing to isolate: this host could not be released afterwards.\n", config->hub_url);
            fflush(stdout);
        }
        g_ApplyRefused = true;
        g_ApplyNote = "policy not applied: the hub address could not be resolved";
        return;
    }

    if (g_ApplyRefused || g_PermitsRetry) {
        /* Said already; the outcome is reported below when it changes. */
    } else if (wantIsolated) {
        printf("[!] Threat Nullification: isolating this host. Permitted: hub %s, loopback, "
               "%d baseline rule(s) and %d allow-listed address(es). %d peer(s) quarantined.\n",
               hubIP, baselineCount, allowCount, peerCount);
    } else if (known && appliedIsolated) {
        printf("[+] Threat neutralized: lifting host isolation. %d peer(s) still quarantined.\n", peerCount);
    } else if (peerCount == 0 && appliedPeerCount > 0 && threatCount == 0) {
        printf("[+] Mesh quarantine cleared; no enforcement rules remain on this host.\n");
    } else if (peerCount != appliedPeerCount) {
        printf("[*] Mesh quarantine updated: %d peer(s).\n", peerCount);
    }
    if (threatCount > 0 && !g_ApplyRefused && !g_PermitsRetry) {
        printf("[*] In-line edge threat intelligence: active drop rules for %d indicator(s).\n", threatCount);
    }
    fflush(stdout);

    bool wasMissing = g_PermitsMissing;
    g_PermitsMissing = g_PermitsRetry = false;
    bool built;
    if (!wantIsolated && peerCount == 0 && threatCount == 0) {
        built = EnforcementTeardown("iptables");
        built = EnforcementTeardown("ip6tables") && built;
    } else {
        built = EnforcementBuild("iptables", wantIsolated, &hubTargets, allow, allowCount, peers, peerCount, threats, threatCount,
                                 baseline, baselineCount);
        built = EnforcementBuild("ip6tables", wantIsolated, &hubTargets, allow, allowCount, peers, peerCount, threats, threatCount,
                                 baseline, baselineCount) && built;
    }
    if (!built) {
        /* One family may already hold the new rules, so what is applied is no
         * longer known and the next beat tries again whatever it asks for. If
         * this was meant to isolate, part of the host may be cut off: the
         * dead-man timer has to count from here. */
        if (!g_ApplyRefused) {
            printf("[-] The firewall refused the new rules; trying again every beat.\n");
            fflush(stdout);
        }
        g_ApplyRefused = true;
        g_ApplyNote = "policy not applied: the firewall refused the new rules";
        known = false;
        if (wantIsolated) {
            appliedIsolated = true;
            appliedHubTargets = hubTargets;
        }
        return;
    }

    g_ApplyRefused = false;
    g_ApplyNote = g_PermitsMissing ? "policy partly applied: the firewall refused some permitted destinations" : "";
    if (g_PermitsMissing && !wasMissing) {
        printf("[-] The firewall refused some permitted destinations; the rest of the policy is in force.\n");
        fflush(stdout);
    }
    appliedHubTargets = hubTargets;
    appliedIsolated = wantIsolated;
    memcpy(appliedAllow, allow, sizeof(allow));
    appliedAllowCount = allowCount;
    memcpy(appliedPeers, peers, sizeof(peers));
    appliedPeerCount = peerCount;
    memcpy(appliedThreats, threats, sizeof(threats));
    appliedThreatCount = threatCount;
    memcpy(appliedBaseline, baseline, sizeof(baseline));
    appliedBaselineCount = baselineCount;
    known = !g_PermitsRetry;            /* a held lock passes; try those permits again */
}

/* HubContact drives the dead-man timer. Every beat reports whether the hub
 * answered and accepted; a run of failures while this host is isolated releases
 * the isolation.
 *
 * The mesh quarantine this host was also holding is not this timer's to lift.
 * Only the default-deny that made the host unreachable goes. */
/* FollowHubAddress: a hub that moved can't say so to an isolated host, whose hole still
 * points at the old address, so the host would wait for the dead-man timer to release
 * it. While the hub isn't answering, its name is looked up again and the hole follows
 * the answer: the hub's TCP port only, and the same lookup every apply already trusts.
 * Needs rules this run built: after a restart the lists aren't known. */
static void FollowHubAddress(const LINUX_AGENT_CONFIG *config) {
    if (!known || !appliedIsolated || appliedHubTargets.count == 0) return;
    OMINULL_HUB_TARGETS current = {0};
    if (!OminullResolveHub(config->hub_url, &current) || OminullHubTargetsSame(&current, &appliedHubTargets)) return;
    bool built = EnforcementBuild("iptables", true, &current, appliedAllow, appliedAllowCount, appliedPeers,
                                  appliedPeerCount, appliedThreats, appliedThreatCount,
                                  appliedBaseline, appliedBaselineCount);
    built = EnforcementBuild("ip6tables", true, &current, appliedAllow, appliedAllowCount, appliedPeers,
                             appliedPeerCount, appliedThreats, appliedThreatCount,
                             appliedBaseline, appliedBaselineCount) && built;
    /* One family may hold the new rules: the hub's next answer rebuilds whatever
     * happens here, and the next beat tries again if it doesn't come. */
    if (!built) {
        g_ForgetApplied = true;
        printf("[-] The hub's address changed to %s but the firewall refused the new rules; "
               "trying again next beat.\n", current.addresses[0]);
        fflush(stdout);
        return;
    }
    printf("[!] Isolated, and the hub isn't answering at its old address: it now resolves to %s, "
           "so its hole moved there.\n", current.addresses[0]);
    fflush(stdout);
    appliedHubTargets = current;
    if (g_PermitsRetry) g_ForgetApplied = true;
}

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
    AdoptRulesInForce();
    if (!appliedIsolated) {
        missed = 0;                          /* nothing to roll back */
        return;
    }
    if (++missed < Trust_DeadmanBeats(&g_Trust, 100, 3000)) return;

    if (!g_ApplyRefused) {
        printf("[!] Isolated, and the hub has not answered for %d consecutive heartbeats. "
               "Releasing this host's isolation: an isolation the hub cannot lift is not a "
               "containment, it is a lost endpoint. Quarantined peers stay blocked.\n",
               missed);
        fflush(stdout);
    }

    bool built = LiftDefaultDeny("iptables");
    built = LiftDefaultDeny("ip6tables") && built;
    if (!built) {
        /* Still isolated, or isolated in one family: the count stays past the
         * limit, and what is applied is no longer known once the hub is back. */
        if (!g_ApplyRefused) {
            printf("[-] The firewall refused the release; trying again every beat.\n");
            fflush(stdout);
        }
        g_ApplyRefused = true;
        g_ApplyNote = "policy not applied: the firewall refused the new rules";
        known = false;
        return;
    }

    g_ApplyRefused = false;
    g_ApplyNote = "";
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
    /* With systemd-resolved, resolv.conf names only the local stub. The server
     * it forwards to is the one an isolation has to leave open for names to keep
     * working, and the readiness check can only warn about what it is told. */
    for (int i = 0, n = resolverCount; i < n; i++) {
        if (strncmp(resolvers[i], "127.", 4) == 0) {
            resolverCount = CollectAddressesFromFile("/run/systemd/resolve/resolv.conf", "nameserver",
                                                     resolvers, 8, resolverCount);
            break;
        }
    }

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
                    rolledBack ? "released by the dead-man timer after losing contact with the hub"
                    : g_ApplyNote);
    return off;
}

// ExtractJsonString pulls a flat "key":"value" pair out of a JSON fragment. The hub's
// update descriptor has no nesting or escaping beyond this, so a full parser is not
// warranted here.
static bool ExtractJsonString(const char* json, const char* key, char* out, size_t outLen) {
    return Scrape_StringFlat(json, key, out, outLen);
}

// AdoptDeviceCredential moves an upgraded legacy endpoint to its unique
// identity when the hub includes the credential in a successful heartbeat.
// The response is TLS-pinned, and the credential is written before the next
// heartbeat. A legacy config with inline OMINULL_ARGS is rewritten without the
// secret so a restart does not fall back to the shared tenant key.
static void AdoptDeviceCredential(LINUX_AGENT_CONFIG* config, const char* respJson) {
    if (!config || !respJson || IsDeviceCredentialValue(config->api_key)) return;
    char credential[128] = {0};
    if (!ExtractJsonString(respJson, "device_credential", credential, sizeof(credential)) ||
        !IsDeviceCredentialValue(credential)) return;

    const char* target = config->key_path[0] ? config->key_path : "/etc/ominull/agent.key";
    if (!WritePrivateFile(target, credential, 0600)) {
        printf("[!] The hub issued this endpoint a unique credential, but it could not be stored in %s.\n", target);
        return;
    }
    snprintf(config->api_key, sizeof(config->api_key), "%s", credential);
    if (!config->key_path[0]) {
        snprintf(config->key_path, sizeof(config->key_path), "%s", target);
    }
    char rendered[2048];
    int n = snprintf(rendered, sizeof(rendered),
                     "hub_url=%s\nkey_path=%s\nendpoint_id=%s\nrole_tag=%s\n"
                     "location_id=%s\nca_path=%s\nclient_cert_path=%s\n"
					 "client_key_path=%s\npin_hub_ca=%d\nallow_plaintext=%d\n",
                     config->hub_url, config->key_path, config->endpoint_id,
                     config->role_tag, config->location_id, config->ca_path,
                     config->client_cert_path, config->client_key_path,
					 config->pin_hub_ca ? 1 : 0,
                     config->allow_plaintext ? 1 : 0);
    if (n < 0 || (size_t)n >= sizeof(rendered) ||
        !WritePrivateFile(config->config_path, rendered, 0600)) {
        printf("[!] The unique credential is active, but the old inline agent configuration could not be rewritten.\n");
    }
    printf("[+] Hub-issued unique device credential installed; legacy shared-key authentication is no longer used by this agent.\n");
}

/* ProbeClientCert proves a certificate and key complete a handshake the hub
 * accepts, on a fresh handle so no pooled connection or resumed TLS session
 * can stand in for the new pair. The hub verifies any certificate offered and
 * refuses the handshake on one it does not trust, so a 200 here means it took
 * this one. */
static bool ProbeClientCert(const LINUX_AGENT_CONFIG* config, const char* certPath, const char* keyPath) {
    LINUX_AGENT_CONFIG probe = *config;
    size_t certLen = strlen(certPath), keyLen = strlen(keyPath);
    if (certLen >= sizeof(probe.client_cert_path) || keyLen >= sizeof(probe.client_key_path)) return false;
    memcpy(probe.client_cert_path, certPath, certLen + 1);
    memcpy(probe.client_key_path, keyPath, keyLen + 1);
    char url[sizeof(config->hub_url) + sizeof(config->endpoint_id) + 48];
    snprintf(url, sizeof(url), "%s/api/v1/agent/config?endpoint_id=%s", config->hub_url, config->endpoint_id);
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    char reply[4096];
    HUB_RESPONSE_BUFFER response = { .data = reply, .cap = sizeof(reply), .len = 0, .overflow = false };
    bool ok = false;
    struct curl_slist* headers = SetupHubCurl(curl, &probe, url, NULL, 0, NULL, &response, 10000L);
    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        long status = 0;
        if (curl_easy_perform(curl) == CURLE_OK &&
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK)
            ok = status == 200;
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);
    return ok;
}

static void FsyncParentDir(const char* path) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char* slash = strrchr(dir, '/');
    if (!slash) return;
    if (slash == dir) slash[1] = '\0';
    else *slash = '\0';
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }
}

/* RecoverClientCertSwap finishes or undoes a certificate swap a crash or power
 * cut interrupted (CertRenewal_Recovery). Without it, a stop between the key
 * and certificate renames leaves a key that does not match the certificate,
 * and every handshake fails until the endpoint is re-enrolled. */
static void RecoverClientCertSwap(const LINUX_AGENT_CONFIG* config) {
    if (!config->client_cert_path[0] || !config->client_key_path[0]) return;
    char newCert[sizeof(config->client_cert_path) + 8], newKey[sizeof(config->client_key_path) + 8];
    char oldKey[sizeof(config->client_key_path) + 8];
    snprintf(newCert, sizeof(newCert), "%s.new", config->client_cert_path);
    snprintf(newKey, sizeof(newKey), "%s.new", config->client_key_path);
    snprintf(oldKey, sizeof(oldKey), "%s.old", config->client_key_path);
    switch (CertRenewal_Recovery(access(newCert, F_OK) == 0, access(newKey, F_OK) == 0, access(oldKey, F_OK) == 0)) {
    case CERT_RECOVERY_FINISH:
        if (rename(newCert, config->client_cert_path) == 0) {
            FsyncParentDir(config->client_cert_path);
            unlink(oldKey);
            printf("[+] Finished installing a renewed client certificate an earlier stop interrupted.\n");
        } else {
            printf("[-] A renewed client certificate was left half installed and could not be finished; "
                   "this endpoint may need re-enrolment.\n");
        }
        break;
    case CERT_RECOVERY_DISCARD:
        unlink(newCert);
        unlink(newKey);
        unlink(oldKey);
        break;
    case CERT_RECOVERY_CLEAN_OLD:
        unlink(oldKey);
        break;
    default:
        break;
    }
}

/* AdoptRenewedClientCert installs the client certificate the hub renewed in
 * this heartbeat reply (cert_renewal.h). The new pair is written beside the
 * old one, proved against the hub, and only then renamed into place, key
 * first; if the certificate cannot follow, the old key is put back. Anything
 * short of that keeps the current certificate, which stays valid until its own
 * expiry, and the hub offers again later. */
static void AdoptRenewedClientCert(const LINUX_AGENT_CONFIG* config, const char* respJson) {
    if (!config || !respJson || !config->client_cert_path[0] || !config->client_key_path[0] ||
        !strstr(respJson, "\"client_certificate\":{"))
        return;
    static char b64[CERT_RENEWAL_B64_MAX];
    static char certPem[CERT_RENEWAL_PEM_MAX], keyPem[CERT_RENEWAL_PEM_MAX];
    char newCert[sizeof(config->client_cert_path) + 8], newKey[sizeof(config->client_key_path) + 8];
    char oldKey[sizeof(config->client_key_path) + 8];
    snprintf(newCert, sizeof(newCert), "%s.new", config->client_cert_path);
    snprintf(newKey, sizeof(newKey), "%s.new", config->client_key_path);
    snprintf(oldKey, sizeof(oldKey), "%s.old", config->client_key_path);
    bool parsed = CertRenewal_Field(respJson, "cert_pem_b64", b64, sizeof(b64)) &&
                  CertRenewal_DecodePEM(b64, "-----BEGIN CERTIFICATE-----", certPem, sizeof(certPem)) > 0 &&
                  CertRenewal_Field(respJson, "key_pem_b64", b64, sizeof(b64)) &&
                  CertRenewal_DecodePEM(b64, "-----BEGIN ", keyPem, sizeof(keyPem)) > 0 &&
                  strstr(keyPem, "PRIVATE KEY-----") != NULL;
    if (!parsed) {
        printf("[!] The hub sent a renewed client certificate that could not be read; keeping the current one.\n");
    } else if (!WritePrivateFile(newKey, keyPem, 0600) || !WritePrivateFile(newCert, certPem, 0600)) {
        printf("[!] A renewed client certificate could not be written beside %s; keeping the current one.\n",
               config->client_cert_path);
    } else if (!ProbeClientCert(config, newCert, newKey)) {
        printf("[!] The hub did not accept the renewed client certificate on a test request; keeping the current one.\n");
    } else if (unlink(oldKey), link(config->client_key_path, oldKey) != 0) {
        printf("[!] The current client key could not be kept aside for the swap; keeping the current certificate.\n");
    } else {
        bool keptOld = true;
        if (rename(newKey, config->client_key_path) != 0) {
            printf("[!] The renewed client key could not replace %s; keeping the current certificate.\n",
                   config->client_key_path);
        } else if (rename(newCert, config->client_cert_path) != 0) {
            if (keptOld && rename(oldKey, config->client_key_path) == 0) {
                printf("[!] The renewed certificate could not replace %s; the previous key was restored.\n",
                       config->client_cert_path);
            } else {
                printf("[-] The renewed certificate could not replace %s and the previous key could not be "
                       "restored; this endpoint may need re-enrolment.\n", config->client_cert_path);
            }
        } else {
            g_HubTlsReset = true;
            printf("[+] Installed the client certificate the hub renewed; the previous one is no longer used.\n");
        }
        FsyncParentDir(config->client_cert_path);
        unlink(oldKey);
    }
    /* Certificate first: a lone <cert>.new means "key already swapped" to
     * RecoverClientCertSwap. */
    unlink(newCert);
    unlink(newKey);
    memset(b64, 0, sizeof(b64));
    memset(keyPem, 0, sizeof(keyPem));
    memset(certPem, 0, sizeof(certPem));
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
                printf("[!] The hub refused this endpoint's telemetry with HTTP %ld. The device credential is not accepted; "
                   "nothing is being recorded until it is fixed.\n", status);
        } else {
            printf("[!] The hub refused this endpoint's telemetry with HTTP %ld; nothing is being "
                   "recorded.\n", status);
        }
        lastReport = now;
        lastStatus = status;
    }
    return true;
}

/* ---------------------------------------------------------------------------
 * Next-Gen Response Dispatcher & Execution (Slice 1D.1)
 * ------------------------------------------------------------------------- */

/* Heartbeats of one script job (docs/RESPONSE_SUPERVISOR.md): posted from the
 * worker's supervising loop on a curl handle of its own with a 5-second
 * ceiling, so a slow or absent hub delays the loop by at most that and never
 * fails the job. A reply carrying "cancel":true is remembered. */
typedef struct {
    const LINUX_AGENT_CONFIG* config;
    CURL* curl;
    bool cancel;
} ScriptHeartbeatSink;

static void ScriptHeartbeatPost(void* ctx, const char* body) {
    ScriptHeartbeatSink* sink = (ScriptHeartbeatSink*)ctx;
    if (!sink || !body) return;
    if (!sink->curl) sink->curl = curl_easy_init();
    if (!sink->curl) return;
    char url[sizeof(sink->config->hub_url) + 64];
    snprintf(url, sizeof(url), "%s/api/v1/response/jobs/progress", sink->config->hub_url);
    char reply[1024] = {0};
    HUB_RESPONSE_BUFFER response = { .data = reply, .cap = sizeof(reply), .len = 0, .overflow = false };
    struct curl_slist* headers = SetupHubCurl(sink->curl, sink->config, url, body, strlen(body), NULL, &response, 5000L);
    if (!headers) return;
    long status = 0;
    if (curl_easy_perform(sink->curl) == CURLE_OK)
        curl_easy_getinfo(sink->curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    if (status >= 200 && status < 300 && Supervisor_ReplyCancels(reply))
        sink->cancel = true;
}

static bool ScriptHeartbeatCancelled(void* ctx) {
    ScriptHeartbeatSink* sink = (ScriptHeartbeatSink*)ctx;
    return sink && sink->cancel;
}

/* RunScriptJobWorker runs one script job to completion inside a detached
 * worker process and posts its result to the hub. */
static int RunScriptJobWorker(const LINUX_AGENT_CONFIG* config, const char* job_id, const char* lease_id,
                              ScriptExecParams* params) {
    /* The payload's output limit (1 MiB default, 5 MiB at most) plus room for
     * the truncation note and an error line. */
    size_t max_out = params->max_output_bytes;
    if (max_out == 0 || max_out > SCRIPT_EXEC_MAX_MAX_OUT) max_out = SCRIPT_EXEC_MAX_MAX_OUT;
    size_t output_cap = max_out + 256;
    char* output_buf = (char*)calloc(1, output_cap);
    if (!output_buf) {
        fprintf(stderr, "[!] Could not allocate the output buffer of script job %s\n", job_id);
        return 1;
    }

    ScriptHeartbeatSink sink = { .config = config, .curl = NULL, .cancel = false };
    ScriptSupervisorHooks hooks = {
        .settings = Supervisor_DefaultSettings(),
        .job_id = job_id,
        .lease_id = lease_id,
        .post = ScriptHeartbeatPost,
        .cancel_requested = ScriptHeartbeatCancelled,
        .ctx = &sink,
    };
    ScriptRunResult run;
    int exit_code = ScriptExec_RunSupervised(params, job_id, output_buf, output_cap, &hooks, &run);
    if (sink.curl) curl_easy_cleanup(sink.curl);

    const char* state = run.cancelled ? "cancelled" : (exit_code == 0) ? "succeeded" : "failed";
    const char* error_code = run.cancelled ? "CANCELLED" : run.timed_out ? "TIMED_OUT" : "";

    char* escaped_out = ScriptExec_EscapeJSON(output_buf);
    free(output_buf);
    size_t body_sz = (escaped_out ? strlen(escaped_out) : 0) + 1024;
    char* res_body = (char*)malloc(body_sz);
    bool posted = false;
    if (res_body) {
        snprintf(res_body, body_sz,
            "{\"job_id\":\"%.63s\",\"lease_id\":\"%.63s\",\"state\":\"%s\",\"exit_code\":%d,\"duration_ms\":%lld%s%s%s%s%s%s%s}",
            job_id, lease_id, state, exit_code, (long long)run.duration_ms,
            (escaped_out ? ",\"stdout\":\"" : ""),
            (escaped_out ? escaped_out : ""),
            (escaped_out ? "\"" : ""),
            (error_code[0] ? ",\"error_code\":\"" : ""),
            (error_code[0] ? error_code : ""),
            (error_code[0] ? "\"" : ""),
            (run.truncated ? ",\"truncated\":true" : ""));
        char res_url[sizeof(config->hub_url) + 64];
        snprintf(res_url, sizeof(res_url), "%s/api/v1/response/jobs/result", config->hub_url);
        CURL* curl = curl_easy_init();
        if (curl) {
            char res_resp[1024] = {0};
            HUB_RESPONSE_BUFFER response = { .data = res_resp, .cap = sizeof(res_resp), .len = 0, .overflow = false };
            struct curl_slist* headers = SetupHubCurl(curl, config, res_url, res_body, strlen(res_body), NULL, &response, 30000L);
            if (headers) {
                posted = curl_easy_perform(curl) == CURLE_OK;
                curl_slist_free_all(headers);
            }
            curl_easy_cleanup(curl);
        }
        free(res_body);
    }
    if (escaped_out) free(escaped_out);
    if (!posted) fprintf(stderr, "[!] Could not post the result of script job %s\n", job_id);
    return posted ? 0 : 1;
}

static void ProcessResponseOffers(const LINUX_AGENT_CONFIG* config, const char* respJson) {
    if (!config || !respJson) return;

    ResponseJobOffer offers[MAX_RESPONSE_OFFERS];
    int offer_count = ParseResponseOffers(respJson, offers, MAX_RESPONSE_OFFERS);
    if (offer_count <= 0) return;

    for (int i = 0; i < offer_count; i++) {
        ResponseJobOffer* offer = &offers[i];

        // 1. Verify EndpointGrant V2, against the pinned key, for this kind,
        //    inside this endpoint's capability manifest
        const char* refusal = Trust_OfferRefusal(&g_Trust, offer->kind, &offer->grant);
        if (refusal) {
            Trust_Refuse(&g_Trust, (int64_t)time(NULL), "response offer refused: %s", refusal);
            continue;
        }
        /* Against the pinned key in memory (trust.pin), never a file copy; a
         * script on a host-authority host against its host key. V3 grants
         * must name this job. */
        refusal = Trust_OfferGrantRefusal(&g_Trust, offer->job_id, &offer->grant, offer->payload_json, config->endpoint_id);
        if (refusal) {
            // No ACK, no result; the reason goes into the trust report
            Trust_Refuse(&g_Trust, (int64_t)time(NULL), "response offer refused: %s", refusal);
            continue;
        }

        // 2. Durable Replay Cache check
        if (!ReplayCache_CheckAndRecord(NULL, offer->grant.grant_id, offer->grant.nonce, offer->grant.expires_at)) {
            // Replay detected: drop offer silently
            continue;
        }

        // 3. Post Acknowledgment to hub
        char ack_url[sizeof(config->hub_url) + 64];
        snprintf(ack_url, sizeof(ack_url), "%s/api/v1/response/jobs/ack", config->hub_url);
        char ack_body[256];
        snprintf(ack_body, sizeof(ack_body), "{\"job_id\":\"%.63s\",\"lease_id\":\"%.63s\",\"accepted\":true}", offer->job_id, offer->lease_id);
        char ack_resp[1024] = {0};
        if (!RunHubCurl(config, ack_url, ack_body, ack_resp, sizeof(ack_resp))) {
            continue;
        }
        // curl succeeds on any HTTP answer. A refused ack (the job was
        // cancelled, or this lease expired and the job went to another offer)
        // means the job is not ours to run.
        long ack_status = SplitHubStatus(ack_resp);
        if (ack_status < 200 || ack_status >= 300) {
            fprintf(stderr, "[!] Hub refused the ack for job %s (HTTP %ld); not running it\n", offer->job_id, ack_status);
            continue;
        }

        // 4. Action Dispatcher: Check if action kind is recognized and supported
        if (strcmp(offer->kind, "forensic_collection") == 0) {
            ForensicCollectionParams params;
            bool params_ok = Forensics_ParsePayload(offer->payload_json, &params);   /* malformed: the worker reports failure */
            const char* bundle_id = Response_BundleId(params.bundle_id, offer->job_id);
            if (!bundle_id) {
                params_ok = false;
                bundle_id = "invalid";
            }

            int pipefd[2];
            if (pipe(pipefd) != 0) {
                pipefd[0] = -1;
                pipefd[1] = -1;
            }

            struct timespec ts_start, ts_end;
            clock_gettime(CLOCK_MONOTONIC, &ts_start);

            // Temporarily restore default SIGCHLD so waitpid works reliably
            struct sigaction sa_old, sa_dfl;
            memset(&sa_dfl, 0, sizeof(sa_dfl));
            sa_dfl.sa_handler = SIG_DFL;
            sigaction(SIGCHLD, &sa_dfl, &sa_old);

            // Spawn worker in contained child process
            pid_t pid = fork();
            if (pid == 0) {
                if (pipefd[0] >= 0) close(pipefd[0]);

                // Child: Create new process group
                setpgid(0, 0);

                // Close inherited file descriptors > 2 (except pipefd[1])
                for (int fd = 3; fd < 1024; fd++) {
                    if (fd != pipefd[1]) {
                        close(fd);
                    }
                }

                // Clean sanitized environment
                clearenv();
                setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", 1);
                setenv("HOME", "/var/lib/ominull", 1);
                setenv("LANG", "C.UTF-8", 1);

                // Explicit safe working directory
                if (chdir("/var/lib/ominull") != 0) {
                    _exit(1);
                }

                // Resource limits (CPU limit 60s)
                struct rlimit rl;
                rl.rlim_cur = 60;
                rl.rlim_max = 60;
                setrlimit(RLIMIT_CPU, &rl);

                char manifest_sha[65] = {0};
                bool success = params_ok && Forensics_RunCollection(
                    params.profile,
                    config->hub_url,
                    config->api_key,
                    IsDeviceCredentialValue(config->api_key),
                    config->client_cert_path,
                    config->client_key_path,
                    config->ca_path,
                    config->endpoint_id,
                    offer->grant.tenant_id,
                    offer->job_id,
                    bundle_id,
                    params.max_bytes,
                    manifest_sha,
                    sizeof(manifest_sha)
                );

                if (pipefd[1] >= 0) {
                    if (manifest_sha[0]) {
                        ssize_t w = write(pipefd[1], manifest_sha, strlen(manifest_sha));
                        (void)w;
                    }
                    close(pipefd[1]);
                }

                _exit(success ? 0 : 2);
            } else if (pid > 0) {
                if (pipefd[1] >= 0) close(pipefd[1]);

                char manifest_sha[65] = {0};
                if (pipefd[0] >= 0) {
                    ssize_t r = read(pipefd[0], manifest_sha, sizeof(manifest_sha) - 1);
                    if (r > 0) {
                        manifest_sha[r] = '\0';
                    }
                    close(pipefd[0]);
                }

                // Parent: wait for child
                int status = 0;
                int exit_code = 1;
                if (waitpid(pid, &status, 0) == pid && WIFEXITED(status)) {
                    exit_code = WEXITSTATUS(status);
                }
                sigaction(SIGCHLD, &sa_old, NULL);

                clock_gettime(CLOCK_MONOTONIC, &ts_end);
                int64_t duration_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000 +
                                      (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000;
                if (duration_ms < 0) duration_ms = 0;

                // Post result to hub
                char res_url[sizeof(config->hub_url) + 64];
                snprintf(res_url, sizeof(res_url), "%s/api/v1/response/jobs/result", config->hub_url);
                char res_body[1024];
                snprintf(res_body, sizeof(res_body),
                    "{\"job_id\":\"%.63s\",\"lease_id\":\"%.63s\",\"state\":\"%s\",\"exit_code\":%d,\"duration_ms\":%lld%s%s%s}",
                    offer->job_id, offer->lease_id, (exit_code == 0 ? "succeeded" : "failed"), exit_code,
                    (long long)duration_ms,
                    (manifest_sha[0] ? ",\"manifest_sha256\":\"" : ""),
                    (manifest_sha[0] ? manifest_sha : ""),
                    (manifest_sha[0] ? "\"" : ""));
                char res_resp[1024] = {0};
                RunHubCurl(config, res_url, res_body, res_resp, sizeof(res_resp));
            } else {
                sigaction(SIGCHLD, &sa_old, NULL);
                if (pipefd[0] >= 0) close(pipefd[0]);
                if (pipefd[1] >= 0) close(pipefd[1]);
            }
        } else if (strcmp(offer->kind, "terminal_session") == 0) {
            TerminalSessionParams params;
            if (!Terminal_ParsePayload(offer->payload_json, &params)) {
                continue;
            }

            // Spawn the worker detached (double fork): the session outlives
            // this heartbeat, and init reaps it. The daemon itself keeps the
            // default SIGCHLD so every waitpid it does gets a real status.
            pid_t mid_pid = fork();
            if (mid_pid == 0) {
                pid_t worker_pid = fork();
                if (worker_pid == 0) {
                    // Worker: close inherited file descriptors
                    for (int fd = 3; fd < 1024; fd++) {
                        close(fd);
                    }
                    int exit_code = Terminal_RunLinuxWorker(
                        config->hub_url,
                        HubUsesTLS(config),
                        config->ca_path,
                        config->pin_hub_ca,
                        config->client_cert_path,
                        config->client_key_path,
                        config->endpoint_id,
                        params.session_id,
                        params.connect_token,
                        params.program
                    );
                    _exit(exit_code == 0 ? 0 : 1);
                }
                _exit(worker_pid < 0 ? 1 : 0);
            }
            if (mid_pid > 0) {
                while (waitpid(mid_pid, NULL, 0) < 0 && errno == EINTR) { }
            }
        } else if (strcmp(offer->kind, "script_exec") == 0) {
            ScriptExecParams params;
            if (!ScriptExec_ParsePayload(offer->payload_json, &params)) {
                char res_url[sizeof(config->hub_url) + 64];
                snprintf(res_url, sizeof(res_url), "%s/api/v1/response/jobs/result", config->hub_url);
                char res_body[512];
                snprintf(res_body, sizeof(res_body),
                    "{\"job_id\":\"%.63s\",\"lease_id\":\"%.63s\",\"state\":\"failed\",\"exit_code\":1,\"duration_ms\":0,\"error_code\":\"INVALID_PAYLOAD\"}",
                    offer->job_id, offer->lease_id);
                char res_resp[1024] = {0};
                RunHubCurl(config, res_url, res_body, res_resp, sizeof(res_resp));
                continue;
            }

            /* A script may run for up to an hour (maintenance packages), so it
               runs in a detached worker (double fork, like a terminal session)
               and the heartbeat loop carries on. The worker posts the result
               on a curl handle of its own: the daemon's cached connection is
               not shared across fork. */
            pid_t mid_pid = fork();
            if (mid_pid == 0) {
                pid_t worker_pid = fork();
                if (worker_pid == 0) {
                    for (int fd = 3; fd < 1024; fd++) {
                        close(fd);
                    }
                    _exit(RunScriptJobWorker(config, offer->job_id, offer->lease_id, &params));
                }
                _exit(worker_pid < 0 ? 1 : 0);
            }
            if (mid_pid > 0) {
                while (waitpid(mid_pid, NULL, 0) < 0 && errno == EINTR) { }
            }
        }
        // Unknown action kinds are ignored: no execution, no synthesis of success
    }
}

/* Upload transport (upload_queue.h): gzip once the hub has said it decodes
 * it, and batches it could not take kept for a replay after the next accepted
 * heartbeat. */
static bool g_HubTakesGzip;
static UPLOAD_QUEUE g_Uploads;
/* The last batch at shutdown is delivered and nothing else: no reply is acted
 * on (no job, update or enforcement change on the way out) and no replays
 * hold up the stop. */
static bool g_FinalBatch;

/* One telemetry POST of a body as built. Returns false when no HTTP answer
 * came back; *status is the hub's status, 0 without one. */
static bool PostTelemetryBody(const LINUX_AGENT_CONFIG* config, const char* url, const uint8_t* body,
                              size_t length, bool gzipped, bool replay, char* out, size_t outCap, long* status) {
    const char* extra[3] = {NULL, NULL, NULL};
    size_t n = 0;
    if (gzipped)
        extra[n++] = "Content-Encoding: gzip";
    if (replay)
        extra[n++] = "X-Ominull-Replay: 1";
    *status = 0;
    bool answered = RunHubCurlBody(config, url, (const char*)body, length, extra, out, outCap, 5000L);
    if (answered)
        *status = SplitHubStatus(out);
    return answered;
}

/* Sends kept batches, oldest first, after an accepted heartbeat. A hub that
 * does not advertise gzip predates replays: what is kept is lost to it. */
static void ReplayQueuedTelemetry(const LINUX_AGENT_CONFIG* config, const char* url, char* reply,
                                  size_t replyCap, UPLOAD_LOSS* loss) {
    if (!g_HubTakesGzip) {
        while (UploadQueue_Peek(&g_Uploads))
            UploadQueue_Pop(&g_Uploads, loss);
        return;
    }
    for (int sent = 0; sent < UPLOAD_QUEUE_REPLAY_PER_BEAT; sent++) {
        UPLOAD_ITEM* item = UploadQueue_Peek(&g_Uploads);
        if (!item)
            break;
        long status = 0;
        bool answered = PostTelemetryBody(config, url, item->data, item->length, item->gzip, true, reply,
                                          replyCap, &status);
        if (answered && status >= 200 && status < 300) {
            UploadQueue_Pop(&g_Uploads, NULL);
        } else if (Upload_Retryable(answered ? status : 0)) {
            break; /* kept for the next beat */
        } else {
            UploadQueue_Pop(&g_Uploads, loss); /* refused for good */
        }
    }
}

static void SendTelemetryBatch(LINUX_AGENT_CONFIG* config, const LINUX_FLOW_EVENT* flows, size_t flowCount) {
    /* The package's postinst restarts the agent while dpkg is still
     * configuring it, so the startup answer can be stale. Ask again, at most
     * once a minute, until the package manager agrees with this binary. */
    static time_t provenanceCheckedAt;
    if (strcmp(config->provenance_status, "native") != 0 && time(NULL) - provenanceCheckedAt >= 60) {
        provenanceCheckedAt = time(NULL);
        DetectPackageProvenance(config);
    }
    /* Checked before the batch is built, not after it fails: the payload and
     * the header that authenticates it are the things being protected. */
    if (!HubTransportReady(config)) return;

    struct utsname sysInfo;
    uname(&sysInfo);

    char osStr[256];
    snprintf(osStr, sizeof(osStr), "%s %s (%s)", sysInfo.sysname, sysInfo.release, sysInfo.machine);

    if (flowCount > MAX_FLOWS_PER_BATCH)
        flowCount = MAX_FLOWS_PER_BATCH;
    size_t bufCap = 32768 + flowCount * 16384;
    char* jsonBuf = (char*)malloc(bufCap);
    if (!jsonBuf) return;

    const char *rawHeader[] = {config->endpoint_id,
                               config->location_id[0] ? config->location_id : "loc-home",
                               config->role_tag[0] ? config->role_tag : "workstation",
                               config->hostname,
                               osStr,
                               config->primary_ip,
                               config->primary_mac,
                               OMINULL_LINUX_AGENT_VERSION,
                               config->install_type,
                               config->package_identifier,
                               config->registered_package_version,
                               config->provenance_status,
                               config->evidence_pubkey_hex};
    char header[sizeof(rawHeader) / sizeof(rawHeader[0])][1537];
    char trustReport[4096];
    Trust_ReportJSON(&g_Trust, trustReport, sizeof(trustReport));
    static uint64_t nonce;
    while (!nonce && syscall(SYS_getrandom, &nonce, sizeof(nonce), 0) != (long)sizeof(nonce))
        nonce = ((uint64_t)time(NULL) << 20) ^ (uint64_t)getpid();
    char batchID[40];
    Upload_BatchID(nonce, batchID, sizeof(batchID));
    for (size_t i = 0; i < sizeof(rawHeader) / sizeof(rawHeader[0]); i++)
        ProcessLineage_EscapeJSON(rawHeader[i], header[i], sizeof(header[i]));

    int offset =
        snprintf(jsonBuf, bufCap,
                 "{\"type\":\"telemetry\",\"endpoint_id\":\"%s\",\"tenant_id\":\"default\",\"location_id\":"
                 "\"%s\",\"role\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\","
                 "\"driver_version\":\"%s\",\"update_capability\":\"deb\",\"install_type\":\"%s\",\"package_"
                 "identifier\":\"%s\",\"registered_package_version\":\"%s\",\"provenance_status\":\"%s\","
                 "\"evidence_signing_key\":\"%s\",\"batch_id\":\"%s\",\"response_capabilities\":%s,\"trust\":%s,"
                 "\"cert_renewal\":%s,\"events\":[",
                 header[0], header[1], header[2], header[3], header[4], header[5], header[6], header[7],
                 header[8], header[9], header[10], header[11], header[12], batchID,
                 g_Trust.have_key[TRUST_KEY_RESPONSE] ? OMINULL_CAPS_LINUX : OMINULL_CAPS_NO_RESPONSE_KEY, trustReport,
                 config->client_cert_path[0] && config->client_key_path[0] ? "true" : "false");

    for (size_t i = 0; i < flowCount; i++) {
        const LINUX_FLOW_EVENT* f = &flows[i];
        const char* comma = (i == flowCount - 1) ? "" : ",";

        char escapedPath[MAX_PATH_LEN * 6 + 1] = {0};
        ProcessLineage_EscapeJSON(f->process_path, escapedPath, sizeof(escapedPath));

        const char* domain = LookupDnsDomain(f->dst_ip);
        char domainJson[256] = {0};
        if (domain && domain[0]) {
            snprintf(domainJson, sizeof(domainJson), ",\"domain\":\"%s\"", domain);
        }

        char escapedCmdline[sizeof(f->enrichment.command_line) * 6 + 1] = {0};
        ProcessLineage_EscapeJSON(f->enrichment.command_line, escapedCmdline, sizeof(escapedCmdline));

        char escapedUser[sizeof(f->enrichment.user_identity) * 6 + 1] = {0};
        ProcessLineage_EscapeJSON(f->enrichment.user_identity, escapedUser, sizeof(escapedUser));

        char obsTimeBuf[64] = {0};
        if (f->enrichment.observed_at > 0) {
            struct tm tmBuf;
            time_t obsSec = (time_t)f->enrichment.observed_at;
            gmtime_r(&obsSec, &tmBuf);
            strftime(obsTimeBuf, sizeof(obsTimeBuf), "%Y-%m-%dT%H:%M:%SZ", &tmBuf);
        }

        char enrichmentJson[8192] = {0};
        int enrichLen = snprintf(enrichmentJson, sizeof(enrichmentJson),
            ",\"process_instance_id\":\"%s\",\"parent_pid\":%u,\"parent_process_instance_id\":\"%s\",\"command_line\":\"%s\",\"user_identity\":\"%s\",\"executable_sha256\":\"%s\",\"attribution_status\":\"%s\"",
            f->enrichment.process_instance_id,
            f->enrichment.ppid,
            f->enrichment.parent_process_instance_id,
            escapedCmdline,
            escapedUser,
            f->enrichment.executable_sha256,
            f->enrichment.attribution_status[0] ? f->enrichment.attribution_status : "unknown"
        );
        if (obsTimeBuf[0] && enrichLen > 0 && (size_t)enrichLen < sizeof(enrichmentJson) - 64) {
            enrichLen += snprintf(enrichmentJson + enrichLen, sizeof(enrichmentJson) - enrichLen,
                ",\"observed_at\":\"%s\"", obsTimeBuf);
        }
        if (f->enrichment.actor[0] && enrichLen > 0 && (size_t)enrichLen < sizeof(enrichmentJson) - sizeof(f->enrichment.actor) * 6 - 16) {
            char escapedActor[sizeof(f->enrichment.actor) * 6 + 1] = {0};
            ProcessLineage_EscapeJSON(f->enrichment.actor, escapedActor, sizeof(escapedActor));
            snprintf(enrichmentJson + enrichLen, sizeof(enrichmentJson) - enrichLen, ",\"actor\":\"%s\"", escapedActor);
        }

        char observationJson[640];
        FlowObservationJSON(f, observationJson, sizeof(observationJson));
        int written =
            snprintf(jsonBuf + offset, bufCap - offset,
                     "{\"layer\":\"%s\",\"action\":\"PERMIT\",\"direction\":\"%s\",\"protocol\":%u,\"src_"
                     "ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"bytes_in\":%lu,\"bytes_"
                     "out\":%lu,\"process_path\":\"%s\",\"process_id\":%u%s%s%s}%s",
                     f->protocol == IPPROTO_UDP ? "linux-udp-bpf-v1" : "linux-socket-v1", f->direction,
                     f->protocol, f->src_ip, f->dst_ip, f->src_port, f->dst_port, (unsigned long)f->bytes_in,
                     (unsigned long)f->bytes_out, escapedPath[0] ? escapedPath : OMINULL_UNATTRIBUTED_PROCESS,
                     f->process_id, domainJson, enrichmentJson, observationJson, comma);

        if (written < 0 || (size_t)written >= bufCap - (size_t)offset) {
            fprintf(stderr, "Telemetry serialization exceeded its bounded buffer; batch not sent.\n");
            free(jsonBuf);
            return;
        }
        offset += written;
    }

    offset += snprintf(jsonBuf + offset, bufCap - offset, "]");
    offset += snprintf(jsonBuf + offset, bufCap - offset,
                       ",\"collector_health\":[{\"name\":\"linux-bpf-udp\",\"state\":\"%s\",\"error\":%d,"
                       "\"dropped\":%llu,\"queued\":%zu},{\"name\":\"linux-sock-diag\",\"state\":\"%s\","
                       "\"dropped\":%llu,\"queued\":%zu,\"unmeasured\":%llu,\"deferred\":%llu}]",
                       g_UDPStatus, g_UDPError, (unsigned long long)UDPCollectorDropped(),
                       g_UDPStarted ? UDP_QUEUE_CAP - g_UDPFreeCount : (size_t)0,
                       g_TCPQueryActive ? "active" : "unavailable", (unsigned long long)g_TCPDrops,
                       g_TCPInitialized ? TCP_PENDING_CAP - g_TCPFreeCount : (size_t)0,
                       (unsigned long long)g_TCPUnmeasured, (unsigned long long)g_TCPDeferred);

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
    /* HUB_REPLY_BYTES (hub_reply.h): trust keys, a manifest, enforcement
     * grants and job offers with whole scripts. */
    static char* respHeap = NULL;
    static char respFallback[32768];
    if (!respHeap) respHeap = (char*)malloc(HUB_REPLY_BYTES);
    char* respBuf = respHeap ? respHeap : respFallback;
    const size_t respCap = respHeap ? HUB_REPLY_BYTES : sizeof(respFallback);
    respBuf[0] = '\0';
    uint64_t tcpObs = 0, udpObs = 0;
    for (size_t i = 0; i < flowCount; i++) {
        if (flows[i].protocol == 17)
            udpObs += flows[i].observation_count;
        else
            tcpObs += flows[i].observation_count;
    }
    size_t bodyLength = strlen(jsonBuf);
    uint8_t* body = (uint8_t*)jsonBuf;
    bool gzipped = false;
    if (g_HubTakesGzip) {
        size_t packedLength = 0;
        uint8_t* packed = Gzip_Encode(jsonBuf, bodyLength, &packedLength);
        if (packed && packedLength < bodyLength) {
            free(jsonBuf);
            body = packed;
            bodyLength = packedLength;
            gzipped = true;
        } else {
            free(packed);
        }
    }
    bool accepted = false;
    long status = 0;
    if (PostTelemetryBody(config, url, body, bodyLength, gzipped, false, respBuf, respCap, &status) &&
        !ReportHubRejection(config, status)) {
        accepted = true;
    }
    if (accepted && !g_FinalBatch) {
        g_HubTakesGzip = Upload_HubAcceptsGzip(respBuf);
        AdoptDeviceCredential(config, respBuf);
        AdoptRenewedClientCert(config, respBuf);
        Trust_ProcessHeartbeat(&g_Trust, respBuf, strlen(respBuf), (int64_t)time(NULL));
        SyncEnforcement(config, respBuf);
        ProcessResponseOffers(config, respBuf);
    }
    if (!accepted) FollowHubAddress(config);
    HubContact(accepted);
    UPLOAD_LOSS loss = {0};
    if (accepted) {
        free(body);
        if (!g_FinalBatch)
            ReplayQueuedTelemetry(config, url, respBuf, respCap, &loss);
    } else if (Upload_Retryable(status)) {
        UploadQueue_Push(&g_Uploads, body, bodyLength, gzipped, tcpObs, udpObs, &loss);
    } else {
        free(body);
        loss.tcp_observations += tcpObs;
        loss.udp_observations += udpObs;
    }
    g_TCPDrops += loss.tcp_observations;
    g_UDPQueueDrops += loss.udp_observations;
}

static time_t g_LastSoftwareInventorySync = 0;
#define SOFTWARE_INVENTORY_SYNC_INTERVAL_SECS 3600

static void SyncSoftwareInventory(const LINUX_AGENT_CONFIG* config) {
    if (!config || !config->hub_url[0]) return;

    SoftwareInventoryBatch* batch = (SoftwareInventoryBatch*)calloc(1, sizeof(SoftwareInventoryBatch));
    if (!batch) return;

    if (SoftwareInv_CollectLinux(NULL, batch) == 0 && batch->count > 0) {
        if (config->verbose) {
            printf("[*] Collected %zu authoritative software packages; uploading to Hub...\n", batch->count);
        }

        size_t cap = 2 * 1024 * 1024;
        char* jsonBuf = (char*)malloc(cap);
        if (jsonBuf) {
            size_t written = SoftwareInv_SerializeJSON(config->endpoint_id, batch, jsonBuf, cap);
            if (written > 0) {
                char url[sizeof(config->hub_url) + 32];
                snprintf(url, sizeof(url), "%s/api/v1/software", config->hub_url);
                char respBuf[2048] = {0};
                if (RunHubCurl(config, url, jsonBuf, respBuf, sizeof(respBuf))) {
                    if (config->verbose) {
                        printf("[+] Software inventory synced: %s\n", respBuf);
                    }
                }
            }
            free(jsonBuf);
        }
    }
    free(batch);
    g_LastSoftwareInventorySync = time(NULL);
}

/* ---------------------------------------------------------------------------
 * Data inventory.
 *
 * The hub decides scope and cadence (a policy fetched hourly; disabled until
 * the hub has this endpoint's canary paths). The scan runs in a sandboxed,
 * idle-priority child (data_inventory_linux.h) that can only read; this loop
 * drains its pipe, posts the metadata document, and commits the resume state
 * only once the hub has accepted it, so a lost upload is simply redone.
 * ------------------------------------------------------------------------- */

#define DATA_POLICY_SYNC_INTERVAL_SECS 3600
#define DATA_INVENTORY_STATE_PATH "/var/lib/ominull/data-inventory.state"
#define DATA_POLICY_RESPONSE_CAP (512 * 1024)

static DataInvPolicy g_DataPolicy;
static bool g_DataPolicyLoaded = false;
static time_t g_LastDataPolicySync = 0;
static time_t g_LastDataDueCheck = 0;
static long long g_LastDataAttemptMs = 0;
static DataInvRun g_DataRun = {.fd = -1};

static void SyncDataPolicy(const LINUX_AGENT_CONFIG* config) {
    g_LastDataPolicySync = time(NULL);
    if (!config || !config->hub_url[0]) return;
    char* resp = (char*)malloc(DATA_POLICY_RESPONSE_CAP);
    if (!resp) return;
    char url[sizeof(config->hub_url) + 32];
    snprintf(url, sizeof(url), "%s/api/v1/data/policy", config->hub_url);
    char body[160];
    snprintf(body, sizeof(body), "{\"endpoint_id\":\"%.100s\",\"platform\":\"linux\",\"rules_version\":%d}",
             config->endpoint_id, DI_RULES_VERSION);
    if (RunHubCurl(config, url, body, resp, DATA_POLICY_RESPONSE_CAP)) {
        long status = SplitHubStatus(resp);
        if (status == 200) {
            DataInvPolicy p;
            char why[160];
            if (DataInv_ParsePolicy(resp, &p, why, sizeof(why))) {
                g_DataPolicy = p;
                g_DataPolicyLoaded = true;
            } else {
                /* An unreadable policy stops scanning rather than keeping an
                 * older scope the hub may have narrowed. */
                g_DataPolicyLoaded = false;
                fprintf(stderr, "[-] Data inventory policy rejected: %s\n", why);
            }
        } else if (status == 404) {
            g_DataPolicyLoaded = false; /* hub predates data inventory */
        }
    }
    free(resp);
}

/* The upload runs on a curl multi handle driven from the main loop, so a
 * slow or stuck hub never holds up telemetry: each tick moves it on without
 * blocking. The document and the state it commits are owned copies. */
static CURLM* g_DataMulti = NULL;
static CURL* g_DataEasy = NULL;
static struct curl_slist* g_DataHeaders = NULL;
static char* g_DataDoc = NULL;
static char* g_DataState = NULL;
static char g_DataResp[2048];
static HUB_RESPONSE_BUFFER g_DataRespBuf;
/* What DataInv_Due needs from the state file, kept between ticks so an idle
 * agent does not re-read and parse it every minute; reloaded after a commit. */
static DataInvState g_DataDueState;
static bool g_DataDueCached = false;

static void EndDataUpload(void) {
    if (g_DataMulti && g_DataEasy) curl_multi_remove_handle(g_DataMulti, g_DataEasy);
    if (g_DataEasy) curl_easy_cleanup(g_DataEasy);
    g_DataEasy = NULL;
    curl_slist_free_all(g_DataHeaders);
    g_DataHeaders = NULL;
    free(g_DataDoc);
    free(g_DataState);
    g_DataDoc = g_DataState = NULL;
}

static void FinishDataInventory(const LINUX_AGENT_CONFIG* config) {
    char* doc = NULL;
    char* state = NULL;
    char why[160];
    if (g_DataRun.overflow) {
        fprintf(stderr, "[-] Data inventory scan exceeded its output or time limit; nothing sent.\n");
    } else if (!DataInv_SplitOutput(g_DataRun.buf, g_DataRun.len, &doc, &state, why, sizeof(why))) {
        fprintf(stderr, "[-] Data inventory scan failed: %s\n", why);
    } else {
        g_DataDoc = strdup(doc);
        g_DataState = strdup(state);
        if (!g_DataMulti) g_DataMulti = curl_multi_init();
        g_DataEasy = curl_easy_init();
        char url[sizeof(config->hub_url) + 32];
        snprintf(url, sizeof(url), "%s/api/v1/data/inventory", config->hub_url);
        g_DataResp[0] = '\0';
        g_DataRespBuf = (HUB_RESPONSE_BUFFER){.data = g_DataResp, .cap = sizeof(g_DataResp), .len = 0, .overflow = false};
        if (g_DataDoc && g_DataState && g_DataMulti && g_DataEasy &&
            (g_DataHeaders = SetupHubCurl(g_DataEasy, config, url, g_DataDoc, strlen(g_DataDoc), NULL, &g_DataRespBuf, 300000L)) != NULL &&
            curl_multi_add_handle(g_DataMulti, g_DataEasy) == CURLM_OK) {
            DataInv_Reset(&g_DataRun);
            return;
        }
        fprintf(stderr, "[-] Data inventory upload could not start; retrying later.\n");
        EndDataUpload();
    }
    DataInv_Reset(&g_DataRun);
}

/* One non-blocking step of the upload; commits the state on HTTP 200. */
static void PollDataUpload(const LINUX_AGENT_CONFIG* config) {
    int running = 0;
    if (curl_multi_perform(g_DataMulti, &running) != CURLM_OK) running = 0;
    if (running) return;
    CURLcode result = CURLE_FAILED_INIT;
    int left = 0;
    for (CURLMsg* m; (m = curl_multi_info_read(g_DataMulti, &left)) != NULL;) {
        if (m->msg == CURLMSG_DONE && m->easy_handle == g_DataEasy) result = m->data.result;
    }
    long status = 0;
    if (result == CURLE_OK && !g_DataRespBuf.overflow) curl_easy_getinfo(g_DataEasy, CURLINFO_RESPONSE_CODE, &status);
    if (status == 200) {
        if (!DataInv_WriteState(DATA_INVENTORY_STATE_PATH, g_DataState))
            fprintf(stderr, "[-] Data inventory state could not be saved; the run repeats.\n");
        else if (config->verbose)
            printf("[+] Data inventory sent (%zu bytes).\n", strlen(g_DataDoc));
        g_DataDueCached = false;
    } else {
        fprintf(stderr, "[-] Data inventory upload not accepted (HTTP %ld, curl %d); retrying later.\n", status, (int)result);
    }
    EndDataUpload();
}

static void TickDataInventory(const LINUX_AGENT_CONFIG* config) {
    time_t now = time(NULL);
    if (g_DataEasy) {
        PollDataUpload(config);
        return;
    }
    if (g_DataRun.active) {
        if (DataInv_Drain(&g_DataRun)) FinishDataInventory(config);
        return;
    }
    if (now - g_LastDataPolicySync >= DATA_POLICY_SYNC_INTERVAL_SECS) SyncDataPolicy(config);
    if (!g_DataPolicyLoaded || !g_DataPolicy.enabled || now - g_LastDataDueCheck < 60) return;
    g_LastDataDueCheck = now;
    long long nowMs = DataInv_NowMs();
    /* A run that failed (upload refused, child killed) waits resume_minutes
     * before the next attempt instead of rescanning every minute. */
    if (g_LastDataAttemptMs && nowMs - g_LastDataAttemptMs < (long long)g_DataPolicy.resume_minutes * 60000) return;
    if (!g_DataDueCached) {
        DataInvState st;
        char* text = DataInv_ReadSmallFile(DATA_INVENTORY_STATE_PATH, DI_STATE_CAP);
        if (!text || !DataInv_ParseState(text, &st)) memset(&st, 0, sizeof(st));
        memset(&g_DataDueState, 0, sizeof(g_DataDueState));
        g_DataDueState.has_cycle = st.has_cycle;
        g_DataDueState.cycle_policy = st.cycle_policy;
        g_DataDueState.cycle_rules = st.cycle_rules;
        g_DataDueState.cycle_done = st.cycle_done;
        g_DataDueState.last_run = st.last_run;
        g_DataDueState.last_done = st.last_done;
        DataInv_StateFree(&st);
        free(text);
        g_DataDueCached = true;
    }
    if (!DataInv_Due(&g_DataPolicy, &g_DataDueState, nowMs)) return;
    g_LastDataAttemptMs = nowMs;
    g_DataDueCached = false; /* the run may change the state */
    if (!DataInv_Start(&g_DataRun, &g_DataPolicy, DATA_INVENTORY_STATE_PATH, config->endpoint_id))
        fprintf(stderr, "[-] Data inventory scan could not start.\n");
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    /* The self-updater runs this on a freshly installed binary before it
     * restarts into it: a binary the host's loader cannot start fails here. */
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("%s\n", OMINULL_LINUX_AGENT_VERSION);
        return 0;
    }
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		fprintf(stderr, "[-] Could not initialize in-process TLS transport.\n");
		return 1;
	}

    LINUX_AGENT_CONFIG config;
    memset(&config, 0, sizeof(config));
    strcpy(config.hub_url, "https://127.0.0.1:9443");
    strcpy(config.api_key, "<provision-via-bootstrap>");
    strcpy(config.ca_path, OMINULL_DEFAULT_CA_PATH);
    strcpy(config.role_tag, "workstation");
    strcpy(config.location_id, "loc-default");
	config.pin_hub_ca = true;
    strcpy(config.config_path, "/etc/ominull/agent.conf");
    gethostname(config.hostname, sizeof(config.hostname) - 1);
    snprintf(config.endpoint_id, sizeof(config.endpoint_id), "linux-%.50s", config.hostname);
    GetPrimaryNetworkInfo(config.primary_ip, sizeof(config.primary_ip), config.primary_mac, sizeof(config.primary_mac));

    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            strncpy(config.config_path, argv[i + 1], sizeof(config.config_path) - 1);
            break;
        }
    }
    LoadConfigFile(&config, config.config_path);

    bool doConfigure = false;
    bool doCleanup = false;
    bool doRepin = false;
    const char* setCeiling = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hub") == 0 && i + 1 < argc) {
            strncpy(config.hub_url, argv[++i], sizeof(config.hub_url) - 1);
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            strncpy(config.api_key, argv[++i], sizeof(config.api_key) - 1);
        } else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) {
            strncpy(config.key_path, argv[++i], sizeof(config.key_path) - 1);
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            strncpy(config.config_path, argv[++i], sizeof(config.config_path) - 1);
        } else if (strcmp(argv[i], "--configure-stdin") == 0) {
            doConfigure = true;
        } else if (strcmp(argv[i], "--cleanup") == 0) {
            doCleanup = true;
        } else if (strcmp(argv[i], "--repin-trust") == 0) {
            doRepin = true;
        } else if (strcmp(argv[i], "--capability-ceiling") == 0 && i + 1 < argc) {
            setCeiling = argv[++i];
        } else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            strncpy(config.endpoint_id, argv[++i], sizeof(config.endpoint_id) - 1);
        } else if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            strncpy(config.role_tag, argv[++i], sizeof(config.role_tag) - 1);
        } else if (strcmp(argv[i], "--location") == 0 && i + 1 < argc) {
            strncpy(config.location_id, argv[++i], sizeof(config.location_id) - 1);
        } else if (strcmp(argv[i], "--cf-id") == 0 || strcmp(argv[i], "--cf-secret") == 0) {
            fprintf(stderr, "[-] Cloudflare service-token authentication is not supported; use the unique device credential.\n");
            return 2;
        } else if (strcmp(argv[i], "--client-cert") == 0 && i + 1 < argc) {
            strncpy(config.client_cert_path, argv[++i], sizeof(config.client_cert_path) - 1);
        } else if (strcmp(argv[i], "--client-key") == 0 && i + 1 < argc) {
            strncpy(config.client_key_path, argv[++i], sizeof(config.client_key_path) - 1);
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            strncpy(config.ca_path, argv[++i], sizeof(config.ca_path) - 1);
        } else if (strcmp(argv[i], "--allow-plaintext") == 0) {
            config.allow_plaintext = true;
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

    if (doConfigure) return ConfigureFromStdin() ? 0 : 1;
    if (doCleanup) {
        /* This is the local way out, so it says when it did not work. */
        bool gone = false;
        for (int i = 0; i < 3 && !gone; i++) {
            gone = EnforcementTeardown("iptables");
            gone = EnforcementTeardown("ip6tables") && gone;
        }
        if (!gone) {
            fprintf(stderr, "[-] The Ominull firewall rules are still there; something may be holding the firewall lock. Run --cleanup again.\n");
            return 1;
        }
        Trust_Init(&g_Trust, config.endpoint_id, NULL, NULL, true);
        if (g_Trust.state.exists) Trust_LocalRelease(&g_Trust);
        return 0;
    }
    if (setCeiling) {
        if (geteuid() != 0) {
            fprintf(stderr, "[-] --capability-ceiling must run as root.\n");
            return 1;
        }
        Trust_Init(&g_Trust, config.endpoint_id, NULL, NULL, true);
        if (!Trust_SetCeiling(&g_Trust, setCeiling)) {
            fprintf(stderr, "[-] --capability-ceiling takes monitor, isolate, signed-scripts, monitor-signed-scripts, respond, engagement or none.\n");
            return 1;
        }
        printf("[+] Capability ceiling %s recorded; restart the agent.\n", setCeiling);
        return 0;
    }
    if (doRepin) {
        if (geteuid() != 0) {
            fprintf(stderr, "[-] --repin-trust must run as root.\n");
            return 1;
        }
        Trust_Init(&g_Trust, config.endpoint_id, NULL, NULL, true);
        int removed = Trust_Repin(&g_Trust);
        if (removed < 0) {
            fprintf(stderr, "[-] The pinned trust bundle could not be removed from /etc/ominull; the current keys stay trusted.\n");
            return 1;
        }
        printf("[+] Removed %d pinned trust bundle(s); restart the agent so it pins the hub's current release-signed bundle.\n", removed);
        return 0;
    }

    /* A key file wins over --key: a unit that carries both is one mid-migration,
     * and the file is the channel being migrated to. */
    if (config.key_path[0] && !ReadKeyFile(config.key_path, config.api_key, sizeof(config.api_key))) {
        fprintf(stderr, "[-] --key-file %s could not be read; refusing to start without a credential.\n",
                config.key_path);
        return 1;
    }
	if (!config.api_key[0] || strcmp(config.api_key, "<provision-via-bootstrap>") == 0) {
		fprintf(stderr, "[-] No enrolled device credential is configured; refusing to start.\n");
		return 1;
	}

    DetectPackageProvenance(&config);

    struct utsname sysInfo;
    uname(&sysInfo);

    printf("===============================================================================\n");
    printf("     OMINULL LINUX AGENT (socket collection + firewall control)\n");
    printf("===============================================================================\n");
    printf("  Endpoint ID:   %s\n", config.endpoint_id);
    printf("  Hostname:      %s\n", config.hostname);
    printf("  Kernel / OS:   %s %s (%s)\n", sysInfo.sysname, sysInfo.release, sysInfo.machine);
    printf("  Hub Endpoint:  %s\n", config.hub_url);
    printf("  Credential:    %s\n", config.key_path[0] ? config.key_path
                                                       : "--key (visible in /proc/<pid>/cmdline; prefer --key-file)");
    if (HubUsesTLS(&config)) {
        if (config.pin_hub_ca) {
            printf("  Hub Trust:     TLS, pinned to %s\n", config.ca_path);
        } else {
            printf("  Hub Trust:     TLS, operating-system certificate trust\n");
        }
        if (config.client_cert_path[0] && access(config.client_cert_path, R_OK) == 0) {
            printf("  Identity:      client certificate %s\n", config.client_cert_path);
        } else {
            printf("  Identity:      unique device credential only (no client certificate; direct native mTLS\n");
            printf("                 adds a second matching proof)\n");
        }
    } else {
        printf("  Hub Trust:     NONE - cleartext transport%s\n",
               config.allow_plaintext ? " (--allow-plaintext)" : " (will refuse to report)");
    }
    printf("  Agent Version: %s\n", OMINULL_LINUX_AGENT_VERSION);
    printf("===============================================================================\n");

    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);
    /* The heartbeat writes its body into a child's stdin. A child that exits
     * first would otherwise take the daemon down with a SIGPIPE. */
    signal(SIGPIPE, SIG_IGN);
    /* SIGCHLD stays at its default. Ignoring it auto-reaped children, which
     * also made every waitpid() fail with ECHILD: RunTool returned -1 for each
     * iptables call, so the isolation readiness probe always reported
     * "iptables would not list the OUTPUT chain (exit -1)" and pclose/system
     * statuses were lost. Every child is reaped by whoever forks it; the
     * terminal worker is double-forked so init reaps it. */

    mkdir("/var/lib/ominull", 0755);
    AdoptRulesInForce();
    Trust_Init(&g_Trust, config.endpoint_id, NULL, NULL, true);
    g_ReleaseVerifyPem = OMINULL_RELEASE_PUBKEY_PEM;
    g_Trust.verify_release = ReleaseVerifyPosix;
    printf("  Trust:         response key %s, auto-isolation key %s, policy key %s; manifest %s\n",
           g_Trust.have_key[TRUST_KEY_RESPONSE] ? "pinned" : "missing", g_Trust.have_key[TRUST_KEY_AUTO] ? "pinned" : "missing",
           g_Trust.have_key[TRUST_KEY_POLICY] ? "pinned" : "missing", g_Trust.manifest.have ? g_Trust.manifest.profile : "none yet");
    uint8_t ep_pub[32];
    uint8_t ep_priv[64];
    if (Forensics_GetOrCreateEndpointKey(FORENSICS_DEFAULT_KEY_PATH, ep_pub, ep_priv, config.evidence_pubkey_hex, sizeof(config.evidence_pubkey_hex))) {
        if (config.verbose) {
            printf("[+] Evidence signing key active: %.16s...\n", config.evidence_pubkey_hex);
        }
    }

    RecoverClientCertSwap(&config);
    SetSelfHubPeer(&config);

    printf("[+] Initializing Linux socket collection and firewall control...\n");
    /* Says what is about to happen, not what has happened. This line used to
     * read "Connected and continuously streaming", printed before a single
     * request had been made - so a host that could not reach the hub at all
     * announced a working connection and then went quiet. The hub's first
     * acceptance is reported by ReportHubRejection, from evidence. */
    printf("[+] Streaming flow telemetry to Hub: %s\n", config.hub_url);

    LINUX_FLOW_EVENT flows[MAX_FLOWS_PER_BATCH];
    size_t flowCount = CollectActiveFlows(flows, MAX_FLOWS_PER_BATCH);
    SendTelemetryBatch(&config, flows, flowCount);
    SyncSoftwareInventory(&config);

    int count = 0;
    while (g_Running) {
        sleep(1);
        UDPCollectorPoll();
        if (++count >= 3) {
            flowCount = CollectActiveFlows(flows, MAX_FLOWS_PER_BATCH);
            SendTelemetryBatch(&config, flows, flowCount);
            count = 0;
        }
        if (time(NULL) - g_LastSoftwareInventorySync >= SOFTWARE_INVENTORY_SYNC_INTERVAL_SECS) {
            SyncSoftwareInventory(&config);
        }
        TickDataInventory(&config);
    }

    /* Held loopback counters go with a last batch rather than with the process. */
    g_UDPFlushLocal = true;
    g_FinalBatch = true;
    flowCount = CollectActiveFlows(flows, MAX_FLOWS_PER_BATCH);
    if (flowCount)
        SendTelemetryBatch(&config, flows, flowCount);

    DataInv_Abort(&g_DataRun);
    EndDataUpload();
    if (g_DataMulti) curl_multi_cleanup(g_DataMulti);
    UDPCollectorClose();
    printf("\n[*] Stopping Linux socket collection and shutting down gracefully...\n");
    return 0;
}
