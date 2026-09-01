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

#ifndef OMINULL_PROC_ROOT
#define OMINULL_PROC_ROOT "/proc"
#endif

#define OMINULL_LINUX_AGENT_VERSION "1.8.0"

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
    bool auto_update;
    /* Direct self-issued hubs use a pinned Ominull CA. Public ACME or
     * Cloudflare endpoints use the operating system trust store instead. */
    bool pin_hub_ca;
    bool allow_plaintext;
} LINUX_AGENT_CONFIG;

static void EnforcementTeardown(const char* tool);

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
    bool valid;
} SOCKET_COUNTER;

#define SOCKET_COUNTER_CAP 1024
static SOCKET_COUNTER g_SocketCounters[SOCKET_COUNTER_CAP];

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
    size_t start = SocketCounterSlot(inode, cookie0, cookie1);
    for (size_t probe = 0; probe < SOCKET_COUNTER_CAP; probe++) {
        SOCKET_COUNTER* slot = &g_SocketCounters[(start + probe) & (SOCKET_COUNTER_CAP - 1)];
        if (!slot->valid) {
            slot->valid = true;
            slot->inode = inode;
            slot->cookie0 = cookie0;
            slot->cookie1 = cookie1;
            slot->bytes_in = bytesIn;
            slot->bytes_out = bytesOut;
            *outIn = 0;
            *outOut = 0;
            return 1;
        }
        if (slot->inode == inode && slot->cookie0 == cookie0 && slot->cookie1 == cookie1) {
            *outIn = bytesIn >= slot->bytes_in ? bytesIn - slot->bytes_in : 0;
            *outOut = bytesOut >= slot->bytes_out ? bytesOut - slot->bytes_out : 0;
            slot->bytes_in = bytesIn;
            slot->bytes_out = bytesOut;
            return 1;
        }
    }
    *outIn = 0;
    *outOut = 0;
    return 0;
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
    struct stat st;
    if (stat(path, &st) != 0) {
        printf("[!] Cannot read the device credential file %s: %s\n", path, strerror(errno));
        return false;
    }
    if (st.st_mode & (S_IRGRP | S_IROTH)) {
        printf("[!] Device credential file %s is readable beyond its owner; tighten it to 0600.\n", path);
    }
    FILE* f = fopen(path, "r");
    if (!f) {
        printf("[!] Cannot open the device credential file %s: %s\n", path, strerror(errno));
        return false;
    }
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
    else if (strcmp(key, "auto_update") == 0) config->auto_update = strcmp(value, "0") != 0;
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
        if (strcmp(option, "--no-auto-update") == 0) {
            config->auto_update = false;
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
    if (mkdir(OMINULL_UPDATE_DIR, 0700) != 0 && errno != EEXIST) return false;
    if (!WritePrivateFile("/etc/ominull/agent.key", key, 0600)) return false;
	if (pinHubCA && !CopyPrivateFile(caSource, "/etc/ominull/ca.crt", 0644)) return false;
    if (certSource[0] && !CopyPrivateFile(certSource, "/etc/ominull/client.crt", 0600)) return false;
    if (keySource[0] && !CopyPrivateFile(keySource, "/etc/ominull/client.key", 0600)) return false;

    char config[2048];
    int n = snprintf(config, sizeof(config),
                     "hub_url=%s\nkey_path=/etc/ominull/agent.key\nendpoint_id=%s\nrole_tag=%s\n"
	                 "location_id=%s\nca_path=%s\npin_hub_ca=%d\nclient_cert_path=/etc/ominull/client.crt\n"
	                     "client_key_path=/etc/ominull/client.key\n"
	                     "auto_update=1\nallow_plaintext=%d\n",
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
	printf("  %s --hub <url> --key-file <path> [--ca <path>] [--role <role>] [--location <id>] [--no-auto-update] [--allow-plaintext] [-v]\n", prog);
    printf("\nOptions:\n");
	printf("  --key-file <path>  Read the unique device credential from a file. Prefer this:\n");
    printf("                     an argument is world-readable through /proc/<pid>/cmdline.\n");
    printf("  --ca <path>        CA certificate the hub is verified against (default %s).\n", OMINULL_DEFAULT_CA_PATH);
    printf("  --client-cert <p>  Certificate this endpoint identifies itself with, and --client-key\n");
    printf("                     its private key. Enrolment issues both; without them the hub has\n");
	printf("                     direct native mTLS adds a second matching proof.\n");
	printf("  --allow-plaintext  Permit an http:// hub. Credentials then cross the network in the clear.\n");
    printf("  --no-auto-update   Report the running version but never install a hub-offered package.\n");
    printf("  --version          Print the version and exit.\n");
    printf("  --config <path>    Read package-owned runtime configuration.\n");
    printf("  --configure-stdin  Install enrollment material from stdin.\n");
    printf("  --cleanup          Remove Ominull-owned host enforcement state.\n");
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

// Read one TCP address-family table from /proc/net. The table is read first,
// then process descriptors are walked once and joined by inode. That keeps
// descriptor reads proportional to the proc tree, not to socket count.
static void CollectSocketTable(const char* tableName, bool ipv6,
                               LINUX_FLOW_EVENT* outEvents, size_t maxEvents,
                               unsigned long* targetInodes, size_t* count) {
    char tablePath[256];
    ProcPath(tablePath, sizeof(tablePath), tableName);
    FILE* fp = fopen(tablePath, "r");
    if (!fp) return;

    char line[512];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return;
    }

    while (*count < maxEvents && fgets(line, sizeof(line), fp)) {
        // Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
        int sl = 0, state = 0;
        char localAddrHex[64] = {0}, remAddrHex[64] = {0};
        unsigned int localPort = 0, remPort = 0;
        unsigned long inode = 0;
        int matched = sscanf(line, "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %*X:%*X %*X:%*X %*X %*d %*d %lu",
                             &sl, localAddrHex, &localPort, remAddrHex, &remPort, &state, &inode);
        if (matched < 7 || inode == 0 || remPort == 0 || IsZeroAddress(remAddrHex)) continue;

        LINUX_FLOW_EVENT* ev = &outEvents[*count];
        memset(ev, 0, sizeof(*ev));
        if (ipv6) {
            if (!ParseHexIPv6(localAddrHex, ev->src_ip, sizeof(ev->src_ip)) ||
                !ParseHexIPv6(remAddrHex, ev->dst_ip, sizeof(ev->dst_ip))) {
                continue;
            }
        } else {
            ParseHexIPv4(localAddrHex, ev->src_ip, sizeof(ev->src_ip));
            ParseHexIPv4(remAddrHex, ev->dst_ip, sizeof(ev->dst_ip));
        }
        ev->src_port = (uint16_t)localPort;
        ev->dst_port = (uint16_t)remPort;
        if (IsLoopbackAddress(ev->dst_ip) || IsLoopbackAddress(ev->src_ip)) continue;
        if (ev->dst_port == 9999 && strcmp(ev->dst_ip, ev->src_ip) == 0) continue;

        ev->protocol = IPPROTO_TCP;
        strncpy(ev->direction, "OUTBOUND", sizeof(ev->direction) - 1);
        targetInodes[*count] = inode;
        (*count)++;
    }
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

typedef struct {
    char ip[64];
    char domain[128];
    uint64_t last_seen;
    bool valid;
} DNS_ATTRIBUTION_SLOT;

#define DNS_ATTR_CAP 512
static DNS_ATTRIBUTION_SLOT g_DnsAttr[DNS_ATTR_CAP];

static void CacheDnsAttribution(const char* ip, const char* domain) {
    if (!ip || !ip[0] || !domain || !domain[0]) return;
    uint64_t hash = 5381;
    for (const char* p = ip; *p; p++) hash = ((hash << 5) + hash) + (unsigned char)*p;
    size_t start = (size_t)(hash & (DNS_ATTR_CAP - 1));
    
    time_t now = time(NULL);
    for (size_t probe = 0; probe < DNS_ATTR_CAP; probe++) {
        DNS_ATTRIBUTION_SLOT* slot = &g_DnsAttr[(start + probe) & (DNS_ATTR_CAP - 1)];
        if (!slot->valid || strcmp(slot->ip, ip) == 0) {
            slot->valid = true;
            snprintf(slot->ip, sizeof(slot->ip), "%s", ip);
            snprintf(slot->domain, sizeof(slot->domain), "%s", domain);
            slot->last_seen = (uint64_t)now;
            return;
        }
    }
}

static void PopulateEtcHosts(void) {
    FILE* fp = fopen("/etc/hosts", "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char ip[64] = {0}, host[128] = {0};
        if (sscanf(line, "%63s %127s", ip, host) == 2) {
            if (strcmp(ip, "127.0.0.1") != 0 && strcmp(ip, "::1") != 0) {
                CacheDnsAttribution(ip, host);
            }
        }
    }
    fclose(fp);
}

static const char* LookupDnsDomain(const char* ip) {
    if (!ip || !ip[0]) return NULL;
    uint64_t hash = 5381;
    for (const char* p = ip; *p; p++) hash = ((hash << 5) + hash) + (unsigned char)*p;
    size_t start = (size_t)(hash & (DNS_ATTR_CAP - 1));
    
    for (size_t probe = 0; probe < DNS_ATTR_CAP; probe++) {
        DNS_ATTRIBUTION_SLOT* slot = &g_DnsAttr[(start + probe) & (DNS_ATTR_CAP - 1)];
        if (!slot->valid) break;
        if (strcmp(slot->ip, ip) == 0) return slot->domain;
    }
    return NULL;
}

typedef struct {
    uint32_t process_id;
    char target_ips[32][64];
    size_t target_count;
    uint64_t window_start;
    bool alerted;
} BEHAVIORAL_PROCESS_TRACKER;

#define BEHAVIORAL_TRACKER_CAP 64
static BEHAVIORAL_PROCESS_TRACKER g_BehavioralTrackers[BEHAVIORAL_TRACKER_CAP];

static void TrackLateralSweep(uint32_t pid, const char* dst_ip) {
    if (pid <= 1 || !dst_ip || !dst_ip[0] || strcmp(dst_ip, "127.0.0.1") == 0 || strcmp(dst_ip, "::1") == 0) return;
    
    // Only track RFC1918 private / local subnet fan-outs
    if (strncmp(dst_ip, "192.168.", 8) != 0 && strncmp(dst_ip, "10.", 3) != 0 && strncmp(dst_ip, "172.", 4) != 0) return;

    time_t now = time(NULL);
    size_t slotIdx = (size_t)(pid % BEHAVIORAL_TRACKER_CAP);
    BEHAVIORAL_PROCESS_TRACKER* tracker = &g_BehavioralTrackers[slotIdx];

    if (tracker->process_id != pid || (uint64_t)now >= tracker->window_start + 60) {
        tracker->process_id = pid;
        tracker->target_count = 0;
        tracker->window_start = (uint64_t)now;
        tracker->alerted = false;
    }

    for (size_t i = 0; i < tracker->target_count; i++) {
        if (strcmp(tracker->target_ips[i], dst_ip) == 0) return;
    }

    if (tracker->target_count < 32) {
        snprintf(tracker->target_ips[tracker->target_count++], 64, "%s", dst_ip);
    }

    if (tracker->target_count >= 15 && !tracker->alerted) {
        tracker->alerted = true;
        printf("[!] ANOMALY ALERT [CRITICAL]: Lateral Fan-Out / Internal Port Sweep detected (PID %u reached %zu internal hosts in 60s)\n",
               pid, tracker->target_count);
        fflush(stdout);
    }
}

typedef struct {
    char ip[64];
    char mac[32];
    char hostname[128];
    char vendor[64];
    char protocol[16];
    uint64_t last_seen;
    bool valid;
} DISCOVERED_DEVICE_ENTRY;

#define DISCOVERED_DEVICES_CAP 64
static DISCOVERED_DEVICE_ENTRY g_DiscoveredDevices[DISCOVERED_DEVICES_CAP];

static void RecordDiscoveredDevice(const char* ip, const char* mac, const char* hostname, const char* vendor, const char* proto) {
    if (!ip || !ip[0] || strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0) return;

    time_t now = time(NULL);
    for (size_t i = 0; i < DISCOVERED_DEVICES_CAP; i++) {
        if (g_DiscoveredDevices[i].valid && strcmp(g_DiscoveredDevices[i].ip, ip) == 0) {
            if (hostname && hostname[0]) snprintf(g_DiscoveredDevices[i].hostname, 128, "%s", hostname);
            if (mac && mac[0]) snprintf(g_DiscoveredDevices[i].mac, 32, "%s", mac);
            g_DiscoveredDevices[i].last_seen = (uint64_t)now;
            return;
        }
    }
    for (size_t i = 0; i < DISCOVERED_DEVICES_CAP; i++) {
        if (!g_DiscoveredDevices[i].valid) {
            g_DiscoveredDevices[i].valid = true;
            snprintf(g_DiscoveredDevices[i].ip, 64, "%s", ip);
            if (mac && mac[0]) snprintf(g_DiscoveredDevices[i].mac, 32, "%s", mac);
            if (hostname && hostname[0]) snprintf(g_DiscoveredDevices[i].hostname, 128, "%s", hostname);
            if (vendor && vendor[0]) snprintf(g_DiscoveredDevices[i].vendor, 64, "%s", vendor);
            snprintf(g_DiscoveredDevices[i].protocol, 16, "%s", proto ? proto : "mdns");
            g_DiscoveredDevices[i].last_seen = (uint64_t)now;
            return;
        }
    }
}

static void HarvestArpTable(void) {
    FILE* fp = fopen("/proc/net/arp", "r");
    if (!fp) return;
    char line[256];
    if (fgets(line, sizeof(line), fp)) {
        while (fgets(line, sizeof(line), fp)) {
            char ip[64] = {0}, hwType[32] = {0}, flags[32] = {0}, mac[32] = {0}, mask[32] = {0}, dev[32] = {0};
            if (sscanf(line, "%63s %31s %31s %31s %31s %31s", ip, hwType, flags, mac, mask, dev) >= 4) {
                if (strcmp(mac, "00:00:00:00:00:00") != 0 && strcmp(flags, "0x0") != 0) {
                    RecordDiscoveredDevice(ip, mac, "", "", "arp");
                }
            }
        }
    }
    fclose(fp);
}

// Capture active TCP socket flows from both Linux address families.
static size_t CollectActiveFlows(LINUX_FLOW_EVENT* outEvents, size_t maxEvents) {
    size_t count = 0;
    unsigned long targetInodes[MAX_FLOWS_PER_BATCH];
    PROC_SOCKET_OWNER owners[MAX_FLOWS_PER_BATCH];
    memset(targetInodes, 0, sizeof(targetInodes));
    memset(owners, 0, sizeof(owners));

    HarvestArpTable();

    CollectSocketTable("net/tcp", false, outEvents, maxEvents, targetInodes, &count);
    CollectSocketTable("net/tcp6", true, outEvents, maxEvents, targetInodes, &count);

    SOCKET_DIAG_RESULT socketStats[MAX_FLOWS_PER_BATCH];
    memset(socketStats, 0, sizeof(socketStats));
    (void)QuerySocketDiag(targetInodes, count, socketStats);
    for (size_t i = 0; i < count; i++) {
        if (!socketStats[i].found) continue;
        uint64_t bytesIn = 0, bytesOut = 0;
        if (SocketCounterDelta(socketStats[i].inode, socketStats[i].cookie0,
                                socketStats[i].cookie1, socketStats[i].bytes_in,
                                socketStats[i].bytes_out, &bytesIn, &bytesOut)) {
            outEvents[i].bytes_in = bytesIn;
            outEvents[i].bytes_out = bytesOut;
        }
    }

    IndexSocketOwners(targetInodes, count, owners);
    for (size_t i = 0; i < count; i++) {
        if (owners[i].pid != 0) {
            outEvents[i].process_id = owners[i].pid;
            snprintf(outEvents[i].process_path, sizeof(outEvents[i].process_path), "%s", owners[i].path);
        } else {
            outEvents[i].process_id = 0;
            snprintf(outEvents[i].process_path, sizeof(outEvents[i].process_path), "/usr/bin/system");
        }
        TrackLateralSweep(outEvents[i].process_id, outEvents[i].dst_ip);
    }

    // Apply edge deduplication: novel flows emit immediately; routine idle flows rollup every 30s.
    size_t filteredCount = 0;
    for (size_t i = 0; i < count; i++) {
        if (ShouldReportFlow(outEvents[i].dst_ip, outEvents[i].dst_port, outEvents[i].protocol,
                             outEvents[i].process_id, outEvents[i].bytes_in, outEvents[i].bytes_out)) {
            if (filteredCount != i) {
                outEvents[filteredCount] = outEvents[i];
            }
            filteredCount++;
        }
    }
    return filteredCount;
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
static bool RunHubCurl(const LINUX_AGENT_CONFIG* config, const char* url,
                       const char* body, char* out, size_t outCap) {
    if (out && outCap) out[0] = '\0';
    static CURL* curl = NULL;
    if (!curl) {
        curl = curl_easy_init();
        if (!curl) return false;
    }

	char apiHeader[256];
	const char* headerName = IsDeviceCredentialValue(config->api_key)
	    ? "X-Ominull-Device-Credential" : "X-API-Key";
	if (snprintf(apiHeader, sizeof(apiHeader), "%s: %s", headerName, config->api_key) >= (int)sizeof(apiHeader)) {
		return false;
	}
	struct curl_slist* headers = curl_slist_append(NULL, "Content-Type: application/json");
	headers = curl_slist_append(headers, apiHeader);
	if (!headers) return false;

    HUB_RESPONSE_BUFFER response = {
        .data = out, .cap = outCap, .len = 0, .overflow = false
    };
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)(body ? strlen(body) : 0));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HubResponseWrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OminullAgent/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
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
/* ---------------------------------------------------------------------------
 * Host isolation.
 *
 * Isolation arrives on the authenticated heartbeat reply, alongside the
 * quarantined-peer list, and is reconciled on every beat: a host that was down
 * when it was released must still come back.
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
                             char threats[][64], int threatCount,
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

    /* 3. DHCP, above the peer blocks. */
    if (baselineKnown) {
        for (int i = 0; i < baselineCount; i++) {
            if (strcmp(baseline[i].service, "dhcp") != 0) continue;
            if ((strchr(baseline[i].destination, ':') != NULL) != v6) continue;
            BaselinePermit(tool, &baseline[i]);
        }
    } else {
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

    /* 4b. In-Line Threat Intelligence indicators drop. */
    for (int i = 0; i < threatCount; i++) {
        if ((strchr(threats[i], ':') != NULL) != v6) continue;
        const char* tIn[]  = { tool, "-A", OMINULL_CHAIN_IN,  "-s", threats[i], "-j", "DROP", NULL };
        const char* tOut[] = { tool, "-A", OMINULL_CHAIN_OUT, "-d", threats[i], "-j", "DROP", NULL };
        (void)RunTool(tIn);
        (void)RunTool(tOut);
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
static char appliedThreats[MAX_QUARANTINED_PEERS][64];
static int appliedThreatCount = 0;
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
    char threats[MAX_QUARANTINED_PEERS][64];
    int threatCount = ParseAddressList(respJson, "threat_indicators", threats, MAX_QUARANTINED_PEERS);

    BASELINE_RULE baseline[MAX_BASELINE_RULES];
    int baselineCount = ParseBaselineRules(respJson, baseline, MAX_BASELINE_RULES);
    bool baselineKnown = baselineCount >= 0;
    if (!baselineKnown) baselineCount = 0;

    bool changed = !known || wantIsolated != appliedIsolated
                   || allowCount != appliedAllowCount || peerCount != appliedPeerCount
                   || threatCount != appliedThreatCount
                   || baselineKnown != appliedBaselineKnown || baselineCount != appliedBaselineCount;
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
    } else if (peerCount == 0 && appliedPeerCount > 0 && threatCount == 0) {
        printf("[+] Mesh quarantine cleared; no enforcement rules remain on this host.\n");
    } else if (peerCount != appliedPeerCount) {
        printf("[*] Mesh quarantine updated: %d peer(s).\n", peerCount);
    }
    if (threatCount > 0) {
        printf("[*] In-line edge threat intelligence: active drop rules for %d indicator(s).\n", threatCount);
    }
    fflush(stdout);

    if (!wantIsolated && peerCount == 0 && threatCount == 0) {
        EnforcementTeardown("iptables");
        EnforcementTeardown("ip6tables");
    } else {
        EnforcementBuild("iptables", wantIsolated, hubIP, allow, allowCount, peers, peerCount, threats, threatCount,
                         baseline, baselineCount, baselineKnown);
        EnforcementBuild("ip6tables", wantIsolated, hubIP, allow, allowCount, peers, peerCount, threats, threatCount,
                         baseline, baselineCount, baselineKnown);
    }

    appliedIsolated = wantIsolated;
    memcpy(appliedAllow, allow, sizeof(allow));
    appliedAllowCount = allowCount;
    memcpy(appliedPeers, peers, sizeof(peers));
    appliedPeerCount = peerCount;
    memcpy(appliedThreats, threats, sizeof(threats));
    appliedThreatCount = threatCount;
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
                     appliedThreats, appliedThreatCount,
                     appliedBaseline, appliedBaselineCount, appliedBaselineKnown);
    EnforcementBuild("ip6tables", false, NULL, appliedAllow, 0,
                     appliedPeers, appliedPeerCount,
                     appliedThreats, appliedThreatCount,
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
					 "client_key_path=%s\npin_hub_ca=%d\nauto_update=%d\nallow_plaintext=%d\n",
                     config->hub_url, config->key_path, config->endpoint_id,
                     config->role_tag, config->location_id, config->ca_path,
                     config->client_cert_path, config->client_key_path,
					 config->pin_hub_ca ? 1 : 0,
                     config->auto_update ? 1 : 0, config->allow_plaintext ? 1 : 0);
    if (n < 0 || (size_t)n >= sizeof(rendered) ||
        !WritePrivateFile(config->config_path, rendered, 0600)) {
        printf("[!] The unique credential is active, but the old inline agent configuration could not be rewritten.\n");
    }
    printf("[+] Hub-issued unique device credential installed; legacy shared-key authentication is no longer used by this agent.\n");
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

static void SendTelemetryBatch(LINUX_AGENT_CONFIG* config, const LINUX_FLOW_EVENT* flows, size_t flowCount) {
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
        "{\"type\":\"telemetry\",\"endpoint_id\":\"%s\",\"tenant_id\":\"default\",\"location_id\":\"%s\",\"role\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\",\"driver_version\":\"%s\",\"update_capability\":\"deb\",\"install_type\":\"%s\",\"package_identifier\":\"%s\",\"registered_package_version\":\"%s\",\"provenance_status\":\"%s\",\"events\":[",
        config->endpoint_id,
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
        config->provenance_status
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

        const char* domain = LookupDnsDomain(f->dst_ip);
        char domainJson[256] = {0};
        if (domain && domain[0]) {
            snprintf(domainJson, sizeof(domainJson), ",\"domain\":\"%s\"", domain);
        }

        int written = snprintf(jsonBuf + offset, bufCap - offset,
            "{\"layer\":\"linux-socket-v1\",\"action\":\"PERMIT\",\"direction\":\"%s\",\"protocol\":%u,\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"bytes_in\":%lu,\"bytes_out\":%lu,\"process_path\":\"%s\",\"process_id\":%u%s}%s",
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
            domainJson,
            comma
        );

        if (written > 0) {
            offset += written;
        }
    }

    offset += snprintf(jsonBuf + offset, bufCap - offset, "]");

    // Append discovered_assets
    bool firstDev = true;
    int devOffset = snprintf(jsonBuf + offset, bufCap - offset, ",\"discovered_assets\":[");
    if (devOffset > 0) offset += devOffset;

    time_t nowTime = time(NULL);
    for (size_t i = 0; i < DISCOVERED_DEVICES_CAP && offset < (int)bufCap - 1024; i++) {
        if (!g_DiscoveredDevices[i].valid || (uint64_t)nowTime > g_DiscoveredDevices[i].last_seen + 300) continue;
        int dWritten = snprintf(jsonBuf + offset, bufCap - offset,
            "%s{\"ip\":\"%s\",\"mac\":\"%s\",\"hostname\":\"%s\",\"protocol\":\"%s\"}",
            firstDev ? "" : ",",
            g_DiscoveredDevices[i].ip,
            g_DiscoveredDevices[i].mac,
            g_DiscoveredDevices[i].hostname,
            g_DiscoveredDevices[i].protocol
        );
        if (dWritten > 0) {
            offset += dWritten;
            firstDev = false;
        }
    }
    int closeOffset = snprintf(jsonBuf + offset, bufCap - offset, "]");
    if (closeOffset > 0) offset += closeOffset;

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
            AdoptDeviceCredential(config, respBuf);
            SyncEnforcement(config, respBuf);
            ApplyAgentUpdate(config, respBuf);
        }
    }
    HubContact(accepted);

    free(jsonBuf);
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		fprintf(stderr, "[-] Could not initialize in-process TLS transport.\n");
		return 1;
	}
    PopulateEtcHosts();

    LINUX_AGENT_CONFIG config;
    memset(&config, 0, sizeof(config));
    strcpy(config.hub_url, "https://127.0.0.1:9443");
    strcpy(config.api_key, "<provision-via-bootstrap>");
    strcpy(config.ca_path, OMINULL_DEFAULT_CA_PATH);
    strcpy(config.role_tag, "workstation");
    strcpy(config.location_id, "loc-default");
    config.auto_update = true;
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

    if (doConfigure) return ConfigureFromStdin() ? 0 : 1;
    if (doCleanup) {
        EnforcementTeardown("iptables");
        EnforcementTeardown("ip6tables");
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
    printf("  Agent Version: %s (self-update %s)\n", OMINULL_LINUX_AGENT_VERSION,
           config.auto_update ? "enabled" : "disabled");
    printf("===============================================================================\n");

    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);
    /* The heartbeat writes its body into a child's stdin. A child that exits
     * first would otherwise take the daemon down with a SIGPIPE. */
    signal(SIGPIPE, SIG_IGN);

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

    int count = 0;
    while (g_Running) {
        sleep(1);
        if (++count >= 3) {
            flowCount = CollectActiveFlows(flows, MAX_FLOWS_PER_BATCH);
            SendTelemetryBatch(&config, flows, flowCount);
            count = 0;
        }
    }

    printf("\n[*] Stopping Linux socket collection and shutting down gracefully...\n");
    return 0;
}
