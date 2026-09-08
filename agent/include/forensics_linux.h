#ifndef OMINULL_FORENSICS_LINUX_H
#define OMINULL_FORENSICS_LINUX_H

/*
 * Ominull Linux Forensic Collection Engine (Slice 4A.1: Diagnostic Profile).
 *
 * Implements:
 * - Contained collection worker with strict resource, privilege, and environment isolation.
 * - Allowlisted Linux diagnostic collectors:
 *   1. os_version.json (OS release, kernel, uptime, btime)
 *   2. network_interfaces.json (interfaces, MACs, IPv4/IPv6, MTU, flags)
 *   3. routes.txt (IPv4/IPv6 routing tables)
 *   4. dns_config.txt (resolv.conf)
 *   5. resource_summary.json (memory, load averages, filesystem capacity)
 *   6. service_state.json (essential system service statuses)
 *   7. system_logs.txt (bounded recent journal/syslog, max 256 KiB)
 *   8. agent_diagnostics.json (agent PID, uptime, VmRSS, version)
 * - Honest collector status reporting:
 *   collected, empty, unsupported, permission_denied, truncated, timed_out, failed.
 * - Per-item and cumulative bundle byte bounding.
 * - Deterministic length-prefixed canonical manifest encoding (OMINULL-MANIFEST-V2).
 * - Self-contained Ed25519 manifest signing using dedicated endpoint evidence key.
 * - Authenticated evidence store protocol integration (bundle, item uploads, finalize, job result).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <utmp.h>
#include <curl/curl.h>

#include "ed25519_verify.h"
#include "response_canonical.h"
#include "response_dispatcher.h"

#define FORENSICS_MAX_ITEMS 16
#define FORENSICS_MAX_ITEM_BYTES (512 * 1024)   // 512 KiB per artifact limit
#define FORENSICS_DEFAULT_MAX_BUNDLE_BYTES (10 * 1024 * 1024) // 10 MiB bundle limit
#define FORENSICS_DEFAULT_KEY_PATH "/var/lib/ominull/evidence_signer.key"
#define FORENSICS_DEFAULT_PUB_PATH "/var/lib/ominull/evidence_signer.pub"

/* ---------------------------------------------------------------------------
 * Collector Status Enum
 * ------------------------------------------------------------------------- */

typedef enum {
    COLLECTOR_STATUS_COLLECTED = 0,
    COLLECTOR_STATUS_EMPTY,
    COLLECTOR_STATUS_UNSUPPORTED,
    COLLECTOR_STATUS_PERMISSION_DENIED,
    COLLECTOR_STATUS_TRUNCATED,
    COLLECTOR_STATUS_TIMED_OUT,
    COLLECTOR_STATUS_FAILED
} ForensicCollectorStatus;

static inline const char* CollectorStatusToString(ForensicCollectorStatus s) {
    switch (s) {
        case COLLECTOR_STATUS_COLLECTED: return "collected";
        case COLLECTOR_STATUS_EMPTY: return "empty";
        case COLLECTOR_STATUS_UNSUPPORTED: return "unsupported";
        case COLLECTOR_STATUS_PERMISSION_DENIED: return "permission_denied";
        case COLLECTOR_STATUS_TRUNCATED: return "truncated";
        case COLLECTOR_STATUS_TIMED_OUT: return "timed_out";
        case COLLECTOR_STATUS_FAILED: return "failed";
        default: return "failed";
    }
}

/* ---------------------------------------------------------------------------
 * Forensic Item and Manifest Structs
 * ------------------------------------------------------------------------- */

typedef struct {
    char name[64];
    char content_type[64];
    uint8_t* data;
    size_t size_bytes;
    char sha256[65];
    ForensicCollectorStatus status;
} ForensicCollectedItem;

typedef struct {
    char bundle_id[64];
    char endpoint_id[64];
    char tenant_id[64];
    char job_id[64];
    char profile[32];
    int64_t max_bytes;
    int timeout_seconds;
} ForensicCollectionParams;

/* ---------------------------------------------------------------------------
 * Payload Parsing
 * ------------------------------------------------------------------------- */

static inline bool Forensics_ParsePayload(const char* json, ForensicCollectionParams* out) {
    if (!json || !out) return false;
    memset(out, 0, sizeof(*out));
    out->max_bytes = FORENSICS_DEFAULT_MAX_BUNDLE_BYTES;
    out->timeout_seconds = 60;
    strncpy(out->profile, "diagnostic", sizeof(out->profile) - 1);

    const char* p = strstr(json, "\"bundle_id\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '"');
            if (p) {
                p++;
                const char* end = strchr(p, '"');
                if (end && (size_t)(end - p) < sizeof(out->bundle_id)) {
                    strncpy(out->bundle_id, p, end - p);
                    out->bundle_id[end - p] = '\0';
                }
            }
        }
    }

    p = strstr(json, "\"profile\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '"');
            if (p) {
                p++;
                const char* end = strchr(p, '"');
                if (end && (size_t)(end - p) < sizeof(out->profile)) {
                    strncpy(out->profile, p, end - p);
                    out->profile[end - p] = '\0';
                }
            }
        }
    }

    p = strstr(json, "\"max_bytes\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            long long mb = atoll(p + 1);
            if (mb > 0) out->max_bytes = mb;
        }
    }

    p = strstr(json, "\"timeout_seconds\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            int to = atoi(p + 1);
            if (to > 0) out->timeout_seconds = to;
        }
    }

    return true;
}

/* ---------------------------------------------------------------------------
 * Key Management
 * ------------------------------------------------------------------------- */

static inline bool Forensics_GetOrCreateEndpointKey(
    const char* key_path,
    uint8_t public_key[32],
    uint8_t secret_key[64],
    char* pub_hex_out,
    size_t pub_hex_cap
) {
    if (!key_path) key_path = FORENSICS_DEFAULT_KEY_PATH;

    // Try reading existing key file (64 binary bytes or 128 hex bytes)
    int fd = open(key_path, O_RDONLY);
    if (fd >= 0) {
        uint8_t file_buf[128];
        ssize_t n = read(fd, file_buf, sizeof(file_buf));
        close(fd);
        if (n == 64) {
            memcpy(secret_key, file_buf, 64);
            memcpy(public_key, file_buf + 32, 32);
            if (pub_hex_out && pub_hex_cap >= 65) {
                for (int i = 0; i < 32; i++) snprintf(pub_hex_out + (i * 2), 3, "%02x", public_key[i]);
            }
            return true;
        } else if (n >= 128) {
            // Hex encoded
            for (int i = 0; i < 64; i++) {
                unsigned int byte_val = 0;
                if (sscanf((char*)file_buf + (i * 2), "%02x", &byte_val) == 1) {
                    secret_key[i] = (uint8_t)byte_val;
                }
            }
            memcpy(public_key, secret_key + 32, 32);
            if (pub_hex_out && pub_hex_cap >= 65) {
                for (int i = 0; i < 32; i++) snprintf(pub_hex_out + (i * 2), 3, "%02x", public_key[i]);
            }
            return true;
        }
    }

    // Generate fresh keypair from /dev/urandom seed
    uint8_t seed[32];
    int rnd = open("/dev/urandom", O_RDONLY);
    if (rnd < 0) return false;
    ssize_t rn = read(rnd, seed, sizeof(seed));
    close(rnd);
    if (rn != (ssize_t)sizeof(seed)) return false;

    if (!Ed25519_CreateKeypairFromSeed(public_key, secret_key, seed)) {
        return false;
    }

    // Save private key with mode 0600
    fd = open(key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        ssize_t w = write(fd, secret_key, 64);
        (void)w;
        close(fd);
    }

    // Save public key hex with mode 0644
    char pub_hex[65];
    for (int i = 0; i < 32; i++) snprintf(pub_hex + (i * 2), 3, "%02x", public_key[i]);
    pub_hex[64] = '\0';

    int pub_fd = open(FORENSICS_DEFAULT_PUB_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pub_fd >= 0) {
        ssize_t w1 = write(pub_fd, pub_hex, 64);
        ssize_t w2 = write(pub_fd, "\n", 1);
        (void)w1;
        (void)w2;
        close(pub_fd);
    }

    if (pub_hex_out && pub_hex_cap >= 65) {
        strncpy(pub_hex_out, pub_hex, pub_hex_cap - 1);
        pub_hex_out[pub_hex_cap - 1] = '\0';
    }
    return true;
}

/* ---------------------------------------------------------------------------
 * Canonical Manifest Encoding (OMINULL-MANIFEST-V2)
 * ------------------------------------------------------------------------- */

static inline bool Forensics_WriteLPStr(ResponseCanonicalBuffer* b, const char* str) {
    if (!str) str = "";
    uint32_t len = (uint32_t)strlen(str);
    if (!CanonicalBuf_WriteUint32(b, len)) return false;
    if (len > 0) {
        if (b->len + len > b->cap) {
            b->overflow = true;
            return false;
        }
        memcpy(b->buf + b->len, str, len);
        b->len += len;
    }
    return true;
}

static inline bool Forensics_WriteRaw(ResponseCanonicalBuffer* b, const void* data, size_t len) {
    if (b->len + len > b->cap) {
        b->overflow = true;
        return false;
    }
    memcpy(b->buf + b->len, data, len);
    b->len += len;
    return true;
}

static inline size_t Forensics_EncodeManifestCanonical(
    uint8_t* out_buf,
    size_t out_cap,
    const char* bundle_id,
    const char* endpoint_id,
    const char* tenant_id,
    const char* job_id,
    const char* profile,
    int64_t collected_at_unix,
    const ForensicCollectedItem* items,
    int item_count
) {
    ResponseCanonicalBuffer b;
    CanonicalBuf_Init(&b, out_buf, out_cap);

    // Literal domain label "OMINULL-MANIFEST-V2\0" (20 bytes)
    if (!Forensics_WriteRaw(&b, "OMINULL-MANIFEST-V2\0", 20)) return 0;
    if (!Forensics_WriteLPStr(&b, bundle_id)) return 0;
    if (!Forensics_WriteLPStr(&b, endpoint_id)) return 0;
    if (!Forensics_WriteLPStr(&b, tenant_id)) return 0;
    if (!Forensics_WriteLPStr(&b, job_id)) return 0;
    if (!Forensics_WriteLPStr(&b, profile)) return 0;
    if (!CanonicalBuf_WriteInt64(&b, collected_at_unix)) return 0;
    if (!CanonicalBuf_WriteUint32(&b, (uint32_t)item_count)) return 0;

    for (int i = 0; i < item_count; i++) {
        if (!Forensics_WriteLPStr(&b, items[i].name)) return 0;
        if (!CanonicalBuf_WriteInt64(&b, (int64_t)items[i].size_bytes)) return 0;
        if (!Forensics_WriteLPStr(&b, items[i].sha256)) return 0;
        if (!Forensics_WriteLPStr(&b, CollectorStatusToString(items[i].status))) return 0;
    }

    if (b.overflow) return 0;
    return b.len;
}

/* ---------------------------------------------------------------------------
 * Safe String & Command Execution Helpers
 * ------------------------------------------------------------------------- */

static inline void Forensics_EscapeJson(const char* src, char* dst, size_t dst_cap) {
    if (!dst || dst_cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t out = 0;
    for (size_t in = 0; src[in] != '\0' && out + 2 < dst_cap; in++) {
        unsigned char c = (unsigned char)src[in];
        if (c == '"') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = '"';
        } else if (c == '\\') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = '\\';
        } else if (c == '\b') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = 'b';
        } else if (c == '\f') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = 'f';
        } else if (c == '\n') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = 'n';
        } else if (c == '\r') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = 'r';
        } else if (c == '\t') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = 't';
        } else if (c < 0x20) {
            dst[out++] = ' ';
        } else {
            dst[out++] = (char)c;
        }
    }
    dst[out] = '\0';
}

static inline int Forensics_RunCommandCapture(const char* const argv[], char* buf, size_t cap, size_t* out_len, int timeout_sec) {
    if (!argv || !argv[0] || !buf || cap == 0) return -1;
    buf[0] = '\0';
    if (out_len) *out_len = 0;

    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        setpgid(0, 0);
        for (int fd = 3; fd < 256; fd++) {
            if (fd != pipefd[1]) close(fd);
        }
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(pipefd[1]);

        clearenv();
        setenv("PATH", "/usr/sbin:/sbin:/usr/bin:/bin", 1);
        setenv("LC_ALL", "C", 1);

        execv(argv[0], (char* const*)argv);
        _exit(127);
    }

    close(pipefd[1]);

    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    size_t total_read = 0;
    time_t start_t = time(NULL);
    while (total_read + 1 < cap) {
        ssize_t n = read(pipefd[0], buf + total_read, cap - total_read - 1);
        if (n > 0) {
            total_read += (size_t)n;
        } else if (n == 0) {
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (timeout_sec > 0 && (time(NULL) - start_t) >= timeout_sec) {
                    kill(-pid, SIGKILL);
                    break;
                }
                usleep(10000);
            } else {
                break;
            }
        }
    }
    buf[total_read] = '\0';
    if (out_len) *out_len = total_read;
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ---------------------------------------------------------------------------
 * Artifact Collectors (Linux Diagnostic Profile)
 * ------------------------------------------------------------------------- */

// 1. OS Version & System Identification
static inline bool Forensics_CollectOSVersion(char** out_data, size_t* out_size, ForensicCollectorStatus* status) {
    *status = COLLECTOR_STATUS_FAILED;
    struct utsname un;
    if (uname(&un) != 0) {
        memset(&un, 0, sizeof(un));
    }

    char os_name[128] = "Linux";
    char os_version[128] = "Unknown";
    char os_id[64] = "linux";
    char pretty_name[256] = "Linux";

    FILE* fp = fopen("/etc/os-release", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            char* eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            char* val = eq + 1;
            // Trim quotes and newlines
            while (*val == '"' || *val == '\'') val++;
            size_t vlen = strlen(val);
            while (vlen > 0 && (val[vlen - 1] == '\n' || val[vlen - 1] == '\r' || val[vlen - 1] == '"' || val[vlen - 1] == '\'')) {
                val[--vlen] = '\0';
            }
            if (strcmp(line, "NAME") == 0) strncpy(os_name, val, sizeof(os_name) - 1);
            else if (strcmp(line, "VERSION_ID") == 0) strncpy(os_version, val, sizeof(os_version) - 1);
            else if (strcmp(line, "ID") == 0) strncpy(os_id, val, sizeof(os_id) - 1);
            else if (strcmp(line, "PRETTY_NAME") == 0) strncpy(pretty_name, val, sizeof(pretty_name) - 1);
        }
        fclose(fp);
    }

    double uptime_sec = 0.0;
    FILE* uf = fopen("/proc/uptime", "r");
    if (uf) {
        if (fscanf(uf, "%lf", &uptime_sec) != 1) uptime_sec = 0.0;
        fclose(uf);
    }

    long long btime = 0;
    FILE* sf = fopen("/proc/stat", "r");
    if (sf) {
        char sline[256];
        while (fgets(sline, sizeof(sline), sf)) {
            if (strncmp(sline, "btime ", 6) == 0) {
                btime = atoll(sline + 6);
                break;
            }
        }
        fclose(sf);
    }

    char* buf = (char*)malloc(4096);
    if (!buf) return false;
    int len = snprintf(buf, 4096,
        "{\n"
        "  \"os_release\": {\n"
        "    \"name\": \"%s\",\n"
        "    \"version\": \"%s\",\n"
        "    \"id\": \"%s\",\n"
        "    \"pretty_name\": \"%s\"\n"
        "  },\n"
        "  \"kernel\": {\n"
        "    \"sysname\": \"%s\",\n"
        "    \"nodename\": \"%s\",\n"
        "    \"release\": \"%s\",\n"
        "    \"version\": \"%s\",\n"
        "    \"machine\": \"%s\"\n"
        "  },\n"
        "  \"uptime_seconds\": %.2f,\n"
        "  \"boot_timestamp\": %lld\n"
        "}\n",
        os_name, os_version, os_id, pretty_name,
        un.sysname, un.nodename, un.release, un.version, un.machine,
        uptime_sec, btime
    );

    if (len < 0) { free(buf); return false; }
    *out_data = buf;
    *out_size = len;
    *status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 2. Network Interfaces
static inline bool Forensics_CollectNetworkInterfaces(char** out_data, size_t* out_size, ForensicCollectorStatus* status) {
    *status = COLLECTOR_STATUS_FAILED;
    struct ifaddrs* ifaddr = NULL;
    if (getifaddrs(&ifaddr) == -1) {
        return false;
    }

    size_t cap = 16384;
    char* buf = (char*)malloc(cap);
    if (!buf) { freeifaddrs(ifaddr); return false; }
    size_t len = 0;
    len += snprintf(buf + len, cap - len, "{\n  \"interfaces\": [\n");

    struct ifaddrs* ifa;
    bool first = true;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        int family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;

        char host[NI_MAXHOST];
        int s = getnameinfo(ifa->ifa_addr,
            (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (s != 0) continue;

        // Fetch MAC address from /sys/class/net/<name>/address
        char mac[32] = "unknown";
        char mac_path[256];
        snprintf(mac_path, sizeof(mac_path), "/sys/class/net/%s/address", ifa->ifa_name);
        FILE* mf = fopen(mac_path, "r");
        if (mf) {
            if (fgets(mac, sizeof(mac), mf)) {
                size_t ml = strlen(mac);
                if (ml > 0 && mac[ml - 1] == '\n') mac[ml - 1] = '\0';
            }
            fclose(mf);
        }

        if (len + 512 >= cap) {
            cap *= 2;
            char* new_buf = (char*)realloc(buf, cap);
            if (!new_buf) break;
            buf = new_buf;
        }

        len += snprintf(buf + len, cap - len,
            "%s    {\n"
            "      \"name\": \"%s\",\n"
            "      \"family\": \"%s\",\n"
            "      \"address\": \"%s\",\n"
            "      \"mac\": \"%s\",\n"
            "      \"flags\": %u\n"
            "    }",
            first ? "" : ",\n",
            ifa->ifa_name,
            (family == AF_INET) ? "IPv4" : "IPv6",
            host,
            mac,
            ifa->ifa_flags
        );
        first = false;
    }
    freeifaddrs(ifaddr);

    len += snprintf(buf + len, cap - len, "\n  ]\n}\n");
    *out_data = buf;
    *out_size = len;
    *status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 3. Routing Tables (/proc/net/route & /proc/net/ipv6_route)
static inline bool Forensics_CollectRoutes(char** out_data, size_t* out_size, ForensicCollectorStatus* status) {
    *status = COLLECTOR_STATUS_FAILED;
    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) return false;
    size_t len = 0;

    len += snprintf(buf + len, cap - len, "# IPv4 Routes (/proc/net/route)\n");
    FILE* f4 = fopen("/proc/net/route", "r");
    if (f4) {
        char line[512];
        while (fgets(line, sizeof(line), f4)) {
            size_t ll = strlen(line);
            if (len + ll + 1 >= cap) break;
            memcpy(buf + len, line, ll);
            len += ll;
        }
        fclose(f4);
    }

    len += snprintf(buf + len, cap - len, "\n# IPv6 Routes (/proc/net/ipv6_route)\n");
    FILE* f6 = fopen("/proc/net/ipv6_route", "r");
    if (f6) {
        char line[512];
        while (fgets(line, sizeof(line), f6)) {
            size_t ll = strlen(line);
            if (len + ll + 1 >= cap) break;
            memcpy(buf + len, line, ll);
            len += ll;
        }
        fclose(f6);
    }
    buf[len] = '\0';

    *out_data = buf;
    *out_size = len;
    *status = (len > 0) ? COLLECTOR_STATUS_COLLECTED : COLLECTOR_STATUS_EMPTY;
    return true;
}

// 4. DNS Configuration (/etc/resolv.conf)
static inline bool Forensics_CollectDNSConfig(char** out_data, size_t* out_size, ForensicCollectorStatus* status) {
    *status = COLLECTOR_STATUS_FAILED;
    FILE* f = fopen("/etc/resolv.conf", "r");
    if (!f) {
        if (errno == EACCES) *status = COLLECTOR_STATUS_PERMISSION_DENIED;
        return false;
    }
    size_t cap = 8192;
    char* buf = (char*)malloc(cap);
    if (!buf) { fclose(f); return false; }
    size_t len = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[len] = '\0';

    *out_data = buf;
    *out_size = len;
    *status = (len > 0) ? COLLECTOR_STATUS_COLLECTED : COLLECTOR_STATUS_EMPTY;
    return true;
}

// 5. Resource Summary (/proc/meminfo, /proc/loadavg, statvfs)
static inline bool Forensics_CollectResourceSummary(char** out_data, size_t* out_size, ForensicCollectorStatus* status) {
    *status = COLLECTOR_STATUS_FAILED;

    long long mem_total = 0, mem_free = 0, mem_avail = 0, swap_total = 0, swap_free = 0;
    FILE* mf = fopen("/proc/meminfo", "r");
    if (mf) {
        char line[256];
        while (fgets(line, sizeof(line), mf)) {
            if (strncmp(line, "MemTotal:", 9) == 0) mem_total = atoll(line + 9) * 1024;
            else if (strncmp(line, "MemFree:", 8) == 0) mem_free = atoll(line + 8) * 1024;
            else if (strncmp(line, "MemAvailable:", 13) == 0) mem_avail = atoll(line + 13) * 1024;
            else if (strncmp(line, "SwapTotal:", 10) == 0) swap_total = atoll(line + 10) * 1024;
            else if (strncmp(line, "SwapFree:", 9) == 0) swap_free = atoll(line + 9) * 1024;
        }
        fclose(mf);
    }

    double l1 = 0, l5 = 0, l15 = 0;
    FILE* lf = fopen("/proc/loadavg", "r");
    if (lf) {
        if (fscanf(lf, "%lf %lf %lf", &l1, &l5, &l15) != 3) { l1 = l5 = l15 = 0; }
        fclose(lf);
    }

    struct statvfs root_vfs;
    memset(&root_vfs, 0, sizeof(root_vfs));
    statvfs("/", &root_vfs);
    uint64_t root_total = (uint64_t)root_vfs.f_blocks * root_vfs.f_frsize;
    uint64_t root_free = (uint64_t)root_vfs.f_bfree * root_vfs.f_frsize;
    uint64_t root_avail = (uint64_t)root_vfs.f_bavail * root_vfs.f_frsize;

    char* buf = (char*)malloc(4096);
    if (!buf) return false;
    int len = snprintf(buf, 4096,
        "{\n"
        "  \"memory_bytes\": {\n"
        "    \"total\": %lld,\n"
        "    \"free\": %lld,\n"
        "    \"available\": %lld,\n"
        "    \"swap_total\": %lld,\n"
        "    \"swap_free\": %lld\n"
        "  },\n"
        "  \"load_average\": {\n"
        "    \"load1\": %.2f,\n"
        "    \"load5\": %.2f,\n"
        "    \"load15\": %.2f\n"
        "  },\n"
        "  \"storage\": {\n"
        "    \"root\": {\n"
        "      \"total_bytes\": %llu,\n"
        "      \"free_bytes\": %llu,\n"
        "      \"avail_bytes\": %llu\n"
        "    }\n"
        "  }\n"
        "}\n",
        mem_total, mem_free, mem_avail, swap_total, swap_free,
        l1, l5, l15,
        (unsigned long long)root_total, (unsigned long long)root_free, (unsigned long long)root_avail
    );

    if (len < 0) { free(buf); return false; }
    *out_data = buf;
    *out_size = len;
    *status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 6. Selected Service State
static inline bool Forensics_CollectServiceState(char** out_data, size_t* out_size, ForensicCollectorStatus* status) {
    *status = COLLECTOR_STATUS_FAILED;
    const char* services[] = {
        "ominull-agent",
        "ominull-hub",
        "ominull-response-authority",
        "ssh",
        "sshd",
        "systemd-resolved",
        "cron",
        "ufw",
        "firewalld",
        NULL
    };

    size_t cap = 4096;
    char* buf = (char*)malloc(cap);
    if (!buf) return false;
    size_t len = 0;
    len += snprintf(buf + len, cap - len, "{\n  \"services\": {\n");

    for (int i = 0; services[i] != NULL; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "systemctl is-active %s 2>/dev/null", services[i]);
        FILE* p = popen(cmd, "r");
        char state[32] = "unknown";
        if (p) {
            if (fgets(state, sizeof(state), p)) {
                size_t sl = strlen(state);
                if (sl > 0 && state[sl - 1] == '\n') state[sl - 1] = '\0';
            }
            pclose(p);
        }
        len += snprintf(buf + len, cap - len, "%s    \"%s\": \"%s\"", (i > 0) ? ",\n" : "", services[i], state);
    }
    len += snprintf(buf + len, cap - len, "\n  }\n}\n");

    *out_data = buf;
    *out_size = len;
    *status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 7. System Logs (Bounded at max_bytes, e.g. 256 KiB)
static inline bool Forensics_CollectSystemLogs(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = 256 * 1024; // 256 KiB cap
    }

    char* buf = (char*)malloc(max_bytes + 1024);
    if (!buf) return false;
    size_t len = 0;

    // Try journalctl first
    FILE* p = popen("journalctl -n 200 --no-pager 2>/dev/null", "r");
    if (p) {
        len = fread(buf, 1, max_bytes, p);
        pclose(p);
    }

    // If journalctl produced nothing, fallback to /var/log/syslog or /var/log/messages
    if (len == 0) {
        FILE* f = fopen("/var/log/syslog", "r");
        if (!f) f = fopen("/var/log/messages", "r");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            long start_offset = (sz > (long)max_bytes) ? (sz - (long)max_bytes) : 0;
            fseek(f, start_offset, SEEK_SET);
            len = fread(buf, 1, max_bytes, f);
            fclose(f);
        }
    }

    if (len == 0) {
        free(buf);
        *status = COLLECTOR_STATUS_EMPTY;
        return true;
    }

    if (len >= max_bytes) {
        *status = COLLECTOR_STATUS_TRUNCATED;
    } else {
        *status = COLLECTOR_STATUS_COLLECTED;
    }

    buf[len] = '\0';
    *out_data = buf;
    *out_size = len;
    return true;
}

// 8. Agent Diagnostics
static inline bool Forensics_CollectAgentDiagnostics(
    const char* endpoint_id,
    const char* hub_url,
    char** out_data,
    size_t* out_size,
    ForensicCollectorStatus* status
) {
    *status = COLLECTOR_STATUS_FAILED;
    pid_t pid = getpid();
    pid_t ppid = getppid();

    char exe_path[512] = "unknown";
    ssize_t elen = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (elen > 0) exe_path[elen] = '\0';

    long long vmrss_kb = 0;
    FILE* sm = fopen("/proc/self/statm", "r");
    if (sm) {
        long long size_pages = 0, resident_pages = 0;
        if (fscanf(sm, "%lld %lld", &size_pages, &resident_pages) >= 2) {
            vmrss_kb = resident_pages * (sysconf(_SC_PAGESIZE) / 1024);
        }
        fclose(sm);
    }

    char* buf = (char*)malloc(2048);
    if (!buf) return false;

    int len = snprintf(buf, 2048,
        "{\n"
        "  \"agent_pid\": %d,\n"
        "  \"parent_pid\": %d,\n"
        "  \"executable_path\": \"%s\",\n"
        "  \"endpoint_id\": \"%s\",\n"
        "  \"hub_url\": \"%s\",\n"
        "  \"vm_rss_kb\": %lld\n"
        "}\n",
        (int)pid, (int)ppid, exe_path,
        endpoint_id ? endpoint_id : "",
        hub_url ? hub_url : "",
        vmrss_kb
    );

    if (len < 0) { free(buf); return false; }
    *out_data = buf;
    *out_size = len;
    *status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

/* ---------------------------------------------------------------------------
 * Artifact Collectors (Linux Live Volatile Profile)
 * ------------------------------------------------------------------------- */

// 1. Process Snapshot
static inline bool Forensics_CollectProcessSnapshot(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    DIR* d = opendir("/proc");
    if (!d) return false;

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) { closedir(d); return false; }

    int off = snprintf(buf, cap, "{\n  \"processes\": [\n");
    const char* sep = "";
    int total_procs = 0;
    bool truncated = false;

    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int pid = atoi(de->d_name);
        if (pid <= 0) continue;

        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        FILE* sf = fopen(path, "r");
        if (!sf) continue;

        char stat_line[1024];
        if (!fgets(stat_line, sizeof(stat_line), sf)) {
            fclose(sf);
            continue;
        }
        fclose(sf);

        // Parse comm between '(' and ')'
        char* lparen = strchr(stat_line, '(');
        char* rparen = strrchr(stat_line, ')');
        if (!lparen || !rparen || rparen <= lparen) continue;

        char comm[64] = {0};
        size_t c_len = (size_t)(rparen - lparen - 1);
        if (c_len >= sizeof(comm)) c_len = sizeof(comm) - 1;
        memcpy(comm, lparen + 1, c_len);
        comm[c_len] = '\0';

        char state = '?';
        int ppid = 0;
        long num_threads = 0;
        unsigned long long starttime = 0;
        unsigned long vsize = 0;
        long rss = 0;

        char* after = rparen + 1;
        (void)sscanf(after, " %c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %ld %*d %llu %lu %ld",
            &state, &ppid, &num_threads, &starttime, &vsize, &rss);

        // Read cmdline
        char cmdline[512] = {0};
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        int cf = open(path, O_RDONLY);
        if (cf >= 0) {
            ssize_t cr = read(cf, cmdline, sizeof(cmdline) - 1);
            close(cf);
            if (cr > 0) {
                for (ssize_t k = 0; k < cr - 1; k++) {
                    if (cmdline[k] == '\0') cmdline[k] = ' ';
                }
                cmdline[cr] = '\0';
            }
        }

        // Read UID from /proc/pid/status
        int uid = -1;
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        FILE* stf = fopen(path, "r");
        if (stf) {
            char st_line[256];
            while (fgets(st_line, sizeof(st_line), stf)) {
                if (strncmp(st_line, "Uid:", 4) == 0) {
                    (void)sscanf(st_line + 4, " %d", &uid);
                    break;
                }
            }
            fclose(stf);
        }

        // Read exe link
        char exe_path[256] = {0};
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        ssize_t er = readlink(path, exe_path, sizeof(exe_path) - 1);
        if (er > 0) exe_path[er] = '\0';

        char esc_comm[128], esc_cmdline[1024], esc_exe[512];
        Forensics_EscapeJson(comm, esc_comm, sizeof(esc_comm));
        Forensics_EscapeJson(cmdline, esc_cmdline, sizeof(esc_cmdline));
        Forensics_EscapeJson(exe_path, esc_exe, sizeof(esc_exe));

        char entry[2048];
        int elen = snprintf(entry, sizeof(entry),
            "%s    {\n"
            "      \"pid\": %d,\n"
            "      \"ppid\": %d,\n"
            "      \"name\": \"%s\",\n"
            "      \"cmdline\": \"%s\",\n"
            "      \"exe\": \"%s\",\n"
            "      \"state\": \"%c\",\n"
            "      \"uid\": %d,\n"
            "      \"threads\": %ld,\n"
            "      \"vsize_bytes\": %lu,\n"
            "      \"rss_pages\": %ld,\n"
            "      \"starttime\": %llu\n"
            "    }",
            sep, pid, ppid, esc_comm, esc_cmdline, esc_exe, state, uid, num_threads, vsize, rss, starttime
        );

        if ((size_t)(off + elen + 256) >= cap) {
            size_t new_cap = cap * 2;
            if (new_cap > max_bytes) new_cap = max_bytes;
            if ((size_t)(off + elen + 256) >= new_cap) {
                truncated = true;
                break;
            }
            char* grown = (char*)realloc(buf, new_cap);
            if (!grown) {
                truncated = true;
                break;
            }
            buf = grown;
            cap = new_cap;
        }

        memcpy(buf + off, entry, elen);
        off += elen;
        buf[off] = '\0';
        sep = ",\n";
        total_procs++;
    }
    closedir(d);

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_processes\": %d,\n"
        "  \"truncated\": %s\n"
        "}\n",
        total_procs, truncated ? "true" : "false"
    );

    *out_data = buf;
    *out_size = (size_t)off;
    *status = truncated ? COLLECTOR_STATUS_TRUNCATED : COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 2. Socket to Process Mapping
static inline const char* Forensics_LinuxTcpStateToString(unsigned int st) {
    switch (st) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default: return "UNKNOWN";
    }
}

typedef struct {
    unsigned long inode;
    int pid;
    char comm[32];
} LinuxSocketInodeMap;

static inline bool Forensics_CollectSocketToProcess(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    size_t map_cap = 2048;
    LinuxSocketInodeMap* map = (LinuxSocketInodeMap*)calloc(map_cap, sizeof(LinuxSocketInodeMap));
    size_t map_count = 0;

    DIR* d = opendir("/proc");
    if (d && map) {
        struct dirent* de;
        while ((de = readdir(d)) != NULL && map_count < map_cap) {
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            int pid = atoi(de->d_name);
            if (pid <= 0) continue;

            char comm[32] = {0};
            char cpath[128];
            snprintf(cpath, sizeof(cpath), "/proc/%d/comm", pid);
            FILE* cf = fopen(cpath, "r");
            if (cf) {
                if (fgets(comm, sizeof(comm), cf)) {
                    size_t cl = strlen(comm);
                    while (cl > 0 && (comm[cl - 1] == '\n' || comm[cl - 1] == '\r')) comm[--cl] = '\0';
                }
                fclose(cf);
            }

            char fdpath[128];
            snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", pid);
            DIR* fdd = opendir(fdpath);
            if (!fdd) continue;

            struct dirent* fde;
            while ((fde = readdir(fdd)) != NULL && map_count < map_cap) {
                if (fde->d_name[0] == '.') continue;
                char linkpath[512];
                snprintf(linkpath, sizeof(linkpath), "%s/%s", fdpath, fde->d_name);
                char target[128];
                ssize_t r = readlink(linkpath, target, sizeof(target) - 1);
                if (r > 0) {
                    target[r] = '\0';
                    if (strncmp(target, "socket:[", 8) == 0) {
                        unsigned long ino = strtoul(target + 8, NULL, 10);
                        if (ino > 0) {
                            map[map_count].inode = ino;
                            size_t c_copy = strlen(comm);
                            if (c_copy >= sizeof(map[map_count].comm)) c_copy = sizeof(map[map_count].comm) - 1;
                            memcpy(map[map_count].comm, comm, c_copy);
                            map[map_count].comm[c_copy] = '\0';
                            map_count++;
                        }
                    }
                }
            }
            closedir(fdd);
        }
        closedir(d);
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) {
        if (map) free(map);
        return false;
    }

    int off = snprintf(buf, cap, "{\n  \"sockets\": [\n");
    const char* sep = "";
    int total_sockets = 0;
    bool truncated = false;

    const char* net_files[] = { "/proc/net/tcp", "/proc/net/udp", "/proc/net/tcp6", "/proc/net/udp6", NULL };
    for (int nf = 0; net_files[nf] && !truncated; nf++) {
        FILE* fp = fopen(net_files[nf], "r");
        if (!fp) continue;

        const char* proto = strstr(net_files[nf], "tcp6") ? "tcp6" :
                           (strstr(net_files[nf], "udp6") ? "udp6" :
                           (strstr(net_files[nf], "tcp") ? "tcp" : "udp"));
        bool is_v6 = (strstr(net_files[nf], "6") != NULL);

        char line[512];
        if (!fgets(line, sizeof(line), fp)) { fclose(fp); continue; } // skip header

        while (fgets(line, sizeof(line), fp)) {
            unsigned int l_ip = 0, l_port = 0, r_ip = 0, r_port = 0, st = 0;
            unsigned long inode = 0;
            char lip6[33] = {0}, rip6[33] = {0};

            if (!is_v6) {
                if (sscanf(line, "%*d: %x:%x %x:%x %x %*x:%*x %*x:%*x %*x %*d %*d %lu",
                    &l_ip, &l_port, &r_ip, &r_port, &st, &inode) != 6) continue;
            } else {
                if (sscanf(line, "%*d: %32s:%x %32s:%x %x %*x:%*x %*x:%*x %*x %*d %*d %lu",
                    lip6, &l_port, rip6, &r_port, &st, &inode) != 6) continue;
            }

            char local_addr[64], remote_addr[64];
            if (!is_v6) {
                struct in_addr lia, ria;
                lia.s_addr = l_ip;
                ria.s_addr = r_ip;
                inet_ntop(AF_INET, &lia, local_addr, sizeof(local_addr));
                inet_ntop(AF_INET, &ria, remote_addr, sizeof(remote_addr));
            } else {
                /* /proc emits four native-endian 32-bit words. Copy each
                 * parsed word as bytes, as for its IPv4 representation. */
                struct in6_addr local6, remote6;
                bool valid = strlen(lip6) == 32 && strlen(rip6) == 32;
                for (size_t word = 0; valid && word < 4; word++) {
                    unsigned int local_word, remote_word;
                    if (sscanf(lip6 + word * 8, "%8x", &local_word) != 1 ||
                        sscanf(rip6 + word * 8, "%8x", &remote_word) != 1) {
                        valid = false;
                        break;
                    }
                    memcpy(local6.s6_addr + word * 4, &local_word, 4);
                    memcpy(remote6.s6_addr + word * 4, &remote_word, 4);
                }
                if (!valid || !inet_ntop(AF_INET6, &local6, local_addr, sizeof(local_addr)) ||
                    !inet_ntop(AF_INET6, &remote6, remote_addr, sizeof(remote_addr))) continue;
            }

            int proc_pid = 0;
            const char* proc_comm = "";
            if (map) {
                for (size_t m = 0; m < map_count; m++) {
                    if (map[m].inode == inode) {
                        proc_pid = map[m].pid;
                        proc_comm = map[m].comm;
                        break;
                    }
                }
            }

            char esc_comm[64];
            Forensics_EscapeJson(proc_comm, esc_comm, sizeof(esc_comm));

            char entry[512];
            int elen = snprintf(entry, sizeof(entry),
                "%s    {\n"
                "      \"protocol\": \"%s\",\n"
                "      \"local_address\": \"%s\",\n"
                "      \"local_port\": %u,\n"
                "      \"remote_address\": \"%s\",\n"
                "      \"remote_port\": %u,\n"
                "      \"state\": \"%s\",\n"
                "      \"inode\": %lu,\n"
                "      \"pid\": %d,\n"
                "      \"process\": \"%s\"\n"
                "    }",
                sep, proto, local_addr, l_port, remote_addr, r_port,
                (strncmp(proto, "tcp", 3) == 0 ? Forensics_LinuxTcpStateToString(st) : (r_port == 0 ? "LISTEN" : "ESTABLISHED")),
                inode, proc_pid, esc_comm
            );

            if ((size_t)(off + elen + 256) >= cap) {
                size_t new_cap = cap * 2;
                if (new_cap > max_bytes) new_cap = max_bytes;
                if ((size_t)(off + elen + 256) >= new_cap) {
                    truncated = true;
                    break;
                }
                char* grown = (char*)realloc(buf, new_cap);
                if (!grown) {
                    truncated = true;
                    break;
                }
                buf = grown;
                cap = new_cap;
            }

            memcpy(buf + off, entry, elen);
            off += elen;
            buf[off] = '\0';
            sep = ",\n";
            total_sockets++;
        }
        fclose(fp);
    }

    if (map) free(map);

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_sockets\": %d,\n"
        "  \"truncated\": %s\n"
        "}\n",
        total_sockets, truncated ? "true" : "false"
    );

    *out_data = buf;
    *out_size = (size_t)off;
    *status = truncated ? COLLECTOR_STATUS_TRUNCATED : (total_sockets == 0 ? COLLECTOR_STATUS_EMPTY : COLLECTOR_STATUS_COLLECTED);
    return true;
}

// 3. Logged-in Sessions
static inline bool Forensics_CollectLoggedInSessions(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    size_t cap = 8192;
    char* buf = (char*)malloc(cap);
    if (!buf) return false;

    int off = snprintf(buf, cap, "{\n  \"sessions\": [\n");
    const char* sep = "";
    int total_sessions = 0;

    setutent();
    struct utmp* u;
    while ((u = getutent()) != NULL) {
        if (u->ut_type == USER_PROCESS) {
            char esc_user[128], esc_line[128], esc_host[256];
            Forensics_EscapeJson(u->ut_user, esc_user, sizeof(esc_user));
            Forensics_EscapeJson(u->ut_line, esc_line, sizeof(esc_line));
            Forensics_EscapeJson(u->ut_host, esc_host, sizeof(esc_host));

            char entry[512];
            int elen = snprintf(entry, sizeof(entry),
                "%s    {\n"
                "      \"user\": \"%s\",\n"
                "      \"line\": \"%s\",\n"
                "      \"host\": \"%s\",\n"
                "      \"login_time\": %ld,\n"
                "      \"pid\": %d\n"
                "    }",
                sep, esc_user, esc_line, esc_host, (long)u->ut_tv.tv_sec, (int)u->ut_pid
            );

            if ((size_t)(off + elen + 128) >= cap) {
                if (cap * 2 <= max_bytes) {
                    char* grown = (char*)realloc(buf, cap * 2);
                    if (grown) { buf = grown; cap *= 2; }
                }
            }

            if ((size_t)(off + elen + 128) < cap) {
                memcpy(buf + off, entry, elen);
                off += elen;
                buf[off] = '\0';
                sep = ",\n";
                total_sessions++;
            }
        }
    }
    endutent();

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_sessions\": %d\n"
        "}\n",
        total_sessions
    );

    *out_data = buf;
    *out_size = (size_t)off;
    *status = (total_sessions == 0) ? COLLECTOR_STATUS_EMPTY : COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 4. Network Neighbors (ARP Table)
static inline bool Forensics_CollectNetworkNeighbors(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    FILE* fp = fopen("/proc/net/arp", "r");
    if (!fp) {
        *status = COLLECTOR_STATUS_UNSUPPORTED;
        return false;
    }

    size_t cap = 16384;
    char* buf = (char*)malloc(cap);
    if (!buf) { fclose(fp); return false; }

    int off = snprintf(buf, cap, "{\n  \"neighbors\": [\n");
    const char* sep = "";
    int total_neigh = 0;

    char line[256];
    if (!fgets(line, sizeof(line), fp)) { // skip header
        fclose(fp);
        free(buf);
        *status = COLLECTOR_STATUS_EMPTY;
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        char ip[64], hw_type[16], flags[16], mac[32], mask[16], dev[32];
        if (sscanf(line, "%63s %15s %15s %31s %15s %31s", ip, hw_type, flags, mac, mask, dev) == 6) {
            const char* state_str = "stale";
            if (strcmp(flags, "0x2") == 0) state_str = "reachable";
            else if (strcmp(flags, "0x0") == 0) state_str = "incomplete";

            char esc_dev[64];
            Forensics_EscapeJson(dev, esc_dev, sizeof(esc_dev));

            char entry[512];
            int elen = snprintf(entry, sizeof(entry),
                "%s    {\n"
                "      \"ip\": \"%s\",\n"
                "      \"mac\": \"%s\",\n"
                "      \"interface\": \"%s\",\n"
                "      \"flags\": \"%s\",\n"
                "      \"state\": \"%s\"\n"
                "    }",
                sep, ip, mac, esc_dev, flags, state_str
            );

            if ((size_t)(off + elen + 128) >= cap) {
                if (cap * 2 <= max_bytes) {
                    char* grown = (char*)realloc(buf, cap * 2);
                    if (grown) { buf = grown; cap *= 2; }
                }
            }

            if ((size_t)(off + elen + 128) < cap) {
                memcpy(buf + off, entry, elen);
                off += elen;
                buf[off] = '\0';
                sep = ",\n";
                total_neigh++;
            }
        }
    }
    fclose(fp);

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_neighbors\": %d\n"
        "}\n",
        total_neigh
    );

    *out_data = buf;
    *out_size = (size_t)off;
    *status = (total_neigh == 0) ? COLLECTOR_STATUS_EMPTY : COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 5. Firewall State
static inline bool Forensics_CollectFirewallState(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    char tables[256] = {0};
    FILE* tf = fopen("/proc/net/ip_tables_names", "r");
    if (tf) {
        char tline[64];
        while (fgets(tline, sizeof(tline), tf)) {
            size_t tl = strlen(tline);
            while (tl > 0 && (tline[tl - 1] == '\n' || tline[tl - 1] == '\r')) tline[--tl] = '\0';
            if (tl > 0) {
                if (tables[0]) strncat(tables, ", ", sizeof(tables) - strlen(tables) - 1);
                strncat(tables, "\"", sizeof(tables) - strlen(tables) - 1);
                strncat(tables, tline, sizeof(tables) - strlen(tables) - 1);
                strncat(tables, "\"", sizeof(tables) - strlen(tables) - 1);
            }
        }
        fclose(tf);
    }

    const char* iptables_bin = (access("/sbin/iptables-save", X_OK) == 0) ? "/sbin/iptables-save" :
                               (access("/usr/sbin/iptables-save", X_OK) == 0 ? "/usr/sbin/iptables-save" : NULL);
    const char* ip6tables_bin = (access("/sbin/ip6tables-save", X_OK) == 0) ? "/sbin/ip6tables-save" :
                                (access("/usr/sbin/ip6tables-save", X_OK) == 0 ? "/usr/sbin/ip6tables-save" : NULL);

    size_t cap = 65536;
    char* buf = (char*)malloc(cap);
    if (!buf) return false;

    char v4_out[32768] = {0};
    size_t v4_len = 0;
    if (iptables_bin) {
        const char* const v4_cmd[] = { iptables_bin, "-c", NULL };
        Forensics_RunCommandCapture(v4_cmd, v4_out, sizeof(v4_out), &v4_len, 5);
    }

    char v6_out[32768] = {0};
    size_t v6_len = 0;
    if (ip6tables_bin) {
        const char* const v6_cmd[] = { ip6tables_bin, "-c", NULL };
        Forensics_RunCommandCapture(v6_cmd, v6_out, sizeof(v6_out), &v6_len, 5);
    }

    bool has_ominull_chains = (strstr(v4_out, "OMINULL") != NULL || strstr(v6_out, "OMINULL") != NULL);

    char* esc_v4 = (char*)malloc(v4_len * 2 + 16);
    char* esc_v6 = (char*)malloc(v6_len * 2 + 16);
    if (esc_v4) Forensics_EscapeJson(v4_out, esc_v4, v4_len * 2 + 16);
    if (esc_v6) Forensics_EscapeJson(v6_out, esc_v6, v6_len * 2 + 16);

    int len = snprintf(buf, cap,
        "{\n"
        "  \"firewall_framework\": \"%s\",\n"
        "  \"tables\": [%s],\n"
        "  \"has_ominull_chains\": %s,\n"
        "  \"ipv4_rules_bytes\": %zu,\n"
        "  \"ipv6_rules_bytes\": %zu,\n"
        "  \"ipv4_rules\": \"%s\",\n"
        "  \"ipv6_rules\": \"%s\"\n"
        "}\n",
        (iptables_bin ? "iptables" : "none"),
        tables[0] ? tables : "\"filter\"",
        has_ominull_chains ? "true" : "false",
        v4_len,
        v6_len,
        esc_v4 ? esc_v4 : "",
        esc_v6 ? esc_v6 : ""
    );

    if (esc_v4) free(esc_v4);
    if (esc_v6) free(esc_v6);

    if (len < 0) { free(buf); return false; }
    *out_data = buf;
    *out_size = (size_t)len;

    if (!iptables_bin && !ip6tables_bin && !tables[0]) {
        *status = COLLECTOR_STATUS_UNSUPPORTED;
    } else {
        *status = COLLECTOR_STATUS_COLLECTED;
    }
    return true;
}

// 6. Loaded Kernel Modules
static inline bool Forensics_CollectLoadedModules(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    FILE* fp = fopen("/proc/modules", "r");
    if (!fp) {
        if (errno == ENOENT) *status = COLLECTOR_STATUS_UNSUPPORTED;
        else if (errno == EACCES) *status = COLLECTOR_STATUS_PERMISSION_DENIED;
        else *status = COLLECTOR_STATUS_FAILED;
        return false;
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) { fclose(fp); return false; }

    int off = snprintf(buf, cap, "{\n  \"modules\": [\n");
    const char* sep = "";
    int total_mods = 0;
    bool truncated = false;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char mod_name[64], state[32];
        unsigned long size_bytes = 0;
        unsigned int ref_count = 0;
        char deps[128] = {0};

        if (sscanf(line, "%63s %lu %u %127s %31s", mod_name, &size_bytes, &ref_count, deps, state) >= 4) {
            char esc_name[128], esc_deps[256], esc_state[64];
            Forensics_EscapeJson(mod_name, esc_name, sizeof(esc_name));
            Forensics_EscapeJson(deps, esc_deps, sizeof(esc_deps));
            Forensics_EscapeJson(state, esc_state, sizeof(esc_state));

            char entry[512];
            int elen = snprintf(entry, sizeof(entry),
                "%s    {\n"
                "      \"name\": \"%s\",\n"
                "      \"size_bytes\": %lu,\n"
                "      \"ref_count\": %u,\n"
                "      \"dependencies\": \"%s\",\n"
                "      \"state\": \"%s\"\n"
                "    }",
                sep, esc_name, size_bytes, ref_count, esc_deps, esc_state
            );

            if ((size_t)(off + elen + 256) >= cap) {
                size_t new_cap = cap * 2;
                if (new_cap > max_bytes) new_cap = max_bytes;
                if ((size_t)(off + elen + 256) >= new_cap) {
                    truncated = true;
                    break;
                }
                char* grown = (char*)realloc(buf, new_cap);
                if (!grown) {
                    truncated = true;
                    break;
                }
                buf = grown;
                cap = new_cap;
            }

            memcpy(buf + off, entry, elen);
            off += elen;
            buf[off] = '\0';
            sep = ",\n";
            total_mods++;
        }
    }
    fclose(fp);

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_modules\": %d,\n"
        "  \"truncated\": %s\n"
        "}\n",
        total_mods, truncated ? "true" : "false"
    );

    *out_data = buf;
    *out_size = (size_t)off;
    *status = truncated ? COLLECTOR_STATUS_TRUNCATED : (total_mods == 0 ? COLLECTOR_STATUS_EMPTY : COLLECTOR_STATUS_COLLECTED);
    return true;
}

/* ---------------------------------------------------------------------------
 * Artifact Collectors (Linux IR Standard Profile)
 * ------------------------------------------------------------------------- */

// 1. Persistence Artifacts
static inline bool Forensics_CollectPersistence(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) return false;

    // Check /etc/ld.so.preload
    char ld_preload[1024] = {0};
    int ldf = open("/etc/ld.so.preload", O_RDONLY);
    if (ldf >= 0) {
        ssize_t r = read(ldf, ld_preload, sizeof(ld_preload) - 1);
        close(ldf);
        if (r > 0) ld_preload[r] = '\0';
    }
    char esc_ld[2048] = {0};
    Forensics_EscapeJson(ld_preload, esc_ld, sizeof(esc_ld));

    // Check /etc/rc.local
    char rc_local[2048] = {0};
    int rcf = open("/etc/rc.local", O_RDONLY);
    if (rcf >= 0) {
        ssize_t r = read(rcf, rc_local, sizeof(rc_local) - 1);
        close(rcf);
        if (r > 0) rc_local[r] = '\0';
    }
    char esc_rc[4096] = {0};
    Forensics_EscapeJson(rc_local, esc_rc, sizeof(esc_rc));

    int off = snprintf(buf, cap,
        "{\n"
        "  \"ld_so_preload\": \"%s\",\n"
        "  \"rc_local\": \"%s\",\n"
        "  \"profile_scripts\": [\n",
        esc_ld, esc_rc
    );

    // Enumerate /etc/profile.d
    DIR* pd = opendir("/etc/profile.d");
    if (pd) {
        struct dirent* de;
        const char* sep = "";
        int pcount = 0;
        while ((de = readdir(pd)) != NULL && pcount < 50) {
            if (de->d_name[0] == '.') continue;
            char esc_pname[128];
            Forensics_EscapeJson(de->d_name, esc_pname, sizeof(esc_pname));
            char entry[256];
            int elen = snprintf(entry, sizeof(entry), "%s    \"%s\"", sep, esc_pname);
            if ((size_t)(off + elen + 64) < cap) {
                memcpy(buf + off, entry, elen);
                off += elen;
                buf[off] = '\0';
                sep = ",\n";
                pcount++;
            }
        }
        closedir(pd);
    }

    off += snprintf(buf + off, cap - off, "\n  ],\n  \"systemd_services\": [\n");

    // Enumerate /etc/systemd/system
    DIR* sd = opendir("/etc/systemd/system");
    if (sd) {
        struct dirent* de;
        const char* sep = "";
        int scount = 0;
        while ((de = readdir(sd)) != NULL && scount < 50) {
            if (de->d_name[0] == '.') continue;
            char esc_sname[128];
            Forensics_EscapeJson(de->d_name, esc_sname, sizeof(esc_sname));
            char entry[256];
            int elen = snprintf(entry, sizeof(entry), "%s    \"%s\"", sep, esc_sname);
            if ((size_t)(off + elen + 64) < cap) {
                memcpy(buf + off, entry, elen);
                off += elen;
                buf[off] = '\0';
                sep = ",\n";
                scount++;
            }
        }
        closedir(sd);
    }

    off += snprintf(buf + off, cap - off, "\n  ],\n  \"init_d_scripts\": [\n");

    // Enumerate /etc/init.d
    DIR* id = opendir("/etc/init.d");
    if (id) {
        struct dirent* de;
        const char* sep = "";
        int icount = 0;
        while ((de = readdir(id)) != NULL && icount < 50) {
            if (de->d_name[0] == '.') continue;
            char esc_iname[128];
            Forensics_EscapeJson(de->d_name, esc_iname, sizeof(esc_iname));
            char entry[256];
            int elen = snprintf(entry, sizeof(entry), "%s    \"%s\"", sep, esc_iname);
            if ((size_t)(off + elen + 64) < cap) {
                memcpy(buf + off, entry, elen);
                off += elen;
                buf[off] = '\0';
                sep = ",\n";
                icount++;
            }
        }
        closedir(id);
    }

    off += snprintf(buf + off, cap - off, "\n  ]\n}\n");

    *out_data = buf;
    *out_size = (size_t)off;
    *status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 2. Scheduled Tasks
static inline bool Forensics_CollectScheduledTasks(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) return false;

    // Read /etc/crontab
    char crontab[4096] = {0};
    int cf = open("/etc/crontab", O_RDONLY);
    if (cf >= 0) {
        ssize_t r = read(cf, crontab, sizeof(crontab) - 1);
        close(cf);
        if (r > 0) crontab[r] = '\0';
    }
    char* esc_crontab = (char*)malloc(sizeof(crontab) * 2 + 16);
    if (esc_crontab) Forensics_EscapeJson(crontab, esc_crontab, sizeof(crontab) * 2 + 16);

    int off = snprintf(buf, cap,
        "{\n"
        "  \"system_crontab\": \"%s\",\n"
        "  \"cron_entries\": [\n",
        esc_crontab ? esc_crontab : ""
    );
    if (esc_crontab) free(esc_crontab);

    // Enumerate /etc/cron.d, cron.daily, etc.
    const char* cron_dirs[] = { "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", NULL };
    const char* sep = "";
    int total_cron_files = 0;

    for (int i = 0; cron_dirs[i] != NULL; i++) {
        DIR* cd = opendir(cron_dirs[i]);
        if (!cd) continue;
        struct dirent* de;
        while ((de = readdir(cd)) != NULL) {
            if (de->d_name[0] == '.') continue;
            char esc_name[128];
            Forensics_EscapeJson(de->d_name, esc_name, sizeof(esc_name));
            char entry[384];
            int elen = snprintf(entry, sizeof(entry),
                "%s    {\n"
                "      \"directory\": \"%s\",\n"
                "      \"file\": \"%s\"\n"
                "    }",
                sep, cron_dirs[i], esc_name
            );
            if ((size_t)(off + elen + 64) < cap) {
                memcpy(buf + off, entry, elen);
                off += elen;
                buf[off] = '\0';
                sep = ",\n";
                total_cron_files++;
            }
        }
        closedir(cd);
    }

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_cron_files\": %d,\n"
        "  \"systemd_timers\": [\n",
        total_cron_files
    );

    // Try reading systemctl list-timers if available
    char timer_out[16384] = {0};
    size_t timer_len = 0;
    const char* systemctl_bin = (access("/bin/systemctl", X_OK) == 0) ? "/bin/systemctl" :
                                (access("/usr/bin/systemctl", X_OK) == 0 ? "/usr/bin/systemctl" : NULL);
    if (systemctl_bin) {
        const char* const timer_cmd[] = { systemctl_bin, "list-timers", "--all", "--no-pager", NULL };
        Forensics_RunCommandCapture(timer_cmd, timer_out, sizeof(timer_out), &timer_len, 5);
    }
    char* esc_timers = (char*)malloc(timer_len * 2 + 16);
    if (esc_timers) Forensics_EscapeJson(timer_out, esc_timers, timer_len * 2 + 16);

    off += snprintf(buf + off, cap - off,
        "    \"%s\"\n"
        "  ]\n"
        "}\n",
        esc_timers ? esc_timers : ""
    );
    if (esc_timers) free(esc_timers);

    *out_data = buf;
    *out_size = (size_t)off;
    *status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 3. Security Events
static inline bool Forensics_CollectSecurityEvents(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > 256 * 1024) {
        max_bytes = 128 * 1024;
    }

    const char* log_candidates[] = {
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        NULL
    };

    const char* chosen = NULL;
    for (int i = 0; log_candidates[i] != NULL; i++) {
        if (access(log_candidates[i], R_OK) == 0) {
            chosen = log_candidates[i];
            break;
        }
    }

    if (chosen) {
        int fd = open(chosen, O_RDONLY);
        if (fd >= 0) {
            off_t sz = lseek(fd, 0, SEEK_END);
            off_t start = 0;
            if (sz > (off_t)max_bytes) {
                start = sz - (off_t)max_bytes;
            }
            lseek(fd, start, SEEK_SET);

            char* buf = (char*)malloc(max_bytes + 256);
            if (!buf) { close(fd); return false; }

            int header_len = snprintf(buf, 256, "# Source: %s (last %zu bytes of %lld total)\n", chosen, max_bytes, (long long)sz);
            ssize_t bytes_read = read(fd, buf + header_len, max_bytes);
            close(fd);

            if (bytes_read >= 0) {
                buf[header_len + bytes_read] = '\0';
                *out_data = buf;
                *out_size = (size_t)(header_len + bytes_read);
                *status = (bytes_read == 0) ? COLLECTOR_STATUS_EMPTY : COLLECTOR_STATUS_COLLECTED;
                return true;
            }
            free(buf);
        }
    }

    // Fallback to journalctl
    const char* journalctl_bin = (access("/bin/journalctl", X_OK) == 0) ? "/bin/journalctl" :
                                 (access("/usr/bin/journalctl", X_OK) == 0 ? "/usr/bin/journalctl" : NULL);
    if (journalctl_bin) {
        char* buf = (char*)malloc(max_bytes + 256);
        if (!buf) return false;
        int header_len = snprintf(buf, 256, "# Source: journalctl -n 200 --no-pager\n");
        size_t cap_out = 0;
        const char* const cmd[] = { journalctl_bin, "-n", "200", "--no-pager", NULL };
        Forensics_RunCommandCapture(cmd, buf + header_len, max_bytes, &cap_out, 5);
        if (cap_out > 0) {
            buf[header_len + cap_out] = '\0';
            *out_data = buf;
            *out_size = (size_t)(header_len + cap_out);
            *status = COLLECTOR_STATUS_COLLECTED;
            return true;
        }
        free(buf);
    }

    *status = COLLECTOR_STATUS_EMPTY;
    char* empty_buf = strdup("# No security logs or journal entries available.\n");
    if (!empty_buf) return false;
    *out_data = empty_buf;
    *out_size = strlen(empty_buf);
    return true;
}

// 4. Shell History
static inline bool Forensics_CollectShellHistory(char** out_data, size_t* out_size, ForensicCollectorStatus* status, size_t max_bytes) {
    *status = COLLECTOR_STATUS_FAILED;
    if (max_bytes == 0 || max_bytes > 256 * 1024) {
        max_bytes = 256 * 1024;
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) return false;
    size_t off = 0;

    const char* history_targets[16];
    int target_count = 0;
    history_targets[target_count++] = "/root/.bash_history";
    history_targets[target_count++] = "/root/.zsh_history";

    // Scan /home for user history files
    char home_history[8][512];
    int home_hist_count = 0;
    DIR* hd = opendir("/home");
    if (hd) {
        struct dirent* de;
        while ((de = readdir(hd)) != NULL && home_hist_count < 4) {
            if (de->d_name[0] == '.') continue;
            snprintf(home_history[home_hist_count], sizeof(home_history[0]), "/home/%s/.bash_history", de->d_name);
            history_targets[target_count++] = home_history[home_hist_count++];
        }
        closedir(hd);
    }

    int files_collected = 0;
    for (int i = 0; i < target_count; i++) {
        const char* target_path = history_targets[i];
        if (access(target_path, F_OK) != 0) continue;

        int fd = open(target_path, O_RDONLY);
        if (fd < 0) {
            char header[512];
            int hlen = snprintf(header, sizeof(header), "=== %s [permission denied] ===\n\n", target_path);
            if (off + (size_t)hlen < max_bytes) {
                if (off + (size_t)hlen >= cap) {
                    char* grown = (char*)realloc(buf, cap * 2);
                    if (grown) { buf = grown; cap *= 2; }
                }
                if (off + (size_t)hlen < cap) {
                    memcpy(buf + off, header, hlen);
                    off += (size_t)hlen;
                    buf[off] = '\0';
                }
            }
            continue;
        }

        off_t sz = lseek(fd, 0, SEEK_END);
        size_t to_read = 32768; // last 32 KiB per file
        off_t start = 0;
        if (sz > (off_t)to_read) {
            start = sz - (off_t)to_read;
        } else {
            to_read = (size_t)sz;
        }
        lseek(fd, start, SEEK_SET);

        char header[512];
        int hlen = snprintf(header, sizeof(header), "=== %s (%lld total bytes, tail %zu bytes) ===\n", target_path, (long long)sz, to_read);
        if (off + (size_t)hlen + to_read + 32 >= cap) {
            size_t new_cap = cap * 2;
            while (new_cap <= off + (size_t)hlen + to_read + 32 && new_cap <= max_bytes) new_cap *= 2;
            if (new_cap > max_bytes) new_cap = max_bytes;
            char* grown = (char*)realloc(buf, new_cap);
            if (grown) { buf = grown; cap = new_cap; }
        }

        if (off + (size_t)hlen < cap) {
            memcpy(buf + off, header, hlen);
            off += (size_t)hlen;
        }

        if (off + to_read < cap) {
            ssize_t rd = read(fd, buf + off, to_read);
            if (rd > 0) {
                off += (size_t)rd;
            }
        }
        close(fd);

        if (off + 2 < cap) {
            buf[off++] = '\n';
            buf[off++] = '\n';
            buf[off] = '\0';
        }
        files_collected++;
    }

    if (files_collected == 0 && off == 0) {
        int hlen = snprintf(buf, cap, "# No shell history files found or accessible on endpoint.\n");
        off = (size_t)hlen;
        *status = COLLECTOR_STATUS_EMPTY;
    } else {
        *status = COLLECTOR_STATUS_COLLECTED;
    }

    buf[off] = '\0';
    *out_data = buf;
    *out_size = off;
    return true;
}

/* ---------------------------------------------------------------------------
 * Forensic Evidence Upload & Finalization Protocol
 * ------------------------------------------------------------------------- */

typedef struct {
    char* data;
    size_t cap;
    size_t len;
} ForensicsHTTPBuffer;

static size_t Forensics_HTTPWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    ForensicsHTTPBuffer* b = (ForensicsHTTPBuffer*)userp;
    if (!b || !b->data || b->cap == 0) return total;
    if (b->len + total >= b->cap) {
        total = b->cap - b->len - 1;
    }
    if (total > 0) {
        memcpy(b->data + b->len, contents, total);
        b->len += total;
        b->data[b->len] = '\0';
    }
    return size * nmemb;
}

static inline bool Forensics_UploadItemHTTP(
    const char* hub_url,
    const char* api_key_or_cred,
    bool is_device_credential,
    const char* client_cert,
    const char* client_key,
    const char* ca_path,
    const char* bundle_id,
    const char* item_name,
    const char* collector_status,
    const uint8_t* payload,
    size_t payload_len
) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    char url[2048];
    snprintf(url, sizeof(url), "%s/api/v1/evidence/items?bundle_id=%s&name=%s&status=%s",
        hub_url, bundle_id, item_name, collector_status);

    char auth_header[256];
    const char* header_name = is_device_credential ? "X-Ominull-Device-Credential" : "X-API-Key";
    snprintf(auth_header, sizeof(auth_header), "%s: %s", header_name, api_key_or_cred);

    struct curl_slist* headers = curl_slist_append(NULL, "Content-Type: application/octet-stream");
    headers = curl_slist_append(headers, auth_header);

    char resp_buf[1024] = {0};
    ForensicsHTTPBuffer response = { .data = resp_buf, .cap = sizeof(resp_buf), .len = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char*)payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)payload_len);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Forensics_HTTPWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    bool is_https = (strncmp(hub_url, "https://", 8) == 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, is_https ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, is_https ? 2L : 0L);
    if (is_https && ca_path && ca_path[0]) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path);
    }
    if (is_https && client_cert && client_key && access(client_cert, R_OK) == 0 && access(client_key, R_OK) == 0) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
    }

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK && (http_code == 200 || http_code == 201));
}

static inline bool Forensics_FinalizeBundleHTTP(
    const char* hub_url,
    const char* api_key_or_cred,
    bool is_device_credential,
    const char* client_cert,
    const char* client_key,
    const char* ca_path,
    const char* finalize_json
) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    char url[2048];
    snprintf(url, sizeof(url), "%s/api/v1/evidence/finalize", hub_url);

    char auth_header[256];
    const char* header_name = is_device_credential ? "X-Ominull-Device-Credential" : "X-API-Key";
    snprintf(auth_header, sizeof(auth_header), "%s: %s", header_name, api_key_or_cred);

    struct curl_slist* headers = curl_slist_append(NULL, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header);

    char resp_buf[2048] = {0};
    ForensicsHTTPBuffer response = { .data = resp_buf, .cap = sizeof(resp_buf), .len = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, finalize_json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(finalize_json));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Forensics_HTTPWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    bool is_https = (strncmp(hub_url, "https://", 8) == 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, is_https ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, is_https ? 2L : 0L);
    if (is_https && ca_path && ca_path[0]) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path);
    }
    if (is_https && client_cert && client_key && access(client_cert, R_OK) == 0 && access(client_key, R_OK) == 0) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
    }

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK && http_code == 200);
}

/* ---------------------------------------------------------------------------
 * High-Level Bundle Publishing & Manifest Finalization Routine
 * ------------------------------------------------------------------------- */

static inline bool Forensics_PublishBundleAndFinalize(
    const char* hub_url,
    const char* api_key_or_cred,
    bool is_device_credential,
    const char* client_cert,
    const char* client_key,
    const char* ca_path,
    const char* endpoint_id,
    const char* tenant_id,
    const char* job_id,
    const char* bundle_id,
    const char* profile,
    int64_t max_bytes,
    ForensicCollectedItem* items,
    int item_count,
    char* out_manifest_sha256,
    size_t sha_cap
) {
    if (!hub_url || !endpoint_id || !tenant_id || !job_id || !bundle_id || !profile) return false;

    // 1. Get or create endpoint evidence signing key
    uint8_t pub_key[32];
    uint8_t priv_key[64];
    char pub_hex[65];
    if (!Forensics_GetOrCreateEndpointKey(FORENSICS_DEFAULT_KEY_PATH, pub_key, priv_key, pub_hex, sizeof(pub_hex))) {
        for (int i = 0; i < item_count; i++) free(items[i].data);
        return false;
    }

    // 2. Upload each collected item and calculate SHA-256
    int64_t total_bytes = 0;
    for (int i = 0; i < item_count; i++) {
        if (!items[i].data) {
            items[i].data = (uint8_t*)strdup("");
            items[i].size_bytes = 0;
        }

        // Compute SHA-256
        uint8_t digest[32];
        Response_SHA256_Sum(items[i].data, items[i].size_bytes, digest);
        for (int d = 0; d < 32; d++) snprintf(items[i].sha256 + (d * 2), 3, "%02x", digest[d]);
        items[i].sha256[64] = '\0';

        // Enforce max bytes cap
        total_bytes += items[i].size_bytes;
        if (max_bytes > 0 && total_bytes > max_bytes) {
            items[i].status = COLLECTOR_STATUS_TRUNCATED;
        }

        // Upload to Hub Evidence Store
        bool uploaded = Forensics_UploadItemHTTP(
            hub_url,
            api_key_or_cred,
            is_device_credential,
            client_cert,
            client_key,
            ca_path,
            bundle_id,
            items[i].name,
            CollectorStatusToString(items[i].status),
            items[i].data,
            items[i].size_bytes
        );

        if (!uploaded) {
            items[i].status = COLLECTOR_STATUS_FAILED;
        }
    }

    // 3. Encode canonical manifest and sign with Ed25519 key
    time_t now_unix = time(NULL);
    uint8_t canonical_buf[8192];
    size_t canonical_len = Forensics_EncodeManifestCanonical(
        canonical_buf,
        sizeof(canonical_buf),
        bundle_id,
        endpoint_id,
        tenant_id,
        job_id,
        profile,
        (int64_t)now_unix,
        items,
        item_count
    );

    if (canonical_len == 0) {
        for (int i = 0; i < item_count; i++) free(items[i].data);
        return false;
    }

    // SHA-256 of canonical bytes
    uint8_t manifest_hash[32];
    Response_SHA256_Sum(canonical_buf, canonical_len, manifest_hash);
    char manifest_hash_hex[65];
    for (int d = 0; d < 32; d++) snprintf(manifest_hash_hex + (d * 2), 3, "%02x", manifest_hash[d]);
    manifest_hash_hex[64] = '\0';
    if (out_manifest_sha256 && sha_cap >= 65) {
        strncpy(out_manifest_sha256, manifest_hash_hex, sha_cap - 1);
        out_manifest_sha256[sha_cap - 1] = '\0';
    }

    // Detached Ed25519 signature
    uint8_t sig_bytes[64];
    if (!Ed25519_Sign(sig_bytes, canonical_buf, canonical_len, priv_key)) {
        for (int i = 0; i < item_count; i++) free(items[i].data);
        return false;
    }
    char sig_hex[129];
    for (int s = 0; s < 64; s++) snprintf(sig_hex + (s * 2), 3, "%02x", sig_bytes[s]);
    sig_hex[128] = '\0';

    // 4. Build Finalize JSON payload
    char time_str[64];
    struct tm* tm_info = gmtime(&now_unix);
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    size_t json_cap = 16384;
    char* fin_json = (char*)malloc(json_cap);
    if (!fin_json) {
        for (int i = 0; i < item_count; i++) free(items[i].data);
        return false;
    }

    size_t jlen = 0;
    jlen += snprintf(fin_json + jlen, json_cap - jlen,
        "{\n"
        "  \"bundle_id\": \"%s\",\n"
        "  \"manifest\": {\n"
        "    \"bundle_id\": \"%s\",\n"
        "    \"endpoint_id\": \"%s\",\n"
        "    \"tenant_id\": \"%s\",\n"
        "    \"job_id\": \"%s\",\n"
        "    \"profile\": \"%s\",\n"
        "    \"collected_at\": \"%s\",\n"
        "    \"items\": [\n",
        bundle_id, bundle_id, endpoint_id, tenant_id, job_id, profile, time_str
    );

    for (int i = 0; i < item_count; i++) {
        jlen += snprintf(fin_json + jlen, json_cap - jlen,
            "%s      {\n"
            "        \"name\": \"%s\",\n"
            "        \"size_bytes\": %llu,\n"
            "        \"sha256\": \"%s\",\n"
            "        \"collector_status\": \"%s\"\n"
            "      }",
            (i > 0) ? ",\n" : "",
            items[i].name,
            (unsigned long long)items[i].size_bytes,
            items[i].sha256,
            CollectorStatusToString(items[i].status)
        );
    }

    jlen += snprintf(fin_json + jlen, json_cap - jlen,
        "\n    ],\n"
        "    \"signature\": \"%s\"\n"
        "  }\n"
        "}\n",
        sig_hex
    );

    // 5. Post Finalize to Hub
    bool fin_ok = Forensics_FinalizeBundleHTTP(
        hub_url,
        api_key_or_cred,
        is_device_credential,
        client_cert,
        client_key,
        ca_path,
        fin_json
    );

    free(fin_json);
    for (int i = 0; i < item_count; i++) free(items[i].data);

    return fin_ok;
}

/* ---------------------------------------------------------------------------
 * High-Level Profile Collection Routines
 * ------------------------------------------------------------------------- */

static inline bool Forensics_RunDiagnosticCollection(
    const char* hub_url,
    const char* api_key_or_cred,
    bool is_device_credential,
    const char* client_cert,
    const char* client_key,
    const char* ca_path,
    const char* endpoint_id,
    const char* tenant_id,
    const char* job_id,
    const char* bundle_id,
    int64_t max_bytes,
    char* out_manifest_sha256,
    size_t sha_cap
) {
    ForensicCollectedItem items[8];
    memset(items, 0, sizeof(items));
    int item_count = 8;

    strncpy(items[0].name, "os_version.json", sizeof(items[0].name) - 1);
    strncpy(items[0].content_type, "application/json", sizeof(items[0].content_type) - 1);
    Forensics_CollectOSVersion((char**)&items[0].data, &items[0].size_bytes, &items[0].status);

    strncpy(items[1].name, "network_interfaces.json", sizeof(items[1].name) - 1);
    strncpy(items[1].content_type, "application/json", sizeof(items[1].content_type) - 1);
    Forensics_CollectNetworkInterfaces((char**)&items[1].data, &items[1].size_bytes, &items[1].status);

    strncpy(items[2].name, "routes.txt", sizeof(items[2].name) - 1);
    strncpy(items[2].content_type, "text/plain", sizeof(items[2].content_type) - 1);
    Forensics_CollectRoutes((char**)&items[2].data, &items[2].size_bytes, &items[2].status);

    strncpy(items[3].name, "dns_config.txt", sizeof(items[3].name) - 1);
    strncpy(items[3].content_type, "text/plain", sizeof(items[3].content_type) - 1);
    Forensics_CollectDNSConfig((char**)&items[3].data, &items[3].size_bytes, &items[3].status);

    strncpy(items[4].name, "resource_summary.json", sizeof(items[4].name) - 1);
    strncpy(items[4].content_type, "application/json", sizeof(items[4].content_type) - 1);
    Forensics_CollectResourceSummary((char**)&items[4].data, &items[4].size_bytes, &items[4].status);

    strncpy(items[5].name, "service_state.json", sizeof(items[5].name) - 1);
    strncpy(items[5].content_type, "application/json", sizeof(items[5].content_type) - 1);
    Forensics_CollectServiceState((char**)&items[5].data, &items[5].size_bytes, &items[5].status);

    strncpy(items[6].name, "system_logs.txt", sizeof(items[6].name) - 1);
    strncpy(items[6].content_type, "text/plain", sizeof(items[6].content_type) - 1);
    Forensics_CollectSystemLogs((char**)&items[6].data, &items[6].size_bytes, &items[6].status, 256 * 1024);

    strncpy(items[7].name, "agent_diagnostics.json", sizeof(items[7].name) - 1);
    strncpy(items[7].content_type, "application/json", sizeof(items[7].content_type) - 1);
    Forensics_CollectAgentDiagnostics(endpoint_id, hub_url, (char**)&items[7].data, &items[7].size_bytes, &items[7].status);

    return Forensics_PublishBundleAndFinalize(
        hub_url, api_key_or_cred, is_device_credential, client_cert, client_key, ca_path,
        endpoint_id, tenant_id, job_id, bundle_id, "diagnostic", max_bytes,
        items, item_count, out_manifest_sha256, sha_cap
    );
}

static inline bool Forensics_RunLiveVolatileCollection(
    const char* hub_url,
    const char* api_key_or_cred,
    bool is_device_credential,
    const char* client_cert,
    const char* client_key,
    const char* ca_path,
    const char* endpoint_id,
    const char* tenant_id,
    const char* job_id,
    const char* bundle_id,
    int64_t max_bytes,
    char* out_manifest_sha256,
    size_t sha_cap
) {
    ForensicCollectedItem items[6];
    memset(items, 0, sizeof(items));
    int item_count = 6;

    strncpy(items[0].name, "process_snapshot.json", sizeof(items[0].name) - 1);
    strncpy(items[0].content_type, "application/json", sizeof(items[0].content_type) - 1);
    Forensics_CollectProcessSnapshot((char**)&items[0].data, &items[0].size_bytes, &items[0].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[1].name, "socket_to_process.json", sizeof(items[1].name) - 1);
    strncpy(items[1].content_type, "application/json", sizeof(items[1].content_type) - 1);
    Forensics_CollectSocketToProcess((char**)&items[1].data, &items[1].size_bytes, &items[1].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[2].name, "logged_in_sessions.json", sizeof(items[2].name) - 1);
    strncpy(items[2].content_type, "application/json", sizeof(items[2].content_type) - 1);
    Forensics_CollectLoggedInSessions((char**)&items[2].data, &items[2].size_bytes, &items[2].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[3].name, "network_neighbors.json", sizeof(items[3].name) - 1);
    strncpy(items[3].content_type, "application/json", sizeof(items[3].content_type) - 1);
    Forensics_CollectNetworkNeighbors((char**)&items[3].data, &items[3].size_bytes, &items[3].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[4].name, "firewall_state.json", sizeof(items[4].name) - 1);
    strncpy(items[4].content_type, "application/json", sizeof(items[4].content_type) - 1);
    Forensics_CollectFirewallState((char**)&items[4].data, &items[4].size_bytes, &items[4].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[5].name, "loaded_modules.json", sizeof(items[5].name) - 1);
    strncpy(items[5].content_type, "application/json", sizeof(items[5].content_type) - 1);
    Forensics_CollectLoadedModules((char**)&items[5].data, &items[5].size_bytes, &items[5].status, FORENSICS_MAX_ITEM_BYTES);

    return Forensics_PublishBundleAndFinalize(
        hub_url, api_key_or_cred, is_device_credential, client_cert, client_key, ca_path,
        endpoint_id, tenant_id, job_id, bundle_id, "live_volatile", max_bytes,
        items, item_count, out_manifest_sha256, sha_cap
    );
}

static inline bool Forensics_RunIRStandardCollection(
    const char* hub_url,
    const char* api_key_or_cred,
    bool is_device_credential,
    const char* client_cert,
    const char* client_key,
    const char* ca_path,
    const char* endpoint_id,
    const char* tenant_id,
    const char* job_id,
    const char* bundle_id,
    int64_t max_bytes,
    char* out_manifest_sha256,
    size_t sha_cap
) {
    ForensicCollectedItem items[18];
    memset(items, 0, sizeof(items));
    int item_count = 18;

    // 1. Diagnostic suite
    strncpy(items[0].name, "os_version.json", sizeof(items[0].name) - 1);
    strncpy(items[0].content_type, "application/json", sizeof(items[0].content_type) - 1);
    Forensics_CollectOSVersion((char**)&items[0].data, &items[0].size_bytes, &items[0].status);

    strncpy(items[1].name, "network_interfaces.json", sizeof(items[1].name) - 1);
    strncpy(items[1].content_type, "application/json", sizeof(items[1].content_type) - 1);
    Forensics_CollectNetworkInterfaces((char**)&items[1].data, &items[1].size_bytes, &items[1].status);

    strncpy(items[2].name, "routes.txt", sizeof(items[2].name) - 1);
    strncpy(items[2].content_type, "text/plain", sizeof(items[2].content_type) - 1);
    Forensics_CollectRoutes((char**)&items[2].data, &items[2].size_bytes, &items[2].status);

    strncpy(items[3].name, "dns_config.txt", sizeof(items[3].name) - 1);
    strncpy(items[3].content_type, "text/plain", sizeof(items[3].content_type) - 1);
    Forensics_CollectDNSConfig((char**)&items[3].data, &items[3].size_bytes, &items[3].status);

    strncpy(items[4].name, "resource_summary.json", sizeof(items[4].name) - 1);
    strncpy(items[4].content_type, "application/json", sizeof(items[4].content_type) - 1);
    Forensics_CollectResourceSummary((char**)&items[4].data, &items[4].size_bytes, &items[4].status);

    strncpy(items[5].name, "service_state.json", sizeof(items[5].name) - 1);
    strncpy(items[5].content_type, "application/json", sizeof(items[5].content_type) - 1);
    Forensics_CollectServiceState((char**)&items[5].data, &items[5].size_bytes, &items[5].status);

    strncpy(items[6].name, "system_logs.txt", sizeof(items[6].name) - 1);
    strncpy(items[6].content_type, "text/plain", sizeof(items[6].content_type) - 1);
    Forensics_CollectSystemLogs((char**)&items[6].data, &items[6].size_bytes, &items[6].status, 256 * 1024);

    strncpy(items[7].name, "agent_diagnostics.json", sizeof(items[7].name) - 1);
    strncpy(items[7].content_type, "application/json", sizeof(items[7].content_type) - 1);
    Forensics_CollectAgentDiagnostics(endpoint_id, hub_url, (char**)&items[7].data, &items[7].size_bytes, &items[7].status);

    // 2. Live volatile suite
    strncpy(items[8].name, "process_snapshot.json", sizeof(items[8].name) - 1);
    strncpy(items[8].content_type, "application/json", sizeof(items[8].content_type) - 1);
    Forensics_CollectProcessSnapshot((char**)&items[8].data, &items[8].size_bytes, &items[8].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[9].name, "socket_to_process.json", sizeof(items[9].name) - 1);
    strncpy(items[9].content_type, "application/json", sizeof(items[9].content_type) - 1);
    Forensics_CollectSocketToProcess((char**)&items[9].data, &items[9].size_bytes, &items[9].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[10].name, "logged_in_sessions.json", sizeof(items[10].name) - 1);
    strncpy(items[10].content_type, "application/json", sizeof(items[10].content_type) - 1);
    Forensics_CollectLoggedInSessions((char**)&items[10].data, &items[10].size_bytes, &items[10].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[11].name, "network_neighbors.json", sizeof(items[11].name) - 1);
    strncpy(items[11].content_type, "application/json", sizeof(items[11].content_type) - 1);
    Forensics_CollectNetworkNeighbors((char**)&items[11].data, &items[11].size_bytes, &items[11].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[12].name, "firewall_state.json", sizeof(items[12].name) - 1);
    strncpy(items[12].content_type, "application/json", sizeof(items[12].content_type) - 1);
    Forensics_CollectFirewallState((char**)&items[12].data, &items[12].size_bytes, &items[12].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[13].name, "loaded_modules.json", sizeof(items[13].name) - 1);
    strncpy(items[13].content_type, "application/json", sizeof(items[13].content_type) - 1);
    Forensics_CollectLoadedModules((char**)&items[13].data, &items[13].size_bytes, &items[13].status, FORENSICS_MAX_ITEM_BYTES);

    // 3. IR standard suite
    strncpy(items[14].name, "persistence.json", sizeof(items[14].name) - 1);
    strncpy(items[14].content_type, "application/json", sizeof(items[14].content_type) - 1);
    Forensics_CollectPersistence((char**)&items[14].data, &items[14].size_bytes, &items[14].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[15].name, "scheduled_tasks.json", sizeof(items[15].name) - 1);
    strncpy(items[15].content_type, "application/json", sizeof(items[15].content_type) - 1);
    Forensics_CollectScheduledTasks((char**)&items[15].data, &items[15].size_bytes, &items[15].status, FORENSICS_MAX_ITEM_BYTES);

    strncpy(items[16].name, "security_events.txt", sizeof(items[16].name) - 1);
    strncpy(items[16].content_type, "text/plain", sizeof(items[16].content_type) - 1);
    Forensics_CollectSecurityEvents((char**)&items[16].data, &items[16].size_bytes, &items[16].status, 128 * 1024);

    strncpy(items[17].name, "shell_history.txt", sizeof(items[17].name) - 1);
    strncpy(items[17].content_type, "text/plain", sizeof(items[17].content_type) - 1);
    Forensics_CollectShellHistory((char**)&items[17].data, &items[17].size_bytes, &items[17].status, 256 * 1024);

    return Forensics_PublishBundleAndFinalize(
        hub_url, api_key_or_cred, is_device_credential, client_cert, client_key, ca_path,
        endpoint_id, tenant_id, job_id, bundle_id, "ir_standard", max_bytes,
        items, item_count, out_manifest_sha256, sha_cap
    );
}

static inline bool Forensics_RunCollection(
    const char* profile,
    const char* hub_url,
    const char* api_key_or_cred,
    bool is_device_credential,
    const char* client_cert,
    const char* client_key,
    const char* ca_path,
    const char* endpoint_id,
    const char* tenant_id,
    const char* job_id,
    const char* bundle_id,
    int64_t max_bytes,
    char* out_manifest_sha256,
    size_t sha_cap
) {
    if (!profile || profile[0] == '\0' || strcmp(profile, "diagnostic") == 0) {
        return Forensics_RunDiagnosticCollection(
            hub_url, api_key_or_cred, is_device_credential, client_cert, client_key, ca_path,
            endpoint_id, tenant_id, job_id, bundle_id, max_bytes, out_manifest_sha256, sha_cap
        );
    } else if (strcmp(profile, "live_volatile") == 0) {
        return Forensics_RunLiveVolatileCollection(
            hub_url, api_key_or_cred, is_device_credential, client_cert, client_key, ca_path,
            endpoint_id, tenant_id, job_id, bundle_id, max_bytes, out_manifest_sha256, sha_cap
        );
    } else if (strcmp(profile, "ir_standard") == 0) {
        return Forensics_RunIRStandardCollection(
            hub_url, api_key_or_cred, is_device_credential, client_cert, client_key, ca_path,
            endpoint_id, tenant_id, job_id, bundle_id, max_bytes, out_manifest_sha256, sha_cap
        );
    }
    return false;
}

#endif /* OMINULL_FORENSICS_LINUX_H */
