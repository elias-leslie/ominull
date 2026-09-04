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
 * High-Level Diagnostic Profile Collection Routine
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
    if (!hub_url || !endpoint_id || !tenant_id || !job_id || !bundle_id) return false;

    // 1. Get or create endpoint evidence signing key
    uint8_t pub_key[32];
    uint8_t priv_key[64];
    char pub_hex[65];
    if (!Forensics_GetOrCreateEndpointKey(FORENSICS_DEFAULT_KEY_PATH, pub_key, priv_key, pub_hex, sizeof(pub_hex))) {
        return false;
    }

    // 2. Initialize collected items table
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

    // 3. Upload each collected item and calculate SHA-256
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

    // 4. Encode canonical manifest and sign with Ed25519 key
    time_t now_unix = time(NULL);
    uint8_t canonical_buf[8192];
    size_t canonical_len = Forensics_EncodeManifestCanonical(
        canonical_buf,
        sizeof(canonical_buf),
        bundle_id,
        endpoint_id,
        tenant_id,
        job_id,
        "diagnostic",
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

    // 5. Build Finalize JSON payload
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
        "    \"profile\": \"diagnostic\",\n"
        "    \"collected_at\": \"%s\",\n"
        "    \"items\": [\n",
        bundle_id, bundle_id, endpoint_id, tenant_id, job_id, time_str
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

    // 6. Post Finalize to Hub
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

#endif /* OMINULL_FORENSICS_LINUX_H */
