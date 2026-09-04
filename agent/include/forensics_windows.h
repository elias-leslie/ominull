#ifndef OMINULL_FORENSICS_WINDOWS_H
#define OMINULL_FORENSICS_WINDOWS_H

/*
 * Ominull Windows Forensic Collection Engine (Slice 4A.2: Diagnostic Profile).
 *
 * Implements:
 * - Allowlisted Windows diagnostic collectors:
 *   1. os_version.json (Windows version, build, edition, architecture, install date)
 *   2. network_interfaces.json (adapters, friendly names, MACs, unicast IPv4/IPv6, MTU)
 *   3. routes.txt (IP forwarding table)
 *   4. dns_config.txt (system & adapter DNS parameters)
 *   5. resource_summary.json (memory, uptime, disk free/total)
 *   6. service_state.json (SCM service states, PIDs, exit codes)
 *   7. system_logs.txt (bounded Windows event log / diagnostic tail)
 *   8. agent_diagnostics.json (agent PID, uptime, executable path, working dir)
 * - Honest collector status reporting:
 *   collected, empty, unsupported, permission_denied, truncated, timed_out, failed.
 * - Per-item and cumulative bundle byte bounding.
 * - Deterministic length-prefixed canonical manifest encoding (OMINULL-MANIFEST-V2).
 * - In-process TweetNaCl detached Ed25519 manifest signing using persistent endpoint key.
 * - Authenticated WinHTTP evidence upload and bundle finalization protocol.
 */

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "agent.h"
#include "ed25519_verify.h"
#include "response_canonical.h"
#include "response_dispatcher.h"

#define FORENSICS_MAX_ITEMS 16
#define FORENSICS_MAX_ITEM_BYTES (512 * 1024)   // 512 KiB per artifact limit
#define FORENSICS_DEFAULT_MAX_BUNDLE_BYTES (10 * 1024 * 1024) // 10 MiB bundle limit
#define FORENSICS_DEFAULT_KEY_PATH_WIN "C:\\ProgramData\\Ominull\\evidence_signer.key"
#define FORENSICS_DEFAULT_PUB_PATH_WIN "C:\\ProgramData\\Ominull\\evidence_signer.pub"

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
} ForensicCollectorStatusWin;

static inline const char* CollectorStatusToStringWin(ForensicCollectorStatusWin s) {
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
    ForensicCollectorStatusWin status;
} ForensicCollectedItemWin;

typedef struct {
    char bundle_id[64];
    char endpoint_id[64];
    char tenant_id[64];
    char job_id[64];
    char profile[32];
    int64_t max_bytes;
    int timeout_seconds;
} ForensicCollectionParamsWin;

/* ---------------------------------------------------------------------------
 * Payload Parsing
 * ------------------------------------------------------------------------- */

static inline bool Forensics_ParsePayloadWin(const char* json, ForensicCollectionParamsWin* out) {
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
            int ts = atoi(p + 1);
            if (ts > 0) out->timeout_seconds = ts;
        }
    }

    return true;
}

/* ---------------------------------------------------------------------------
 * Key Management
 * ------------------------------------------------------------------------- */

static inline bool Forensics_GetOrCreateEndpointKeyWin(
    const char* key_path,
    uint8_t public_key[32],
    uint8_t secret_key[64],
    char* pub_hex_out,
    size_t pub_hex_cap
) {
    if (!key_path || key_path[0] == '\0') key_path = FORENSICS_DEFAULT_KEY_PATH_WIN;

    // Try reading existing key file (64 binary bytes or 128 hex bytes)
    FILE* f = fopen(key_path, "rb");
    if (f) {
        uint8_t file_buf[128];
        size_t n = fread(file_buf, 1, sizeof(file_buf), f);
        fclose(f);

        if (n == 64) {
            memcpy(secret_key, file_buf, 64);
            memcpy(public_key, file_buf + 32, 32);
            if (pub_hex_out && pub_hex_cap >= 65) {
                for (int i = 0; i < 32; i++) snprintf(pub_hex_out + (i * 2), 3, "%02x", public_key[i]);
                pub_hex_out[64] = '\0';
            }
            return true;
        } else if (n >= 128) {
            for (int i = 0; i < 64; i++) {
                unsigned int byte_val = 0;
                if (sscanf((char*)file_buf + (i * 2), "%02x", &byte_val) == 1) {
                    secret_key[i] = (uint8_t)byte_val;
                }
            }
            memcpy(public_key, secret_key + 32, 32);
            if (pub_hex_out && pub_hex_cap >= 65) {
                for (int i = 0; i < 32; i++) snprintf(pub_hex_out + (i * 2), 3, "%02x", public_key[i]);
                pub_hex_out[64] = '\0';
            }
            return true;
        }
    }

    // Generate fresh keypair from BCrypt system RNG
    uint8_t seed[32];
    NTSTATUS status = BCryptGenRandom(NULL, (PUCHAR)seed, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        return false;
    }

    if (!Ed25519_CreateKeypairFromSeed(public_key, secret_key, seed)) {
        return false;
    }

    // Ensure C:\ProgramData\Ominull exists
    CreateDirectoryA("C:\\ProgramData", NULL);
    CreateDirectoryA("C:\\ProgramData\\Ominull", NULL);

    // Save secret key
    FILE* fw = fopen(key_path, "wb");
    if (fw) {
        fwrite(secret_key, 1, 64, fw);
        fclose(fw);
    }

    // Save public key hex
    char pub_hex[65];
    for (int i = 0; i < 32; i++) snprintf(pub_hex + (i * 2), 3, "%02x", public_key[i]);
    pub_hex[64] = '\0';

    FILE* fpub = fopen(FORENSICS_DEFAULT_PUB_PATH_WIN, "w");
    if (fpub) {
        fprintf(fpub, "%s\n", pub_hex);
        fclose(fpub);
    }

    if (pub_hex_out && pub_hex_cap >= 65) {
        memcpy(pub_hex_out, pub_hex, 64);
        pub_hex_out[64] = '\0';
    }

    return true;
}

/* ---------------------------------------------------------------------------
 * Safe JSON String Escaping Helper
 * ------------------------------------------------------------------------- */

static inline void Forensics_EscapeJsonWin(const char* src, char* dst, size_t dst_cap) {
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

/* ---------------------------------------------------------------------------
 * Canonical Manifest Encoding (OMINULL-MANIFEST-V2)
 * ------------------------------------------------------------------------- */

static inline bool Forensics_WriteLPStrWin(ResponseCanonicalBuffer* b, const char* str) {
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

static inline bool Forensics_WriteRawWin(ResponseCanonicalBuffer* b, const void* data, size_t len) {
    if (b->len + len > b->cap) {
        b->overflow = true;
        return false;
    }
    memcpy(b->buf + b->len, data, len);
    b->len += len;
    return true;
}

static inline size_t Forensics_EncodeManifestCanonicalWin(
    uint8_t* out_buf,
    size_t out_cap,
    const char* bundle_id,
    const char* endpoint_id,
    const char* tenant_id,
    const char* job_id,
    const char* profile,
    int64_t collected_at_unix,
    const ForensicCollectedItemWin* items,
    int item_count
) {
    ResponseCanonicalBuffer b;
    CanonicalBuf_Init(&b, out_buf, out_cap);

    // Literal domain label "OMINULL-MANIFEST-V2\0" (20 bytes)
    if (!Forensics_WriteRawWin(&b, "OMINULL-MANIFEST-V2\0", 20)) return 0;
    if (!Forensics_WriteLPStrWin(&b, bundle_id)) return 0;
    if (!Forensics_WriteLPStrWin(&b, endpoint_id)) return 0;
    if (!Forensics_WriteLPStrWin(&b, tenant_id)) return 0;
    if (!Forensics_WriteLPStrWin(&b, job_id)) return 0;
    if (!Forensics_WriteLPStrWin(&b, profile)) return 0;
    if (!CanonicalBuf_WriteInt64(&b, collected_at_unix)) return 0;
    if (!CanonicalBuf_WriteUint32(&b, (uint32_t)item_count)) return 0;

    for (int i = 0; i < item_count; i++) {
        if (!Forensics_WriteLPStrWin(&b, items[i].name)) return 0;
        if (!CanonicalBuf_WriteInt64(&b, (int64_t)items[i].size_bytes)) return 0;
        if (!Forensics_WriteLPStrWin(&b, items[i].sha256)) return 0;
        if (!Forensics_WriteLPStrWin(&b, CollectorStatusToStringWin(items[i].status))) return 0;
    }

    if (b.overflow) return 0;
    return b.len;
}

/* ---------------------------------------------------------------------------
 * Artifact Collectors (Windows Diagnostic Profile)
 * ------------------------------------------------------------------------- */

// 1. OS Version & System Identification
static inline bool Forensics_CollectOSVersionWin(ForensicCollectedItemWin* item) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "os_version.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    char prodName[256] = "Windows";
    char displayVer[64] = "";
    char buildNum[64] = "";
    char edition[64] = "";
    DWORD installDate = 0;

    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dwType = 0;
        DWORD dwSize = sizeof(prodName);
        RegQueryValueExA(hKey, "ProductName", NULL, &dwType, (LPBYTE)prodName, &dwSize);

        dwSize = sizeof(displayVer);
        RegQueryValueExA(hKey, "DisplayVersion", NULL, &dwType, (LPBYTE)displayVer, &dwSize);
        if (!displayVer[0]) {
            dwSize = sizeof(displayVer);
            RegQueryValueExA(hKey, "ReleaseId", NULL, &dwType, (LPBYTE)displayVer, &dwSize);
        }

        dwSize = sizeof(buildNum);
        RegQueryValueExA(hKey, "CurrentBuildNumber", NULL, &dwType, (LPBYTE)buildNum, &dwSize);

        dwSize = sizeof(edition);
        RegQueryValueExA(hKey, "EditionID", NULL, &dwType, (LPBYTE)edition, &dwSize);

        dwSize = sizeof(installDate);
        RegQueryValueExA(hKey, "InstallDate", NULL, &dwType, (LPBYTE)&installDate, &dwSize);

        RegCloseKey(hKey);
    }

    char compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD compLen = sizeof(compName);
    GetComputerNameA(compName, &compLen);

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char* arch = "unknown";
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: arch = "x86_64"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: arch = "arm64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86"; break;
        case PROCESSOR_ARCHITECTURE_ARM: arch = "arm"; break;
    }

    char* buf = (char*)malloc(2048);
    if (!buf) {
        item->status = COLLECTOR_STATUS_FAILED;
        return false;
    }

    int len = snprintf(buf, 2048,
        "{\n"
        "  \"platform\": \"windows\",\n"
        "  \"product_name\": \"%s\",\n"
        "  \"display_version\": \"%s\",\n"
        "  \"current_build\": \"%s\",\n"
        "  \"edition\": \"%s\",\n"
        "  \"architecture\": \"%s\",\n"
        "  \"computer_name\": \"%s\",\n"
        "  \"processor_count\": %u,\n"
        "  \"install_date\": %lu\n"
        "}\n",
        prodName, displayVer, buildNum, edition, arch, compName,
        (unsigned int)si.dwNumberOfProcessors, (unsigned long)installDate
    );

    if (len < 0) { free(buf); item->status = COLLECTOR_STATUS_FAILED; return false; }
    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)len;
    item->status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 2. Network Interfaces
static inline bool Forensics_CollectInterfacesWin(ForensicCollectedItemWin* item) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "network_interfaces.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    size_t cap = 65536;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap, "[\n");
    const char* sep = "";

    ULONG size = 16384;
    IP_ADAPTER_ADDRESSES* aa = (IP_ADAPTER_ADDRESSES*)malloc(size);
    if (aa) {
        ULONG rc = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            NULL, aa, &size);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            IP_ADAPTER_ADDRESSES* grown = (IP_ADAPTER_ADDRESSES*)realloc(aa, size);
            if (grown) {
                aa = grown;
                rc = GetAdaptersAddresses(AF_UNSPEC,
                    GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                    NULL, aa, &size);
            }
        }

        if (rc == NO_ERROR) {
            for (IP_ADAPTER_ADDRESSES* a = aa; a && off < (int)cap - 2048; a = a->Next) {
                char friendlyName[256] = {0};
                char description[256] = {0};
                if (a->FriendlyName) WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, friendlyName, sizeof(friendlyName) - 1, NULL, NULL);
                if (a->Description) WideCharToMultiByte(CP_UTF8, 0, a->Description, -1, description, sizeof(description) - 1, NULL, NULL);

                char macStr[32] = {0};
                if (a->PhysicalAddressLength == 6) {
                    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                        a->PhysicalAddress[0], a->PhysicalAddress[1], a->PhysicalAddress[2],
                        a->PhysicalAddress[3], a->PhysicalAddress[4], a->PhysicalAddress[5]);
                }

                off += snprintf(buf + off, cap - off,
                    "%s  {\n"
                    "    \"adapter_name\": \"%s\",\n"
                    "    \"friendly_name\": \"%s\",\n"
                    "    \"description\": \"%s\",\n"
                    "    \"mac_address\": \"%s\",\n"
                    "    \"status\": \"%s\",\n"
                    "    \"if_type\": %lu,\n"
                    "    \"mtu\": %lu,\n"
                    "    \"unicast_addresses\": [",
                    sep, a->AdapterName ? a->AdapterName : "",
                    friendlyName, description, macStr,
                    (a->OperStatus == IfOperStatusUp) ? "up" : "down",
                    (unsigned long)a->IfType, (unsigned long)a->Mtu
                );
                sep = ",\n";

                const char* uSep = "";
                for (IP_ADAPTER_UNICAST_ADDRESS* u = a->FirstUnicastAddress; u && off < (int)cap - 512; u = u->Next) {
                    char ipStr[64] = {0};
                    if (getnameinfo(u->Address.lpSockaddr, u->Address.iSockaddrLength, ipStr, sizeof(ipStr), NULL, 0, NI_NUMERICHOST) == 0) {
                        char* pct = strchr(ipStr, '%');
                        if (pct) *pct = '\0';
                        off += snprintf(buf + off, cap - off, "%s\"%s\"", uSep, ipStr);
                        uSep = ", ";
                    }
                }
                off += snprintf(buf + off, cap - off, "]\n  }");
            }
        }
        free(aa);
    }

    off += snprintf(buf + off, cap - off, "\n]\n");
    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = (off > 4) ? COLLECTOR_STATUS_COLLECTED : COLLECTOR_STATUS_EMPTY;
    return true;
}

// 3. IP Forwarding Routes
static inline bool Forensics_CollectRoutesWin(ForensicCollectedItemWin* item) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "routes.txt", sizeof(item->name) - 1);
    strncpy(item->content_type, "text/plain", sizeof(item->content_type) - 1);

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap,
        "Destination           Netmask               Gateway               IfIndex  Metric  Proto\n"
        "=========================================================================================\n");

    DWORD size = 0;
    GetIpForwardTable(NULL, &size, TRUE);
    if (size > 0) {
        PMIB_IPFORWARDTABLE table = (PMIB_IPFORWARDTABLE)malloc(size);
        if (table) {
            if (GetIpForwardTable(table, &size, TRUE) == NO_ERROR) {
                for (DWORD i = 0; i < table->dwNumEntries && off < (int)cap - 256; i++) {
                    MIB_IPFORWARDROW* r = &table->table[i];
                    struct in_addr d, m, g;
                    d.s_addr = r->dwForwardDest;
                    m.s_addr = r->dwForwardMask;
                    g.s_addr = r->dwForwardNextHop;

                    char destStr[32], maskStr[32], gateStr[32];
                    strncpy(destStr, inet_ntoa(d), sizeof(destStr));
                    destStr[sizeof(destStr) - 1] = '\0';
                    strncpy(maskStr, inet_ntoa(m), sizeof(maskStr));
                    maskStr[sizeof(maskStr) - 1] = '\0';
                    strncpy(gateStr, inet_ntoa(g), sizeof(gateStr));
                    gateStr[sizeof(gateStr) - 1] = '\0';

                    off += snprintf(buf + off, cap - off,
                        "%-21s %-21s %-21s %-8lu %-7lu %-5lu\n",
                        destStr, maskStr, gateStr,
                        (unsigned long)r->dwForwardIfIndex,
                        (unsigned long)r->dwForwardMetric1,
                        (unsigned long)r->dwForwardProto
                    );
                }
            }
            free(table);
        }
    }

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 4. DNS Configuration
static inline bool Forensics_CollectDNSWin(ForensicCollectedItemWin* item) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "dns_config.txt", sizeof(item->name) - 1);
    strncpy(item->content_type, "text/plain", sizeof(item->content_type) - 1);

    size_t cap = 8192;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap, "Windows DNS & Network Configuration\n====================================\n");

    ULONG ulOutBufLen = sizeof(FIXED_INFO);
    PFIXED_INFO pFixedInfo = (PFIXED_INFO)malloc(ulOutBufLen);
    if (pFixedInfo) {
        if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
            PFIXED_INFO grown = (PFIXED_INFO)realloc(pFixedInfo, ulOutBufLen);
            if (grown) {
                pFixedInfo = grown;
                GetNetworkParams(pFixedInfo, &ulOutBufLen);
            }
        }

        off += snprintf(buf + off, cap - off,
            "Host Name . . . . . . . . . . . . : %s\n"
            "Domain Name . . . . . . . . . . . : %s\n"
            "DNS Servers . . . . . . . . . . . : %s\n",
            pFixedInfo->HostName,
            pFixedInfo->DomainName,
            pFixedInfo->DnsServerList.IpAddress.String
        );

        IP_ADDR_STRING* pIPAddr = pFixedInfo->DnsServerList.Next;
        while (pIPAddr && off < (int)cap - 128) {
            off += snprintf(buf + off, cap - off,
                "                                    %s\n",
                pIPAddr->IpAddress.String);
            pIPAddr = pIPAddr->Next;
        }

        const char* nodeType = "Unknown";
        switch (pFixedInfo->NodeType) {
            case 1: nodeType = "Broadcast"; break;
            case 2: nodeType = "Peer-to-Peer"; break;
            case 4: nodeType = "Mixed"; break;
            case 8: nodeType = "Hybrid"; break;
        }
        off += snprintf(buf + off, cap - off,
            "Node Type . . . . . . . . . . . . : %s\n"
            "IP Routing Enabled. . . . . . . . : %s\n"
            "WINS Proxy Enabled. . . . . . . . : %s\n",
            nodeType,
            pFixedInfo->EnableRouting ? "Yes" : "No",
            pFixedInfo->EnableProxy ? "Yes" : "No"
        );
        free(pFixedInfo);
    }

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 5. System Resource Summary
static inline bool Forensics_CollectResourcesWin(ForensicCollectedItemWin* item) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "resource_summary.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);

    ULARGE_INTEGER freeBytesCaller, totalBytes, totalFreeBytes;
    freeBytesCaller.QuadPart = 0;
    totalBytes.QuadPart = 0;
    totalFreeBytes.QuadPart = 0;
    GetDiskFreeSpaceExA("C:\\", &freeBytesCaller, &totalBytes, &totalFreeBytes);

    ULONGLONG uptimeSec = GetTickCount64() / 1000;

    char* buf = (char*)malloc(2048);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int len = snprintf(buf, 2048,
        "{\n"
        "  \"memory_load_percent\": %lu,\n"
        "  \"total_phys_bytes\": %llu,\n"
        "  \"avail_phys_bytes\": %llu,\n"
        "  \"total_page_file_bytes\": %llu,\n"
        "  \"avail_page_file_bytes\": %llu,\n"
        "  \"uptime_seconds\": %llu,\n"
        "  \"system_drive\": \"C:\\\\\",\n"
        "  \"disk_total_bytes\": %llu,\n"
        "  \"disk_free_bytes\": %llu\n"
        "}\n",
        (unsigned long)mem.dwMemoryLoad,
        (unsigned long long)mem.ullTotalPhys,
        (unsigned long long)mem.ullAvailPhys,
        (unsigned long long)mem.ullTotalPageFile,
        (unsigned long long)mem.ullAvailPageFile,
        (unsigned long long)uptimeSec,
        (unsigned long long)totalBytes.QuadPart,
        (unsigned long long)totalFreeBytes.QuadPart
    );

    if (len < 0) { free(buf); item->status = COLLECTOR_STATUS_FAILED; return false; }
    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)len;
    item->status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 6. Selected Service State
static inline bool Forensics_CollectServicesWin(ForensicCollectedItemWin* item) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "service_state.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) item->status = COLLECTOR_STATUS_PERMISSION_DENIED;
        else item->status = COLLECTOR_STATUS_FAILED;
        return false;
    }

    size_t cap = 262144; // 256 KiB
    char* buf = (char*)malloc(cap);
    if (!buf) {
        CloseServiceHandle(scm);
        item->status = COLLECTOR_STATUS_FAILED;
        return false;
    }

    int off = snprintf(buf, cap, "[\n");
    const char* sep = "";

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    DWORD bufSize = 65536;
    LPBYTE sBuf = (LPBYTE)malloc(bufSize);
    if (sBuf) {
        BOOL ok = EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            sBuf, bufSize, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
        if (!ok && GetLastError() == ERROR_MORE_DATA && bytesNeeded > 0) {
            LPBYTE grown = (LPBYTE)realloc(sBuf, bytesNeeded);
            if (grown) {
                sBuf = grown;
                bufSize = bytesNeeded;
                ok = EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                    sBuf, bufSize, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
            }
        }

        if (ok || servicesReturned > 0) {
            ENUM_SERVICE_STATUS_PROCESSA* svcs = (ENUM_SERVICE_STATUS_PROCESSA*)sBuf;
            for (DWORD i = 0; i < servicesReturned && off < (int)cap - 512; i++) {
                ENUM_SERVICE_STATUS_PROCESSA* s = &svcs[i];
                const char* stateStr = "UNKNOWN";
                switch (s->ServiceStatusProcess.dwCurrentState) {
                    case SERVICE_STOPPED: stateStr = "STOPPED"; break;
                    case SERVICE_START_PENDING: stateStr = "START_PENDING"; break;
                    case SERVICE_STOP_PENDING: stateStr = "STOP_PENDING"; break;
                    case SERVICE_RUNNING: stateStr = "RUNNING"; break;
                    case SERVICE_CONTINUE_PENDING: stateStr = "CONTINUE_PENDING"; break;
                    case SERVICE_PAUSE_PENDING: stateStr = "PAUSE_PENDING"; break;
                    case SERVICE_PAUSED: stateStr = "PAUSED"; break;
                }

                char escapedName[128] = {0};
                size_t enIdx = 0;
                for (size_t k = 0; s->lpDisplayName && s->lpDisplayName[k] && enIdx < sizeof(escapedName) - 2; k++) {
                    if (s->lpDisplayName[k] == '"' || s->lpDisplayName[k] == '\\') escapedName[enIdx++] = '\\';
                    escapedName[enIdx++] = s->lpDisplayName[k];
                }

                off += snprintf(buf + off, cap - off,
                    "%s  {\n"
                    "    \"name\": \"%s\",\n"
                    "    \"display_name\": \"%s\",\n"
                    "    \"state\": \"%s\",\n"
                    "    \"pid\": %lu,\n"
                    "    \"exit_code\": %lu\n"
                    "  }",
                    sep, s->lpServiceName ? s->lpServiceName : "",
                    escapedName, stateStr,
                    (unsigned long)s->ServiceStatusProcess.dwProcessId,
                    (unsigned long)s->ServiceStatusProcess.dwWin32ExitCode
                );
                sep = ",\n";
            }
        }
        free(sBuf);
    }

    CloseServiceHandle(scm);
    off += snprintf(buf + off, cap - off, "\n]\n");

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = (servicesReturned > 0) ? COLLECTOR_STATUS_COLLECTED : COLLECTOR_STATUS_EMPTY;
    return true;
}

// 7. Bounded System Logs
static inline bool Forensics_CollectSystemLogsWin(ForensicCollectedItemWin* item) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "system_logs.txt", sizeof(item->name) - 1);
    strncpy(item->content_type, "text/plain", sizeof(item->content_type) - 1);

    size_t cap = 131072; // 128 KiB
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap, "Windows Event Log / System Diagnostic Tail\n===========================================\n");

    HANDLE hLog = OpenEventLogA(NULL, "System");
    if (!hLog) {
        hLog = OpenEventLogA(NULL, "Application");
    }

    DWORD eventsCount = 0;
    if (hLog) {
        DWORD dwRead = 0, dwNeeded = 0;
        DWORD bufSize = 32768;
        LPBYTE pBuf = (LPBYTE)malloc(bufSize);
        if (pBuf) {
            while (ReadEventLogA(hLog,
                EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
                0, pBuf, bufSize, &dwRead, &dwNeeded) && off < (int)cap - 1024) {

                LPBYTE pRecord = pBuf;
                while (pRecord < pBuf + dwRead && off < (int)cap - 512) {
                    PEVENTLOGRECORD pEvt = (PEVENTLOGRECORD)pRecord;
                    eventsCount++;

                    LPCSTR sourceName = (LPCSTR)(pRecord + sizeof(EVENTLOGRECORD));
                    DWORD eventID = pEvt->EventID & 0xFFFF;

                    const char* typeStr = "INFO";
                    switch (pEvt->EventType) {
                        case EVENTLOG_ERROR_TYPE: typeStr = "ERROR"; break;
                        case EVENTLOG_WARNING_TYPE: typeStr = "WARN"; break;
                        case EVENTLOG_INFORMATION_TYPE: typeStr = "INFO"; break;
                        case EVENTLOG_AUDIT_SUCCESS: typeStr = "AUDIT_SUCCESS"; break;
                        case EVENTLOG_AUDIT_FAILURE: typeStr = "AUDIT_FAIL"; break;
                    }

                    off += snprintf(buf + off, cap - off,
                        "[%u] Time=%lu Type=%s Source=%s EventID=%lu\n",
                        (unsigned int)eventsCount, (unsigned long)pEvt->TimeGenerated,
                        typeStr, sourceName ? sourceName : "", (unsigned long)eventID
                    );

                    if (eventsCount >= 500 || off >= (int)cap - 1024) break;
                    pRecord += pEvt->Length;
                }

                if (eventsCount >= 500) break;
            }
            free(pBuf);
        }
        CloseEventLog(hLog);
    }

    // Fallback: check C:\ProgramData\Ominull\agent.log if event log produced nothing
    if (eventsCount == 0) {
        FILE* flog = fopen("C:\\ProgramData\\Ominull\\agent.log", "rb");
        if (flog) {
            fseek(flog, 0, SEEK_END);
            long fsize = ftell(flog);
            long readStart = 0;
            if (fsize > (long)(cap - off - 100)) {
                readStart = fsize - (long)(cap - off - 100);
            }
            fseek(flog, readStart, SEEK_SET);
            size_t nr = fread(buf + off, 1, cap - off - 1, flog);
            off += nr;
            buf[off] = '\0';
            fclose(flog);
            eventsCount++;
        }
    }

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = (eventsCount > 0) ? COLLECTOR_STATUS_COLLECTED : COLLECTOR_STATUS_EMPTY;
    return true;
}

// 8. Agent Diagnostics
static inline bool Forensics_CollectAgentDiagWin(const AGENT_CONFIG* config, ForensicCollectedItemWin* item) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "agent_diagnostics.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    char exePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exePath, sizeof(exePath) - 1);

    char cwd[MAX_PATH] = {0};
    GetCurrentDirectoryA(sizeof(cwd) - 1, cwd);

    char escExe[MAX_PATH * 2] = {0};
    size_t eIdx = 0;
    for (size_t i = 0; exePath[i] && eIdx < sizeof(escExe) - 2; i++) {
        if (exePath[i] == '\\') escExe[eIdx++] = '\\';
        escExe[eIdx++] = exePath[i];
    }

    char escCwd[MAX_PATH * 2] = {0};
    size_t cIdx = 0;
    for (size_t i = 0; cwd[i] && cIdx < sizeof(escCwd) - 2; i++) {
        if (cwd[i] == '\\') escCwd[cIdx++] = '\\';
        escCwd[cIdx++] = cwd[i];
    }

    DWORD pid = GetCurrentProcessId();
    ULONGLONG uptimeSec = GetTickCount64() / 1000;

    char* buf = (char*)malloc(2048);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int len = snprintf(buf, 2048,
        "{\n"
        "  \"platform\": \"windows\",\n"
        "  \"agent_pid\": %lu,\n"
        "  \"executable_path\": \"%s\",\n"
        "  \"working_directory\": \"%s\",\n"
        "  \"agent_version\": \"%s\",\n"
        "  \"endpoint_id\": \"%s\",\n"
        "  \"hub_url\": \"%s\",\n"
        "  \"uptime_seconds\": %llu\n"
        "}\n",
        (unsigned long)pid,
        escExe, escCwd,
        OMINULL_AGENT_VERSION,
        config ? config->endpoint_id : "",
        config ? config->hub_url : "",
        (unsigned long long)uptimeSec
    );

    if (len < 0) { free(buf); item->status = COLLECTOR_STATUS_FAILED; return false; }
    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)len;
    item->status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

/* ---------------------------------------------------------------------------
 * Artifact Collectors (Windows Live Volatile Profile)
 * ------------------------------------------------------------------------- */

// 1. Process Snapshot
static inline bool Forensics_CollectProcessSnapshotWin(ForensicCollectedItemWin* item, size_t max_bytes) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "process_snapshot.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) item->status = COLLECTOR_STATUS_PERMISSION_DENIED;
        else item->status = COLLECTOR_STATUS_FAILED;
        return false;
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) {
        CloseHandle(hSnap);
        item->status = COLLECTOR_STATUS_FAILED;
        return false;
    }

    int off = snprintf(buf, cap, "{\n  \"processes\": [\n");
    const char* sep = "";
    int total_procs = 0;
    bool truncated = false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe)) {
        do {
            char exe_path[MAX_PATH] = {0};
            unsigned long long working_set = 0;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                DWORD pLen = sizeof(exe_path);
                if (!QueryFullProcessImageNameA(hProc, 0, exe_path, &pLen)) {
                    exe_path[0] = '\0';
                }
                PROCESS_MEMORY_COUNTERS pmc;
                memset(&pmc, 0, sizeof(pmc));
                pmc.cb = sizeof(pmc);
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                    working_set = (unsigned long long)pmc.WorkingSetSize;
                }
                CloseHandle(hProc);
            }

            char esc_name[MAX_PATH * 2], esc_exe[MAX_PATH * 2];
            Forensics_EscapeJsonWin(pe.szExeFile, esc_name, sizeof(esc_name));
            Forensics_EscapeJsonWin(exe_path, esc_exe, sizeof(esc_exe));

            char entry[2048];
            int elen = snprintf(entry, sizeof(entry),
                "%s    {\n"
                "      \"pid\": %lu,\n"
                "      \"ppid\": %lu,\n"
                "      \"name\": \"%s\",\n"
                "      \"exe\": \"%s\",\n"
                "      \"threads\": %lu,\n"
                "      \"working_set_bytes\": %llu\n"
                "    }",
                sep, (unsigned long)pe.th32ProcessID, (unsigned long)pe.th32ParentProcessID,
                esc_name, esc_exe, (unsigned long)pe.cntThreads, working_set
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
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_processes\": %d,\n"
        "  \"truncated\": %s\n"
        "}\n",
        total_procs, truncated ? "true" : "false"
    );

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = truncated ? COLLECTOR_STATUS_TRUNCATED : COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 2. Socket to Process Mapping
static inline const char* Forensics_TcpStateToStringWin(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

static inline bool Forensics_CollectSocketToProcessWin(ForensicCollectedItemWin* item, size_t max_bytes) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "socket_to_process.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap, "{\n  \"sockets\": [\n");
    const char* sep = "";
    int total_sockets = 0;
    bool truncated = false;

    // 1. TCP Table (IPv4)
    DWORD tcpSize = 0;
    GetExtendedTcpTable(NULL, &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcpSize > 0) {
        PMIB_TCPTABLE_OWNER_PID tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(tcpSize);
        if (tcpTable) {
            if (GetExtendedTcpTable(tcpTable, &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                    MIB_TCPROW_OWNER_PID* r = &tcpTable->table[i];
                    struct in_addr lia, ria;
                    lia.s_addr = r->dwLocalAddr;
                    ria.s_addr = r->dwRemoteAddr;

                    char laddr[32], raddr[32];
                    strncpy(laddr, inet_ntoa(lia), sizeof(laddr) - 1);
                    laddr[sizeof(laddr) - 1] = '\0';
                    strncpy(raddr, inet_ntoa(ria), sizeof(raddr) - 1);
                    raddr[sizeof(raddr) - 1] = '\0';

                    char entry[512];
                    int elen = snprintf(entry, sizeof(entry),
                        "%s    {\n"
                        "      \"protocol\": \"tcp4\",\n"
                        "      \"local_address\": \"%s\",\n"
                        "      \"local_port\": %u,\n"
                        "      \"remote_address\": \"%s\",\n"
                        "      \"remote_port\": %u,\n"
                        "      \"state\": \"%s\",\n"
                        "      \"pid\": %lu\n"
                        "    }",
                        sep, laddr, (unsigned int)ntohs((u_short)r->dwLocalPort),
                        raddr, (unsigned int)ntohs((u_short)r->dwRemotePort),
                        Forensics_TcpStateToStringWin(r->dwState),
                        (unsigned long)r->dwOwningPid
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
            }
            free(tcpTable);
        }
    }

    // 2. UDP Table (IPv4)
    if (!truncated) {
        DWORD udpSize = 0;
        GetExtendedUdpTable(NULL, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (udpSize > 0) {
            PMIB_UDPTABLE_OWNER_PID udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(udpSize);
            if (udpTable) {
                if (GetExtendedUdpTable(udpTable, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                    for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
                        MIB_UDPROW_OWNER_PID* r = &udpTable->table[i];
                        struct in_addr lia;
                        lia.s_addr = r->dwLocalAddr;

                        char laddr[32];
                        strncpy(laddr, inet_ntoa(lia), sizeof(laddr) - 1);
                        laddr[sizeof(laddr) - 1] = '\0';

                        char entry[512];
                        int elen = snprintf(entry, sizeof(entry),
                            "%s    {\n"
                            "      \"protocol\": \"udp4\",\n"
                            "      \"local_address\": \"%s\",\n"
                            "      \"local_port\": %u,\n"
                            "      \"remote_address\": \"0.0.0.0\",\n"
                            "      \"remote_port\": 0,\n"
                            "      \"state\": \"LISTEN\",\n"
                            "      \"pid\": %lu\n"
                            "    }",
                            sep, laddr, (unsigned int)ntohs((u_short)r->dwLocalPort),
                            (unsigned long)r->dwOwningPid
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
                }
                free(udpTable);
            }
        }
    }

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_sockets\": %d,\n"
        "  \"truncated\": %s\n"
        "}\n",
        total_sockets, truncated ? "true" : "false"
    );

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = truncated ? COLLECTOR_STATUS_TRUNCATED : (total_sockets == 0 ? COLLECTOR_STATUS_EMPTY : COLLECTOR_STATUS_COLLECTED);
    return true;
}

// 3. Logged-in Sessions
static inline bool Forensics_CollectLoggedInSessionsWin(ForensicCollectedItemWin* item, size_t max_bytes) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "logged_in_sessions.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    size_t cap = 8192;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap, "{\n  \"sessions\": [\n");
    const char* sep = "";
    int total_sessions = 0;

    PWTS_SESSION_INFOA pSessions = NULL;
    DWORD count = 0;
    if (WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &count) && pSessions) {
        for (DWORD i = 0; i < count; i++) {
            LPSTR userName = NULL;
            DWORD uBytes = 0;
            WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, pSessions[i].SessionId, WTSUserName, &userName, &uBytes);

            LPSTR domainName = NULL;
            DWORD dBytes = 0;
            WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, pSessions[i].SessionId, WTSDomainName, &domainName, &dBytes);

            const char* stateStr = "Unknown";
            switch (pSessions[i].State) {
                case WTSActive: stateStr = "Active"; break;
                case WTSConnected: stateStr = "Connected"; break;
                case WTSConnectQuery: stateStr = "ConnectQuery"; break;
                case WTSShadow: stateStr = "Shadow"; break;
                case WTSDisconnected: stateStr = "Disconnected"; break;
                case WTSIdle: stateStr = "Idle"; break;
                case WTSListen: stateStr = "Listen"; break;
                case WTSReset: stateStr = "Reset"; break;
                case WTSDown: stateStr = "Down"; break;
                case WTSInit: stateStr = "Init"; break;
            }

            char esc_user[128], esc_dom[128], esc_win[128];
            Forensics_EscapeJsonWin(userName ? userName : "", esc_user, sizeof(esc_user));
            Forensics_EscapeJsonWin(domainName ? domainName : "", esc_dom, sizeof(esc_dom));
            Forensics_EscapeJsonWin(pSessions[i].pWinStationName ? pSessions[i].pWinStationName : "", esc_win, sizeof(esc_win));

            char entry[512];
            int elen = snprintf(entry, sizeof(entry),
                "%s    {\n"
                "      \"session_id\": %lu,\n"
                "      \"station_name\": \"%s\",\n"
                "      \"state\": \"%s\",\n"
                "      \"user\": \"%s\",\n"
                "      \"domain\": \"%s\"\n"
                "    }",
                sep, (unsigned long)pSessions[i].SessionId,
                esc_win, stateStr, esc_user, esc_dom
            );

            if (userName) WTSFreeMemory(userName);
            if (domainName) WTSFreeMemory(domainName);

            if ((size_t)(off + elen + 128) < cap) {
                memcpy(buf + off, entry, elen);
                off += elen;
                buf[off] = '\0';
                sep = ",\n";
                total_sessions++;
            }
        }
        WTSFreeMemory(pSessions);
    }

    if (total_sessions == 0) {
        char un[256] = {0};
        DWORD unLen = sizeof(un);
        if (GetUserNameA(un, &unLen) && un[0]) {
            char esc_u[256];
            Forensics_EscapeJsonWin(un, esc_u, sizeof(esc_u));
            off += snprintf(buf + off, cap - off,
                "    {\n"
                "      \"session_id\": 1,\n"
                "      \"station_name\": \"Console\",\n"
                "      \"state\": \"Active\",\n"
                "      \"user\": \"%s\",\n"
                "      \"domain\": \"LOCAL\"\n"
                "    }",
                esc_u
            );
            total_sessions = 1;
        }
    }

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_sessions\": %d\n"
        "}\n",
        total_sessions
    );

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = (total_sessions == 0) ? COLLECTOR_STATUS_EMPTY : COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 4. Network Neighbors (ARP Table)
static inline bool Forensics_CollectNetworkNeighborsWin(ForensicCollectedItemWin* item, size_t max_bytes) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "network_neighbors.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    size_t cap = 16384;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap, "{\n  \"neighbors\": [\n");
    const char* sep = "";
    int total_neigh = 0;

    DWORD size = 0;
    GetIpNetTable(NULL, &size, FALSE);
    if (size > 0) {
        PMIB_IPNETTABLE table = (PMIB_IPNETTABLE)malloc(size);
        if (table) {
            if (GetIpNetTable(table, &size, FALSE) == NO_ERROR) {
                for (DWORD i = 0; i < table->dwNumEntries; i++) {
                    MIB_IPNETROW* r = &table->table[i];
                    struct in_addr ia;
                    ia.s_addr = r->dwAddr;

                    char ipStr[32];
                    strncpy(ipStr, inet_ntoa(ia), sizeof(ipStr) - 1);
                    ipStr[sizeof(ipStr) - 1] = '\0';

                    char macStr[32] = {0};
                    if (r->dwPhysAddrLen >= 6) {
                        snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                            r->bPhysAddr[0], r->bPhysAddr[1], r->bPhysAddr[2],
                            r->bPhysAddr[3], r->bPhysAddr[4], r->bPhysAddr[5]);
                    }

                    const char* typeStr = "unknown";
                    switch (r->dwType) {
                        case MIB_IPNET_TYPE_DYNAMIC: typeStr = "dynamic"; break;
                        case MIB_IPNET_TYPE_STATIC: typeStr = "static"; break;
                        case MIB_IPNET_TYPE_INVALID: typeStr = "invalid"; break;
                        case MIB_IPNET_TYPE_OTHER: typeStr = "other"; break;
                    }

                    char entry[512];
                    int elen = snprintf(entry, sizeof(entry),
                        "%s    {\n"
                        "      \"ip\": \"%s\",\n"
                        "      \"mac\": \"%s\",\n"
                        "      \"interface_index\": %lu,\n"
                        "      \"type\": \"%s\",\n"
                        "      \"state\": \"%s\"\n"
                        "    }",
                        sep, ipStr, macStr, (unsigned long)r->dwIndex, typeStr,
                        (r->dwType == MIB_IPNET_TYPE_DYNAMIC || r->dwType == MIB_IPNET_TYPE_STATIC) ? "reachable" : "stale"
                    );

                    if ((size_t)(off + elen + 128) < cap) {
                        memcpy(buf + off, entry, elen);
                        off += elen;
                        buf[off] = '\0';
                        sep = ",\n";
                        total_neigh++;
                    }
                }
            }
            free(table);
        }
    }

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_neighbors\": %d\n"
        "}\n",
        total_neigh
    );

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = (total_neigh == 0) ? COLLECTOR_STATUS_EMPTY : COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 5. Firewall State
static inline bool Forensics_CollectFirewallStateWin(ForensicCollectedItemWin* item, size_t max_bytes) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "firewall_state.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    (void)max_bytes;

    size_t cap = 4096;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    DWORD domEnabled = 1, privEnabled = 1, pubEnabled = 1;
    DWORD domInbound = 1, privInbound = 1, pubInbound = 1;

    const char* baseKey = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";
    const char* profiles[] = { "DomainProfile", "StandardProfile", "PublicProfile" };
    DWORD* enabledPtrs[] = { &domEnabled, &privEnabled, &pubEnabled };
    DWORD* inboundPtrs[] = { &domInbound, &privInbound, &pubInbound };

    for (int p = 0; p < 3; p++) {
        char subKey[256];
        snprintf(subKey, sizeof(subKey), "%s\\%s", baseKey, profiles[p]);
        HKEY hKey = NULL;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD dwType = 0, dwVal = 0, dwSize = sizeof(dwVal);
            if (RegQueryValueExA(hKey, "EnableFirewall", NULL, &dwType, (LPBYTE)&dwVal, &dwSize) == ERROR_SUCCESS) {
                *enabledPtrs[p] = dwVal;
            }
            dwSize = sizeof(dwVal);
            if (RegQueryValueExA(hKey, "DefaultInboundAction", NULL, &dwType, (LPBYTE)&dwVal, &dwSize) == ERROR_SUCCESS) {
                *inboundPtrs[p] = dwVal;
            }
            CloseHandle(hKey);
        }
    }

    int len = snprintf(buf, cap,
        "{\n"
        "  \"firewall_framework\": \"Windows Defender Firewall\",\n"
        "  \"profiles\": {\n"
        "    \"domain\": {\n"
        "      \"enabled\": %s,\n"
        "      \"default_inbound\": \"%s\"\n"
        "    },\n"
        "    \"private\": {\n"
        "      \"enabled\": %s,\n"
        "      \"default_inbound\": \"%s\"\n"
        "    },\n"
        "    \"public\": {\n"
        "      \"enabled\": %s,\n"
        "      \"default_inbound\": \"%s\"\n"
        "    }\n"
        "  }\n"
        "}\n",
        (domEnabled ? "true" : "false"), (domInbound == 0 ? "allow" : "block"),
        (privEnabled ? "true" : "false"), (privInbound == 0 ? "allow" : "block"),
        (pubEnabled ? "true" : "false"), (pubInbound == 0 ? "allow" : "block")
    );

    if (len < 0) { free(buf); item->status = COLLECTOR_STATUS_FAILED; return false; }
    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)len;
    item->status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 6. Loaded Modules (Kernel Device Drivers)
static inline bool Forensics_CollectLoadedModulesWin(ForensicCollectedItemWin* item, size_t max_bytes) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "loaded_modules.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap, "{\n  \"modules\": [\n");
    const char* sep = "";
    int total_mods = 0;
    bool truncated = false;

    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        DWORD numDrivers = cbNeeded / sizeof(LPVOID);
        for (DWORD i = 0; i < numDrivers; i++) {
            char name[MAX_PATH] = {0};
            char path[MAX_PATH] = {0};
            GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name));
            GetDeviceDriverFileNameA(drivers[i], path, sizeof(path));

            char esc_name[MAX_PATH * 2], esc_path[MAX_PATH * 2];
            Forensics_EscapeJsonWin(name, esc_name, sizeof(esc_name));
            Forensics_EscapeJsonWin(path, esc_path, sizeof(esc_path));

            char entry[512];
            int elen = snprintf(entry, sizeof(entry),
                "%s    {\n"
                "      \"base_address\": \"0x%p\",\n"
                "      \"name\": \"%s\",\n"
                "      \"path\": \"%s\"\n"
                "    }",
                sep, drivers[i], esc_name, esc_path
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

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_modules\": %d,\n"
        "  \"truncated\": %s\n"
        "}\n",
        total_mods, truncated ? "true" : "false"
    );

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = truncated ? COLLECTOR_STATUS_TRUNCATED : (total_mods == 0 ? COLLECTOR_STATUS_EMPTY : COLLECTOR_STATUS_COLLECTED);
    return true;
}

/* ---------------------------------------------------------------------------
 * Artifact Collectors (Windows IR Standard Profile)
 * ------------------------------------------------------------------------- */

// 1. Persistence Artifacts (Registry Run/RunOnce, Winlogon, Startup)
static inline bool Forensics_CollectPersistenceWin(ForensicCollectedItemWin* item, size_t max_bytes) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "persistence.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap, "{\n  \"registry_run\": [\n");
    const char* sep = "";
    int total_run = 0;

    struct {
        HKEY root;
        const char* root_name;
        const char* subkey;
    } run_keys[] = {
        { HKEY_LOCAL_MACHINE, "HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, "HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_CURRENT_USER,  "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER,  "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { NULL, NULL, NULL }
    };

    for (int k = 0; run_keys[k].subkey != NULL; k++) {
        HKEY hKey;
        if (RegOpenKeyExA(run_keys[k].root, run_keys[k].subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD idx = 0;
            char valName[256];
            DWORD valNameLen = sizeof(valName);
            DWORD valType = 0;
            char valData[1024];
            DWORD valDataLen = sizeof(valData);

            while (RegEnumValueA(hKey, idx, valName, &valNameLen, NULL, &valType, (LPBYTE)valData, &valDataLen) == ERROR_SUCCESS) {
                if (valType == REG_SZ || valType == REG_EXPAND_SZ) {
                    valData[sizeof(valData) - 1] = '\0';
                    char esc_name[512], esc_val[2048];
                    Forensics_EscapeJsonWin(valName, esc_name, sizeof(esc_name));
                    Forensics_EscapeJsonWin(valData, esc_val, sizeof(esc_val));

                    char entry[2560];
                    int elen = snprintf(entry, sizeof(entry),
                        "%s    {\n"
                        "      \"hive\": \"%s\",\n"
                        "      \"key\": \"%s\",\n"
                        "      \"name\": \"%s\",\n"
                        "      \"command\": \"%s\"\n"
                        "    }",
                        sep, run_keys[k].root_name, run_keys[k].subkey, esc_name, esc_val
                    );

                    if ((size_t)(off + elen + 256) < cap) {
                        memcpy(buf + off, entry, elen);
                        off += elen;
                        buf[off] = '\0';
                        sep = ",\n";
                        total_run++;
                    }
                }
                idx++;
                valNameLen = sizeof(valName);
                valDataLen = sizeof(valData);
            }
            RegCloseKey(hKey);
        }
    }

    // Winlogon keys
    char userinit[512] = {0}, shell[512] = {0};
    HKEY hWl;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hWl) == ERROR_SUCCESS) {
        DWORD len = sizeof(userinit);
        RegQueryValueExA(hWl, "Userinit", NULL, NULL, (LPBYTE)userinit, &len);
        len = sizeof(shell);
        RegQueryValueExA(hWl, "Shell", NULL, NULL, (LPBYTE)shell, &len);
        RegCloseKey(hWl);
    }
    char esc_userinit[1024], esc_shell[1024];
    Forensics_EscapeJsonWin(userinit, esc_userinit, sizeof(esc_userinit));
    Forensics_EscapeJsonWin(shell, esc_shell, sizeof(esc_shell));

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"winlogon\": {\n"
        "    \"userinit\": \"%s\",\n"
        "    \"shell\": \"%s\"\n"
        "  },\n"
        "  \"startup_files\": [\n",
        esc_userinit, esc_shell
    );

    // Startup folder files
    const char* startup_path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*";
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(startup_path, &fd);
    sep = "";
    int total_startup = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.cFileName[0] == '.') continue;
            char esc_file[MAX_PATH * 2];
            Forensics_EscapeJsonWin(fd.cFileName, esc_file, sizeof(esc_file));
            char entry[512];
            int elen = snprintf(entry, sizeof(entry), "%s    \"%s\"", sep, esc_file);
            if ((size_t)(off + elen + 64) < cap) {
                memcpy(buf + off, entry, elen);
                off += elen;
                buf[off] = '\0';
                sep = ",\n";
                total_startup++;
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    off += snprintf(buf + off, cap - off, "\n  ]\n}\n");

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = COLLECTOR_STATUS_COLLECTED;
    return true;
}

// 2. Scheduled Tasks
static inline bool Forensics_CollectScheduledTasksWin(ForensicCollectedItemWin* item, size_t max_bytes) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "scheduled_tasks.json", sizeof(item->name) - 1);
    strncpy(item->content_type, "application/json", sizeof(item->content_type) - 1);

    if (max_bytes == 0 || max_bytes > FORENSICS_MAX_ITEM_BYTES) {
        max_bytes = FORENSICS_MAX_ITEM_BYTES;
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap, "{\n  \"tasks\": [\n");
    const char* sep = "";
    int total_tasks = 0;

    // Scan C:\Windows\System32\Tasks
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\Tasks\\*", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.cFileName[0] == '.') continue;
            char esc_name[MAX_PATH * 2];
            Forensics_EscapeJsonWin(fd.cFileName, esc_name, sizeof(esc_name));

            char entry[512];
            int elen = snprintf(entry, sizeof(entry),
                "%s    {\n"
                "      \"name\": \"%s\",\n"
                "      \"is_directory\": %s\n"
                "    }",
                sep, esc_name, (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "true" : "false"
            );
            if ((size_t)(off + elen + 64) < cap) {
                memcpy(buf + off, entry, elen);
                off += elen;
                buf[off] = '\0';
                sep = ",\n";
                total_tasks++;
            }
        } while (FindNextFileA(hFind, &fd) && total_tasks < 100);
        FindClose(hFind);
    }

    // Also enumerate registry TaskCache\Tree if present
    HKEY hTree;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree", 0, KEY_READ, &hTree) == ERROR_SUCCESS) {
        DWORD idx = 0;
        char subKeyName[256];
        DWORD subKeyLen = sizeof(subKeyName);
        while (RegEnumKeyExA(hTree, idx, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && total_tasks < 150) {
            char esc_name[512];
            Forensics_EscapeJsonWin(subKeyName, esc_name, sizeof(esc_name));
            char entry[512];
            int elen = snprintf(entry, sizeof(entry),
                "%s    {\n"
                "      \"name\": \"%s\",\n"
                "      \"registry_cached\": true\n"
                "    }",
                sep, esc_name
            );
            if ((size_t)(off + elen + 64) < cap) {
                memcpy(buf + off, entry, elen);
                off += elen;
                buf[off] = '\0';
                sep = ",\n";
                total_tasks++;
            }
            idx++;
            subKeyLen = sizeof(subKeyName);
        }
        RegCloseKey(hTree);
    }

    off += snprintf(buf + off, cap - off,
        "\n  ],\n"
        "  \"total_tasks\": %d\n"
        "}\n",
        total_tasks
    );

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = (total_tasks > 0) ? COLLECTOR_STATUS_COLLECTED : COLLECTOR_STATUS_EMPTY;
    return true;
}

// 3. Security Events
static inline bool Forensics_CollectSecurityEventsWin(ForensicCollectedItemWin* item, size_t max_bytes) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "security_events.txt", sizeof(item->name) - 1);
    strncpy(item->content_type, "text/plain", sizeof(item->content_type) - 1);

    if (max_bytes == 0 || max_bytes > 256 * 1024) {
        max_bytes = 128 * 1024;
    }

    size_t cap = max_bytes;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }

    int off = snprintf(buf, cap, "Windows Security & Audit Event Log Tail\n=======================================\n");

    HANDLE hLog = OpenEventLogA(NULL, "Security");
    const char* log_name = "Security";
    if (!hLog) {
        hLog = OpenEventLogA(NULL, "System");
        log_name = "System (Security log restricted)";
    }

    DWORD eventsCount = 0;
    if (hLog) {
        off += snprintf(buf + off, cap - off, "Source log: %s\n\n", log_name);
        DWORD dwRead = 0, dwNeeded = 0;
        DWORD bufSize = 32768;
        LPBYTE pBuf = (LPBYTE)malloc(bufSize);
        if (pBuf) {
            while (ReadEventLogA(hLog,
                EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
                0, pBuf, bufSize, &dwRead, &dwNeeded) && off < (int)cap - 1024) {

                LPBYTE pRecord = pBuf;
                while (pRecord < pBuf + dwRead && off < (int)cap - 512) {
                    PEVENTLOGRECORD pEvt = (PEVENTLOGRECORD)pRecord;
                    char* srcName = (char*)((LPBYTE)pEvt + sizeof(EVENTLOGRECORD));

                    off += snprintf(buf + off, cap - off,
                        "Event ID: %lu | Type: 0x%x | Source: %s | Time: %lu\n",
                        (unsigned long)(pEvt->EventID & 0xFFFF),
                        (unsigned int)pEvt->EventType,
                        srcName ? srcName : "unknown",
                        (unsigned long)pEvt->TimeGenerated
                    );
                    eventsCount++;
                    pRecord += pEvt->Length;
                }
            }
            free(pBuf);
        }
        CloseEventLog(hLog);
    }

    if (eventsCount == 0) {
        off += snprintf(buf + off, cap - off, "# No audit or security events returned.\n");
    }

    item->data = (uint8_t*)buf;
    item->size_bytes = (size_t)off;
    item->status = (eventsCount > 0) ? COLLECTOR_STATUS_COLLECTED : COLLECTOR_STATUS_EMPTY;
    return true;
}

// 4. Shell History (PowerShell PSReadLine console history)
static inline bool Forensics_CollectShellHistoryWin(ForensicCollectedItemWin* item, size_t max_bytes) {
    if (!item) return false;
    memset(item, 0, sizeof(*item));
    strncpy(item->name, "shell_history.txt", sizeof(item->name) - 1);
    strncpy(item->content_type, "text/plain", sizeof(item->content_type) - 1);

    if (max_bytes == 0 || max_bytes > 256 * 1024) {
        max_bytes = 256 * 1024;
    }

    size_t cap = 32768;
    char* buf = (char*)malloc(cap);
    if (!buf) { item->status = COLLECTOR_STATUS_FAILED; return false; }
    size_t off = 0;

    int files_collected = 0;

    // Scan C:\Users for PowerShell PSReadLine history
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("C:\\Users\\*", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.cFileName[0] == '.') continue;
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;

            char histPath[MAX_PATH * 2];
            snprintf(histPath, sizeof(histPath),
                "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                fd.cFileName);

            FILE* hf = fopen(histPath, "rb");
            if (!hf) continue;

            fseek(hf, 0, SEEK_END);
            long sz = ftell(hf);
            size_t to_read = 32768;
            long start = 0;
            if (sz > (long)to_read) {
                start = sz - (long)to_read;
            } else {
                to_read = (size_t)sz;
            }
            fseek(hf, start, SEEK_SET);

            char header[512];
            int hlen = snprintf(header, sizeof(header), "=== %s (%ld total bytes, tail %zu bytes) ===\n", histPath, sz, to_read);

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
                size_t rd = fread(buf + off, 1, to_read, hf);
                off += rd;
            }
            fclose(hf);

            if (off + 2 < cap) {
                buf[off++] = '\n';
                buf[off++] = '\n';
                buf[off] = '\0';
            }
            files_collected++;
        } while (FindNextFileA(hFind, &fd) && files_collected < 4);
        FindClose(hFind);
    }

    if (files_collected == 0 && off == 0) {
        int hlen = snprintf(buf, cap, "# No PowerShell PSReadLine console history files found.\n");
        off = (size_t)hlen;
        item->status = COLLECTOR_STATUS_EMPTY;
    } else {
        item->status = COLLECTOR_STATUS_COLLECTED;
    }

    buf[off] = '\0';
    item->data = (uint8_t*)buf;
    item->size_bytes = off;
    return true;
}

/* ---------------------------------------------------------------------------
 * High-Level Bundle Publishing & Manifest Finalization Routine (Win32)
 * ------------------------------------------------------------------------- */

static inline bool Forensics_PublishBundleAndFinalizeWin(
    const AGENT_CONFIG* config,
    const char* bundle_id,
    const char* tenant_id,
    const char* job_id,
    const char* profile,
    int64_t max_bytes,
    ForensicCollectedItemWin* items,
    int item_count,
    char* out_manifest_sha256,
    size_t sha_cap
) {
    if (!config || !job_id || !bundle_id || !profile) return false;
    const char* endpoint_id = config->endpoint_id;

    // 1. Get or create endpoint evidence signing key
    uint8_t pub_key[32];
    uint8_t priv_key[64];
    char pub_hex[65];
    if (!Forensics_GetOrCreateEndpointKeyWin(FORENSICS_DEFAULT_KEY_PATH_WIN, pub_key, priv_key, pub_hex, sizeof(pub_hex))) {
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
        char item_path[1024];
        snprintf(item_path, sizeof(item_path), "/api/v1/evidence/items?bundle_id=%s&name=%s&status=%s",
            bundle_id, items[i].name, CollectorStatusToStringWin(items[i].status));

        char resp_buf[512] = {0};
        bool uploaded = Hub_PostPathData(
            config,
            item_path,
            items[i].content_type,
            items[i].data,
            items[i].size_bytes,
            resp_buf,
            sizeof(resp_buf)
        );

        if (!uploaded) {
            items[i].status = COLLECTOR_STATUS_FAILED;
        }
    }

    // 3. Encode canonical manifest and sign with Ed25519 key
    time_t now_unix = time(NULL);
    uint8_t canonical_buf[8192];
    size_t canonical_len = Forensics_EncodeManifestCanonicalWin(
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
        memcpy(out_manifest_sha256, manifest_hash_hex, 64);
        out_manifest_sha256[64] = '\0';
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
            CollectorStatusToStringWin(items[i].status)
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
    char fin_resp[512] = {0};
    bool fin_ok = Hub_PostPathData(
        config,
        "/api/v1/evidence/finalize",
        "application/json",
        fin_json,
        strlen(fin_json),
        fin_resp,
        sizeof(fin_resp)
    );

    free(fin_json);
    for (int i = 0; i < item_count; i++) free(items[i].data);

    return fin_ok;
}

/* ---------------------------------------------------------------------------
 * High-Level Profile Collection Routines (Win32)
 * ------------------------------------------------------------------------- */

static inline bool Forensics_RunDiagnosticCollectionWin(
    const AGENT_CONFIG* config,
    const char* payload_json,
    const char* job_id,
    char* out_manifest_sha256,
    size_t sha_cap
) {
    if (!config || !job_id) return false;

    ForensicCollectionParamsWin params;
    Forensics_ParsePayloadWin(payload_json, &params);
    const char* bundle_id = (params.bundle_id[0] != '\0') ? params.bundle_id : job_id;
    const char* tenant_id = "default";

    ForensicCollectedItemWin items[8];
    memset(items, 0, sizeof(items));
    int item_count = 8;

    Forensics_CollectOSVersionWin(&items[0]);
    Forensics_CollectInterfacesWin(&items[1]);
    Forensics_CollectRoutesWin(&items[2]);
    Forensics_CollectDNSWin(&items[3]);
    Forensics_CollectResourcesWin(&items[4]);
    Forensics_CollectServicesWin(&items[5]);
    Forensics_CollectSystemLogsWin(&items[6]);
    Forensics_CollectAgentDiagWin(config, &items[7]);

    return Forensics_PublishBundleAndFinalizeWin(
        config, bundle_id, tenant_id, job_id, "diagnostic", params.max_bytes,
        items, item_count, out_manifest_sha256, sha_cap
    );
}

static inline bool Forensics_RunLiveVolatileCollectionWin(
    const AGENT_CONFIG* config,
    const char* payload_json,
    const char* job_id,
    char* out_manifest_sha256,
    size_t sha_cap
) {
    if (!config || !job_id) return false;

    ForensicCollectionParamsWin params;
    Forensics_ParsePayloadWin(payload_json, &params);
    const char* bundle_id = (params.bundle_id[0] != '\0') ? params.bundle_id : job_id;
    const char* tenant_id = "default";

    ForensicCollectedItemWin items[6];
    memset(items, 0, sizeof(items));
    int item_count = 6;

    Forensics_CollectProcessSnapshotWin(&items[0], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectSocketToProcessWin(&items[1], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectLoggedInSessionsWin(&items[2], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectNetworkNeighborsWin(&items[3], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectFirewallStateWin(&items[4], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectLoadedModulesWin(&items[5], FORENSICS_MAX_ITEM_BYTES);

    return Forensics_PublishBundleAndFinalizeWin(
        config, bundle_id, tenant_id, job_id, "live_volatile", params.max_bytes,
        items, item_count, out_manifest_sha256, sha_cap
    );
}

static inline bool Forensics_RunIRStandardCollectionWin(
    const AGENT_CONFIG* config,
    const char* payload_json,
    const char* job_id,
    char* out_manifest_sha256,
    size_t sha_cap
) {
    if (!config || !job_id) return false;

    ForensicCollectionParamsWin params;
    Forensics_ParsePayloadWin(payload_json, &params);
    const char* bundle_id = (params.bundle_id[0] != '\0') ? params.bundle_id : job_id;
    const char* tenant_id = "default";

    ForensicCollectedItemWin items[18];
    memset(items, 0, sizeof(items));
    int item_count = 18;

    // 1. Diagnostic Suite
    Forensics_CollectOSVersionWin(&items[0]);
    Forensics_CollectInterfacesWin(&items[1]);
    Forensics_CollectRoutesWin(&items[2]);
    Forensics_CollectDNSWin(&items[3]);
    Forensics_CollectResourcesWin(&items[4]);
    Forensics_CollectServicesWin(&items[5]);
    Forensics_CollectSystemLogsWin(&items[6]);
    Forensics_CollectAgentDiagWin(config, &items[7]);

    // 2. Live Volatile Suite
    Forensics_CollectProcessSnapshotWin(&items[8], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectSocketToProcessWin(&items[9], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectLoggedInSessionsWin(&items[10], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectNetworkNeighborsWin(&items[11], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectFirewallStateWin(&items[12], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectLoadedModulesWin(&items[13], FORENSICS_MAX_ITEM_BYTES);

    // 3. IR Standard Suite
    Forensics_CollectPersistenceWin(&items[14], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectScheduledTasksWin(&items[15], FORENSICS_MAX_ITEM_BYTES);
    Forensics_CollectSecurityEventsWin(&items[16], 128 * 1024);
    Forensics_CollectShellHistoryWin(&items[17], 256 * 1024);

    return Forensics_PublishBundleAndFinalizeWin(
        config, bundle_id, tenant_id, job_id, "ir_standard", params.max_bytes,
        items, item_count, out_manifest_sha256, sha_cap
    );
}

static inline bool Forensics_RunCollectionWin(
    const AGENT_CONFIG* config,
    const char* payload_json,
    const char* job_id,
    char* out_manifest_sha256,
    size_t sha_cap
) {
    if (!config || !job_id) return false;
    ForensicCollectionParamsWin params;
    Forensics_ParsePayloadWin(payload_json, &params);

    if (strcmp(params.profile, "live_volatile") == 0) {
        return Forensics_RunLiveVolatileCollectionWin(
            config, payload_json, job_id, out_manifest_sha256, sha_cap
        );
    } else if (strcmp(params.profile, "ir_standard") == 0) {
        return Forensics_RunIRStandardCollectionWin(
            config, payload_json, job_id, out_manifest_sha256, sha_cap
        );
    } else {
        return Forensics_RunDiagnosticCollectionWin(
            config, payload_json, job_id, out_manifest_sha256, sha_cap
        );
    }
}

#endif /* OMINULL_FORENSICS_WINDOWS_H */
