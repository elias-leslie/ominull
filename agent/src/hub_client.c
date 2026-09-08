#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <iphlpapi.h>
#include <stdarg.h>
#include "../include/agent.h"

/* WinHTTP keeps a connection alive when its response body is drained. The old
 * heartbeat path opened and closed a session and a connection every 2.5s, so
 * every beat paid proxy discovery, TCP setup, and TLS session work again. The
 * service sends telemetry serially, but the updater can share the process, so
 * keep this small handle pool behind one process lock. Requests remain
 * short-lived: response and request state never leak between heartbeats. */
typedef struct {
    CRITICAL_SECTION lock;
    HINTERNET session;
    HINTERNET connect;
    WCHAR host[128];
    WORD port;
    BOOL isHttps;
} HUB_HTTP_CONTEXT;

static HUB_HTTP_CONTEXT g_http;
static INIT_ONCE g_httpInit = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK InitializeHubHTTP(PINIT_ONCE initOnce, PVOID parameter, PVOID* context) {
    (void)initOnce;
    (void)parameter;
    (void)context;
    InitializeCriticalSection(&g_http.lock);
    return TRUE;
}

static bool HubHTTPEnter(void) {
    if (!InitOnceExecuteOnce(&g_httpInit, InitializeHubHTTP, NULL, NULL)) {
        return false;
    }
    EnterCriticalSection(&g_http.lock);
    return true;
}

static void HubHTTPDropConnection(void) {
    if (g_http.connect) {
        WinHttpCloseHandle(g_http.connect);
        g_http.connect = NULL;
    }
    g_http.host[0] = L'\0';
    g_http.port = 0;
    g_http.isHttps = FALSE;
}

static bool HubHTTPPrepare(const WCHAR* host, WORD port, BOOL isHttps) {
    if (!g_http.session) {
        g_http.session = WinHttpOpen(L"OminullAgent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!g_http.session) {
            return false;
        }
        if (!WinHttpSetTimeouts(g_http.session, 5000, 5000, 10000, 10000)) {
            WinHttpCloseHandle(g_http.session);
            g_http.session = NULL;
            return false;
        }
    }

    if (g_http.connect && (g_http.port != port || g_http.isHttps != isHttps ||
                           wcscmp(g_http.host, host) != 0)) {
        HubHTTPDropConnection();
    }
    if (!g_http.connect) {
        g_http.connect = WinHttpConnect(g_http.session, host, port, 0);
        if (!g_http.connect) {
            return false;
        }
        wcsncpy(g_http.host, host, sizeof(g_http.host) / sizeof(g_http.host[0]) - 1);
        g_http.host[sizeof(g_http.host) / sizeof(g_http.host[0]) - 1] = L'\0';
        g_http.port = port;
        g_http.isHttps = isHttps;
    }
    return true;
}

static bool HubHTTPReadBody(HINTERNET request, char* out, size_t outCap) {
    size_t used = 0;
    char discard[1024];

    if (out && outCap > 0) {
        out[0] = '\0';
    }
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available)) {
            return false;
        }
        if (available == 0) {
            break;
        }

        char* destination = discard;
        DWORD wanted = (DWORD)sizeof(discard);
        bool capture = false;
        if (out && outCap > 1 && used < outCap - 1) {
            size_t remaining = outCap - 1 - used;
            wanted = remaining < available ? (DWORD)remaining : available;
            destination = out + used;
            capture = true;
        } else if (available < wanted) {
            wanted = available;
        }

        DWORD received = 0;
        if (!WinHttpReadData(request, destination, wanted, &received) || received == 0) {
            return false;
        }
        if (capture) {
            used += received;
        }
    }
    if (out && outCap > 0) {
        out[used < outCap ? used : outCap - 1] = '\0';
    }
    return true;
}

/* ---------------------------------------------------------------------------
 * Host identity
 *
 * The hub keys asset identity on the hardware address, so what the agent
 * reports here decides whether a machine stays one asset record across a DHCP
 * lease change or forks a second one. Everything below is observed; nothing is
 * assumed. A field that cannot be determined is left empty, and the hub treats
 * empty as unknown rather than recording a guess as ground truth.
 * ------------------------------------------------------------------------- */

static void ReadRegString(const char* value, char* out, DWORD outLen) {
    out[0] = '\0';
    DWORD size = outLen;
    if (RegGetValueA(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     value, RRF_RT_REG_SZ, NULL, out, &size) != ERROR_SUCCESS) {
        out[0] = '\0';
    }
}

static void DetectOSVersion(char* out, size_t outLen) {
    char product[96] = {0};
    char display[32] = {0};
    char build[32] = {0};

    ReadRegString("ProductName", product, sizeof(product));
    ReadRegString("DisplayVersion", display, sizeof(display));
    ReadRegString("CurrentBuildNumber", build, sizeof(build));

    /* Windows 11 still reports a ProductName of "Windows 10 ..." - the edition
     * is right, the number is not. Build 22000 is the 10/11 boundary and is the
     * only reliable discriminator available from the registry. */
    char name[128] = {0};
    if (product[0]) {
        snprintf(name, sizeof(name), "%s", product);
        if (atoi(build) >= 22000 && strncmp(name, "Windows 10", 10) == 0) {
            char tail[128] = {0};
            snprintf(tail, sizeof(tail), "%s", name + 10);
            snprintf(name, sizeof(name), "Windows 11%s", tail);
        }
    } else {
        snprintf(name, sizeof(name), "Windows");
    }

    SYSTEM_INFO si;
    ZeroMemory(&si, sizeof(si));
    GetNativeSystemInfo(&si);
    const char* arch = "unknown";
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: arch = "x86_64"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: arch = "arm64";  break;
        case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86";    break;
        default: break;
    }

    if (display[0]) {
        snprintf(out, outLen, "%s %s (%s)", name, display, arch);
    } else {
        snprintf(out, outLen, "%s (%s)", name, arch);
    }
}

/* Picks the adapter that actually carries this host's traffic: up, not
 * loopback, holding an IPv4 or globally scoped IPv6 address. An adapter with a gateway wins outright -
 * that is the same "default route" test the Linux agent makes - so a host with
 * a live NIC plus a stack of virtual bridges reports the NIC. */
static void DetectPrimaryAdapter(char* outIp, size_t ipLen, char* outMac, size_t macLen) {
    outIp[0] = '\0';
    outMac[0] = '\0';

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW || size == 0) {
        return;
    }

    IP_ADAPTER_ADDRESSES* adapters = (IP_ADAPTER_ADDRESSES*)malloc(size);
    if (!adapters) {
        return;
    }
    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, adapters, &size) != NO_ERROR) {
        free(adapters);
        return;
    }

    bool haveGateway = false;
    for (IP_ADAPTER_ADDRESSES* a = adapters; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->PhysicalAddressLength != 6) continue;
        if (!a->FirstUnicastAddress) continue;

        char address[64] = {0};
        for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
            struct sockaddr *sa = u->Address.lpSockaddr;
            if (!sa) continue;
            if (sa->sa_family == AF_INET) {
                struct sockaddr_in *v4 = (void *)sa;
                if (v4->sin_addr.s_addr && InetNtopA(AF_INET, &v4->sin_addr, address, sizeof(address))) break;
            } else if (sa->sa_family == AF_INET6 && !address[0]) {
                struct sockaddr_in6 *v6 = (void *)sa;
                /* A globally scoped address identifies an IPv6-only endpoint.
                 * Link-local needs an interface and is retained by flow rows. */
                if (IN6_IS_ADDR_UNSPECIFIED(&v6->sin6_addr) || IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr) ||
                    IN6_IS_ADDR_LINKLOCAL(&v6->sin6_addr)) continue;
                InetNtopA(AF_INET6, &v6->sin6_addr, address, sizeof(address));
            }
        }
        if (!address[0]) continue;

        bool hasGateway = (a->FirstGatewayAddress != NULL);
        if (haveGateway && !hasGateway) continue;

        snprintf(outIp, ipLen, "%s", address);

        const unsigned char* m = a->PhysicalAddress;
        snprintf(outMac, macLen, "%02x:%02x:%02x:%02x:%02x:%02x",
                 m[0], m[1], m[2], m[3], m[4], m[5]);

        if (hasGateway) {
            haveGateway = true;
            break;
        }
    }

    free(adapters);
}

void Agent_DetectHostIdentity(AGENT_CONFIG* config) {
    if (!config) return;
    DetectPrimaryAdapter(config->primary_ip, sizeof(config->primary_ip),
                         config->primary_mac, sizeof(config->primary_mac));
    DetectOSVersion(config->os_version, sizeof(config->os_version));
    Agent_DetectInstallProvenance(config);
}


static void IPToString(uint32_t ip, char* outStr, size_t maxLen) {
    uint8_t b1 = (ip >> 24) & 0xFF;
    uint8_t b2 = (ip >> 16) & 0xFF;
    uint8_t b3 = (ip >> 8) & 0xFF;
    uint8_t b4 = ip & 0xFF;
    snprintf(outStr, maxLen, "%u.%u.%u.%u", b1, b2, b3, b4);
}

static const char* EventTypeToString(uint32_t evtType) {
    switch (evtType) {
        case OMINULL_EVENT_CONNECT_V4: return "CONNECT_V4";
        case OMINULL_EVENT_CONNECT_V6: return "CONNECT_V6";
        case OMINULL_EVENT_RECV_ACCEPT_V4: return "RECV_ACCEPT_V4";
        case OMINULL_EVENT_RECV_ACCEPT_V6: return "RECV_ACCEPT_V6";
        case OMINULL_EVENT_FLOW_ESTABLISHED_V4: return "FLOW_ESTABLISHED_V4";
        case OMINULL_EVENT_FLOW_ESTABLISHED_V6: return "FLOW_ESTABLISHED_V6";
        case OMINULL_EVENT_FLOW_CLOSED: return "FLOW_CLOSED";
        case OMINULL_EVENT_BLOCKED: return "BLOCKED";
        default: return "UNKNOWN";
    }
}

/* AppendObservations writes the observed-services array and the readiness object
 * into the telemetry payload.
 *
 * GetAdaptersAddresses is asked for the adapters that are up and have a
 * gateway - the resolvers on a disconnected virtual adapter are not what this
 * host resolves against, and reporting them would put entries in front of an
 * operator that no baseline will ever need to cover. GetAdaptersInfo carries the
 * DHCP server and the DHCP-enabled flag, which the newer call does not expose in
 * a form this needs. */
static int AppendObservations(const AGENT_CONFIG* config, char* buf, size_t cap) {
    int off = _snprintf(buf, cap, ",\"observed_services\":[");
    const char* sep = "";
    bool dhcpSeen = false;

    ULONG size = 16384;
    IP_ADAPTER_ADDRESSES* aa = (IP_ADAPTER_ADDRESSES*)malloc(size);
    if (aa) {
        ULONG rc = GetAdaptersAddresses(AF_UNSPEC,
                                        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                        GAA_FLAG_SKIP_FRIENDLY_NAME,
                                        NULL, aa, &size);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            IP_ADAPTER_ADDRESSES* grown = (IP_ADAPTER_ADDRESSES*)realloc(aa, size);
            if (grown) {
                aa = grown;
                rc = GetAdaptersAddresses(AF_UNSPEC,
                                          GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                          GAA_FLAG_SKIP_FRIENDLY_NAME,
                                          NULL, aa, &size);
            }
        }
        if (rc == NO_ERROR) {
            for (IP_ADAPTER_ADDRESSES* a = aa; a && off < (int)cap - 256; a = a->Next) {
                if (a->OperStatus != IfOperStatusUp) continue;
                if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
                for (IP_ADAPTER_DNS_SERVER_ADDRESS* d = a->FirstDnsServerAddress;
                     d && off < (int)cap - 256; d = d->Next) {
                    char ip[64] = {0};
                    if (getnameinfo(d->Address.lpSockaddr, d->Address.iSockaddrLength,
                                    ip, sizeof(ip), NULL, 0, NI_NUMERICHOST) != 0) continue;
                    /* A scoped v6 literal arrives as fe80::1%12; the scope is
                     * local to this host and means nothing in a hub-side policy. */
                    char* pct = strchr(ip, '%');
                    if (pct) *pct = '\0';
                    if (!ip[0]) continue;
                    off += _snprintf(buf + off, cap - off,
                                     "%s{\"service\":\"dns\",\"destination\":\"%s\",\"source\":\"adapter configuration\"}",
                                     sep, ip);
                    sep = ",";
                }
            }
        }
        free(aa);
    }

    ULONG infoSize = 0;
    if (GetAdaptersInfo(NULL, &infoSize) == ERROR_BUFFER_OVERFLOW && infoSize) {
        IP_ADAPTER_INFO* info = (IP_ADAPTER_INFO*)malloc(infoSize);
        if (info) {
            if (GetAdaptersInfo(info, &infoSize) == NO_ERROR) {
                for (IP_ADAPTER_INFO* a = info; a && off < (int)cap - 256; a = a->Next) {
                    if (!a->DhcpEnabled) continue;
                    const char* server = a->DhcpServer.IpAddress.String;
                    if (!server || !server[0] || strcmp(server, "0.0.0.0") == 0) continue;
                    dhcpSeen = true;
                    off += _snprintf(buf + off, cap - off,
                                     "%s{\"service\":\"dhcp\",\"destination\":\"%s\",\"source\":\"dhcp lease\"}",
                                     sep, server);
                    sep = ",";
                }
            }
            free(info);
        }
    }

    char hubLiteral[64] = {0};
    if (!HubAddressLiteral(config, hubLiteral, sizeof(hubLiteral))) hubLiteral[0] = '\0';

    off += _snprintf(buf + off, cap - off,
                     "],\"isolation_readiness\":{\"enforcement_engine\":\"%s\",\"hub_literal\":\"%s\","
                     "\"address_origin\":\"%s\",\"last_applied\":\"%s\"}",
                     Agent_EnforcementStatus(),
                     hubLiteral,
                     dhcpSeen ? "dhcp" : "static",
                     Agent_LastAppliedNote());
    return off;
}

static bool TelemetryAppend(char *json, size_t capacity, size_t *offset, const char *format, ...) {
    if (*offset >= capacity)
        return false;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(json + *offset, capacity - *offset, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= capacity - *offset)
        return false;
    *offset += (size_t)n;
    return true;
}
static bool TelemetryTime(UINT64 ticks, char *out, size_t capacity) {
    if (!ticks)
        return false;
    FILETIME ft = {(DWORD)ticks, (DWORD)(ticks >> 32)};
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st))
        return false;
    int n = snprintf(out, capacity, "%04u-%02u-%02uT%02u:%02u:%02u.%07lluZ", st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond, ticks % 10000000);
    return n > 0 && (size_t)n < capacity;
}
/* A link-local TCP row supplies its interface index. ETW rows without one
 * are omitted by their collector; never serialize an ambiguous address. */
static bool IPv6AddressText(const UINT8 address[16], DWORD scope, char *out, size_t capacity) {
    if (!InetNtopA(AF_INET6, (void *)address, out, capacity)) return false;
    if (address[0] == 0xfe && (address[1] & 0xc0) == 0x80) {
        if (!scope) return false;
        size_t length = strlen(out);
        int n = snprintf(out + length, capacity - length, "%%%lu", (unsigned long)scope);
        if (n < 0 || (size_t)n >= capacity - length) return false;
    }
    return true;
}

char *Hub_BuildTelemetryJSON(const AGENT_CONFIG *config, const OMINULL_EVENT *events, size_t count) {
    if (!config || count > 64 || (count && !events))
        return NULL;
    size_t capacity = 16384 + 16384 * count, offset = 0;
    char *json = malloc(capacity);
    if (!json)
        return NULL;
#define APPEND(...)                                                                                          \
    do {                                                                                                     \
        if (!TelemetryAppend(json, capacity, &offset, __VA_ARGS__))                                          \
            goto failed;                                                                                     \
    } while (0)
#define FIELD(name, value)                                                                                   \
    do {                                                                                                     \
        char escaped[6145];                                                                                  \
        ProcessLineageWin_EscapeJSON(value, escaped, sizeof(escaped));                                       \
        APPEND(",\"%s\":\"%s\"", name, escaped);                                                             \
    } while (0)
    APPEND("{\"type\":\"telemetry\",\"tenant_id\":\"default\"");
    FIELD("endpoint_id", config->endpoint_id);
    if (config->evidence_signing_key[0])
        FIELD("evidence_signing_key", config->evidence_signing_key);
    FIELD("location_id", config->location_id[0] ? config->location_id : "loc-home");
    FIELD("role", config->role_tag[0] ? config->role_tag : "workstation");
    FIELD("hostname", config->hostname);
    FIELD("os", config->os_version);
    FIELD("ip", config->primary_ip);
    FIELD("mac", config->primary_mac);
    FIELD("driver_version", OMINULL_AGENT_VERSION);
    FIELD("update_capability", "msi");
    FIELD("install_type", config->install_type);
    FIELD("package_identifier", config->package_identifier);
    FIELD("registered_package_version", config->registered_package_version);
    FIELD("provenance_status", config->provenance_status);
    APPEND(",\"events\":[");
    for (size_t i = 0; i < count; i++) {
        const OMINULL_EVENT *e = &events[i];
        char local[64], remote[64];
        if (e->IpVersion == 4) {
            IPToString(e->Addr.Ipv4.LocalIp, local, sizeof(local));
            IPToString(e->Addr.Ipv4.RemoteIp, remote, sizeof(remote));
        } else if (e->IpVersion == 6) {
            if (!IPv6AddressText(e->Addr.Ipv6.LocalIp, e->LocalScopeId, local, sizeof(local)) ||
                !IPv6AddressText(e->Addr.Ipv6.RemoteIp, e->RemoteScopeId, remote, sizeof(remote)))
                goto failed;
        } else
            goto failed;
        char path[OMINULL_MAX_PATH * 4] = {0};
        if (e->ProcessPath[0] && !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, e->ProcessPath, -1, path,
                                                      sizeof(path), NULL, NULL))
            goto failed;
        APPEND("%s{\"protocol\":%u,\"src_port\":%u,\"dst_port\":%u,\"bytes_in\":%llu,\"bytes_out\":%llu,"
               "\"process_id\":%llu",
               i ? "," : "", e->Protocol, e->LocalPort, e->RemotePort, e->BytesIn, e->BytesOut, e->ProcessId);
        FIELD("layer", e->Protocol == 17 ? "windows-etw-udp-v1" : EventTypeToString(e->EventType));
        FIELD("action", e->Action == 1 ? "BLOCK" : "PERMIT");
        FIELD("direction", e->Direction == 1 ? "OUTBOUND" : "INBOUND");
        FIELD("src_ip", local);
        FIELD("dst_ip", remote);
        FIELD("process_path", path);
        FIELD("process_instance_id", e->Enrichment.process_instance_id);
        APPEND(",\"parent_pid\":%lu", e->Enrichment.ppid);
        FIELD("parent_process_instance_id", e->Enrichment.parent_process_instance_id);
        FIELD("command_line", e->Enrichment.command_line);
        FIELD("user_identity", e->Enrichment.user_identity);
        FIELD("executable_sha256", e->Enrichment.executable_sha256);
        FIELD("attribution_status",
              e->Enrichment.attribution_status[0] ? e->Enrichment.attribution_status : "unknown");
        if (e->Enrichment.observed_at > 0) {
            char observed[64];
            UINT64 ticks = ((UINT64)e->Enrichment.observed_at + 11644473600ULL) * 10000000ULL;
            if (!TelemetryTime(ticks, observed, sizeof(observed)))
                goto failed;
            FIELD("observed_at", observed);
        }
        if (e->ObservationCount) {
            char first[64], last[64];
            if (!TelemetryTime(e->FirstObservedAt, first, sizeof(first)) ||
                !TelemetryTime(e->LastObservedAt, last, sizeof(last)))
                goto failed;
            FIELD("timestamp", last);
            APPEND(",\"observation\":{\"source\":\"%s\",\"timing\":\"%s\",\"byte_basis\":\"%s\",\"count\":%"
                   "llu,\"first_at\":\"%s\",\"last_at\":\"%s\"}",
                   e->Protocol == 17 ? "windows-etw-udp" : "windows-estats",
                   e->Protocol == 17 ? "socket_io" : "counter_sample",
                   e->Protocol == 17 ? "udp_payload" : (e->BytesMeasured ? "tcp_socket_counter" : "unknown"),
                   e->ObservationCount, first, last);
        }
        APPEND("}");
    }
    APPEND("]");
    char health[1024];
    if (Agent_CollectorHealthJSON(health, sizeof(health)))
        APPEND(",\"collector_health\":[%s]", health);
    char observations[4096];
    if (AppendObservations(config, observations, sizeof(observations)) > 0)
        APPEND("%s", observations);
    APPEND("}");
#undef FIELD
#undef APPEND
    return json;
failed:
    free(json);
    return NULL;
}

bool Hub_SendTelemetryBatch(const AGENT_CONFIG* config, const OMINULL_EVENT* events, size_t count,
                            char* respOut, size_t respCap) {
    if (!config) {
        return false;
    }
    if (respOut && respCap > 0) {
        respOut[0] = '\0';
    }

    /* Checked before the batch is built, not after the send fails. The payload
     * and the device credential header that authenticates it are the things being
     * protected, so the hub has to be proven to be the hub first. */
    if (!Hub_TransportReady(config)) {
        return false;
    }

    char hostStr[128] = {0};
    WCHAR wHost[128] = {0};
    WORD port = 80;
    BOOL isHttps = FALSE;
    Hub_SplitURL(config->hub_url, hostStr, sizeof(hostStr), &port, &isHttps);
    MultiByteToWideChar(CP_UTF8, 0, hostStr, -1, wHost, 128);

    char *jsonBuf = Hub_BuildTelemetryJSON(config, events, count);
    if (!jsonBuf) return false;

    // Send HTTP POST via the persistent WinHTTP session/connection.
    if (!HubHTTPEnter()) {
        free(jsonBuf);
        return false;
    }

    if (!HubHTTPPrepare(wHost, port, isHttps)) {
        LeaveCriticalSection(&g_http.lock);
        free(jsonBuf);
        return false;
    }
    HINTERNET hConnect = g_http.connect;

    /* New identities use their endpoint credential header. A retained legacy
     * install keeps its legacy shared key on X-API-Key only until the hub's
     * successful response delivers the unique credential. */
    WCHAR wPath[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, "/api/v1/events", -1, wPath, 512);

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        wPath,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        isHttps ? WINHTTP_FLAG_SECURE : 0
    );

    if (!hRequest) {
        HubHTTPDropConnection();
        LeaveCriticalSection(&g_http.lock);
        free(jsonBuf);
        return false;
    }

    /* Present this endpoint's certificate, when enrolment issued one. It has to
     * be set on the handle before WinHttpSendRequest: the client certificate is
     * chosen during the handshake, and by the time the request has been sent
     * there is nothing left to negotiate. */
    Hub_AttachClientCert(hRequest, config);

    /* No SECURITY_FLAG_IGNORE_* overrides. They were here because there was no
     * trusted anchor to check against; enrolment installs the hub's CA now, so
     * an unknown issuer, a mismatched name or an expired certificate fails the
     * handshake instead of being waved through. */

    WCHAR wHeaders[1024] = {0};
    WCHAR wKey[128] = {0};
    MultiByteToWideChar(CP_UTF8, 0, config->api_key, -1, wKey, 128);
    const wchar_t* credentialHeader = strncmp(config->api_key, "omd_", 4) == 0
        ? L"X-Ominull-Device-Credential" : L"X-API-Key";
    swprintf(wHeaders, 1024, L"%ls: %ls\r\nContent-Type: application/json\r\n", credentialHeader, wKey);

    WinHttpAddRequestHeaders(hRequest, wHeaders, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    BOOL bResults = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        jsonBuf,
        (DWORD)strlen(jsonBuf),
        (DWORD)strlen(jsonBuf),
        0
    );

    /* A hub that verifies certificates asks for one during the handshake, and
     * WinHTTP fails the send rather than answering an ask it cannot satisfy.
     * Resend once having said there is none; the hub accepts an endpoint that
     * has not enrolled an identity yet. */
    if (!bResults && Hub_RetryWithoutClientCert(hRequest, GetLastError())) {
        bResults = WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            jsonBuf,
            (DWORD)strlen(jsonBuf),
            (DWORD)strlen(jsonBuf),
            0
        );
    }

    DWORD dwStatusCode = 0;
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        /* The body carries isolation state and the update descriptor. Confirm
         * the peer is still the enrolled hub before any of it is read, so a
         * mid-session identity change cannot steer this endpoint. */
        if (bResults && !Hub_VerifyRequestPin(hRequest, config)) {
            bResults = FALSE;
        }
        if (bResults) {
            DWORD dwSize = sizeof(dwStatusCode);
            if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                     WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize,
                                     WINHTTP_NO_HEADER_INDEX)) {
                bResults = FALSE;
            }

            /* Keep the body. Until now it was discarded, which is why this
             * agent never noticed the update descriptor the hub has been
             * sending it all along. Drain the full body even when the caller
             * does not want it, otherwise WinHTTP cannot reuse this connection. */
            if (bResults && !HubHTTPReadBody(hRequest, respOut, respCap)) {
                bResults = FALSE;
            }
        }
    }

    /* Rate-limited, and specific about a rejected credential. A hub that is
     * refusing this endpoint repeats the refusal on every heartbeat, so an
     * unthrottled line would bury the one that says when it started - and
     * "HTTP 401" on its own reads like a transient hub problem rather than a
     * key this endpoint will never authenticate with again. */
    if (dwStatusCode == 401 || dwStatusCode == 403) {
        static DWORD lastAuthReport = 0;
        DWORD now = GetTickCount();
        if (lastAuthReport == 0 || now - lastAuthReport >= 60000) {
            /* 403 while presenting a certificate is the identity check and not
             * the key: the hub compares the name in the certificate against the
             * endpoint id being reported and refuses the two disagreeing. */
            if (dwStatusCode == 403 && Hub_HasClientCert()) {
                printf("[!] The hub refused this endpoint's telemetry with HTTP %lu. It reports as "
                       "\"%s\", which is not the endpoint named by %s; re-enrol or correct --id. "
                       "Nothing is being recorded until it is fixed.\n",
                       dwStatusCode, config->endpoint_id, config->client_pfx_path);
            } else {
                printf("[!] The hub refused this endpoint's telemetry with HTTP %lu. The API key in "
                       "--key-file is not one it accepts; nothing is being recorded until it is fixed.\n",
                       dwStatusCode);
            }
            lastAuthReport = now;
        }
    } else if (dwStatusCode >= 200 && dwStatusCode < 300) {
        /* Reported from evidence, once. The startup banner says what the agent
         * is about to do; this says the hub actually took it. */
        static bool everAccepted = false;
        if (!everAccepted) {
            everAccepted = true;
            printf("[+] The hub accepted this endpoint's first telemetry batch (HTTP %lu).\n", dwStatusCode);
        }
        if (config->verbose) {
            printf("[*] Telemetry POST status: HTTP %lu\n", dwStatusCode);
        }
    } else if (config->verbose || !bResults || dwStatusCode != 200) {
        printf("[*] Telemetry POST status: HTTP %lu (WinHTTP: %d, Err: %lu)\n", dwStatusCode, bResults, GetLastError());
    }

    WinHttpCloseHandle(hRequest);
    if (!bResults) {
        HubHTTPDropConnection();
    }
    LeaveCriticalSection(&g_http.lock);
    free(jsonBuf);

    return (bResults && (dwStatusCode == 200 || dwStatusCode == 204));
}

bool Hub_PostPathData(const AGENT_CONFIG* config, const char* apiPath, const char* contentType,
                      const void* data, size_t dataLen, char* respOut, size_t respCap) {
    if (!Hub_TransportReady(config) || !apiPath || (!data && dataLen > 0)) return false;

    char host[256] = {0};
    WORD port = 0;
    BOOL isHttps = FALSE;
    Hub_SplitURL(config->hub_url, host, sizeof(host), &port, &isHttps);
    WCHAR wHost[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, host, -1, wHost, 256);

    if (!HubHTTPEnter()) {
        return false;
    }

    if (!HubHTTPPrepare(wHost, port, isHttps)) {
        LeaveCriticalSection(&g_http.lock);
        return false;
    }
    HINTERNET hConnect = g_http.connect;

    WCHAR wPath[1024] = {0};
    MultiByteToWideChar(CP_UTF8, 0, apiPath, -1, wPath, 1024);

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        wPath,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        isHttps ? WINHTTP_FLAG_SECURE : 0
    );

    if (!hRequest) {
        HubHTTPDropConnection();
        LeaveCriticalSection(&g_http.lock);
        return false;
    }

    Hub_AttachClientCert(hRequest, config);

    WCHAR wHeaders[1024] = {0};
    WCHAR wKey[128] = {0};
    WCHAR wContentType[128] = {0};
    MultiByteToWideChar(CP_UTF8, 0, config->api_key, -1, wKey, 128);
    MultiByteToWideChar(CP_UTF8, 0, (contentType && contentType[0]) ? contentType : "application/octet-stream", -1, wContentType, 128);
    const wchar_t* credentialHeader = strncmp(config->api_key, "omd_", 4) == 0
        ? L"X-Ominull-Device-Credential" : L"X-API-Key";
    swprintf(wHeaders, 1024, L"%ls: %ls\r\nContent-Type: %ls\r\n", credentialHeader, wKey, wContentType);

    WinHttpAddRequestHeaders(hRequest, wHeaders, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    BOOL bResults = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        (LPVOID)data,
        (DWORD)dataLen,
        (DWORD)dataLen,
        0
    );

    if (!bResults && Hub_RetryWithoutClientCert(hRequest, GetLastError())) {
        bResults = WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            (LPVOID)data,
            (DWORD)dataLen,
            (DWORD)dataLen,
            0
        );
    }

    DWORD dwStatusCode = 0;
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (bResults && !Hub_VerifyRequestPin(hRequest, config)) {
            bResults = FALSE;
        }
        if (bResults) {
            DWORD dwSize = sizeof(dwStatusCode);
            if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                     WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize,
                                     WINHTTP_NO_HEADER_INDEX)) {
                bResults = FALSE;
            }

            if (bResults && respOut && respCap > 0) {
                if (!HubHTTPReadBody(hRequest, respOut, respCap)) {
                    bResults = FALSE;
                }
            } else if (bResults) {
                char sink[512];
                HubHTTPReadBody(hRequest, sink, sizeof(sink));
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    if (!bResults) {
        HubHTTPDropConnection();
    }
    LeaveCriticalSection(&g_http.lock);

    return (bResults && (dwStatusCode >= 200 && dwStatusCode < 300));
}

bool Hub_PostPathJSON(const AGENT_CONFIG* config, const char* apiPath, const char* jsonBody, char* respOut, size_t respCap) {
    if (!jsonBody) return false;
    return Hub_PostPathData(config, apiPath, "application/json", jsonBody, strlen(jsonBody), respOut, respCap);
}
