#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <psapi.h>
#include <errno.h>
#include <sddl.h>
#include <aclapi.h>
#include "../include/agent.h"

static SERVICE_STATUS g_ServiceStatus;
static SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static HANDLE g_StopEvent = NULL;
static AGENT_CONFIG g_Config;

static void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            if (g_StopEvent) SetEvent(g_StopEvent);
            break;
        default:
            break;
    }
}


/* ---------------------------------------------------------------------------
 * Per-flow byte counts from the Windows user-mode APIs.
 *
 * This agent reported every flow as zero bytes because the user-mode collector
 * "has no byte counter to read". It does: TCP Extended Statistics keeps
 * DataBytesIn/DataBytesOut per connection, readable through iphlpapi by any
 * caller with administrator rights, which a service running as LocalSystem
 * has. No privileged extension or additional signed binary is involved.
 *
 * ESTATS counts for the life of a connection. PollActiveSocketFlows reports
 * every established connection on every poll, so reporting that cumulative
 * figure would have the hub add the same bytes again on each poll: a
 * connection alive for twenty polls counted twenty times. What is reported is
 * the delta since this agent last looked, which is what "bytes on this flow"
 * means everywhere else in the pipeline.
 *
 * A connection is reported as zero the first time it is seen even when ESTATS
 * already has a total for it. That total is traffic that crossed before this
 * agent was watching, and attributing it to the interval it happened to be
 * discovered in is a spike: real bytes reported at the wrong time. Zero once,
 * then true deltas.
 *
 * Collection is off by default per connection and has to be enabled, which is
 * done on first sight. Anything that fails - the enable, the read, a full
 * table - leaves the flow at zero, and zero travels the whole pipeline as "not
 * measured" rather than as "no traffic".
 * ------------------------------------------------------------------------- */

#define ESTATS_TABLE_SIZE 4096

typedef struct {
    UINT32  localIp, remoteIp;      /* network order, exactly as the table gives them */
    UINT16  localPort, remotePort;  /* network order */
    UINT8   used;
    UINT32  generation;
    ULONG64 bytesIn, bytesOut;      /* last cumulative reading */
} ESTATS_SLOT;

static ESTATS_SLOT g_estats[ESTATS_TABLE_SIZE];
static UINT32 g_estatsGeneration = 0;

#define PROCESS_PATH_CACHE_SIZE 256
typedef struct {
    DWORD pid;
    FILETIME created;
    WCHAR path[OMINULL_MAX_PATH];
    bool used;
} PROCESS_PATH_SLOT;

static PROCESS_PATH_SLOT g_processPathCache[PROCESS_PATH_CACHE_SIZE];

static bool SameFileTime(FILETIME left, FILETIME right) {
    return left.dwLowDateTime == right.dwLowDateTime && left.dwHighDateTime == right.dwHighDateTime;
}

static size_t ProcessPathSlot(DWORD pid) {
    return (size_t)((pid * 2654435761u) & (PROCESS_PATH_CACHE_SIZE - 1));
}

/* QueryFullProcessImageNameW is a cross-process lookup. The old loop repeated
 * it for every socket, so one busy process with many connections made the
 * service pay the same handle/open/path cost once per row. Cache by PID and
 * process creation time: PID reuse cannot inherit the old process's identity,
 * and the fixed table keeps stale process churn bounded. */
static void ProcessPathFor(DWORD pid, WCHAR* out, DWORD outCap) {
	if (outCap == 0) return;
    _snwprintf(out, outCap, L"C:\\Windows\\System32\\ntoskrnl.exe");
    out[outCap - 1] = L'\0';
    if (pid <= 4) return;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return;

    FILETIME created, exited, kernel, user;
    bool haveCreation = GetProcessTimes(hProc, &created, &exited, &kernel, &user) != 0;
    PROCESS_PATH_SLOT* slot = &g_processPathCache[ProcessPathSlot(pid)];
    if (haveCreation && slot->used && slot->pid == pid && SameFileTime(slot->created, created)) {
        wcsncpy(out, slot->path, outCap - 1);
        out[outCap - 1] = L'\0';
        CloseHandle(hProc);
        return;
    }

    DWORD pathLen = outCap;
    WCHAR queried[OMINULL_MAX_PATH] = {0};
    if (QueryFullProcessImageNameW(hProc, 0, queried, &pathLen)) {
        wcsncpy(out, queried, outCap - 1);
        out[outCap - 1] = L'\0';
        if (haveCreation) {
            slot->pid = pid;
            slot->created = created;
            wcsncpy(slot->path, queried, OMINULL_MAX_PATH - 1);
            slot->path[OMINULL_MAX_PATH - 1] = L'\0';
            slot->used = true;
        }
    }
    CloseHandle(hProc);
}

static size_t EstatsHash(UINT32 lip, UINT16 lport, UINT32 rip, UINT16 rport) {
    UINT32 h = lip * 2654435761u;
    h ^= (UINT32)rip + 0x9e3779b9u + (h << 6) + (h >> 2);
    h ^= ((UINT32)lport << 16 | (UINT32)rport) + 0x85ebca6bu + (h << 6) + (h >> 2);
    return (size_t)(h & (ESTATS_TABLE_SIZE - 1));
}

/* Finds this connection's slot, claiming a free one if it is new. NULL when the
 * table is full: the flow is then reported unmeasured rather than attributed to
 * whichever connection happened to hash to the same place. */
static ESTATS_SLOT* EstatsSlot(UINT32 lip, UINT16 lport, UINT32 rip, UINT16 rport, bool* isNew) {
    size_t start = EstatsHash(lip, lport, rip, rport);
    for (size_t probe = 0; probe < ESTATS_TABLE_SIZE; probe++) {
        ESTATS_SLOT* slot = &g_estats[(start + probe) & (ESTATS_TABLE_SIZE - 1)];
        if (!slot->used) {
            slot->used = 1;
            slot->localIp = lip; slot->localPort = lport;
            slot->remoteIp = rip; slot->remotePort = rport;
            slot->bytesIn = 0; slot->bytesOut = 0;
            *isNew = true;
            return slot;
        }
        if (slot->localIp == lip && slot->localPort == lport &&
            slot->remoteIp == rip && slot->remotePort == rport) {
            *isNew = false;
            return slot;
        }
    }
    return NULL;
}

/* Connections that were not seen this poll are gone. Their slots are released
 * so a later connection reusing the same ports starts from zero rather than
 * inheriting a stale total and reporting a negative delta as a huge one. */
static void EstatsEvictUnseen(void) {
    for (size_t i = 0; i < ESTATS_TABLE_SIZE; i++) {
        if (g_estats[i].used && g_estats[i].generation != g_estatsGeneration) {
            memset(&g_estats[i], 0, sizeof(g_estats[i]));
        }
    }
}

/* Reads this connection's byte counters and returns what crossed it since the
 * previous poll. Enables collection the first time the connection is seen. */
static void EstatsMeasure(const MIB_TCPROW_OWNER_PID* src, OMINULL_EVENT* ev) {
    bool isNew = false;
    ESTATS_SLOT* slot = EstatsSlot(src->dwLocalAddr, (UINT16)src->dwLocalPort,
                                   src->dwRemoteAddr, (UINT16)src->dwRemotePort, &isNew);
    if (!slot) return;
    slot->generation = g_estatsGeneration;

    MIB_TCPROW row;
    memset(&row, 0, sizeof(row));
    row.dwState = src->dwState;
    row.dwLocalAddr = src->dwLocalAddr;
    row.dwLocalPort = src->dwLocalPort;
    row.dwRemoteAddr = src->dwRemoteAddr;
    row.dwRemotePort = src->dwRemotePort;

    if (isNew) {
        TCP_ESTATS_DATA_RW_v0 rw;
        memset(&rw, 0, sizeof(rw));
        rw.EnableCollection = TRUE;
        /* Failure is not fatal and not worth logging every poll: the flow stays
         * at zero, which is the honest report for a flow nobody counted. */
        (void)SetPerTcpConnectionEStats(&row, TcpConnectionEstatsData,
                                        (PUCHAR)&rw, 0, sizeof(rw), 0);
        return;
    }

    TCP_ESTATS_DATA_ROD_v0 rod;
    memset(&rod, 0, sizeof(rod));
    if (GetPerTcpConnectionEStats(&row, TcpConnectionEstatsData,
                                  NULL, 0, 0, NULL, 0, 0,
                                  (PUCHAR)&rod, 0, sizeof(rod)) != NO_ERROR) {
        return;
    }

    /* A counter that went backwards means the four-tuple was reused by a new
     * connection between polls. Re-baseline rather than report the difference,
     * which would be a negative number in an unsigned field. */
    if (rod.DataBytesIn >= slot->bytesIn) ev->BytesIn = rod.DataBytesIn - slot->bytesIn;
    if (rod.DataBytesOut >= slot->bytesOut) ev->BytesOut = rod.DataBytesOut - slot->bytesOut;
    slot->bytesIn = rod.DataBytesIn;
    slot->bytesOut = rod.DataBytesOut;
}

static size_t PollActiveSocketFlows(OMINULL_EVENT* outEvents, size_t maxEvents) {
    size_t count = 0;
    DWORD dwSize = 0;

    g_estatsGeneration++;

    DWORD ret = GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret == ERROR_INSUFFICIENT_BUFFER && dwSize > 0) {
        PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        if (pTcpTable) {
            if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pTcpTable->dwNumEntries && count < maxEvents; i++) {
                    MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];
                    if (row.dwRemoteAddr == 0 || row.dwRemotePort == 0) continue;

                    OMINULL_EVENT* ev = &outEvents[count];
                    memset(ev, 0, sizeof(OMINULL_EVENT));
                    ev->EventType = OMINULL_EVENT_FLOW_ESTABLISHED_V4;
                    ev->Action = 0; // Permit
                    ev->Direction = 1; // Outbound
                    ev->Protocol = IPPROTO_TCP;
                    ev->IpVersion = 4;
                    ev->ProcessId = row.dwOwningPid;
                    ev->LocalPort = ntohs((u_short)row.dwLocalPort);
                    ev->RemotePort = ntohs((u_short)row.dwRemotePort);
                    ev->Addr.Ipv4.LocalIp = ntohl(row.dwLocalAddr);
                    ev->Addr.Ipv4.RemoteIp = ntohl(row.dwRemoteAddr);

                    ProcessPathFor(row.dwOwningPid, ev->ProcessPath, OMINULL_MAX_PATH);
                    EstatsMeasure(&row, ev);
                    count++;
                }
            }
            free(pTcpTable);
        }
    }
    EstatsEvictUnseen();
    return count;
}


/* ---------------------------------------------------------------------------
 * Enforcing what the hub decided.
 *
 * The hub delivers isolation in the heartbeat reply, next to the quarantined-
 * peer list, and this agent reconciles it every beat so a host that was down
 * when it was released still comes back.
 * ------------------------------------------------------------------------- */

#define MAX_BLOCKED_PEERS 64
#define PEER_ADDR_LEN 64

/* HubAddressLiteral reduces the configured hub URL to an IPv4 literal.
 *
 * Isolation must leave a hole for the hub or it can never be lifted, and the
 * hole is written as an address, so a name is resolved here while this host can
 * still resolve names. */
bool HubAddressLiteral(const AGENT_CONFIG* config, char* out, size_t cap) {
    const char* p = strstr(config->hub_url, "://");
    p = p ? p + 3 : config->hub_url;

    char host[256] = {0};
    size_t i = 0;
    while (*p && *p != ':' && *p != '/' && i < sizeof(host) - 1) host[i++] = *p++;
    host[i] = '\0';
    if (!host[0]) return false;

    struct in_addr probe;
    if (inet_pton(AF_INET, host, &probe) == 1) {
        _snprintf(out, cap, "%s", host);
        out[cap - 1] = '\0';
        return true;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;          /* the filters are v4; a v6-only hub has no hole */
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return false;

    bool ok = false;
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf))) {
        _snprintf(out, cap, "%s", buf);
        out[cap - 1] = '\0';
        ok = true;
    }
    freeaddrinfo(res);
    return ok;
}

static bool IsIPv4Literal(const char* s) {
    struct in_addr v4;
    return s && s[0] && inet_pton(AF_INET, s, &v4) == 1;
}

/* An address literal of either family. The peer and allow lists are IPv4 only
 * on this platform, but a baseline destination is not: a DHCPv6 server or the
 * ff02::1:2 relay address are both legitimate entries, and the filter engine
 * builds conditions for both families. */
static bool IsIPLiteralAny(const char* s) {
    struct in_addr v4;
    struct in6_addr v6;
    if (!s || !s[0]) return false;
    if (inet_pton(AF_INET, s, &v4) == 1) return true;
    return inet_pton(AF_INET6, s, &v6) == 1;
}

/* JsonStringField pulls one flat "key":"value" out of an object fragment. The
 * hub's baseline rules have no nesting and no escaping beyond this. */
static bool JsonStringField(const char* json, const char* key, char* out, size_t outLen) {
    char needle[48];
    _snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    needle[sizeof(needle) - 1] = '\0';
    const char* p = strstr(json, needle);
    if (!p) return false;
    p += strlen(needle);
    size_t idx = 0;
    while (*p && *p != '"' && idx < outLen - 1) out[idx++] = *p++;
    out[idx] = '\0';
    return idx > 0;
}

/* ParseBaselineRules reads the resolved baseline policy off the heartbeat reply.
 *
 * Returns the number of usable rules, or -1 when the key is absent entirely. The
 * caller has to be able to tell "this hub has no policy" from "this hub's policy
 * is empty", because they mean opposite things: the first keeps the compiled-in
 * permits, the second means hub and loopback only. */
static int ParseBaselineRules(const char* json, OMINULL_BASELINE_RULE* out, int maxOut) {
    const char* p = strstr(json, "\"isolation_baseline\":[");
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
        p = end + 1;

        OMINULL_BASELINE_RULE r;
        memset(&r, 0, sizeof(r));
        JsonStringField(frag, "service", r.service, sizeof(r.service));
        JsonStringField(frag, "destination", r.destination, sizeof(r.destination));
        JsonStringField(frag, "protocol", r.protocol, sizeof(r.protocol));
        const char* portKey = strstr(frag, "\"port\":");
        if (portKey) r.port = atoi(portKey + strlen("\"port\":"));

        /* Re-validated even though the hub validates it. These values become
         * filter conditions in the user-mode filtering API; the value itself is never echoed,
         * because it is attacker-controlled text on its way to a log. */
        if (!IsIPLiteralAny(r.destination)) {
            printf("[!] Hub sent a baseline rule whose destination is not an IP address; ignoring it.\n");
            continue;
        }
        if (strcmp(r.protocol, "udp") != 0 && strcmp(r.protocol, "tcp") != 0) {
            printf("[!] Hub sent a baseline rule for an unsupported protocol; ignoring it.\n");
            continue;
        }
        if (r.port < 1 || r.port > 65535) {
            printf("[!] Hub sent a baseline rule with an out-of-range port; ignoring it.\n");
            continue;
        }
        if (count < maxOut) out[count++] = r;
    }
    return count;
}

/* ParseAddressArray pulls the entries of a flat "key":["a","b"] array. */
static int ParseAddressArray(const char* json, const char* key,
                             char out[][PEER_ADDR_LEN], int maxOut) {
    char needle[64];
    _snprintf(needle, sizeof(needle), "\"%s\":[", key);
    needle[sizeof(needle) - 1] = '\0';
    const char* p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);

    int count = 0;
    while (*p && *p != ']' && count < maxOut) {
        while (*p && (*p == ' ' || *p == ',' || *p == '"')) p++;
        if (*p == ']' || !*p) break;
        char ip[PEER_ADDR_LEN] = {0};
        int idx = 0;
        while (*p && *p != '"' && *p != ']' && *p != ',' && idx < (int)sizeof(ip) - 1) {
            ip[idx++] = *p++;
        }
        if (!ip[0]) continue;
        /* Not echoed: it is attacker-controlled text on its way to a log. */
        if (!IsIPv4Literal(ip)) {
            printf("[!] Hub sent an entry in %s that is not an IPv4 address; ignoring it.\n", key);
            continue;
        }
        _snprintf(out[count], PEER_ADDR_LEN, "%s", ip);
        out[count][PEER_ADDR_LEN - 1] = '\0';
        count++;
    }
    return count;
}

/* What this agent has actually put in the filtering engine. At file scope rather than
 * inside SyncEnforcement because the dead-man timer has to rebuild from it -
 * specifically, to lift this host's isolation while leaving the mesh quarantine
 * it was also holding in place. */
static bool known = false;
static bool appliedIsolated = false;
static char appliedPeers[MAX_BLOCKED_PEERS][PEER_ADDR_LEN];
static int appliedPeerCount = 0;
static char appliedAllow[MAX_BLOCKED_PEERS][PEER_ADDR_LEN];
static int appliedAllowCount = 0;
static OMINULL_BASELINE_RULE appliedBaseline[OMINULL_MAX_BASELINE_RULES];
static int appliedBaselineCount = 0;
static bool appliedBaselineKnown = false;
static bool engineReady = false;
static bool engineTried = false;
static bool g_ForgetApplied = false;
static char g_DeadmanNote[160] = {0};

/* OMINULL_DEADMAN_BEATS is how many consecutive heartbeats may fail while this
 * host is isolated before it releases itself.
 *
 * The readiness gate is a prediction made before the host is cut off; this is
 * what happens when the prediction was wrong. Without it, a defect in the floor
 * means a host is gone until somebody reaches it out of band - and on this
 * platform "out of band" has meant a hypervisor console twice. With it, the same
 * defect means the host comes back and says why.
 *
 * Not 1: a hub restart, a brief network event or a rolling release must not lift
 * every isolation in the fleet. This loop flushes every 2500ms, so 120 is five
 * minutes - long enough to outlast all three, short enough that the person who
 * just isolated the host is still watching. */
#define OMINULL_DEADMAN_BEATS 120

/* EnforcementEngineReady probes the filtering engine once and caches the answer.
 *
 * It is called from two places that want it for different reasons: the enforcer,
 * which needs the engine before it can apply anything, and the readiness report,
 * which has to be able to say "this host could not enforce an isolation" *before*
 * anyone asks for one. Probing it lazily inside the enforcer only would mean the
 * first honest answer arrived one beat after it was needed.
 *
 * Not a dynamic session: isolation has to outlive a restart of this service the
 * way the Linux agent's chains do. */
static bool EnforcementEngineReady(void) {
    if (engineTried) return engineReady;
    engineTried = true;
    engineReady = (Wfp_Init(0) == ERROR_SUCCESS);
    if (!engineReady) {
        printf("[-] The user-mode filtering engine would not open, so isolation cannot be "
               "enforced on this host. Administrator rights are required.\n");
    }
    return engineReady;
}

const char* Agent_EnforcementStatus(void) {
    return EnforcementEngineReady()
        ? "ok"
        : "the user-mode filtering engine would not open; this host cannot enforce an isolation";
}

const char* Agent_LastAppliedNote(void) { return g_DeadmanNote; }

/* SyncEnforcement reconciles isolation and the mesh block list against the hub's
 * answer. The user-mode Windows Filtering Platform is the only enforcement
 * path. */
static void SyncEnforcement(const AGENT_CONFIG* config, const char* respJson) {
    if (!respJson) return;

    /* The dead-man timer released this host without the hub's agreement.
     * Forget what was applied so the next answer is treated as new and the
     * isolation is re-applied if the hub still wants one. */
    if (g_ForgetApplied) {
        known = false;
        g_ForgetApplied = false;
    }

    const char* p = strstr(respJson, "\"is_isolated\":");
    if (!p) return;                     /* an older hub; nothing to obey */
    p += strlen("\"is_isolated\":");
    while (*p == ' ') p++;
    bool wantIsolated = (strncmp(p, "true", 4) == 0);

    char peers[MAX_BLOCKED_PEERS][PEER_ADDR_LEN];
    int peerCount = ParseAddressArray(respJson, "quarantined_peers", peers, MAX_BLOCKED_PEERS);

    char allow[MAX_BLOCKED_PEERS][PEER_ADDR_LEN];
    int allowCount = ParseAddressArray(respJson, "isolation_allow_ips", allow, MAX_BLOCKED_PEERS);

    OMINULL_BASELINE_RULE baseline[OMINULL_MAX_BASELINE_RULES];
    int baselineCount = ParseBaselineRules(respJson, baseline, OMINULL_MAX_BASELINE_RULES);
    bool baselineKnown = baselineCount >= 0;
    if (!baselineKnown) baselineCount = 0;

    bool changed = !known || wantIsolated != appliedIsolated ||
                   peerCount != appliedPeerCount || allowCount != appliedAllowCount ||
                   baselineKnown != appliedBaselineKnown || baselineCount != appliedBaselineCount;
    for (int i = 0; !changed && i < baselineCount; i++) {
        if (strcmp(baseline[i].destination, appliedBaseline[i].destination) != 0 ||
            strcmp(baseline[i].protocol, appliedBaseline[i].protocol) != 0 ||
            strcmp(baseline[i].service, appliedBaseline[i].service) != 0 ||
            baseline[i].port != appliedBaseline[i].port) changed = true;
    }
    for (int i = 0; !changed && i < peerCount; i++) {
        if (strcmp(peers[i], appliedPeers[i]) != 0) changed = true;
    }
    /* The allow list is part of the applied state now that this engine enforces
     * it. Leaving it out of the comparison meant editing a trust rule changed
     * nothing until something else about the host happened to change too. */
    for (int i = 0; !changed && i < allowCount; i++) {
        if (strcmp(allow[i], appliedAllow[i]) != 0) changed = true;
    }
    if (!changed) return;

    char hubIP[64] = {0};
    if (wantIsolated && !HubAddressLiteral(config, hubIP, sizeof(hubIP))) {
        /* Refused on purpose. An isolation with no hole for the hub can never
         * be lifted by the hub - it is not a quarantine, it is a host taken off
         * the network by a failed name lookup. The order stands and is retried
         * on the next beat. */
        printf("[-] Isolation ordered, but the hub address could not be resolved from %s. "
               "Refusing to isolate: this host could not be released afterwards.\n", config->hub_url);
        return;
    }

        if (!EnforcementEngineReady()) return;

        const char* blocked[MAX_BLOCKED_PEERS];
        for (int i = 0; i < peerCount; i++) blocked[i] = peers[i];
        const char* allowed[MAX_BLOCKED_PEERS];
        for (int i = 0; i < allowCount; i++) allowed[i] = allow[i];

        if (Wfp_ApplyState(hubIP, wantIsolated ? 1 : 0, blocked, peerCount,
                           allowed, allowCount, baseline, baselineCount,
                           baselineKnown ? 1 : 0) != ERROR_SUCCESS) {
            printf("[-] The user-mode filtering engine refused the change; state not applied.\n");
            return;
        }
        if (wantIsolated && baselineKnown) {
            printf("[!] Threat Nullification: host isolated. Permitted: hub %s, loopback, "
                   "%d baseline rule(s), %d allow-list address(es). %d peer block(s) in force.\n",
                   hubIP, baselineCount, allowCount, peerCount);
        } else if (wantIsolated) {
            printf("[!] Threat Nullification: host isolated. This hub sends no baseline policy, so "
                   "the built-in floor applies: hub %s, loopback, DHCP and DNS to any destination, "
                   "%d allow-list address(es). %d peer block(s) in force.\n",
                   hubIP, allowCount, peerCount);
        } else {
            printf("[+] Threat neutralized: host isolation lifted. %d peer block(s) in force.\n", peerCount);
        }

	appliedIsolated = wantIsolated;
    memcpy(appliedPeers, peers, sizeof(peers));
    appliedPeerCount = peerCount;
    memcpy(appliedAllow, allow, sizeof(allow));
    appliedAllowCount = allowCount;
    memcpy(appliedBaseline, baseline, sizeof(baseline));
    appliedBaselineCount = baselineCount;
    appliedBaselineKnown = baselineKnown;
    known = true;
    fflush(stdout);
}

/* HubContact drives the dead-man timer. Every flush reports whether the hub
 * answered; a run of failures while this host is isolated releases the
 * isolation.
 *
 * The release rebuilds rather than tears down: the mesh quarantine this host was
 * also holding is not this timer's to lift. Only the default-deny that made the
 * host unreachable goes.
 *
 * The Windows endpoint is the one where this matters most. When an isolation
 * here cannot be released, the only channel left is the agent's own outbound
 * pinhole to the hub - and if the floor is what broke, that is gone too. */
static void HubContact(bool accepted) {
    static int missed = 0;

    if (accepted) {
        if (g_DeadmanNote[0]) {
            printf("[+] The hub is reachable again after a dead-man release. Its current answer "
                   "decides what this host enforces from here.\n");
            g_DeadmanNote[0] = '\0';
        }
        missed = 0;
        return;
    }
    if (!appliedIsolated) {
        missed = 0;
        return;
    }
    if (++missed < OMINULL_DEADMAN_BEATS) return;

    printf("[!] Isolated, and the hub has not answered for %d consecutive heartbeats. Releasing "
           "this host's isolation: an isolation the hub cannot lift is not a containment, it is a "
           "lost endpoint. %d quarantined peer(s) stay blocked.\n", missed, appliedPeerCount);
    fflush(stdout);

    bool released = false;
    if (engineReady) {
        const char* blocked[MAX_BLOCKED_PEERS];
        for (int i = 0; i < appliedPeerCount; i++) blocked[i] = appliedPeers[i];
        released = (Wfp_ApplyState(NULL, 0, blocked, appliedPeerCount, NULL, 0,
                                   appliedBaseline, appliedBaselineCount,
                                   appliedBaselineKnown ? 1 : 0) == ERROR_SUCCESS);
    }

    if (released) {
        appliedIsolated = false;
        g_ForgetApplied = true;
        _snprintf(g_DeadmanNote, sizeof(g_DeadmanNote),
                  "released by the dead-man timer after losing contact with the hub");
        g_DeadmanNote[sizeof(g_DeadmanNote) - 1] = '\0';
    } else {
        printf("[-] The dead-man release failed; this host is still isolated and still cannot "
               "reach the hub.\n");
    }
    fflush(stdout);
    missed = 0;
}

void RunAgentLoop(AGENT_CONFIG* config) {
    printf("[+] Windows collection layer: user-mode TCP socket table and ESTATS.\n");

    OMINULL_EVENT eventBatch[64];
    size_t batchCount = 0;
    DWORD lastFlush = GetTickCount();

    printf("[+] Ominull Agent running. Streaming network flows to Hub: %s\n", config->hub_url);

    while (1) {
        if (g_StopEvent && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0) {
            break;
        }

        // Poll live socket table flows.
        DWORD now = GetTickCount();
        if (now - lastFlush >= 2500) {
            size_t socketCount = PollActiveSocketFlows(eventBatch + batchCount, 64 - batchCount);
            batchCount += socketCount;

            /* The reply now carries the resolved baseline policy as well as the
             * peer list and the allow list. Four kilobytes truncated it once the
             * policy had a handful of rules in it, and a truncated reply is not
             * a parse error - it is a silently shorter enforcement state. */
            char hubResponse[16384];
            bool accepted = Hub_SendTelemetryBatch(config, eventBatch, batchCount,
                                                   hubResponse, sizeof(hubResponse));
            batchCount = 0;
            lastFlush = now;
            HubContact(accepted);

            // The hub answers with an agent_update descriptor when a newer
            // release is published. Update_Apply verifies it against the
            // pinned release key before anything is installed, and does not
            // return if the swap succeeds.
            SyncEnforcement(config, hubResponse);

            Update_Apply(config, hubResponse);
        }

        Sleep(100);
    }

    if (batchCount > 0) {
        Hub_SendTelemetryBatch(config, eventBatch, batchCount, NULL, 0);
    }

    /* The engine handle is closed, not the filters: the session is not dynamic,
     * so an isolated host stays isolated across a restart of this service and is
     * reconciled against the hub on the next beat. */
    Wfp_Close();
}

static void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
    // The SCM dispatch arguments are not the service's configuration; that was parsed
    // from the registered binPath in main() and handed over via Service_SetConfig.
    (void)argc;
    (void)argv;
    g_StatusHandle = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    RunAgentLoop(&g_Config);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// Service_SetConfig hands the command line main() parsed to the SCM entry point.
// ServiceMain cannot parse it itself: the arguments it receives come from the SCM, not
// from the registered binPath, so without this the service ran with an empty hub URL
// and key and could never report telemetry.
void Service_SetConfig(const AGENT_CONFIG* config) {
    // Repair the recovery configuration on every start, so a service that was
    // upgraded in place rather than reinstalled still has what self-update needs.
    Service_EnsureRecovery();
    // Same reasoning for the key: self-update replaces the binary and never the
    // registration, so an endpoint enrolled before --key-file existed still has
    // the key on its command line until a new build moves it.
    Service_MigrateKeyToFile(config);
    if (config) {
        g_Config = *config;
        g_Config.is_service = true;
    }
}

void Service_Run(void) {
    SERVICE_TABLE_ENTRYA ServiceTable[] = {
        {(LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)ServiceMain},
        {NULL, NULL}
    };
    StartServiceCtrlDispatcherA(ServiceTable);
}

// Service_WriteRecoveryScript drops the script the SCM's last recovery action
// runs. It is generated on every start rather than shipped in the package, so a
// service upgraded in place gets it too, and it is written into the install
// directory because that is the one place only administrators can write - the
// SCM runs it as LocalSystem.
//
// Every line of it has to be safe to run when nothing is wrong. The SCM repeats
// the last configured action once the failure count runs past the end of the
// list, so an unconditional "put the previous binary back", which is what
// shipped through v1.4.1, turns any unrelated failure into a silent downgrade.
// The update.pending guard is what makes the rollback conditional on there
// actually being an update to roll back, and the trailing start is what makes
// the repeat useful rather than merely harmless.
static bool Service_WriteRecoveryScript(const char* installDir, char* outPath, size_t cap) {
    snprintf(outPath, cap, "%s\\ominull-recover.bat", installDir);
    /* Binary mode on purpose: the CRT's text mode would translate each \n in the
     * CRLF pairs below into a second \r, and cmd is not owed that. */
    FILE* f = fopen(outPath, "wb");
    if (!f) return false;
    fprintf(f,
            "@echo off\r\n"
            "rem Generated by the Ominull agent on every start; edits are overwritten.\r\n"
            "rem Run by the SCM as the last service recovery action.\r\n"
            "if exist \"%s\\update.pending\" if exist \"%s\\ominulld.old\" (\r\n"
            "  move /y \"%s\\ominulld.old\" \"%s\\ominulld.exe\"\r\n"
            "  del /q \"%s\\update.pending\"\r\n"
            ")\r\n"
            "\"%%SystemRoot%%\\System32\\sc.exe\" start %s\r\n",
            installDir, installDir, installDir, installDir, installDir, SERVICE_NAME);
    bool ok = (ferror(f) == 0);
    return (fclose(f) == 0) && ok;
}

// Service_EnsureRecovery registers the SCM recovery actions, and does it every
// time the agent starts rather than only at install.
//
// These are the outer net, not the mechanism. Self-update restarts the service
// itself (Service_SpawnRestart below); what the SCM is for here is the case no
// code of ours can cover, a binary so broken it never runs at all. Leaning on
// the SCM for the ordinary restart is what left endpoints stopped after both
// the 1.3.3 -> 1.4.0 and 1.4.0 -> 1.4.1 rolls: the counter these actions are
// indexed by counts every abnormal exit on the host, not just this update's, so
// which action fires is decided by unrelated history.
//
// The reset period is deliberately short for the same reason. At the shipped
// 86400s a single taskkill in the morning still counted against an update in
// the evening; at 900s the list is only ever walked by a service that is
// failing now, which is what it was meant to describe. A binary that cannot
// start walks all three actions in about seventy seconds, well inside it.
//
// Registering this only at install time would have left every service upgraded
// in place without any of it: CreateService returns ERROR_SERVICE_EXISTS on an
// already-installed service, so a one-time registration path never reaches the configuration.
void Service_EnsureRecovery(void) {
    char binaryPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, binaryPath, MAX_PATH)) return;

    char installDir[MAX_PATH];
    snprintf(installDir, sizeof(installDir), "%s", binaryPath);
    char* slash = strrchr(installDir, '\\');
    if (slash) *slash = '\0';

    SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!schSCManager) return;
    // SERVICE_START is required alongside SERVICE_CHANGE_CONFIG, not optional:
    // the recovery actions include SC_ACTION_RESTART, and the SCM checks that
    // the caller may actually start the service before it will record an action
    // that starts it. Without it ChangeServiceConfig2 fails with
    // ERROR_ACCESS_DENIED even for LocalSystem - OpenService still hands back a
    // perfectly valid handle, so the failure surfaces only at the point of use.
    SC_HANDLE schService = OpenServiceA(schSCManager, SERVICE_NAME,
                                        SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_CONFIG);
    if (!schService) {
        CloseServiceHandle(schSCManager);
        return;
    }

    char sysDir[MAX_PATH];
    if (!GetSystemDirectoryA(sysDir, MAX_PATH)) {
        snprintf(sysDir, sizeof(sysDir), "C:\\Windows\\System32");
    }

    // The last action recovers from outside the process. Both the script and
    // the interpreter are named by absolute path: this runs as LocalSystem, and
    // resolving either through PATH would be a place to plant something.
    char script[MAX_PATH], rollback[MAX_PATH * 2];
    if (!Service_WriteRecoveryScript(installDir, script, sizeof(script))) {
        fprintf(stderr, "[!] Could not write the recovery script in %s (errno %d); "
                        "a failed update will not roll itself back.\n", installDir, errno);
        script[0] = '\0';
    }
    snprintf(rollback, sizeof(rollback), "%s\\cmd.exe /c call \"%s\"", sysDir, script);

    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;     actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART;     actions[1].Delay = 5000;
    actions[2].Type = script[0] ? SC_ACTION_RUN_COMMAND : SC_ACTION_RESTART;
    actions[2].Delay = script[0] ? 60000 : 30000;

    SERVICE_FAILURE_ACTIONSA fa;
    ZeroMemory(&fa, sizeof(fa));
    fa.dwResetPeriod = 900;
    fa.lpCommand = rollback;
    fa.cActions = 3;
    fa.lpsaActions = actions;
    if (!ChangeServiceConfig2A(schService, SERVICE_CONFIG_FAILURE_ACTIONS, &fa)) {
        fprintf(stderr, "[!] Could not register service recovery actions (Error: %lu); "
                        "self-update will install but not restart itself.\n", GetLastError());
    }

    // Without this flag the SCM applies recovery only to crashes, not to a
    // clean non-zero exit - which is exactly how the updater signals that the
    // binary has been replaced.
    SERVICE_FAILURE_ACTIONS_FLAG faFlag;
    faFlag.fFailureActionsOnNonCrashFailures = TRUE;
    ChangeServiceConfig2A(schService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &faFlag);

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

/* ------------------------------------------------------------------ restart
 *
 * A service cannot restart itself: the process that would issue the start is
 * the one exiting. Through v1.4.1 the agent left that to the SCM's recovery
 * actions, and that was the wrong mechanism for it. Which action the SCM runs
 * is chosen by a per-service failure counter that counts every abnormal exit on
 * the host - a crash, a taskkill, a hung stop - not just this update's, and once
 * it runs past the end of the action list the SCM repeats the last action rather
 * than starting over. On an endpoint with any earlier failure that day the
 * update's own exit landed past the end of the list, so the service installed
 * its new binary and then sat stopped until someone ran "sc start" by hand.
 * That is how both the 1.3.3 -> 1.4.0 and the 1.4.0 -> 1.4.1 rolls ended.
 *
 * The restart is explicit now. Before it exits, the updater launches a detached
 * copy of the installed binary in --restart-service mode; that process outlives
 * the service, waits for the SCM to report it STOPPED, and starts it again.
 * Nothing in that path consults, or is affected by, how many times the service
 * has failed today. The recovery actions stay registered for the one case this
 * cannot cover - a binary too broken to run the helper at all.
 */

#define RESTART_WAIT_MS     120000  /* how long a stop may take before we try anyway */
#define RESTART_POLL_MS     500
#define RESTART_ATTEMPTS    5
#define RESTART_RETRY_MS    3000

bool Service_SpawnRestart(void) {
    char self[MAX_PATH];
    if (!GetModuleFileNameA(NULL, self, MAX_PATH)) return false;

    /* The path is taken from the running module, not built from the install
     * directory, so this restarts whatever binary is actually registered - and
     * after a swap that is the new one, which is the point. */
    char cmd[MAX_PATH + 32];
    snprintf(cmd, sizeof(cmd), "\"%s\" --restart-service", self);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    /* The helper has to outlive the process that spawned it. DETACHED_PROCESS
     * keeps it off the service's console and CREATE_BREAKAWAY_FROM_JOB keeps it
     * out of a job object that would tear it down with the parent. Not every
     * host puts services in a job, and CreateProcess fails outright when a job
     * forbids breakaway, so a plain detached spawn is the fallback rather than
     * the failure. Handles are not inherited: this process is about to exit and
     * anything it held open would stay open in the child. */
    DWORD flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
        flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
            fprintf(stderr, "[!] Could not launch the restart helper (Error: %lu); "
                            "falling back to the SCM recovery actions.\n", GetLastError());
            return false;
        }
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("[+] Restart helper launched; the service will come back on its own.\n");
    return true;
}

int Service_WaitStoppedAndStart(void) {
    SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!schSCManager) {
        fprintf(stderr, "[-] Restart helper: OpenSCManager failed (Error: %lu)\n", GetLastError());
        return 1;
    }
    SC_HANDLE schService = OpenServiceA(schSCManager, SERVICE_NAME,
                                        SERVICE_QUERY_STATUS | SERVICE_START);
    if (!schService) {
        fprintf(stderr, "[-] Restart helper: OpenService failed (Error: %lu)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return 1;
    }

    /* Wait for the service that spawned this helper to actually be gone.
     * StartService against a STOP_PENDING service is refused outright, and a
     * refusal here would leave the endpoint in exactly the state being fixed. */
    SERVICE_STATUS status;
    DWORD waited = 0;
    while (QueryServiceStatus(schService, &status) &&
           status.dwCurrentState != SERVICE_STOPPED &&
           waited < RESTART_WAIT_MS) {
        Sleep(RESTART_POLL_MS);
        waited += RESTART_POLL_MS;
    }

    int rc = 1;
    for (int attempt = 1; attempt <= RESTART_ATTEMPTS; attempt++) {
        if (StartServiceA(schService, 0, NULL)) {
            rc = 0;
            break;
        }
        DWORD err = GetLastError();
        /* The SCM's own recovery restart won the race. That is the outcome we
         * wanted, so it is a success and not something to report as an error. */
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            rc = 0;
            break;
        }
        fprintf(stderr, "[!] Restart helper: start attempt %d of %d failed (Error: %lu)\n",
                attempt, RESTART_ATTEMPTS, err);
        Sleep(RESTART_RETRY_MS);
    }

    if (rc == 0) {
        printf("[+] Restart helper: %s is running again.\n", SERVICE_NAME);
    } else {
        fprintf(stderr, "[-] Restart helper: gave up after %d attempts; the SCM recovery "
                        "actions are the remaining path back.\n", RESTART_ATTEMPTS);
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return rc;
}

/* --------------------------------------------------------------- the key ---
 *
 * The tenant API key used to live on the service command line, and a service
 * command line is not private. `sc qc ominulld` needs only SERVICE_QUERY_CONFIG,
 * which the default service DACL grants to Interactive Users, so any logged-on
 * account could read it; and the SCM writes the whole binPath into a System
 * event log 7045 record when the service is installed, where it stays for the
 * life of the log. The key goes in a protected file, and the command line carries
 * only its path.
 *
 * Program Files is not enough on its own. It is writable only by
 * administrators, but it is *readable* by Users, so the key file gets an
 * explicit DACL of SYSTEM and Administrators with inheritance switched off. */

#define AGENT_KEY_FILE "agent.key"

static bool WriteProtectedFile(const char* path, const char* data) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Cannot write %s (Error: %lu)\n", path, GetLastError());
        return false;
    }
    DWORD len = (DWORD)strlen(data), wrote = 0;
    BOOL ok = WriteFile(h, data, len, &wrote, NULL) && wrote == len;
    CloseHandle(h);
    if (!ok) {
        DeleteFileA(path);
        return false;
    }

    /* D:P drops inherited access - without the P this file would keep the
     * Users read entry it inherits from Program Files, which is the whole
     * problem being fixed. FA to SY and BA leaves SYSTEM (the account the
     * service runs as) and administrators, and nobody else. */
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &sd, NULL)) {
        fprintf(stderr, "[-] Cannot build the key file DACL (Error: %lu)\n", GetLastError());
        DeleteFileA(path);
        return false;
    }

    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = NULL;
    DWORD rc = ERROR_INVALID_PARAMETER;
    if (GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present) {
        rc = SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   NULL, NULL, dacl, NULL);
    }
    LocalFree(sd);

    if (rc != ERROR_SUCCESS) {
        /* An unprotected key file is worse than none: it would be readable by
         * everyone *and* believed safe. Leave nothing behind. */
        fprintf(stderr, "[-] Cannot restrict %s (Error: %lu); not leaving a readable key on disk.\n",
                path, rc);
        DeleteFileA(path);
        return false;
    }
    return true;
}

static bool ProtectExistingFile(const char* path) {
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &sd, NULL)) {
        return false;
    }
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = NULL;
    DWORD rc = ERROR_INVALID_PARAMETER;
    if (GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present) {
        rc = SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   NULL, NULL, dacl, NULL);
    }
    LocalFree(sd);
    return rc == ERROR_SUCCESS;
}

static bool CopyProtectedFile(const char* source, const char* destination) {
    if (!source[0] || !CopyFileA(source, destination, FALSE)) return false;
    if (!ProtectExistingFile(destination)) {
        DeleteFileA(destination);
        return false;
    }
    return true;
}

/* Service_ConfigureFromStdin is the only package-facing enrollment writer.
 * Bootstrap supplies paths to staged CA/PFX files and the tenant credential on
 * stdin; this process, installed by the MSI, places them under ProgramData and
 * applies the SYSTEM/Administrators ACL before the service can start. */
bool Service_ConfigureFromStdin(void) {
    char hub[256] = {0}, key[128] = {0}, endpoint[64] = {0};
    char role[64] = "workstation", location[64] = "loc-home";
    char caSource[260] = {0}, pfxSource[260] = {0};
    char cfID[128] = {0}, cfSecret[128] = {0};
    bool allowPlaintext = false;
    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        char* value = strchr(line, '=');
        if (!value) continue;
        *value++ = '\0';
        value[strcspn(value, "\r\n")] = '\0';
        if (strchr(value, '\r') || strchr(value, '\n')) return false;
        if (strcmp(line, "hub_url") == 0) snprintf(hub, sizeof(hub), "%s", value);
        else if (strcmp(line, "api_key") == 0) snprintf(key, sizeof(key), "%s", value);
        else if (strcmp(line, "endpoint_id") == 0) snprintf(endpoint, sizeof(endpoint), "%s", value);
        else if (strcmp(line, "role_tag") == 0) snprintf(role, sizeof(role), "%s", value);
        else if (strcmp(line, "location_id") == 0) snprintf(location, sizeof(location), "%s", value);
        else if (strcmp(line, "ca_source") == 0) snprintf(caSource, sizeof(caSource), "%s", value);
        else if (strcmp(line, "client_pfx_source") == 0) snprintf(pfxSource, sizeof(pfxSource), "%s", value);
        else if (strcmp(line, "cf_client_id") == 0) snprintf(cfID, sizeof(cfID), "%s", value);
        else if (strcmp(line, "cf_client_secret") == 0) snprintf(cfSecret, sizeof(cfSecret), "%s", value);
        else if (strcmp(line, "allow_plaintext") == 0) allowPlaintext = strcmp(value, "1") == 0;
    }
    if (!hub[0] || !key[0] || !endpoint[0] || !caSource[0]) {
        fprintf(stderr, "[-] Package enrollment is missing a required field.\n");
        return false;
    }
    if (!allowPlaintext && strncmp(hub, "https://", 8) != 0) {
        fprintf(stderr, "[-] Package enrollment requires an https hub URL.\n");
        return false;
    }
    if (!CreateDirectoryA("C:\\ProgramData\\Ominull", NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        fprintf(stderr, "[-] Cannot create the package data directory (Error: %lu)\n", GetLastError());
        return false;
    }

    if (!WriteProtectedFile(OMINULL_DEFAULT_KEY_PATH, key)) {
        fprintf(stderr, "[-] Cannot install the package API key (Error: %lu).\n", GetLastError());
        return false;
    }
    if (!CopyProtectedFile(caSource, "C:\\ProgramData\\Ominull\\ca.crt")) {
        fprintf(stderr, "[-] Cannot install the package CA file (Error: %lu)\n", GetLastError());
        return false;
    }
    if (pfxSource[0] && !CopyProtectedFile(pfxSource, "C:\\ProgramData\\Ominull\\client.pfx")) {
        fprintf(stderr, "[-] Cannot install the package client certificate (Error: %lu)\n", GetLastError());
        return false;
    }

    char config[2048];
    int n = snprintf(config, sizeof(config),
                     "hub_url=%s\nkey_path=%s\nendpoint_id=%s\nrole_tag=%s\nlocation_id=%s\n"
                     "ca_path=C:\\ProgramData\\Ominull\\ca.crt\nclient_pfx_path=C:\\ProgramData\\Ominull\\client.pfx\n"
                     "cf_client_id=%s\ncf_client_secret=%s\nallow_plaintext=%d\n",
                     hub, OMINULL_DEFAULT_KEY_PATH, endpoint, role, location, cfID, cfSecret, allowPlaintext ? 1 : 0);
    if (n < 0 || (size_t)n >= sizeof(config) || !WriteProtectedFile(OMINULL_DEFAULT_CONFIG_PATH, config)) {
        DeleteFileA(OMINULL_DEFAULT_KEY_PATH);
        return false;
    }
    printf("[+] Package-owned agent configuration installed.\n");
    return true;
}

/* BuildServiceCommandLine writes the binPath. It is the only place the
 * service's configuration exists - ServiceMain gets the SCM's argv, not this
 * one - so anything omitted here is silently lost at the next start. It once
 * carried only the hub URL and the key, which dropped the role and location an
 * operator enrolled with.
 *
 * The quoting matters: paths under Program Files contain a space. */
static int BuildServiceCommandLine(const AGENT_CONFIG* config, const char* binaryPath,
                                   char* out, size_t cap) {
    int n;
    if (config->key_path[0]) {
        n = snprintf(out, cap,
                     "\"%s\" --service --hub %s --key-file \"%s\" --role %s --location %s --id %s --ca \"%s\"",
                     binaryPath, config->hub_url, config->key_path,
                     config->role_tag[0] ? config->role_tag : "workstation",
                     config->location_id[0] ? config->location_id : "loc-home",
                     config->endpoint_id, config->ca_path);
    } else {
        n = snprintf(out, cap,
                     "\"%s\" --service --hub %s --key %s --role %s --location %s --id %s --ca \"%s\"",
                     binaryPath, config->hub_url, config->api_key,
                     config->role_tag[0] ? config->role_tag : "workstation",
                     config->location_id[0] ? config->location_id : "loc-home",
                     config->endpoint_id, config->ca_path);
    }
    if (n < 0 || (size_t)n >= cap) return -1;

    if (config->cf_client_id[0] && config->cf_client_secret[0]) {
        int m = snprintf(out + n, cap - n, " --cf-id %s --cf-secret %s",
                         config->cf_client_id, config->cf_client_secret);
        if (m < 0 || (size_t)(n + m) >= cap) return -1;
        n += m;
    }
    if (config->allow_plaintext) {
        int m = snprintf(out + n, cap - n, " --allow-plaintext");
        if (m < 0 || (size_t)(n + m) >= cap) return -1;
        n += m;
    }
    if (config->client_pfx_path[0]) {
        int m = snprintf(out + n, cap - n, " --client-pfx \"%s\"", config->client_pfx_path);
        if (m < 0 || (size_t)(n + m) >= cap) return -1;
        n += m;
    }
    if (config->verbose) {
        int m = snprintf(out + n, cap - n, " --verbose");
        if (m < 0 || (size_t)(n + m) >= cap) return -1;
        n += m;
    }
    return n;
}

/* StoreKeyBesideBinary writes the running key into the install directory and
 * reports the path it used. */
static bool StoreKeyBesideBinary(const AGENT_CONFIG* config, char* outPath, size_t cap) {
    char binaryPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, binaryPath, MAX_PATH)) return false;
    char* slash = strrchr(binaryPath, '\\');
    if (!slash) return false;
    *slash = '\0';
    snprintf(outPath, cap, "%s\\%s", binaryPath, AGENT_KEY_FILE);
    return WriteProtectedFile(outPath, config->api_key);
}

void Service_MigrateKeyToFile(const AGENT_CONFIG* config) {
    if (!config || config->key_path[0]) return;   /* already off the command line */
    if (!config->api_key[0]) return;

    AGENT_CONFIG moved = *config;
    if (!StoreKeyBesideBinary(config, moved.key_path, sizeof(moved.key_path))) {
        fprintf(stderr, "[!] Could not move the API key off the service command line; "
                        "it stays readable through `sc qc %s`.\n", SERVICE_NAME);
        return;
    }

    char binaryPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, binaryPath, MAX_PATH)) return;

    char cmdLine[MAX_PATH * 4];
    if (BuildServiceCommandLine(&moved, binaryPath, cmdLine, sizeof(cmdLine)) < 0) {
        fprintf(stderr, "[!] Service command line would be truncated; leaving the registration alone.\n");
        return;
    }

    SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!schSCManager) return;
    SC_HANDLE schService = OpenServiceA(schSCManager, SERVICE_NAME,
                                        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
    if (!schService) {
        CloseServiceHandle(schSCManager);
        return;
    }

    if (ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                             cmdLine, NULL, NULL, NULL, NULL, NULL, NULL)) {
        /* The key is out of the live configuration from here. The 7045 record
         * the SCM wrote at install still holds the old one, and nothing can
         * redact that - the key it names has to be rotated. */
        printf("[+] Moved the API key out of the service command line into %s.\n", moved.key_path);
    } else {
        fprintf(stderr, "[!] Could not rewrite the service command line (Error: %lu); "
                        "the key stays readable through `sc qc %s`.\n", GetLastError(), SERVICE_NAME);
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

/* Service_OwnsBinary reports whether the installed service runs the binary at
 * path. It exists so a console session cannot quietly replace a service's
 * installation: the updater swaps the binary on disk and exits, and run from a
 * console that swap lands on the file the SCM will start next time while the
 * service carries on running the image it already has. An operator debugging a
 * service with --console would have upgraded it by accident, with nothing to
 * say so until the next restart.
 *
 * The comparison is on the first token of the binPath, unquoted, case
 * insensitively - Windows paths are not case sensitive and the registration
 * quotes the path because Program Files contains a space. */
bool Service_OwnsBinary(const char* path) {
    if (!path || !path[0]) return false;

    SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!schSCManager) return false;
    SC_HANDLE schService = OpenServiceA(schSCManager, SERVICE_NAME, SERVICE_QUERY_CONFIG);
    if (!schService) {
        CloseServiceHandle(schSCManager);
        return false;
    }

    bool owns = false;
    DWORD needed = 0;
    QueryServiceConfigA(schService, NULL, 0, &needed);
    if (needed > 0) {
        LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)malloc(needed);
        if (cfg && QueryServiceConfigA(schService, cfg, needed, &needed) && cfg->lpBinaryPathName) {
            const char* p = cfg->lpBinaryPathName;
            char exe[MAX_PATH] = {0};
            size_t n = 0;
            if (*p == '"') {
                p++;
                while (*p && *p != '"' && n + 1 < sizeof(exe)) exe[n++] = *p++;
            } else {
                while (*p && *p != ' ' && n + 1 < sizeof(exe)) exe[n++] = *p++;
            }
            exe[n] = '\0';
            owns = (_stricmp(exe, path) == 0);
        }
        free(cfg);
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return owns;
}
