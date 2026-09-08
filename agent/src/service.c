#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <psapi.h>
#include <sddl.h>
#include <aclapi.h>
#include "../include/agent.h"
#include "../windows/udp_collector.h"
#include "../windows/tcp_pending.h"
#include "../include/forensics_windows.h"
#include "../include/software_inventory_windows.h"

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

/* All address bytes and ports use network order. Zero initialized keys include
 * family, scope and process creation time, never a TCP state or counter. */
typedef struct {
    UINT8 family;
    UINT8 local[16], remote[16];
    UINT16 localPort, remotePort;
    DWORD localScope, remoteScope, pid;
    UINT64 created;
} TCP_KEY_WIN;
typedef struct { TCP_KEY_WIN key; DWORD state; } TCP_ROW_WIN;
typedef struct {
    TCP_KEY_WIN key;
    bool used;
    UINT32 generation;
    ULONG64 bytesIn, bytesOut;
    UINT64 lastSample;
} ESTATS_SLOT;

static UINT64 TCPProcessCreated(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return 0;
    FILETIME created, exited, kernel, user;
    UINT64 value = GetProcessTimes(process, &created, &exited, &kernel, &user)
        ? UDPWinFileTime(created) : 0;
    CloseHandle(process);
    return value;
}

static size_t TCPKeyHash(const TCP_KEY_WIN *key) {
    const unsigned char *bytes = (const unsigned char *)key;
    UINT32 hash = 2166136261u;
    for (size_t i = 0; i < sizeof(*key); i++) hash = (hash ^ bytes[i]) * 16777619u;
    return hash;
}

static bool TCPAddressReportable(const TCP_KEY_WIN *key) {
    static const UINT8 zero[16] = {0}, loop6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (!key->remotePort) return false;
    if (key->family == 4)
        return key->local[0] != 127 && key->remote[0] != 127 && memcmp(key->remote, zero, 4);
    if ((key->local[0] == 0xfe && (key->local[1] & 0xc0) == 0x80 && !key->localScope) ||
        (key->remote[0] == 0xfe && (key->remote[1] & 0xc0) == 0x80 && !key->remoteScope)) return false;
    return memcmp(key->remote, zero, 16) && memcmp(key->local, loop6, 16) &&
           memcmp(key->remote, loop6, 16);
}

static ESTATS_SLOT g_estats[ESTATS_TABLE_SIZE];
static UINT32 g_estatsGeneration = 0;
static UINT64 g_TCPWinUnmeasured, g_TCPWinDeferred;
static DWORD g_TCPWinQueryError;

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
/* What is sent when no process can be attributed to a socket.
 *
 * This used to answer with the path of the Windows kernel image, which is not
 * a process that owns sockets and is not what was on the other end. It was a
 * fabricated attribution, and because that name sits on the hub's quiet list,
 * every destination behind it was quietly excused as well - a closed socket to
 * an address this host had never contacted before raised nothing at all. An
 * unowned socket now says so. Process id 4 is left alone: that one really is
 * the System process, and it really does own sockets. */
static void ProcessPathFor(DWORD pid, WCHAR* out, DWORD outCap) {
	if (outCap == 0) return;
    _snwprintf(out, outCap, L"unknown");
    out[outCap - 1] = L'\0';
    if (pid == 4) {
        _snwprintf(out, outCap, L"System");
        out[outCap - 1] = L'\0';
        return;
    }
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

static ESTATS_SLOT* EstatsSlot(const TCP_KEY_WIN *key, bool *isNew) {
    size_t start = TCPKeyHash(key) & (ESTATS_TABLE_SIZE - 1);
    ESTATS_SLOT *available = NULL;
    for (size_t probe = 0; probe < ESTATS_TABLE_SIZE; probe++) {
        ESTATS_SLOT *slot = &g_estats[(start + probe) & (ESTATS_TABLE_SIZE - 1)];
        if (slot->used && !memcmp(&slot->key, key, sizeof(*key))) {
            *isNew = false;
            return slot;
        }
        if (!slot->used && !available) available = slot;
    }
    if (!available) return NULL;
    memset(available, 0, sizeof(*available));
    available->used = true;
    available->key = *key;
    *isNew = true;
    return available;
}

/* Connections that were not seen this poll are gone. Their slots are released
 * so a later connection reusing the same ports starts from zero rather than
 * inheriting a stale total and reporting a negative delta as a huge one. */
static void EstatsEvictUnseen(void) {
    FILETIME sample; GetSystemTimeAsFileTime(&sample);
    UINT64 now = UDPWinFileTime(sample);
    for (size_t i = 0; i < ESTATS_TABLE_SIZE; i++) {
        if (g_estats[i].used && g_estats[i].generation != g_estatsGeneration &&
            now >= g_estats[i].lastSample && now - g_estats[i].lastSample > 300ULL * 10000000ULL) {
            memset(&g_estats[i], 0, sizeof(g_estats[i]));
        }
    }
}

/* Reads this connection's byte counters and returns what crossed it since the
 * previous poll. Enables collection the first time the connection is seen. */
static DWORD TCPReadCounters(const TCP_ROW_WIN *src, bool enable, TCP_ESTATS_DATA_ROD_v0 *rod) {
    MIB_TCPROW row = {0};
    MIB_TCP6ROW row6 = {0};
    const TCP_KEY_WIN *key = &src->key;
    if (key->family == 6) {
        row6.State = src->state;
        memcpy(&row6.LocalAddr, key->local, 16);
        memcpy(&row6.RemoteAddr, key->remote, 16);
        row6.dwLocalScopeId = key->localScope;
        row6.dwRemoteScopeId = key->remoteScope;
        row6.dwLocalPort = key->localPort;
        row6.dwRemotePort = key->remotePort;
    } else {
        row.dwState = src->state;
        memcpy(&row.dwLocalAddr, key->local, 4);
        memcpy(&row.dwRemoteAddr, key->remote, 4);
        row.dwLocalPort = key->localPort;
        row.dwRemotePort = key->remotePort;
    }
    if (enable) {
        TCP_ESTATS_DATA_RW_v0 rw = {0}; rw.EnableCollection = TRUE;
        DWORD result = key->family == 6
            ? SetPerTcp6ConnectionEStats(&row6, TcpConnectionEstatsData, (PUCHAR)&rw, 0, sizeof(rw), 0)
            : SetPerTcpConnectionEStats(&row, TcpConnectionEstatsData, (PUCHAR)&rw, 0, sizeof(rw), 0);
        if (result != NO_ERROR) return result;
    }
    return key->family == 6
        ? GetPerTcp6ConnectionEStats(&row6, TcpConnectionEstatsData, NULL, 0, 0, NULL, 0, 0, (PUCHAR)rod, 0, sizeof(*rod))
        : GetPerTcpConnectionEStats(&row, TcpConnectionEstatsData, NULL, 0, 0, NULL, 0, 0, (PUCHAR)rod, 0, sizeof(*rod));
}

static void EstatsMeasure(const TCP_ROW_WIN *src, OMINULL_EVENT *ev) {
    bool isNew = false;
    ESTATS_SLOT *slot = EstatsSlot(&src->key, &isNew);
    if (!slot) { g_TCPWinUnmeasured++; return; }
    slot->generation = g_estatsGeneration;
    FILETIME sample; GetSystemTimeAsFileTime(&sample);
    UINT64 now = UDPWinFileTime(sample);
    ev->FirstObservedAt = slot->lastSample ? slot->lastSample : now;
    ev->LastObservedAt = now;
    TCP_ESTATS_DATA_ROD_v0 rod = {0};
    if (TCPReadCounters(src, isNew, &rod) != NO_ERROR) {
        g_TCPWinUnmeasured++;
        slot->used = false;
        return;
    }
    /* Either counter going backwards invalidates the whole interval. */
    if (!isNew && rod.DataBytesIn >= slot->bytesIn && rod.DataBytesOut >= slot->bytesOut) {
        ev->BytesIn = rod.DataBytesIn - slot->bytesIn;
        ev->BytesOut = rod.DataBytesOut - slot->bytesOut;
        ev->BytesMeasured = true;
    }
    slot->bytesIn = rod.DataBytesIn;
    slot->bytesOut = rod.DataBytesOut;
    slot->lastSample = now;
}

typedef struct { TCP_KEY_WIN key; DWORD lastReported; bool valid; } FLOW_DEDUP_SLOT_WIN;
#define FLOW_DEDUP_CAP_WIN 2048
#define FLOW_ROLLUP_MS_WIN 30000
#define FLOW_CONTACT_ROLLUP_MS_WIN 600000
static FLOW_DEDUP_SLOT_WIN g_FlowDedupWin[FLOW_DEDUP_CAP_WIN];
static bool ShouldReportFlowWin(const TCP_KEY_WIN *key, ULONG64 bytesIn, ULONG64 bytesOut, DWORD rollupMs) {
    if (!TCPAddressReportable(key)) return false;
    if (bytesIn || bytesOut) return true;
    DWORD now = GetTickCount();
    size_t start = TCPKeyHash(key) & (FLOW_DEDUP_CAP_WIN - 1);
    FLOW_DEDUP_SLOT_WIN *available = NULL;
    for (size_t probe = 0; probe < FLOW_DEDUP_CAP_WIN; probe++) {
        FLOW_DEDUP_SLOT_WIN *slot = &g_FlowDedupWin[(start + probe) & (FLOW_DEDUP_CAP_WIN - 1)];
        if (slot->valid && !memcmp(&slot->key, key, sizeof(*key))) {
            if (now - slot->lastReported < rollupMs) return false;
            slot->lastReported = now;
            return true;
        }
        if ((!slot->valid || now - slot->lastReported >= FLOW_CONTACT_ROLLUP_MS_WIN) && !available)
            available = slot;
    }
    if (!available) available = &g_FlowDedupWin[start];
    available->valid = true;
    available->key = *key;
    available->lastReported = now;
    return true;
}

/* One socket this poll may report, before any process enrichment. Windows
 * lists every socket the stack still remembers, and enriching one costs a
 * process open, a path read and a lineage walk, so candidates stay cheap
 * enough to hold several times the wire cap. */
typedef struct {
    TCP_ROW_WIN row;
    ULONG64 bytesIn;
    ULONG64 bytesOut;
    UINT64 firstSample, lastSample;
    bool measured;
    bool live;
} FLOW_CANDIDATE_WIN;

#define MAX_FLOW_CANDIDATES_WIN 256

/* IsReportableTcpStateWin answers whether a socket in this state is a
 * conversation or a corpse.
 *
 * GetExtendedTcpTable with TCP_TABLE_OWNER_PID_ALL returns finished sockets
 * alongside live ones: TIME_WAIT lingers after every normal close, and a
 * leaked handle sits in CLOSE_WAIT indefinitely. Neither can move another
 * byte, so both measure a zero-byte delta on every poll - and a zero-byte
 * record on a fixed timer is the shape of a beacon, which is what the hub
 * then reported. Windows also gives TIME_WAIT rows an owning process of 0,
 * so they cannot even be attributed to what opened them.
 *
 * SYN_SENT is kept on purpose: a connection attempt that never completes is
 * a real signal, and one of the few ways a dead command-and-control address
 * announces itself. */
static bool IsLiveTcpStateWin(DWORD state) {
    return state == MIB_TCP_STATE_ESTAB || state == MIB_TCP_STATE_SYN_SENT ||
           state == MIB_TCP_STATE_FIN_WAIT1 || state == MIB_TCP_STATE_FIN_WAIT2;
}

/* TIME_WAIT is the one finished state still worth reporting, and it is
 * reported as a record of contact rather than as a flow.
 *
 * Windows holds a closed connection here for about two minutes, and most of
 * what this host does is shorter than the polling interval - a name lookup, a
 * telemetry post, an update check - so TIME_WAIT is the only state in which
 * those connections are ever visible. Dropping it outright cost four fifths of
 * the destinations this endpoint reported. It carries no byte counts and no
 * owning process, so it says one true thing - that this host contacted that
 * address - and it is released at the contact cadence, not the flow one.
 *
 * The other finished states are not kept. CLOSE_WAIT, LAST_ACK and CLOSING all
 * describe a connection that was established, and an established connection
 * has already been reported with its real process and its real bytes; the only
 * thing re-reporting it adds is a timer. */
static bool IsContactTcpStateWin(DWORD state) {
    return state == MIB_TCP_STATE_TIME_WAIT;
}

/* The agent's own connection to the hub, so it is not reported back to the
 * hub as telemetry.
 *
 * A flow record exists to tell the hub something it does not already know.
 * The hub receiving a heartbeat is complete evidence that the heartbeat
 * happened, so re-describing that socket as a flow says nothing, and on an
 * idle host it made this agent the largest talker in its own telemetry. Only
 * the exact configured hub endpoint is dropped, and only for this process: if
 * this binary ever connects anywhere else, that is the thing worth seeing.
 *
 * Resolved once. HubAddressLiteral may consult DNS, which has no place on a
 * three-second polling path. */
bool HubAddressLiteral(const AGENT_CONFIG* config, char* out, size_t cap);

static bool ResolveHubTargets(const AGENT_CONFIG *config, OMINULL_HUB_TARGETS *targets);
static OMINULL_HUB_TARGETS g_HubPeers;
static DWORD g_SelfPid;
static bool g_HubPeerResolved;
static void ResolveSelfHubPeer(void) {
    if (g_HubPeerResolved) return;
    g_SelfPid = GetCurrentProcessId();
    g_HubPeerResolved = ResolveHubTargets(&g_Config, &g_HubPeers);
}
static bool IsOwnHubFlowWin(const FLOW_CANDIDATE_WIN *candidate) {
    const TCP_KEY_WIN *key = &candidate->row.key;
    if (!g_HubPeers.port || key->pid != g_SelfPid || ntohs(key->remotePort) != g_HubPeers.port) return false;
    char address[64];
    if (!inet_ntop(key->family == 6 ? AF_INET6 : AF_INET, key->remote, address, sizeof(address))) return false;
    for (size_t i = 0; i < g_HubPeers.count; i++)
        if (!strcmp(address, g_HubPeers.addresses[i])) return true;
    return false;
}

/* SelectFlowCandidatesWin chooses which sockets get this batch's wire slots.
 *
 * There are more sockets on a busy host than a batch can carry, and the
 * previous selection was "whatever the table listed first", which has nothing
 * to do with importance: a host holding hundreds of idle connections could
 * spend its whole batch on them and never report the transfer that mattered.
 * Sockets that moved bytes this interval go first; the rest fill what is
 * left, still subject to the idle rollup.
 *
 * The rollup is consulted only while a slot is actually free, because
 * ShouldReportFlowWin records that it released a flow. Asking it about a
 * socket that could not be sent anyway would silence that socket for the next
 * thirty seconds without anything having been reported. */
static size_t SelectFlowCandidatesWin(const FLOW_CANDIDATE_WIN* candidates, size_t count,
                                      size_t maxEvents, size_t* order) {
    size_t selected = 0;
    for (int pass = 0; pass < 2 && selected < maxEvents; pass++) {
        for (size_t i = 0; i < count && selected < maxEvents; i++) {
            bool active = candidates[i].bytesIn > 0 || candidates[i].bytesOut > 0;
            if ((pass == 0) != active) continue;
            if (IsOwnHubFlowWin(&candidates[i])) continue;
            if (!ShouldReportFlowWin(&candidates[i].row.key,
                                     candidates[i].bytesIn, candidates[i].bytesOut,
                                     candidates[i].live ? FLOW_ROLLUP_MS_WIN
                                                        : FLOW_CONTACT_ROLLUP_MS_WIN)) {
                continue;
            }
            order[selected++] = i;
        }
    }
    return selected;
}

static size_t PollTCPObservations(OMINULL_EVENT *outEvents, size_t maxEvents) {
    static FLOW_CANDIDATE_WIN candidates[MAX_FLOW_CANDIDATES_WIN];
    static size_t order[MAX_FLOW_CANDIDATES_WIN];
    size_t count = 0;
    DWORD dwSize = 0;

    if (maxEvents == 0) return 0;
    ResolveSelfHubPeer();
    g_estatsGeneration++;
    g_TCPWinDeferred = 0;
    g_TCPWinQueryError = NO_ERROR;

    static DWORD cursor[2];
    static unsigned firstFamily;
    for (unsigned pass = 0; pass < 2; pass++) {
        unsigned f = (firstFamily + pass) % 2;
        ULONG family = f ? AF_INET6 : AF_INET;
        dwSize = 0;
        DWORD ret = GetExtendedTcpTable(NULL, &dwSize, TRUE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret != ERROR_INSUFFICIENT_BUFFER || !dwSize) {
            if (ret != NO_ERROR) g_TCPWinQueryError = ret;
            continue;
        }
        void *table = malloc(dwSize);
        if (!table) { g_TCPWinQueryError = ERROR_NOT_ENOUGH_MEMORY; continue; }
        ret = GetExtendedTcpTable(table, &dwSize, TRUE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret != NO_ERROR) { g_TCPWinQueryError = ret; free(table); continue; }
        DWORD entries = *(DWORD *)table, next = cursor[f];
        size_t limit = pass == 0 ? MAX_FLOW_CANDIDATES_WIN / 2 : MAX_FLOW_CANDIDATES_WIN;
        for (DWORD visited = 0; visited < entries; visited++) {
            DWORD i = (cursor[f] + visited) % entries;
            TCP_ROW_WIN row; memset(&row, 0, sizeof(row));
            row.key.family = f ? 6 : 4;
            if (f) {
                MIB_TCP6ROW_OWNER_PID *r = &((MIB_TCP6TABLE_OWNER_PID *)table)->table[i];
                memcpy(row.key.local, r->ucLocalAddr, 16); memcpy(row.key.remote, r->ucRemoteAddr, 16);
                row.key.localScope = r->dwLocalScopeId; row.key.remoteScope = r->dwRemoteScopeId;
                row.key.localPort = (UINT16)r->dwLocalPort; row.key.remotePort = (UINT16)r->dwRemotePort;
                row.key.pid = r->dwOwningPid; row.state = r->dwState;
            } else {
                MIB_TCPROW_OWNER_PID *r = &((MIB_TCPTABLE_OWNER_PID *)table)->table[i];
                memcpy(row.key.local, &r->dwLocalAddr, 4); memcpy(row.key.remote, &r->dwRemoteAddr, 4);
                row.key.localPort = (UINT16)r->dwLocalPort; row.key.remotePort = (UINT16)r->dwRemotePort;
                row.key.pid = r->dwOwningPid; row.state = r->dwState;
            }
            if (!TCPAddressReportable(&row.key)) continue;
            bool live = IsLiveTcpStateWin(row.state);
            if (!live && !IsContactTcpStateWin(row.state)) continue;
            if (count >= limit) { g_TCPWinDeferred++; continue; }
            next = (i + 1) % entries;
            row.key.created = TCPProcessCreated(row.key.pid);
            OMINULL_EVENT measured; memset(&measured, 0, sizeof(measured));
            if (live) EstatsMeasure(&row, &measured);
            candidates[count].row = row;
            candidates[count].bytesIn = measured.BytesIn;
            candidates[count].bytesOut = measured.BytesOut;
            candidates[count].measured = measured.BytesMeasured;
            candidates[count].firstSample = measured.FirstObservedAt;
            candidates[count].lastSample = measured.LastObservedAt;
            candidates[count].live = live;
            count++;
        }
        cursor[f] = next;
        free(table);
    }
    firstFamily ^= 1;
    EstatsEvictUnseen();

    size_t selected = SelectFlowCandidatesWin(candidates, count, maxEvents, order);
    for (size_t s = 0; s < selected; s++) {
        const FLOW_CANDIDATE_WIN* candidate = &candidates[order[s]];
        OMINULL_EVENT* ev = &outEvents[s];
        memset(ev, 0, sizeof(OMINULL_EVENT));
        ev->EventType = candidate->row.key.family == 6 ? OMINULL_EVENT_FLOW_ESTABLISHED_V6 : OMINULL_EVENT_FLOW_ESTABLISHED_V4;
        ev->Action = 0; // Permit
        ev->Direction = 1; // Outbound
        ev->Protocol = IPPROTO_TCP;
        ev->IpVersion = candidate->row.key.family;
        ev->ProcessId = candidate->row.key.pid;
        ev->LocalPort = ntohs((u_short)candidate->row.key.localPort);
        ev->RemotePort = ntohs((u_short)candidate->row.key.remotePort);
        if (ev->IpVersion == 6) {
            memcpy(ev->Addr.Ipv6.LocalIp, candidate->row.key.local, 16);
            memcpy(ev->Addr.Ipv6.RemoteIp, candidate->row.key.remote, 16);
            ev->LocalScopeId = candidate->row.key.localScope;
            ev->RemoteScopeId = candidate->row.key.remoteScope;
        } else {
            UINT32 local, remote;
            memcpy(&local, candidate->row.key.local, 4); memcpy(&remote, candidate->row.key.remote, 4);
            ev->Addr.Ipv4.LocalIp = ntohl(local); ev->Addr.Ipv4.RemoteIp = ntohl(remote);
        }
        ev->BytesIn = candidate->bytesIn;
        ev->BytesOut = candidate->bytesOut;
        ev->BytesMeasured = candidate->measured;
        FILETIME sample;
        GetSystemTimeAsFileTime(&sample);
        ev->FirstObservedAt = ev->LastObservedAt = UDPWinFileTime(sample);
        if (candidate->firstSample && candidate->lastSample) {
            ev->FirstObservedAt = candidate->firstSample;
            ev->LastObservedAt = candidate->lastSample;
        }
        ev->Timestamp = ev->LastObservedAt;
        ev->ObservationCount = 1;

        ProcessPathFor(candidate->row.key.pid, ev->ProcessPath, OMINULL_MAX_PATH);

        bool foundInBatch = false;
        for (size_t j = 0; j < s; j++) {
            if (outEvents[j].ProcessId == candidate->row.key.pid) {
                ev->Enrichment = outEvents[j].Enrichment;
                foundInBatch = true;
                break;
            }
        }
        if (!foundInBatch) {
            ProcessLineageWin_InspectProcess(candidate->row.key.pid, &ev->Enrichment);
        }
        if (!candidate->row.key.created || TCPProcessCreated(candidate->row.key.pid) != candidate->row.key.created) {
            memset(&ev->Enrichment, 0, sizeof(ev->Enrichment));
            wcscpy(ev->ProcessPath, L"unknown");
        }
    }
    return selected;
}

static size_t PollActiveSocketFlows(OMINULL_EVENT *outEvents, size_t maxEvents) {
    static OMINULL_EVENT observed[MAX_FLOW_CANDIDATES_WIN];
    size_t count = PollTCPObservations(observed, MAX_FLOW_CANDIDATES_WIN);
    for (size_t i = 0; i < count; i++)
        TCPPendingAdd(&observed[i]);
    return TCPPendingDrain(outEvents, maxEvents);
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

/* WFP address-only rules cannot distinguish link-local interfaces. Refuse
 * those policy destinations rather than widen an interface-specific order. */
static bool IsIPLiteralAny(const char *s) { return OminullUnscopedPolicyIP(s); }
static bool ResolveHubTargets(const AGENT_CONFIG *config, OMINULL_HUB_TARGETS *targets) {
    return OminullResolveHub(config->hub_url, targets);
}

bool HubAddressLiteral(const AGENT_CONFIG *config, char *out, size_t cap) {
    OMINULL_HUB_TARGETS targets;
    if (!cap || !ResolveHubTargets(config, &targets) || strlen(targets.addresses[0]) >= cap) return false;
    strcpy(out, targets.addresses[0]);
    return true;
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
            printf("[!] Unsupported baseline destination; refusing policy update.\n");
            return -2;
        }
        if (strcmp(r.protocol, "udp") != 0 && strcmp(r.protocol, "tcp") != 0) {
            return -2;
        }
        if (r.port < 1 || r.port > 65535) {
            return -2;
        }
        if (count >= maxOut) return -2;
        out[count++] = r;
    }
    return count;
}

/* ParseAddressArray pulls the entries of a flat "key":["a","b"] array. */
static int ParseAddressArray(const char* json, const char* key,
                             char out[][PEER_ADDR_LEN], int maxOut) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
    if (*p++ != ':') return -1;
    while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
    if (*p++ != '[') return -1;
    int count = 0;
    for (;;) {
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
        if (*p == ']') return count;
        if (count >= maxOut || *p++ != '"') return -1;
        char ip[PEER_ADDR_LEN]; size_t length = 0;
        while (*p && *p != '"') {
            if (length >= sizeof(ip) - 1 || *p == '\\') return -1;
            ip[length++] = *p++;
        }
        if (*p++ != '"') return -1;
        ip[length] = '\0';
        if (!IsIPLiteralAny(ip)) return -1;
        strcpy(out[count++], ip);
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
        if (*p == ']') return count;
        if (*p++ != ',') return -1;
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
        if (*p == ']') return -1;
    }
}

/* What this agent has actually put in the filtering engine. At file scope rather than
 * inside SyncEnforcement because the dead-man timer has to rebuild from it -
 * specifically, to lift this host's isolation while leaving the mesh quarantine
 * it was also holding in place. */
static bool known = false;
static bool appliedIsolated = false;
static OMINULL_HUB_TARGETS appliedHubTargets;
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
static char g_ApplyNote[160] = {0};

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

const char* Agent_LastAppliedNote(void) { return g_ApplyNote[0] ? g_ApplyNote : g_DeadmanNote; }

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
    if (peerCount < 0 || allowCount < 0) {
        strcpy(g_ApplyNote, "policy not applied: invalid, unsupported or oversized address list");
        return;
    }

    OMINULL_BASELINE_RULE baseline[OMINULL_MAX_BASELINE_RULES];
    int baselineCount = ParseBaselineRules(respJson, baseline, OMINULL_MAX_BASELINE_RULES);
    if (baselineCount == -2) {
        strcpy(g_ApplyNote, "policy not applied: invalid or oversized baseline");
        return;
    }
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
    if (!changed) { g_ApplyNote[0] = '\0'; return; }

    OMINULL_HUB_TARGETS hubTargets = {0};
    if ((wantIsolated || peerCount) && !ResolveHubTargets(config, &hubTargets)) {
        strcpy(g_ApplyNote, "policy not applied: no complete usable hub address set");
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

        DWORD status = Wfp_ApplyState(&hubTargets, wantIsolated ? 1 : 0, blocked, peerCount,
                           allowed, allowCount, baseline, baselineCount, baselineKnown ? 1 : 0);
        if (status != ERROR_SUCCESS) {
            snprintf(g_ApplyNote, sizeof(g_ApplyNote), "policy not applied: WFP error 0x%08lx", (unsigned long)status);
            printf("[-] The user-mode filtering engine refused the change; state not applied.\n");
            return;
        }
        if (wantIsolated && baselineKnown) {
            printf("[!] Threat Nullification: host isolated. Permitted: hub %s, loopback, "
                   "%d baseline rule(s), %d allow-list address(es). %d peer block(s) in force.\n",
                   hubTargets.addresses[0], baselineCount, allowCount, peerCount);
        } else if (wantIsolated) {
            printf("[!] Threat Nullification: host isolated. This hub sends no baseline policy, so "
                   "the built-in floor applies: hub %s, loopback, DHCP and DNS to any destination, "
                   "%d allow-list address(es). %d peer block(s) in force.\n",
                   hubTargets.addresses[0], allowCount, peerCount);
        } else {
            printf("[+] Threat neutralized: host isolation lifted. %d peer block(s) in force.\n", peerCount);
        }

    g_ApplyNote[0] = '\0';
    appliedHubTargets = hubTargets;
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
        released = (Wfp_ApplyState(&appliedHubTargets, 0, blocked, appliedPeerCount, NULL, 0,
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

static ULONGLONG g_LastSoftwareInventorySyncWin = 0;
#define SOFTWARE_INVENTORY_SYNC_INTERVAL_WIN_MS (3600ULL * 1000ULL)

static void SyncSoftwareInventoryWin(const AGENT_CONFIG* config) {
    if (!config || !config->hub_url[0]) return;

    SoftwareInventoryBatchWin* batch = (SoftwareInventoryBatchWin*)calloc(1, sizeof(SoftwareInventoryBatchWin));
    if (!batch) return;

    if (SoftwareInvWin_Collect(batch) == 0 && batch->count > 0) {
        if (config->verbose) {
            printf("[*] Collected %zu authoritative Windows software packages; uploading to Hub...\n", batch->count);
        }

        size_t cap = 2 * 1024 * 1024;
        char* jsonBuf = (char*)malloc(cap);
        if (jsonBuf) {
            size_t written = SoftwareInvWin_SerializeJSON(config->endpoint_id, batch, jsonBuf, cap);
            if (written > 0) {
                char respBuf[2048] = {0};
                Hub_PostPathJSON(config, "/api/v1/software", jsonBuf, respBuf, sizeof(respBuf));
            }
            free(jsonBuf);
        }
    }
    free(batch);
    g_LastSoftwareInventorySyncWin = GetTickCount64();
}

void RunAgentLoop(AGENT_CONFIG* config) {
    printf("[+] Windows collection layer: TCP socket table/ESTATS and passive UDP ETW.\n");

    if (config->evidence_signing_key[0] == '\0') {
        uint8_t ep_pub[32], ep_priv[64];
        Forensics_GetOrCreateEndpointKeyWin(NULL, ep_pub, ep_priv, config->evidence_signing_key, sizeof(config->evidence_signing_key));
    }

    OMINULL_EVENT eventBatch[64];
    size_t batchCount = 0;
    DWORD lastFlush = GetTickCount();

    printf("[+] Ominull Agent running. Streaming network flows to Hub: %s\n", config->hub_url);
    UDPWinStart();
    SyncSoftwareInventoryWin(config);

    while (1) {
        if (g_StopEvent && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0) {
            break;
        }

        // Poll live socket table flows.
        DWORD now = GetTickCount();
        if (now - lastFlush >= 2500) {
            /* Reserve capacity for both sources, then lend unused TCP slots to
             * UDP. Pending UDP observations survive between heartbeats. */
            batchCount += UDPWinDrain(eventBatch + batchCount, (64 - batchCount) / 2);
            batchCount += PollActiveSocketFlows(eventBatch + batchCount, 64 - batchCount);
            batchCount += UDPWinDrain(eventBatch + batchCount, 64 - batchCount);

            /* The reply now carries the resolved baseline policy as well as the
             * peer list and the allow list. Four kilobytes truncated it once the
             * policy had a handful of rules in it, and a truncated reply is not
             * a parse error - it is a silently shorter enforcement state. */
            char hubResponse[16384];
            bool accepted = Hub_SendTelemetryBatch(config, eventBatch, batchCount,
                                                   hubResponse, sizeof(hubResponse));
            if (!accepted) {
                UDPWinTransportLost(eventBatch, batchCount);
                for (size_t i = 0; i < batchCount; i++)
                    if (eventBatch[i].Protocol == 6)
                        g_TCPDrops += eventBatch[i].ObservationCount;
            }
            batchCount = 0;
            lastFlush = now;
            HubContact(accepted);

            Service_AdoptDeviceCredential(config, hubResponse);

            // The hub answers with an agent_update descriptor when a newer
            // release is published. Update_Apply verifies it against the
            // pinned release key before anything is installed, and does not
            // return if the swap succeeds.
            SyncEnforcement(config, hubResponse);

            Update_Apply(config, hubResponse);

            ProcessResponseOffersWindows(config, hubResponse);

            if (GetTickCount64() - g_LastSoftwareInventorySyncWin >= SOFTWARE_INVENTORY_SYNC_INTERVAL_WIN_MS) {
                SyncSoftwareInventoryWin(config);
            }
        }

        Sleep(100);
    }

    UDPWinStop();

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
static void RemoveLegacyUpdaterResidue(void) {
    char binaryPath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(NULL, binaryPath, sizeof(binaryPath))) return;
    char* slash = strrchr(binaryPath, '\\');
    if (!slash) return;
    *slash = '\0';

    static const char* const names[] = {
        "ominull-recover.bat",
        "ominulld.old",
        "update.pending",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[MAX_PATH];
        int n = snprintf(path, sizeof(path), "%s\\%s", binaryPath, names[i]);
        if (n >= 0 && (size_t)n < sizeof(path)) DeleteFileA(path);
    }
}

void Service_SetConfig(const AGENT_CONFIG* config) {
    // Remove exact files created by the retired direct-binary updater. MSI
    // keeps this cleanup inside the package-owned service startup path during
    // a major upgrade; no enrollment identity is touched.
    RemoveLegacyUpdaterResidue();
    // Repair the package-owned service recovery configuration on every start,
    // including an in-place MSI upgrade.
    Service_EnsureRecovery();
    // Migrate older registrations that still carry the key inline. New MSI
    // enrolments write the protected file before the service starts.
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

// Service_EnsureRecovery registers the SCM recovery actions, and does it every
// time the agent starts rather than only at install.
//
// The native MSI owns update transactions and rollback. These actions only
// restart a service that crashes after installation; they never replace files
// or run an unowned recovery script.
//
// Registering this only at install time would have left every service upgraded
// in place without any of it: CreateService returns ERROR_SERVICE_EXISTS on an
// already-installed service, so a one-time registration path never reaches the configuration.
void Service_EnsureRecovery(void) {
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

    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;     actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART;     actions[1].Delay = 5000;
    actions[2].Type = SC_ACTION_RESTART;     actions[2].Delay = 30000;

    SERVICE_FAILURE_ACTIONSA fa;
    ZeroMemory(&fa, sizeof(fa));
    fa.dwResetPeriod = 900;
    fa.lpCommand = NULL;
    fa.cActions = 3;
    fa.lpsaActions = actions;
    if (!ChangeServiceConfig2A(schService, SERVICE_CONFIG_FAILURE_ACTIONS, &fa)) {
        fprintf(stderr, "[!] Could not register service recovery actions (Error: %lu).\n", GetLastError());
    }

    // Apply recovery to non-crash failures too: a service that exits cleanly
    // after a failed start still needs the SCM's restart behavior.
    SERVICE_FAILURE_ACTIONS_FLAG faFlag;
    faFlag.fFailureActionsOnNonCrashFailures = TRUE;
    ChangeServiceConfig2A(schService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &faFlag);

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
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

static bool ExtractDeviceCredential(const char* json, char* out, size_t outLen) {
    const char* marker = strstr(json, "\"device_credential\":\"");
    if (!marker || outLen == 0) return false;
    marker += strlen("\"device_credential\":\"");
    size_t n = 0;
    while (marker[n] && marker[n] != '"' && n < outLen - 1) n++;
    if (marker[n] != '"') return false;
    memcpy(out, marker, n);
    out[n] = '\0';
    return n == 68 && strncmp(out, "omd_", 4) == 0;
}

bool Service_AdoptDeviceCredential(AGENT_CONFIG* config, const char* responseJson) {
    if (!config || !responseJson || strncmp(config->api_key, "omd_", 4) == 0) return false;

    char credential[128] = {0};
    if (!ExtractDeviceCredential(responseJson, credential, sizeof(credential))) return false;

    const char* target = config->key_path[0] ? config->key_path : OMINULL_DEFAULT_KEY_PATH;
    if (!WriteProtectedFile(target, credential)) {
        fprintf(stderr, "[!] The hub issued this endpoint a unique credential, but it could not be stored in %s.\n", target);
        return false;
    }
    snprintf(config->api_key, sizeof(config->api_key), "%s", credential);

    if (!config->key_path[0]) {
        snprintf(config->key_path, sizeof(config->key_path), "%s", target);
    }
    char rendered[2048];
    int n = snprintf(rendered, sizeof(rendered),
                     "hub_url=%s\nkey_path=%s\nendpoint_id=%s\nrole_tag=%s\n"
                     "location_id=%s\nca_path=%s\npin_hub_ca=%d\nclient_pfx_path=%s\nallow_plaintext=%d\n",
                     config->hub_url, config->key_path, config->endpoint_id,
                     config->role_tag, config->location_id, config->ca_path,
                     config->pin_hub_ca ? 1 : 0, config->client_pfx_path,
                     config->allow_plaintext ? 1 : 0);
    if (n < 0 || (size_t)n >= sizeof(rendered) ||
        !WriteProtectedFile(config->config_path, rendered)) {
        fprintf(stderr, "[!] The unique credential is active, but the old inline agent configuration could not be rewritten.\n");
    }
    printf("[+] Hub-issued unique device credential installed; legacy shared-key authentication is no longer used by this agent.\n");
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
 * Bootstrap supplies paths to staged CA/PFX files and the device credential on
 * stdin; this process, installed by the MSI, places them under ProgramData and
 * applies the SYSTEM/Administrators ACL before the service can start. */
bool Service_ConfigureFromStdin(void) {
    char hub[256] = {0}, key[128] = {0}, endpoint[64] = {0};
    char role[64] = "workstation", location[64] = "loc-home";
    char caSource[260] = {0}, pfxSource[260] = {0};
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
        else if (strcmp(line, "client_pfx_source") == 0) snprintf(pfxSource, sizeof(pfxSource), "%s", value);
        else if (strcmp(line, "pin_hub_ca") == 0) pinHubCA = strcmp(value, "0") != 0;
        else if (strcmp(line, "allow_plaintext") == 0) allowPlaintext = strcmp(value, "1") == 0;
    }
    if (!hub[0] || !key[0] || !endpoint[0] || (pinHubCA && !caSource[0])) {
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
        fprintf(stderr, "[-] Cannot install the package device credential (Error: %lu).\n", GetLastError());
        return false;
    }
	if (pinHubCA && !CopyProtectedFile(caSource, "C:\\ProgramData\\Ominull\\ca.crt")) {
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
                     "ca_path=%s\npin_hub_ca=%d\nclient_pfx_path=C:\\ProgramData\\Ominull\\client.pfx\n"
                     "allow_plaintext=%d\n",
                     hub, OMINULL_DEFAULT_KEY_PATH, endpoint, role, location,
                     pinHubCA ? "C:\\ProgramData\\Ominull\\ca.crt" : "",
                     pinHubCA ? 1 : 0, allowPlaintext ? 1 : 0);
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
                     "\"%s\" --service --hub %s --key-file \"%s\" --role %s --location %s --id %s",
                     binaryPath, config->hub_url, config->key_path,
                     config->role_tag[0] ? config->role_tag : "workstation",
                     config->location_id[0] ? config->location_id : "loc-home",
                     config->endpoint_id);
    } else {
        return -1;
    }
    if (n < 0 || (size_t)n >= cap) return -1;
	if (config->pin_hub_ca && config->ca_path[0]) {
		int m = snprintf(out + n, cap - n, " --ca \"%s\"", config->ca_path);
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
        fprintf(stderr, "[!] Could not move the device credential off the service command line; "
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
        printf("[+] Moved the device credential out of the service command line into %s.\n", moved.key_path);
    } else {
        fprintf(stderr, "[!] Could not rewrite the service command line (Error: %lu); "
                        "the credential stays readable through `sc qc %s`.\n", GetLastError(), SERVICE_NAME);
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

size_t Agent_CollectorHealthJSON(char *out, size_t capacity) {
    size_t offset = UDPWinHealthJSON(out, capacity);
    if (!offset || offset >= capacity)
        return 0;
    int n =
        snprintf(out + offset, capacity - offset,
                 ",{\"name\":\"windows-estats\",\"state\":\"%s\",\"error\":%lu,\"dropped\":%llu,\"queued\":%"
                 "llu,\"unmeasured\":%llu,\"deferred\":%llu}",
                 g_TCPWinQueryError ? "error" : "active", g_TCPWinQueryError, (unsigned long long)g_TCPDrops,
                 (unsigned long long)(g_TCPInitialized ? TCP_PENDING_CAP - g_TCPFreeCount : 0),
                 g_TCPWinUnmeasured, g_TCPWinDeferred);
    return n > 0 && (size_t)n < capacity - offset ? offset + (size_t)n : 0;
}
