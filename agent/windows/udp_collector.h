#ifndef OMINULL_UDP_COLLECTOR_WIN_H
#define OMINULL_UDP_COLLECTOR_WIN_H
#include "../include/agent.h"
#include <evntrace.h>
#include <evntcons.h>
#include <stddef.h>
#include "udp_trace_owner.h"

/* Manifest provider, not the classic UdpIp provider. Version 0 was inspected
 * on Windows 11 and exercised by test_udp_windows_live.c. Unknown layouts are
 * counted as lost observations, never interpreted using guessed offsets. */
static const GUID g_UDPWinProvider = {
    0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
#define UDP_WIN_CAP 1024
#define UDP_WIN_BUCKETS 2048
#define UDP_WIN_PROCESSES 256

typedef struct {
    OMINULL_EVENT event;
    int next;
    bool used;
} UDP_WIN_SLOT;
typedef struct {
    DWORD pid;
    HANDLE handle;
    UINT64 created;
    WCHAR path[OMINULL_MAX_PATH];
} UDP_WIN_PROCESS;
static UDP_WIN_SLOT g_UDPWinQueue[UDP_WIN_CAP];
static UDP_WIN_PROCESS g_UDPWinProcesses[UDP_WIN_PROCESSES];
static int g_UDPWinBuckets[UDP_WIN_BUCKETS], g_UDPWinFree[UDP_WIN_CAP];
static size_t g_UDPWinFreeCount, g_UDPWinCursor;
static CRITICAL_SECTION g_UDPWinLock;
static bool g_UDPWinInitialized;
static TRACEHANDLE g_UDPWinSession, g_UDPWinConsumer = INVALID_PROCESSTRACE_HANDLE;
static HANDLE g_UDPWinThread;
static struct {
    EVENT_TRACE_PROPERTIES p;
    WCHAR name[80];
} g_UDPWinProperties;
static volatile LONG g_UDPWinError;
static UINT64 g_UDPWinDropped, g_UDPWinTraceLost, g_UDPWinBuffersLost;
static UINT64 g_UDPWinScopeOmitted, g_UDPWinSchemaOmitted;

static UINT64 UDPWinFileTime(FILETIME t) { return ((UINT64)t.dwHighDateTime << 32) | t.dwLowDateTime; }
static unsigned UDPWinHash(const OMINULL_EVENT *e) {
    unsigned h =
        (unsigned)e->ProcessId ^ e->LocalPort ^ ((unsigned)e->RemotePort << 16) ^ e->Direction ^ e->IpVersion;
    const unsigned char *bytes = (const void *)&e->Addr;
    for (size_t i = 0; i < sizeof(e->Addr); i++)
        h = (h ^ bytes[i]) * 16777619u;
    return h & (UDP_WIN_BUCKETS - 1);
}
static bool UDPWinSame(const OMINULL_EVENT *a, const OMINULL_EVENT *b) {
    return a->ProcessId == b->ProcessId && a->IpVersion == b->IpVersion && a->Direction == b->Direction &&
           a->LocalPort == b->LocalPort && a->RemotePort == b->RemotePort &&
           !memcmp(&a->Addr, &b->Addr, sizeof(a->Addr)) &&
           !strcmp(a->Enrichment.process_instance_id, b->Enrichment.process_instance_id);
}
/* Cache handles, not PID-only claims. A recycled PID cannot acquire the path
 * of its replacement, even when ETW delivery is delayed. Protected or exited
 * processes remain unattributed rather than borrowing a current snapshot. */
static void UDPWinProcess(OMINULL_EVENT *e) {
    DWORD pid = (DWORD)e->ProcessId;
    UDP_WIN_PROCESS *p = &g_UDPWinProcesses[pid % UDP_WIN_PROCESSES];
    if (p->handle && (p->pid != pid || WaitForSingleObject(p->handle, 0) != WAIT_TIMEOUT)) {
        CloseHandle(p->handle);
        memset(p, 0, sizeof(*p));
    }
    if (!p->handle) {
        p->handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
        if (p->handle) {
            FILETIME create, exit, kernel, user;
            DWORD cap = OMINULL_MAX_PATH;
            if (!GetProcessTimes(p->handle, &create, &exit, &kernel, &user)) {
                CloseHandle(p->handle);
                memset(p, 0, sizeof(*p));
            } else {
                p->pid = pid;
                p->created = UDPWinFileTime(create);
                QueryFullProcessImageNameW(p->handle, 0, p->path, &cap);
            }
        }
    }
    strcpy(e->Enrichment.attribution_status, "unknown");
    if (p->handle && p->created <= e->Timestamp) {
        memcpy(e->ProcessPath, p->path, sizeof(e->ProcessPath));
        snprintf(e->Enrichment.process_instance_id, sizeof(e->Enrichment.process_instance_id), "%s:%lu:%llu",
                 ProcessLineageWin_GetBootID(), pid, p->created);
        strcpy(e->Enrichment.attribution_status, p->path[0] ? "authoritative" : "permission_denied");
    }
}
static void WINAPI UDPWinEvent(PEVENT_RECORD record) {
    unsigned id = record->EventHeader.EventDescriptor.Id;
    if (!IsEqualGUID(&record->EventHeader.ProviderId, &g_UDPWinProvider) ||
        (id != 42 && id != 43 && id != 58 && id != 59))
        return;
    bool v6 = id >= 58, outbound = id == 42 || id == 58;
    EnterCriticalSection(&g_UDPWinLock);
    if (record->EventHeader.EventDescriptor.Version != 0 || record->UserDataLength != (v6 ? 52 : 28)) {
        g_UDPWinSchemaOmitted++;
        g_UDPWinDropped++;
        goto done;
    }
    const unsigned char *data = record->UserData;
    UINT32 pid, bytes;
    UINT16 dstPort, srcPort;
    memcpy(&pid, data, 4);
    memcpy(&bytes, data + 4, 4);
    size_t width = v6 ? 16 : 4;
    memcpy(&dstPort, data + 8 + 2 * width, 2);
    memcpy(&srcPort, data + 10 + 2 * width, 2);
    OMINULL_EVENT e = {0};
    e.ProcessId = pid;
    e.Protocol = 17;
    e.BytesMeasured = true;
    e.IpVersion = v6 ? 6 : 4;
    e.Direction = outbound ? 1 : 0;
    e.EventType = v6 ? OMINULL_EVENT_FLOW_ESTABLISHED_V6 : OMINULL_EVENT_FLOW_ESTABLISHED_V4;
    e.LocalPort = ntohs(outbound ? srcPort : dstPort);
    e.RemotePort = ntohs(outbound ? dstPort : srcPort);
    const unsigned char *local = data + 8 + (outbound ? width : 0),
                        *remote = data + 8 + (outbound ? 0 : width);
    if (v6) {
        /* This provider has no interface scope. Reject link-local observations
         * rather than merging identical addresses from distinct interfaces. */
        if ((local[0] == 0xfe && (local[1] & 0xc0) == 0x80) ||
            (remote[0] == 0xfe && (remote[1] & 0xc0) == 0x80)) {
            g_UDPWinScopeOmitted++;
            g_UDPWinDropped++;
            goto done;
        }
        memcpy(e.Addr.Ipv6.LocalIp, local, 16);
        memcpy(e.Addr.Ipv6.RemoteIp, remote, 16);
    } else {
        UINT32 a, b;
        memcpy(&a, local, 4);
        memcpy(&b, remote, 4);
        e.Addr.Ipv4.LocalIp = ntohl(a);
        e.Addr.Ipv4.RemoteIp = ntohl(b);
    }
    e.Timestamp = (UINT64)record->EventHeader.TimeStamp.QuadPart;
    e.FirstObservedAt = e.LastObservedAt = e.Timestamp;
    e.ObservationCount = 1;
    if (outbound)
        e.BytesOut = bytes;
    else
        e.BytesIn = bytes;
    UDPWinProcess(&e);
    unsigned bucket = UDPWinHash(&e);
    int index = g_UDPWinBuckets[bucket];
    while (index >= 0 && !UDPWinSame(&e, &g_UDPWinQueue[index].event))
        index = g_UDPWinQueue[index].next;
    if (index < 0) {
        if (!g_UDPWinFreeCount) {
            g_UDPWinDropped++;
            goto done;
        }
        index = g_UDPWinFree[--g_UDPWinFreeCount];
        UDP_WIN_SLOT *slot = &g_UDPWinQueue[index];
        slot->event = e;
        slot->used = true;
        slot->next = g_UDPWinBuckets[bucket];
        g_UDPWinBuckets[bucket] = index;
    } else {
        OMINULL_EVENT *old = &g_UDPWinQueue[index].event;
        old->BytesIn += e.BytesIn;
        old->BytesOut += e.BytesOut;
        old->ObservationCount++;
        if (e.Timestamp < old->FirstObservedAt)
            old->FirstObservedAt = e.Timestamp;
        if (e.Timestamp > old->LastObservedAt)
            old->LastObservedAt = e.Timestamp;
        old->Timestamp = old->LastObservedAt;
    }
done:
    LeaveCriticalSection(&g_UDPWinLock);
}
static DWORD WINAPI UDPWinConsume(void *unused) {
    (void)unused;
    ULONG result = ProcessTrace(&g_UDPWinConsumer, 1, NULL, NULL);
    if (result != ERROR_SUCCESS && result != ERROR_CANCELLED)
        InterlockedExchange(&g_UDPWinError, (LONG)result);
    return result;
}
static DWORD UDPWinStart(void) {
    if (g_UDPWinInitialized)
        return (DWORD)g_UDPWinError;
    (void)ProcessLineageWin_GetBootID(); /* Initialize before the consumer thread. */
    InitializeCriticalSection(&g_UDPWinLock);
    g_UDPWinInitialized = true;
    for (size_t i = 0; i < UDP_WIN_BUCKETS; i++)
        g_UDPWinBuckets[i] = -1;
    for (size_t i = 0; i < UDP_WIN_CAP; i++)
        g_UDPWinFree[i] = (int)i;
    g_UDPWinFreeCount = UDP_WIN_CAP;
    EVENT_TRACE_PROPERTIES *p = &g_UDPWinProperties.p;
    p->Wnode.BufferSize = sizeof(g_UDPWinProperties);
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 2;
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->LoggerNameOffset = offsetof(typeof(g_UDPWinProperties), name);
    p->FlushTimer = 1;
    p->BufferSize = 64;
    p->MinimumBuffers = 16;
    p->MaximumBuffers = 64;
    swprintf(g_UDPWinProperties.name, 80, L"Ominull-UDP-%lu-%llu", GetCurrentProcessId(), GetTickCount64());
    ULONG result = UDPTraceClaim(p, g_UDPWinProperties.name);
    if (result)
        goto failed;
    result = StartTraceW(&g_UDPWinSession, g_UDPWinProperties.name, p);
    if (result)
        goto failed;
    /* EVENT_FILTER_EVENT_ID ABI from evntprov.h, missing in older MinGW.
     * Restrict this session to UDP before delivery, not just in the callback. */
    struct {
        BOOLEAN FilterIn;
        UCHAR Reserved;
        USHORT Count;
        USHORT Events[4];
    } ids = {TRUE, 0, 4, {42, 43, 58, 59}};
    EVENT_FILTER_DESCRIPTOR filter = {(ULONGLONG)(ULONG_PTR)&ids, sizeof(ids), 0x80000200};
    ENABLE_TRACE_PARAMETERS parameters = {0};
    parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    parameters.EnableFilterDesc = &filter;
    parameters.FilterDescCount = 1;
    result = EnableTraceEx2(g_UDPWinSession, &g_UDPWinProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, 0x30, 0, 0, &parameters);
    if (result)
        goto failed;
    EVENT_TRACE_LOGFILEW log = {0};
    log.LoggerName = g_UDPWinProperties.name;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = UDPWinEvent;
    g_UDPWinConsumer = OpenTraceW(&log);
    if (g_UDPWinConsumer == INVALID_PROCESSTRACE_HANDLE) {
        result = GetLastError();
        goto failed;
    }
    g_UDPWinThread = CreateThread(NULL, 0, UDPWinConsume, NULL, 0, NULL);
    if (!g_UDPWinThread) {
        result = GetLastError();
        goto failed;
    }
    return ERROR_SUCCESS;
failed:
    g_UDPWinError = (LONG)result;
    bool stopped = true;
    if (g_UDPWinSession) {
        ULONG stopResult = ControlTraceW(g_UDPWinSession, NULL, p, EVENT_TRACE_CONTROL_STOP);
        stopped = stopResult == ERROR_SUCCESS || stopResult == ERROR_WMI_INSTANCE_NOT_FOUND;
        g_UDPWinSession = 0;
    }
    if (g_UDPWinConsumer != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_UDPWinConsumer);
        g_UDPWinConsumer = INVALID_PROCESSTRACE_HANDLE;
    }
    UDPTraceRelease(stopped);
    return result;
}
static size_t UDPWinDrain(OMINULL_EVENT *events, size_t capacity) {
    if (!g_UDPWinInitialized)
        return 0;
    size_t count = 0;
    EnterCriticalSection(&g_UDPWinLock);
    for (size_t visited = 0; visited < UDP_WIN_CAP && count < capacity; visited++) {
        int index = (int)g_UDPWinCursor;
        g_UDPWinCursor = (g_UDPWinCursor + 1) % UDP_WIN_CAP;
        UDP_WIN_SLOT *slot = &g_UDPWinQueue[index];
        if (!slot->used)
            continue;
        events[count++] = slot->event;
        unsigned bucket = UDPWinHash(&slot->event);
        int *link = &g_UDPWinBuckets[bucket];
        while (*link >= 0 && *link != index)
            link = &g_UDPWinQueue[*link].next;
        if (*link == index)
            *link = slot->next;
        slot->used = false;
        g_UDPWinFree[g_UDPWinFreeCount++] = index;
    }
    LeaveCriticalSection(&g_UDPWinLock);
    return count;
}
static void UDPWinTransportLost(const OMINULL_EVENT *events, size_t count) {
    if (!g_UDPWinInitialized)
        return;
    EnterCriticalSection(&g_UDPWinLock);
    for (size_t i = 0; i < count; i++)
        if (events[i].Protocol == 17)
            g_UDPWinDropped += events[i].ObservationCount;
    LeaveCriticalSection(&g_UDPWinLock);
}
static size_t UDPWinHealthJSON(char *out, size_t capacity) {
    if (!g_UDPWinInitialized)
        return 0;
    if (g_UDPWinSession) {
        ULONG result = ControlTraceW(g_UDPWinSession, NULL, &g_UDPWinProperties.p, EVENT_TRACE_CONTROL_QUERY);
        if (result == ERROR_SUCCESS) {
            g_UDPWinTraceLost = g_UDPWinProperties.p.EventsLost;
            g_UDPWinBuffersLost = g_UDPWinProperties.p.RealTimeBuffersLost;
        } else
            InterlockedExchange(&g_UDPWinError, (LONG)result);
    }
    EnterCriticalSection(&g_UDPWinLock);
    int n = snprintf(out, capacity,
                     "{\"name\":\"windows-etw-udp\",\"state\":\"%s\",\"error\":%ld,\"dropped\":%llu,"
                     "\"queued\":%llu,\"scope_omitted\":%llu,\"schema_omitted\":%llu,\"buffers_lost\":%llu}",
                     g_UDPWinError ? (g_UDPWinThread ? "error" : "unavailable") : "active", g_UDPWinError,
                     g_UDPWinDropped + g_UDPWinTraceLost, (UINT64)(UDP_WIN_CAP - g_UDPWinFreeCount),
                     g_UDPWinScopeOmitted, g_UDPWinSchemaOmitted, g_UDPWinBuffersLost);
    LeaveCriticalSection(&g_UDPWinLock);
    return n > 0 && (size_t)n < capacity ? (size_t)n : 0;
}
static void UDPWinStop(void) {
    bool stopped = true;
    if (!g_UDPWinInitialized)
        return;
    if (g_UDPWinSession) {
        ULONG result = ControlTraceW(g_UDPWinSession, NULL, &g_UDPWinProperties.p, EVENT_TRACE_CONTROL_STOP);
        stopped = result == ERROR_SUCCESS || result == ERROR_WMI_INSTANCE_NOT_FOUND;
        g_UDPWinTraceLost = g_UDPWinProperties.p.EventsLost;
        g_UDPWinBuffersLost = g_UDPWinProperties.p.RealTimeBuffersLost;
        g_UDPWinSession = 0;
    }
    if (g_UDPWinConsumer != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_UDPWinConsumer);
        g_UDPWinConsumer = INVALID_PROCESSTRACE_HANDLE;
    }
    if (g_UDPWinThread) {
        WaitForSingleObject(g_UDPWinThread, INFINITE);
        CloseHandle(g_UDPWinThread);
        g_UDPWinThread = NULL;
    }
    for (size_t i = 0; i < UDP_WIN_PROCESSES; i++)
        if (g_UDPWinProcesses[i].handle) {
            CloseHandle(g_UDPWinProcesses[i].handle);
            g_UDPWinProcesses[i].handle = NULL;
        }
    UDPTraceRelease(stopped);
}
#endif
