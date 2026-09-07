#ifndef OMINULL_TCP_PENDING_WIN_H
#define OMINULL_TCP_PENDING_WIN_H
/* Retain measured deltas until their flow gets a wire slot. A busy first page
 * must not consume every slot or erase measurements from closed sockets. */
#define TCP_PENDING_CAP 1024
#define TCP_PENDING_BUCKETS 2048
typedef struct {
    OMINULL_EVENT flow;
    bool used;
    int next;
} TCP_PENDING_SLOT;
static TCP_PENDING_SLOT g_TCPPending[TCP_PENDING_CAP];
static int g_TCPBuckets[TCP_PENDING_BUCKETS], g_TCPFree[TCP_PENDING_CAP];
static size_t g_TCPFreeCount, g_TCPCursor;
static bool g_TCPInitialized;
static uint64_t g_TCPDrops;
static unsigned TCPHash(const OMINULL_EVENT *f) {
    uint64_t h = f->FlowId ^ f->ProcessId ^ f->LocalPort ^ ((uint64_t)f->RemotePort << 16);
    return (unsigned)((h ^ (h >> 32)) & (TCP_PENDING_BUCKETS - 1));
}
static bool TCPKeyEqual(const OMINULL_EVENT *a, const OMINULL_EVENT *b) {
    return a->FlowId == b->FlowId && a->ProcessId == b->ProcessId && a->IpVersion == b->IpVersion &&
           a->LocalPort == b->LocalPort && a->RemotePort == b->RemotePort &&
           !memcmp(&a->Addr, &b->Addr, sizeof(a->Addr)) &&
           !strcmp(a->Enrichment.process_instance_id, b->Enrichment.process_instance_id);
}
static void TCPPendingAdd(const OMINULL_EVENT *f) {
    if (!g_TCPInitialized) {
        for (size_t i = 0; i < TCP_PENDING_BUCKETS; i++)
            g_TCPBuckets[i] = -1;
        for (size_t i = 0; i < TCP_PENDING_CAP; i++)
            g_TCPFree[i] = (int)i;
        g_TCPFreeCount = TCP_PENDING_CAP;
        g_TCPInitialized = true;
    }
    unsigned bucket = TCPHash(f);
    int index = g_TCPBuckets[bucket];
    while (index >= 0 && !TCPKeyEqual(f, &g_TCPPending[index].flow))
        index = g_TCPPending[index].next;
    if (index < 0) {
        if (!g_TCPFreeCount) {
            g_TCPDrops += f->ObservationCount;
            return;
        }
        index = g_TCPFree[--g_TCPFreeCount];
        TCP_PENDING_SLOT *slot = &g_TCPPending[index];
        slot->flow = *f;
        slot->used = true;
        slot->next = g_TCPBuckets[bucket];
        g_TCPBuckets[bucket] = index;
    } else {
        OMINULL_EVENT *old = &g_TCPPending[index].flow;
        old->BytesMeasured = old->BytesMeasured || f->BytesMeasured;
        old->BytesIn += f->BytesIn;
        old->BytesOut += f->BytesOut;
        old->ObservationCount += f->ObservationCount;
        if (f->FirstObservedAt < old->FirstObservedAt)
            old->FirstObservedAt = f->FirstObservedAt;
        if (f->LastObservedAt > old->LastObservedAt)
            old->LastObservedAt = f->LastObservedAt;
    }
}
static size_t TCPPendingDrain(OMINULL_EVENT *out, size_t capacity) {
    size_t count = 0;
    for (size_t visited = 0; visited < TCP_PENDING_CAP && count < capacity; visited++) {
        int index = (int)g_TCPCursor;
        g_TCPCursor = (g_TCPCursor + 1) % TCP_PENDING_CAP;
        TCP_PENDING_SLOT *slot = &g_TCPPending[index];
        if (!slot->used)
            continue;
        out[count++] = slot->flow;
        int *link = &g_TCPBuckets[TCPHash(&slot->flow)];
        while (*link >= 0 && *link != index)
            link = &g_TCPPending[*link].next;
        if (*link == index)
            *link = slot->next;
        slot->used = false;
        g_TCPFree[g_TCPFreeCount++] = index;
    }
    return count;
}
#endif
