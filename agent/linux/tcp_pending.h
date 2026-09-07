#ifndef OMINULL_TCP_PENDING_H
#define OMINULL_TCP_PENDING_H
/* Retain measured deltas until their flow gets a wire slot. A busy first page
 * must not consume every slot or erase measurements from closed sockets. */
#define TCP_PENDING_CAP 1024
#define TCP_PENDING_BUCKETS 2048
typedef struct {
    LINUX_FLOW_EVENT flow;
    bool used;
    int next;
} TCP_PENDING_SLOT;
static TCP_PENDING_SLOT g_TCPPending[TCP_PENDING_CAP];
static int g_TCPBuckets[TCP_PENDING_BUCKETS], g_TCPFree[TCP_PENDING_CAP];
static size_t g_TCPFreeCount, g_TCPCursor;
static bool g_TCPInitialized;
static uint64_t g_TCPDrops;
static unsigned TCPHash(const LINUX_FLOW_EVENT *f) {
    uint64_t h = f->socket_identity ^ f->process_id ^ f->src_port ^ ((uint64_t)f->dst_port << 16);
    return (unsigned)((h ^ (h >> 32)) & (TCP_PENDING_BUCKETS - 1));
}
static bool TCPKeyEqual(const LINUX_FLOW_EVENT *a, const LINUX_FLOW_EVENT *b) {
    return a->socket_identity == b->socket_identity && a->process_id == b->process_id &&
           a->src_port == b->src_port && a->dst_port == b->dst_port && !strcmp(a->src_ip, b->src_ip) &&
           !strcmp(a->dst_ip, b->dst_ip) &&
           !strcmp(a->enrichment.process_instance_id, b->enrichment.process_instance_id);
}
static void TCPPendingAdd(const LINUX_FLOW_EVENT *f) {
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
            g_TCPDrops += f->observation_count;
            return;
        }
        index = g_TCPFree[--g_TCPFreeCount];
        TCP_PENDING_SLOT *slot = &g_TCPPending[index];
        slot->flow = *f;
        slot->used = true;
        slot->next = g_TCPBuckets[bucket];
        g_TCPBuckets[bucket] = index;
    } else {
        LINUX_FLOW_EVENT *old = &g_TCPPending[index].flow;
        old->bytes_measured = old->bytes_measured || f->bytes_measured;
        old->bytes_in += f->bytes_in;
        old->bytes_out += f->bytes_out;
        old->observation_count += f->observation_count;
        if (f->first_observed_ns < old->first_observed_ns)
            old->first_observed_ns = f->first_observed_ns;
        if (f->last_observed_ns > old->last_observed_ns)
            old->last_observed_ns = f->last_observed_ns;
    }
}
static size_t TCPPendingDrain(LINUX_FLOW_EVENT *out, size_t capacity) {
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
