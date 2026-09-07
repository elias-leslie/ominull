#ifndef OMINULL_LINUX_UDP_COLLECTOR_H
#define OMINULL_LINUX_UDP_COLLECTOR_H
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include "../../build/bpf/udp.skel.h"
#include "udp_observation.h"

#define UDP_QUEUE_CAP 1024
#define UDP_BUCKETS 2048
#define UDP_POLL_CAP 16384

typedef struct {
    struct ominull_udp_observation event;
    uint64_t first_ns, bytes, observations;
    int next;
    bool used;
} UDP_PENDING;
static struct udp_bpf *g_UDPProgram;
static struct ring_buffer *g_UDPRing;
static UDP_PENDING g_UDPQueue[UDP_QUEUE_CAP];
static int g_UDPBuckets[UDP_BUCKETS], g_UDPFree[UDP_QUEUE_CAP];
static size_t g_UDPFreeCount, g_UDPCursor, g_UDPPollCount;
static uint64_t g_UDPQueueDrops, g_UDPDecodeDrops;
static bool g_UDPStarted;
static const char *g_UDPStatus = "not_started";
static int g_UDPError;

static uint32_t UDPHash(const struct ominull_udp_observation *e) {
    uint32_t h = e->pid ^ (uint32_t)e->process_start_ns ^ e->ifindex;
    for (size_t i = 0; i < 16; i++)
        h = (h ^ e->local_ip[i] ^ ((uint32_t)e->remote_ip[i] << 8)) * 16777619u;
    return (h ^ e->local_port ^ ((uint32_t)e->remote_port << 16) ^ e->outbound) & (UDP_BUCKETS - 1);
}
static bool UDPKeyEqual(const struct ominull_udp_observation *a, const struct ominull_udp_observation *b) {
    return a->pid == b->pid && a->process_start_ns == b->process_start_ns && a->ip_version == b->ip_version &&
           a->outbound == b->outbound && a->ifindex == b->ifindex && a->local_port == b->local_port &&
           a->remote_port == b->remote_port && memcmp(a->local_ip, b->local_ip, 16) == 0 &&
           memcmp(a->remote_ip, b->remote_ip, 16) == 0;
}
static int UDPReceive(void *context, void *data, size_t size) {
    (void)context;
    if (size != sizeof(struct ominull_udp_observation)) {
        g_UDPDecodeDrops++;
        return 0;
    }
    const struct ominull_udp_observation *e = data;
    unsigned bucket = UDPHash(e);
    int index = g_UDPBuckets[bucket];
    while (index >= 0 && !UDPKeyEqual(e, &g_UDPQueue[index].event))
        index = g_UDPQueue[index].next;
    if (index < 0) {
        if (g_UDPFreeCount == 0) {
            g_UDPQueueDrops++;
            goto done;
        }
        index = g_UDPFree[--g_UDPFreeCount];
        UDP_PENDING *slot = &g_UDPQueue[index];
        memset(slot, 0, sizeof(*slot));
        slot->event = *e;
        slot->first_ns = e->observed_ns;
        slot->used = true;
        slot->next = g_UDPBuckets[bucket];
        g_UDPBuckets[bucket] = index;
    }
    g_UDPQueue[index].event.observed_ns = e->observed_ns;
    g_UDPQueue[index].bytes += e->payload_bytes;
    g_UDPQueue[index].observations++;
done:
    /* A busy producer must not keep a collector poll inside libbpf forever. */
    return ++g_UDPPollCount >= UDP_POLL_CAP ? 1 : 0;
}
static void UDPCollectorClose(void) {
    ring_buffer__free(g_UDPRing);
    g_UDPRing = NULL;
    udp_bpf__destroy(g_UDPProgram);
    g_UDPProgram = NULL;
}
static bool UDPKernelSignaturesSupported(void) {
    struct btf *types = btf__load_vmlinux_btf();
    if (!types || libbpf_get_error(types))
        return false;
    const char *names[] = {"udp_send_skb", "udp_v6_send_skb", "udp_recvmsg", "udpv6_recvmsg",
                           "skb_consume_udp"};
    const unsigned counts[] = {3, 3, 5, 5, 3};
    bool supported = true;
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        int id = btf__find_by_name_kind(types, names[i], BTF_KIND_FUNC);
        const struct btf_type *function = id > 0 ? btf__type_by_id(types, (uint32_t)id) : NULL;
        const struct btf_type *prototype = function ? btf__type_by_id(types, function->type) : NULL;
        if (!prototype || btf_vlen(prototype) != counts[i]) {
            supported = false;
            break;
        }
        if (i == 2 || i == 3) {
            const struct btf_param *args = btf_params(prototype);
            const char *name = btf__name_by_offset(types, args[3].name_off);
            if (!name || strcmp(name, "flags") != 0) {
                supported = false;
                break;
            }
        }
    }
    btf__free(types);
    return supported;
}
static void UDPCollectorStart(void) {
    if (g_UDPStarted)
        return;
    g_UDPStarted = true;
    struct stat ns;
    if (stat("/proc/self/ns/net", &ns))
        goto failed;
    for (size_t i = 0; i < UDP_BUCKETS; i++)
        g_UDPBuckets[i] = -1;
    for (size_t i = 0; i < UDP_QUEUE_CAP; i++)
        g_UDPFree[i] = (int)i;
    g_UDPFreeCount = UDP_QUEUE_CAP;
    if (!UDPKernelSignaturesSupported()) {
        g_UDPError = -EPROTONOSUPPORT;
        goto failed;
    }
    g_UDPProgram = udp_bpf__open();
    if (!g_UDPProgram)
        goto failed;
    g_UDPProgram->rodata->target_netns = (uint32_t)ns.st_ino;
    if ((g_UDPError = udp_bpf__load(g_UDPProgram)) != 0)
        goto failed;
    if ((g_UDPError = udp_bpf__attach(g_UDPProgram)) != 0)
        goto failed;
    g_UDPRing = ring_buffer__new(bpf_map__fd(g_UDPProgram->maps.observations), UDPReceive, NULL, NULL);
    if (!g_UDPRing)
        goto failed;
    g_UDPStatus = "active";
    return;
failed:
    if (!g_UDPError)
        g_UDPError = errno ? -errno : -1;
    g_UDPStatus = "unavailable";
    UDPCollectorClose();
}
static void UDPCollectorPoll(void) {
    UDPCollectorStart();
    if (!g_UDPRing)
        return;
    g_UDPPollCount = 0;
    int result = ring_buffer__consume(g_UDPRing);
    if (result < 0) {
        g_UDPError = result;
        g_UDPStatus = "error";
    }
}
static bool UDPAddress(const unsigned char *raw, unsigned char version, uint32_t ifindex, char *out,
                       size_t capacity) {
    if (!inet_ntop(version == 4 ? AF_INET : AF_INET6, raw, out, (socklen_t)capacity))
        return false;
    if (version == 6 && raw[0] == 0xfe && (raw[1] & 0xc0) == 0x80) {
        if (!ifindex)
            return false;
        size_t length = strlen(out);
        int n = snprintf(out + length, capacity - length, "%%%u", ifindex);
        if (n < 0 || (size_t)n >= capacity - length)
            return false;
    }
    return true;
}
static size_t UDPCollectorDrain(LINUX_FLOW_EVENT *output, size_t capacity) {
    size_t count = 0;
    for (size_t visited = 0; visited < UDP_QUEUE_CAP && count < capacity; visited++) {
        int index = (int)g_UDPCursor;
        g_UDPCursor = (g_UDPCursor + 1) % UDP_QUEUE_CAP;
        UDP_PENDING *slot = &g_UDPQueue[index];
        if (!slot->used)
            continue;
        struct ominull_udp_observation *e = &slot->event;
        LINUX_FLOW_EVENT *f = &output[count];
        memset(f, 0, sizeof(*f));
        if (!UDPAddress(e->local_ip, e->ip_version, e->ifindex, f->src_ip, sizeof(f->src_ip)) ||
            !UDPAddress(e->remote_ip, e->ip_version, e->ifindex, f->dst_ip, sizeof(f->dst_ip))) {
            g_UDPDecodeDrops++;
        } else {
            f->protocol = IPPROTO_UDP;
            f->bytes_measured = true;
            f->src_port = ntohs(e->local_port);
            f->dst_port = ntohs(e->remote_port);
            f->process_id = e->pid;
            snprintf(f->direction, sizeof(f->direction), "%s", e->outbound ? "OUTBOUND" : "INBOUND");
            if (e->outbound)
                f->bytes_out = slot->bytes;
            else
                f->bytes_in = slot->bytes;
            f->observation_count = slot->observations;
            f->first_observed_ns = slot->first_ns;
            f->last_observed_ns = e->observed_ns;
            /* A reused PID must not borrow the new process's path or identity. */
            unsigned long long ticks = 0;
            uint32_t parent = 0;
            long hz = sysconf(_SC_CLK_TCK);
            uint64_t observed_ticks = hz > 0 ? e->process_start_ns / (1000000000ULL / (uint64_t)hz) : 0;
            snprintf(f->process_path, sizeof(f->process_path), "%.*s", (int)sizeof(e->comm), e->comm);
            bool same_process = ProcessLineage_ReadStat(e->pid, &ticks, &parent) && ticks == observed_ticks;
            if (same_process) {
                ProcessLineage_InspectProcess(e->pid, &f->enrichment);
                char procpath[64];
                snprintf(procpath, sizeof(procpath), "/proc/%u/exe", e->pid);
                ssize_t length = readlink(procpath, f->process_path, sizeof(f->process_path) - 1);
                if (length >= 0)
                    f->process_path[length] = 0;
                same_process = ProcessLineage_ReadStat(e->pid, &ticks, &parent) && ticks == observed_ticks;
            }
            if (!same_process) {
                memset(&f->enrichment, 0, sizeof(f->enrichment));
                snprintf(f->process_path, sizeof(f->process_path), "%.*s", (int)sizeof(e->comm), e->comm);
                snprintf(f->enrichment.attribution_status, sizeof(f->enrichment.attribution_status),
                         "observed_comm_only");
                snprintf(f->enrichment.process_instance_id, sizeof(f->enrichment.process_instance_id),
                         "%s:%u:%llu", ProcessLineage_GetBootID(), e->pid,
                         (unsigned long long)observed_ticks);
            }
            count++;
        }
        int *link = &g_UDPBuckets[UDPHash(e)];
        while (*link >= 0 && *link != index)
            link = &g_UDPQueue[*link].next;
        if (*link == index)
            *link = slot->next;
        slot->used = false;
        g_UDPFree[g_UDPFreeCount++] = index;
    }
    return count;
}
static uint64_t UDPCollectorDropped(void) {
    uint64_t total = g_UDPQueueDrops + g_UDPDecodeDrops;
    if (g_UDPProgram) {
        for (uint32_t reason = 0; reason < 4; reason++) {
            uint64_t value = 0;
            if (bpf_map_lookup_elem(bpf_map__fd(g_UDPProgram->maps.health), &reason, &value) == 0)
                total += value;
        }
    }
    return total;
}
static void ObservationTime(uint64_t observed_ns, uint64_t boot_ns, uint64_t real_ns, char *output,
                            size_t capacity) {
    if (observed_ns && observed_ns <= boot_ns)
        real_ns -= boot_ns - observed_ns;
    time_t seconds = (time_t)(real_ns / 1000000000ULL);
    struct tm utc;
    gmtime_r(&seconds, &utc);
    char date[32];
    strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &utc);
    snprintf(output, capacity, "%s.%09uZ", date, (unsigned)(real_ns % 1000000000ULL));
}
static void FlowObservationJSON(const LINUX_FLOW_EVENT *flow, char *output, size_t capacity) {
    char first[64], last[64];
    struct timespec real, boot;
    clock_gettime(CLOCK_REALTIME, &real);
    clock_gettime(CLOCK_BOOTTIME, &boot);
    uint64_t boot_ns = (uint64_t)boot.tv_sec * 1000000000ULL + boot.tv_nsec;
    uint64_t real_ns = (uint64_t)real.tv_sec * 1000000000ULL + real.tv_nsec;
    ObservationTime(flow->first_observed_ns, boot_ns, real_ns, first, sizeof(first));
    ObservationTime(flow->last_observed_ns, boot_ns, real_ns, last, sizeof(last));
    bool udp = flow->protocol == IPPROTO_UDP;
    snprintf(output, capacity,
             ",\"timestamp\":\"%s\",\"observation\":{\"source\":\"%s\",\"byte_basis\":\"%s\",\"timing\":\"%"
             "s\",\"count\":%llu,\"first_at\":\"%s\",\"last_at\":\"%s\"}",
             last, udp ? "linux-bpf-udp" : "linux-sock-diag",
             udp ? "udp_payload" : (flow->bytes_measured ? "tcp_socket_counter" : "unknown"),
             udp ? "socket_io" : "counter_sample",
             (unsigned long long)(flow->observation_count ? flow->observation_count : 1), first, last);
}

#endif
