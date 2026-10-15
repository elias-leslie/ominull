/* Loopback UDP is counted per process, direction and service port and held
 * up to five minutes; other UDP drains at once. No kernel program needed: the
 * ring buffer callback is fed directly. */
#define _GNU_SOURCE
#define main ominull_linux_main_unused
#include "../linux/main.c"
#undef main
#include <assert.h>

static uint64_t boot_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_BOOTTIME, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static void observe(const char *local, uint16_t lport, const char *remote, uint16_t rport, bool outbound,
                    uint32_t bytes, uint64_t at) {
    struct ominull_udp_observation e = {0};
    e.observed_ns = at;
    e.pid = (uint32_t)getpid();
    e.payload_bytes = bytes;
    e.ip_version = 4;
    e.outbound = outbound;
    e.local_port = htons(lport);
    e.remote_port = htons(rport);
    inet_pton(AF_INET, local, e.local_ip);
    inet_pton(AF_INET, remote, e.remote_ip);
    snprintf(e.comm, sizeof(e.comm), "rollup-test");
    assert(UDPReceive(NULL, &e, sizeof(e)) == 0);
}

int main(void) {
    for (size_t i = 0; i < UDP_BUCKETS; i++)
        g_UDPBuckets[i] = -1;
    for (size_t i = 0; i < UDP_QUEUE_CAP; i++)
        g_UDPFree[i] = (int)i;
    g_UDPFreeCount = UDP_QUEUE_CAP;
    LINUX_FLOW_EVENT out[16];
    uint64_t now = boot_ns();

    /* Three queries to the local resolver from three ephemeral ports, and one
     * query to the LAN resolver. */
    observe("127.0.0.1", 40001, "127.0.0.53", 53, true, 40, now);
    observe("127.0.0.1", 40002, "127.0.0.53", 53, true, 41, now);
    observe("127.0.0.1", 40003, "127.0.0.53", 53, true, 42, now);
    observe("10.0.0.5", 40004, "10.0.0.1", 53, true, 43, now);
    assert(g_UDPFreeCount == UDP_QUEUE_CAP - 2);

    size_t n = UDPCollectorDrain(out, 16);
    assert(n == 1 && !strcmp(out[0].dst_ip, "10.0.0.1") && out[0].src_port == 40004);
    assert(UDPCollectorDrain(out, 16) == 0); /* the loopback counter is held */

    /* Once five minutes old it goes, as one record: service port kept, the
     * ephemeral side zeroed, bytes and observations summed. */
    for (size_t i = 0; i < UDP_QUEUE_CAP; i++)
        if (g_UDPQueue[i].used)
            g_UDPQueue[i].first_ns = now - UDP_LOCAL_HOLD_NS - 1;
    n = UDPCollectorDrain(out, 16);
    assert(n == 1);
    assert(!strcmp(out[0].dst_ip, "127.0.0.53") && out[0].dst_port == 53 && out[0].src_port == 0);
    assert(out[0].bytes_out == 123 && out[0].observation_count == 3);

    /* The resolver's side: received on 53 from ephemeral ports, keyed by 53. */
    observe("127.0.0.53", 53, "127.0.0.1", 40005, false, 10, now);
    observe("127.0.0.53", 53, "127.0.0.1", 40006, false, 11, now);
    assert(UDPCollectorDrain(out, 16) == 0);
    g_UDPFlushLocal = true;
    n = UDPCollectorDrain(out, 16);
    assert(n == 1 && out[0].src_port == 53 && out[0].dst_port == 0 && out[0].bytes_in == 21);
    g_UDPFlushLocal = false;

    /* Held counters never crowd out new observations. */
    for (unsigned i = 0; i < UDP_QUEUE_CAP; i++)
        observe("127.0.0.1", 40000, "127.0.0.1", (uint16_t)(1 + i), true, 1, now);
    assert(g_UDPFreeCount == 0);
    n = UDPCollectorDrain(out, 16);
    assert(n == 16);
    printf("[+] loopback UDP rolls up per service port and is held, other UDP is not.\n");
    return 0;
}
