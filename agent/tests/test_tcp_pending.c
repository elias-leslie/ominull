/* Check measured deltas survive deferral and do not starve behind hot flows. */
#define _GNU_SOURCE
#define main ominull_linux_main_unused
#include "../linux/main.c"
#undef main
#include <assert.h>
int main(void) {
    LINUX_FLOW_EVENT e = {0}, out[2];
    strcpy(e.src_ip, "10.0.4.1");
    strcpy(e.dst_ip, "10.0.4.2");
    e.protocol = 6;
    e.process_id = 123;
    e.dst_port = 443;
    e.observation_count = 1;
    e.first_observed_ns = 100;
    e.last_observed_ns = 200;
    e.bytes_out = 5;
    for (unsigned i = 0; i < 8; i++) {
        e.src_port = (uint16_t)(9000 + i);
        e.socket_identity = i;
        TCPPendingAdd(&e);
    }
    /* No new observation arrives for seven sockets: the retained values must
     * still reach the drain even if those sockets have closed meanwhile. */
    bool seen[8] = {0};
    for (int round = 0; round < 4; round++) {
        e.src_port = 9000;
        e.socket_identity = 0;
        TCPPendingAdd(&e);
        size_t n = TCPPendingDrain(out, 2);
        assert(n == 2);
        for (size_t i = 0; i < n; i++) {
            assert(out[i].src_port >= 9000 && out[i].src_port < 9008);
            seen[out[i].src_port - 9000] = true;
            assert(out[i].bytes_out >= 5);
            assert(out[i].first_observed_ns == 100 && out[i].last_observed_ns == 200);
        }
    }
    for (size_t i = 0; i < 8; i++)
        assert(seen[i]);
    while (TCPPendingDrain(out, 2)) {
    }
    for (unsigned i = 0; i < TCP_PENDING_CAP + 1; i++) {
        e.socket_identity = i;
        e.src_port = (uint16_t)i;
        TCPPendingAdd(&e);
    }
    assert(g_TCPFreeCount == 0 && g_TCPDrops == 1);
    size_t drained = 0;
    while (1) {
        size_t n = TCPPendingDrain(out, 2);
        if (!n)
            break;
        drained += n;
    }
    assert(drained == TCP_PENDING_CAP);
    puts("TCP pending: closed-flow retention, fair drain, bounded overflow passed");
    return 0;
}
