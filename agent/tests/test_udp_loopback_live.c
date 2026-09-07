/* Native kernel compatibility probe. Run in an isolated network namespace. */
#define _GNU_SOURCE
#define main ominull_linux_main_unused
#include "../linux/main.c"
#undef main
#include <assert.h>
static void exchange(int family) {
    int server = socket(family, SOCK_DGRAM, 0), client = socket(family, SOCK_DGRAM, 0);
    assert(server >= 0 && client >= 0);
    struct sockaddr_storage addr = {0};
    socklen_t len;
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)&addr;
        a->sin_family = family;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        len = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (void *)&addr;
        a->sin6_family = family;
        a->sin6_addr = in6addr_loopback;
        len = sizeof(*a);
    }
    assert(bind(server, (void *)&addr, len) == 0);
    assert(getsockname(server, (void *)&addr, &len) == 0);
    assert(connect(client, (void *)&addr, len) == 0);
    struct timeval timeout = {.tv_sec = 2};
    assert(setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    char bytes[5];
    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    assert(send(client, "hello", 5, 0) == 5);
    assert(recvfrom(server, bytes, 5, 0, (void *)&peer, &plen) == 5);
    assert(sendto(server, bytes, 5, 0, (void *)&peer, plen) == 5);
    assert(recv(client, bytes, 5, 0) == 5);
    close(client);
    close(server);
}
int main(void) {
    UDPCollectorStart();
    assert(!strcmp(g_UDPStatus, "active"));
    exchange(AF_INET);
    exchange(AF_INET6);
    UDPCollectorPoll();
    LINUX_FLOW_EVENT events[64];
    size_t count = UDPCollectorDrain(events, 64);
    uint64_t in4 = 0, out4 = 0, in6 = 0, out6 = 0;
    for (size_t i = 0; i < count; i++) {
        LINUX_FLOW_EVENT *e = &events[i];
        assert(e->process_id == (unsigned)getpid());
        if (!strcmp(e->dst_ip, "127.0.0.1")) {
            in4 += e->bytes_in;
            out4 += e->bytes_out;
        } else {
            assert(!strcmp(e->dst_ip, "::1"));
            in6 += e->bytes_in;
            out6 += e->bytes_out;
        }
    }
    printf("UDP kernel probe: %zu rows, v4=%llu/%llu v6=%llu/%llu drops=%llu\n", count,
           (unsigned long long)in4, (unsigned long long)out4, (unsigned long long)in6,
           (unsigned long long)out6, (unsigned long long)UDPCollectorDropped());
    assert(count == 8 && in4 == 10 && out4 == 10 && in6 == 10 && out6 == 10 && UDPCollectorDropped() == 0);
    UDPCollectorClose();
    return 0;
}
