/* Run only on the isolated two-host segment created by the lab fixture.
 * A real TCP flow proves collection works before checking missing UDP coverage. */
#define _GNU_SOURCE
#define main ominull_linux_main_unused
#include "../linux/main.c"
#undef main
#include <assert.h>

static int connect_peer(int family, int type, const char *ip, unsigned short port) {
    int fd = socket(family, type, 0);
    assert(fd >= 0);
    struct timeval timeout = {.tv_sec = 2};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_storage addr = {0};
    socklen_t len;
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)&addr;
        a->sin_family = family;
        a->sin_port = htons(port);
        assert(inet_pton(family, ip, &a->sin_addr) == 1);
        len = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (void *)&addr;
        a->sin6_family = family;
        a->sin6_port = htons(port);
        assert(inet_pton(family, ip, &a->sin6_addr) == 1);
        len = sizeof(*a);
    }
    assert(connect(fd, (struct sockaddr *)&addr, len) == 0);
    return fd;
}

int main(int argc, char **argv) {
    assert(argc == 3);
    int tcp = connect_peer(AF_INET, SOCK_STREAM, argv[1], 9001);
    assert(send(tcp, "control", 7, 0) == 7);
    LINUX_FLOW_EVENT flows[64];
    size_t count = CollectActiveFlows(flows, 64), tcp_count = 0;
    for (size_t i = 0; i < count; i++)
        if (flows[i].protocol == 6 && flows[i].dst_port == 9001)
            tcp_count++;
    printf("control: %zu collector rows, %zu matching TCP flows\n", count, tcp_count);
    assert(tcp_count > 0);
    int udp4 = connect_peer(AF_INET, SOCK_DGRAM, argv[1], 9000);
    int udp6 = connect_peer(AF_INET6, SOCK_DGRAM, argv[2], 9000);
    for (int round = 0; round < 2; round++) {
        char reply[5];
        assert(send(udp4, "hello", 5, 0) == 5);
        assert(recv(udp4, reply, sizeof(reply), 0) == 5);
        assert(send(udp6, "hello", 5, 0) == 5);
        assert(recv(udp6, reply, sizeof(reply), 0) == 5);
    }
    unsigned long long in4 = 0, out4 = 0, in6 = 0, out6 = 0;
    size_t udp_count = 0;
    for (int round = 0; round < 3; round++) {
        usleep(100000);
        count = CollectActiveFlows(flows, 64);
        for (size_t i = 0; i < count; i++) {
            LINUX_FLOW_EVENT *f = &flows[i];
            if (f->protocol != 17 || f->dst_port != 9000)
                continue;
            assert(f->process_id == (unsigned)getpid());
            if (!strcmp(f->dst_ip, argv[1])) {
                in4 += f->bytes_in;
                out4 += f->bytes_out;
            } else if (!strcmp(f->dst_ip, argv[2])) {
                in6 += f->bytes_in;
                out6 += f->bytes_out;
            } else
                assert(!"invented UDP peer");
            udp_count++;
        }
    }
    printf("UDP rows=%zu v4 in/out=%llu/%llu v6 in/out=%llu/%llu\n", udp_count, in4, out4, in6, out6);
    fflush(stdout);
    assert(in4 == 10 && out4 == 10 && in6 == 10 && out6 == 10);
    close(tcp);
    close(udp4);
    close(udp6);
    return 0;
}
