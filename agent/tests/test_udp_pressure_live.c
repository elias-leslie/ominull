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
    UDPCollectorStart();
    assert(!strcmp(g_UDPStatus, "active"));
    enum { FLOWS = 140 };
    unsigned short ports[FLOWS];
    unsigned counts[FLOWS] = {0};
    int sockets[FLOWS];
    for (unsigned i = 0; i < FLOWS; i++) {
        int family = i % 2 ? AF_INET6 : AF_INET;
        int fd = connect_peer(family, SOCK_DGRAM, argv[i % 2 ? 2 : 1], 9000);
        sockets[i] = fd;
        struct sockaddr_storage local;
        socklen_t length = sizeof(local);
        assert(getsockname(fd, (void *)&local, &length) == 0);
        ports[i] = ntohs(family == AF_INET ? ((struct sockaddr_in *)&local)->sin_port
                                           : ((struct sockaddr_in6 *)&local)->sin6_port);
        char reply[5];
        assert(send(fd, "hello", 5, 0) == 5);
        if (i == 0) {
            assert(recv(fd, reply, 5, MSG_PEEK) == 5);
            assert(recv(fd, reply, 5, MSG_PEEK) == 5);
        }
        assert(recv(fd, reply, 5, 0) == 5);
    }
    for (unsigned i = 0; i < FLOWS; i++)
        close(sockets[i]);
    LINUX_FLOW_EVENT out[64];
    size_t rows = 0;
    for (int round = 0; round < 10; round++) {
        UDPCollectorPoll();
        size_t n = UDPCollectorDrain(out, 64);
        assert(n <= 64);
        rows += n;
        for (size_t j = 0; j < n; j++) {
            assert(out[j].process_id == (unsigned)getpid());
            assert(out[j].bytes_in + out[j].bytes_out == 5);
            assert(out[j].observation_count == 1);
            bool matched = false;
            for (unsigned i = 0; i < FLOWS; i++)
                if (ports[i] == out[j].src_port && !strcmp(out[j].dst_ip, argv[i % 2 ? 2 : 1])) {
                    counts[i]++;
                    matched = true;
                    break;
                }
            assert(matched);
        }
        usleep(10000);
    }
    for (unsigned i = 0; i < FLOWS; i++)
        assert(counts[i] == 2);
    assert(rows == 2 * FLOWS);
    assert(UDPCollectorDropped() == 0);
    printf("UDP pressure: %zu rows from %d closed dual-stack sockets, 64-record cap, MSG_PEEK not "
           "double-counted, zero loss\n",
           rows, FLOWS);
    UDPCollectorClose();
    return 0;
}
