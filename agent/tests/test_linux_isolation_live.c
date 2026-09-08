/* Requires a dedicated network namespace and echo peer. Never runs in the
 * VM's initial network namespace. Existing agent policy stays untouched. */
#define _GNU_SOURCE
#define main unused_agent_main
#include "../linux/main.c"
#undef main
#include <assert.h>
static void Cleanup(void) {
    EnforcementTeardown("iptables");
    EnforcementTeardown("ip6tables");
}
static bool ConnectPeer(const char *ip, unsigned port) {
    int family = strchr(ip, ':') ? AF_INET6 : AF_INET;
    struct sockaddr_storage address = {0};
    socklen_t size;
    if (family == AF_INET6) {
        struct sockaddr_in6 *a = (void *)&address;
        a->sin6_family = family;
        a->sin6_port = htons(port);
        inet_pton(family, ip, &a->sin6_addr);
        size = sizeof(*a);
    } else {
        struct sockaddr_in *a = (void *)&address;
        a->sin_family = family;
        a->sin_port = htons(port);
        inet_pton(family, ip, &a->sin_addr);
        size = sizeof(*a);
    }
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return false;
    bool ok = connect(fd, (void *)&address, size) == 0;
    if (!ok && errno == EINPROGRESS) {
        fd_set write;
        FD_ZERO(&write);
        FD_SET(fd, &write);
        struct timeval timeout = {2, 0};
        if (select(fd + 1, NULL, &write, NULL, &timeout) > 0) {
            int error = 0;
            socklen_t length = sizeof(error);
            ok = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 &&
                 !error;
        }
    }
    close(fd);
    return ok;
}
#define CHECK(c)                                                               \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "Linux isolation check failed at line %d\n",       \
                    __LINE__);                                                 \
            return 1;                                                          \
        }                                                                      \
    } while (0)
int main(int argc, char **argv) {
    struct stat current, initial;
    CHECK(argc == 3 && geteuid() == 0);
    CHECK(stat("/proc/self/ns/net", &current) == 0 &&
          stat("/proc/1/ns/net", &initial) == 0 &&
          current.st_ino != initial.st_ino);
    CHECK(ConnectPeer(argv[1], 9003) && ConnectPeer(argv[2], 9003));
    CHECK(ConnectPeer(argv[1], 9004) && ConnectPeer(argv[2], 9004));
    puts("Precondition: four reachable services inside isolated namespaces");
    atexit(Cleanup);
    OMINULL_HUB_TARGETS hub = {0};
    strcpy(hub.addresses[0], argv[1]);
    strcpy(hub.addresses[1], argv[2]);
    hub.count = 2;
    hub.port = 9003;
    char allowed[1][64], empty[1][64] = {{0}};
    strcpy(allowed[0], argv[2]);
    EnforcementBuild("iptables", true, &hub, allowed, 1, empty, 0, empty, 0,
                     NULL, 0, true);
    EnforcementBuild("ip6tables", true, &hub, allowed, 1, empty, 0, empty, 0,
                     NULL, 0, true);
    const char *flush[] = {"ip", "-6", "neigh", "flush", "all", NULL};
    CHECK(RunTool(flush) == 0);
    CHECK(ConnectPeer(argv[1], 9003) && ConnectPeer(argv[2], 9003));
    CHECK(!ConnectPeer(argv[1], 9004) && ConnectPeer(argv[2], 9004));
    puts("Exact dual-stack hub ports and IPv6 neighbor rediscovery passed");
    EnforcementBuild("ip6tables", true, &hub, allowed, 1, allowed, 1, empty, 0,
                     NULL, 0, true);
    CHECK(ConnectPeer(argv[2], 9003) && !ConnectPeer(argv[2], 9004));
    Cleanup();
    CHECK(ConnectPeer(argv[1], 9004) && ConnectPeer(argv[2], 9004));
    puts("IPv6 block precedence and release passed");
    return 0;
}
