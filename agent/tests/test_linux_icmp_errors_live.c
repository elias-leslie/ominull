/* An allowed connection through a smaller link needs the router's "packet too big",
 * and that router is on no allow list. Requires a dedicated network namespace and
 * the peer scripts/test-linux-icmp-errors.sh sets up. */
#define _GNU_SOURCE
#define main unused_agent_main
#include "../linux/main.c"
#undef main
#include <assert.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAILED %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static void Cleanup(void) {
    EnforcementTeardown("iptables");
    EnforcementTeardown("ip6tables");
}

static void ForgetPathMTU(void) {
    const char *v4[] = {"ip", "route", "flush", "cache", NULL};
    const char *v6[] = {"ip", "-6", "route", "flush", "cache", NULL};
    CHECK(RunTool(v4) == 0 && RunTool(v6) == 0);
}

/* Sends more than the small link takes in one packet and waits for the peer to say
 * it read it all. Without the router's error the sender keeps resending too-big
 * packets until the timeout. */
static bool Transfer(const char *ip, unsigned port) {
    static char data[1 << 20];
    struct sockaddr_storage address = {0};
    socklen_t size;
    int family = strchr(ip, ':') ? AF_INET6 : AF_INET;
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
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) return false;
    struct timeval timeout = {6, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    bool ok = connect(fd, (void *)&address, size) == 0;
    size_t sent = 0;
    while (ok && sent < sizeof(data)) {
        ssize_t n = send(fd, data + sent, sizeof(data) - sent, MSG_NOSIGNAL);
        if (n <= 0) ok = false;
        else sent += (size_t)n;
    }
    char reply = 0;
    ok = ok && shutdown(fd, SHUT_WR) == 0 && recv(fd, &reply, 1, 0) == 1 && reply == 'k';
    close(fd);
    return ok;
}

int main(int argc, char **argv) {
    struct stat current, initial;
    CHECK(argc == 3 && geteuid() == 0);
    CHECK(stat("/proc/self/ns/net", &current) == 0 && stat("/proc/1/ns/net", &initial) == 0 &&
          current.st_ino != initial.st_ino);
    const unsigned port = 9005;
    ForgetPathMTU();
    CHECK(Transfer(argv[1], port) && Transfer(argv[2], port));
    puts("Precondition: both transfers work through the smaller link with no rules");

    atexit(Cleanup);
    char allowed[2][64], empty[1][64] = {{0}};
    strcpy(allowed[0], argv[1]);
    strcpy(allowed[1], argv[2]);
    OMINULL_HUB_TARGETS hub = {0};
    CHECK(EnforcementBuild("iptables", true, &hub, allowed, 2, empty, 0, empty, 0, NULL, 0));
    CHECK(EnforcementBuild("ip6tables", true, &hub, allowed, 2, empty, 0, empty, 0, NULL, 0));
    ForgetPathMTU();
    bool v4 = Transfer(argv[1], port), v6 = Transfer(argv[2], port);
    printf("Isolated, to an allowed address: IPv4 %s, IPv6 %s\n", v4 ? "ok" : "stalled", v6 ? "ok" : "stalled");
    CHECK(v4 && v6);
    puts("An allowed connection hears the router's packet-too-big while isolated");
    return 0;
}
