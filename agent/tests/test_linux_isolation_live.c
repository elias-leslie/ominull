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
/* OpenedDuringRebuilds keeps trying a blocked service from a second process
 * while the policy is rebuilt over and over. One connection is one gap. */
static int OpenedDuringRebuilds(const char *ip, unsigned port,
                                OMINULL_HUB_TARGETS *hub, char allowed[][64],
                                char empty[][64], bool afterCrash) {
    int pipefd[2];
    if (pipe(pipefd) != 0)
        return -1;
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        int opened = 0;
        char stop;
        close(pipefd[1]);
        fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
        struct sockaddr_storage address = {0};
        socklen_t size = sizeof(struct sockaddr_in);
        struct sockaddr_in *a = (void *)&address;
        a->sin_family = AF_INET;
        a->sin_port = htons(port);
        inet_pton(AF_INET, ip, &a->sin_addr);
        while (read(pipefd[0], &stop, 1) < 0) {
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (fd < 0)
                _exit(255);
            (void)connect(fd, (void *)&address, size);
            fd_set write;
            FD_ZERO(&write);
            FD_SET(fd, &write);
            struct timeval wait = {0, 5000};
            if (select(fd + 1, NULL, &write, NULL, &wait) > 0) {
                int error = 0;
                socklen_t length = sizeof(error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && !error)
                    opened++;
            }
            close(fd);
        }
        _exit(opened > 100 ? 100 : opened);
    }
    close(pipefd[0]);
    for (int i = 0; i < 20; i++) {
        if (afterCrash) {
            /* What a swap leaves when it dies right after unhooking the old
             * chain: the second chain is the only policy in force. */
            const char *renameIn[] = {"iptables", "-w", "5", "-E", OMINULL_CHAIN_IN, OMINULL_NEXT_IN, NULL};
            const char *renameOut[] = {"iptables", "-w", "5", "-E", OMINULL_CHAIN_OUT, OMINULL_NEXT_OUT, NULL};
            const char *leftIn[] = {"iptables", "-w", "5", "-N", OMINULL_CHAIN_IN, NULL};
            const char *leftOut[] = {"iptables", "-w", "5", "-N", OMINULL_CHAIN_OUT, NULL};
            if (RunTool(renameIn) || RunTool(renameOut) || RunTool(leftIn) || RunTool(leftOut))
                return -1;
        }
        /* Every pass swaps, whether or not the list changed. */
        if (!EnforcementBuild("iptables", true, hub, allowed, i % 2, empty, 0, empty,
                              0, NULL, 0))
            return -1;
    }
    close(pipefd[1]);
    int status = 0;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}
#define CHECK(c)                                                               \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "Linux isolation check failed at line %d\n",       \
                    __LINE__);                                                 \
            return 1;                                                          \
        }                                                                      \
    } while (0)
static int HubNameAnswers(const char *hosts, const char *ip) {
    FILE *f = fopen(hosts, "w");
    CHECK(f);
    fprintf(f, "%s hub.rig.invalid\n", ip);
    fclose(f);
    return 0;
}
/* Another program on the host, as an unprivileged process would be. */
static bool ConnectAsNobody(const char *ip, unsigned port) {
    pid_t child = fork();
    if (child == 0) {
        if (setgid(65534) != 0 || setuid(65534) != 0) _exit(2);
        _exit(ConnectPeer(ip, port) ? 0 : 1);
    }
    int status = 0;
    if (child < 0 || waitpid(child, &status, 0) != child) return true;
    return !(WIFEXITED(status) && WEXITSTATUS(status) == 1);
}
static int FollowsAMovedHub(const char *oldIP, const char *newIP, const char *hosts) {
    LINUX_AGENT_CONFIG config;
    memset(&config, 0, sizeof(config));
    strcpy(config.hub_url, "https://hub.rig.invalid:9003");
    CHECK(HubNameAnswers(hosts, oldIP) == 0);
    CHECK(OminullResolveHub(config.hub_url, &appliedHubTargets));
    char empty[1][64] = {{0}};
    CHECK(EnforcementBuild("iptables", true, &appliedHubTargets, empty, 0, empty, 0, empty, 0, NULL, 0));
    known = appliedIsolated = true;
    CHECK(ConnectPeer(oldIP, 9003) && !ConnectPeer(newIP, 9003));
    FollowHubAddress(&config);          /* the same answer changes nothing */
    CHECK(ConnectPeer(oldIP, 9003) && !ConnectPeer(newIP, 9003));
    CHECK(HubNameAnswers(hosts, newIP) == 0);
    FollowHubAddress(&config);
    CHECK(appliedHubTargets.count == 2 && !strcmp(appliedHubTargets.addresses[1], newIP));
    /* The old hole stays in case the answer was wrong; the new one is the agent's. */
    CHECK(ConnectPeer(newIP, 9003) && ConnectPeer(oldIP, 9003));
    CHECK(!ConnectPeer(newIP, 9004));
    CHECK(!ConnectAsNobody(newIP, 9003) && ConnectAsNobody(oldIP, 9003));
    known = appliedIsolated = false;
    memset(&appliedHubTargets, 0, sizeof(appliedHubTargets));
    Cleanup();
    return 0;
}
int main(int argc, char **argv) {
    struct stat current, initial;
    CHECK((argc == 3 || argc == 4 || argc == 5) && geteuid() == 0);
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
    CHECK(EnforcementBuild("iptables", true, &hub, allowed, 1, empty, 0, empty, 0,
                           NULL, 0));
    CHECK(EnforcementBuild("ip6tables", true, &hub, allowed, 1, empty, 0, empty, 0,
                           NULL, 0));
    const char *flush[] = {"ip", "-6", "neigh", "flush", "all", NULL};
    CHECK(RunTool(flush) == 0);
    CHECK(ConnectPeer(argv[1], 9003) && ConnectPeer(argv[2], 9003));
    CHECK(!ConnectPeer(argv[1], 9004) && ConnectPeer(argv[2], 9004));
    puts("Exact dual-stack hub ports and IPv6 neighbor rediscovery passed");
    if (argc == 5) {
        /* argv[4] is the file mounted over this namespace's /etc/hosts. */
        CHECK(FollowsAMovedHub(argv[1], argv[3], argv[4]) == 0);
        puts("An isolated host's hub hole follows the hub's new address, for the agent alone");
    }
    EnforcementBuild("ip6tables", true, &hub, allowed, 1, allowed, 1, empty, 0,
                     NULL, 0);
    CHECK(ConnectPeer(argv[2], 9003) && !ConnectPeer(argv[2], 9004));
    Cleanup();
    CHECK(ConnectPeer(argv[1], 9004) && ConnectPeer(argv[2], 9004));
    puts("IPv6 block precedence and release passed");
    /* A rebuild must not open the host. argv[3] is an IPv4 address on the peer
     * that nothing allows. */
    if (argc == 4) {
        EnforcementBuild("iptables", true, &hub, allowed, 1, empty, 0, empty, 0,
                         NULL, 0);
        CHECK(!ConnectPeer(argv[3], 9004));
        int opened = OpenedDuringRebuilds(argv[3], 9004, &hub, allowed, empty, false);
        CHECK(opened == 0);
        puts("Twenty rebuilds under isolation opened nothing");
        opened = OpenedDuringRebuilds(argv[3], 9004, &hub, allowed, empty, true);
        CHECK(opened == 0);
        puts("Twenty rebuilds after a swap that died opened nothing");
        const char *chains[] = {"iptables", "-w", "5", "-S", OMINULL_NEXT_OUT, NULL};
        CHECK(RunTool(chains) != 0);
        /* The dead-man timer: only the default deny goes, the quarantine stays. */
        char peer[1][64];
        strcpy(peer[0], argv[3]);
        CHECK(EnforcementBuild("iptables", true, &hub, allowed, 1, peer, 1, empty, 0,
                               NULL, 0));
        CHECK(!ConnectPeer(argv[1], 9004));
        CHECK(LiftDefaultDeny("iptables") && LiftDefaultDeny("ip6tables"));
        CHECK(ConnectPeer(argv[1], 9004) && !ConnectPeer(argv[3], 9004));
        puts("Lifting the default deny keeps the peer block");
        Cleanup();
        CHECK(ConnectPeer(argv[3], 9004));
    }
    return 0;
}
