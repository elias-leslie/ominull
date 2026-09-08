/* Lab only. A separate dynamic sublayer leaves the installed agent's filters
 * untouched. Use QEMU guest execution; isolation briefly denies SSH. */
#define OMINULL_WFP_EMBEDDED
#define OMINULL_WFP_SUBLAYER_LAST_BYTE 0x71
#include "../windows/wfp_user.c"
#include <iphlpapi.h>
#include <netioapi.h>
static bool ConnectPeer(const char *address, unsigned port) {
    int family = strchr(address, ':') ? AF_INET6 : AF_INET;
    struct sockaddr_storage storage = {0};
    int size;
    if (family == AF_INET6) {
        struct sockaddr_in6 *a = (void *)&storage;
        a->sin6_family = family;
        a->sin6_port = htons(port);
        if (inet_pton(family, address, &a->sin6_addr) != 1)
            return false;
        size = sizeof(*a);
    } else {
        struct sockaddr_in *a = (void *)&storage;
        a->sin_family = family;
        a->sin_port = htons(port);
        if (inet_pton(family, address, &a->sin_addr) != 1)
            return false;
        size = sizeof(*a);
    }
    SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return false;
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
    int result = connect(s, (struct sockaddr *)&storage, size);
    bool connected = result == 0;
    if (!connected && WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set write, error;
        FD_ZERO(&write);
        FD_ZERO(&error);
        FD_SET(s, &write);
        FD_SET(s, &error);
        struct timeval timeout = {2, 0};
        if (select(0, NULL, &write, &error, &timeout) > 0 &&
            FD_ISSET(s, &write)) {
            int code = 0, len = sizeof(code);
            connected =
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&code, &len) == 0 &&
                !code;
        }
    }
    closesocket(s);
    return connected;
}
#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "WFP native check failed at line %d\n", __LINE__); \
            Wfp_Close();                                                       \
            return 1;                                                          \
        }                                                                      \
    } while (0)
int main(int argc, char **argv) {
    if (argc != 4)
        return 2;
    WSADATA data;
    CHECK(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    CHECK(ConnectPeer(argv[1], 9001) && ConnectPeer(argv[2], 9001));
    CHECK(ConnectPeer(argv[1], 9002) && ConnectPeer(argv[2], 9002));
    puts("Precondition: four reachable IPv4/IPv6 test services");
    CHECK(Wfp_Init(1) == 0);
    OMINULL_HUB_TARGETS hub = {0};
    snprintf(hub.addresses[0], 64, "%s", argv[1]);
    snprintf(hub.addresses[1], 64, "%s", argv[2]);
    hub.count = 2;
    hub.port = 9001;
    OMINULL_BASELINE_RULE management = {0};
    snprintf(management.destination, sizeof(management.destination), "%s",
             argv[3]);
    strcpy(management.protocol, "tcp");
    management.port = 9443;
    const char *allowed[] = {argv[2]}, *blocked[] = {argv[2]},
               *invalid[] = {"fe80::1%11"};
    CHECK(Wfp_ApplyState(&hub, 1, NULL, 0, allowed, 1, &management, 1, 1) == 0);
    MIB_IPNET_ROW2 neighbor = {0};
    neighbor.Address.Ipv6.sin6_family = AF_INET6;
    CHECK(inet_pton(AF_INET6, argv[2], &neighbor.Address.Ipv6.sin6_addr) == 1);
    CHECK(GetBestInterfaceEx((struct sockaddr *)&neighbor.Address.Ipv6,
                             &neighbor.InterfaceIndex) == 0);
    CHECK(DeleteIpNetEntry2(&neighbor) == 0);

    CHECK(ConnectPeer(argv[1], 9001) && ConnectPeer(argv[2], 9001));
    CHECK(!ConnectPeer(argv[1], 9002) && ConnectPeer(argv[2], 9002));
    puts("Default deny, both hub addresses, exact TCP port and IPv6 allow-list "
         "passed");
    CHECK(Wfp_ApplyState(&hub, 1, blocked, 1, allowed, 1, &management, 1, 1) ==
          0);
    CHECK(ConnectPeer(argv[2], 9001) && !ConnectPeer(argv[2], 9002));
    CHECK(Wfp_ApplyState(&hub, 1, invalid, 1, allowed, 1, &management, 1, 1) !=
          0);
    CHECK(ConnectPeer(argv[2], 9001) && !ConnectPeer(argv[2], 9002));
    puts("IPv6 peer block beats allow-list; hub survives; rejected scope "
         "preserves prior state");
    CHECK(Wfp_ApplyState(&hub, 0, blocked, 1, NULL, 0, NULL, 0, 1) == 0);
    CHECK(ConnectPeer(argv[1], 9002) && !ConnectPeer(argv[2], 9002) &&
          ConnectPeer(argv[2], 9001));
    CHECK(Wfp_UnisolateHost() == 0);
    CHECK(ConnectPeer(argv[1], 9002) && ConnectPeer(argv[2], 9002));
    Wfp_Close();
    puts("Release retains peer quarantine and hub recovery; final cleanup "
         "restores connectivity");
    return 0;
}
