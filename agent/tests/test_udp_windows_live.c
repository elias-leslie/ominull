/* Native ETW regression: successful dual-stack traffic must produce observations.
 * Loopback is intentional here; this test does not claim cross-host coverage. */
#include <ws2tcpip.h>
#define OMINULL_UDP_OWNER L"Probe"
#include "../windows/udp_collector.h"
#include <assert.h>
#undef assert
#define assert(condition)                                                                                    \
    do {                                                                                                     \
        if (!(condition)) {                                                                                  \
            fprintf(stderr, "Check failed: %s at line %d\n", #condition, __LINE__);                          \
            UDPWinStop();                                                                                    \
            exit(1);                                                                                         \
        }                                                                                                    \
    } while (0)
static void exchange(int family) {
    SOCKET server = socket(family, SOCK_DGRAM, IPPROTO_UDP), client = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    assert(server != INVALID_SOCKET && client != INVALID_SOCKET);
    struct sockaddr_storage addr = {0};
    int len;
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)&addr;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        len = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (void *)&addr;
        a->sin6_family = AF_INET6;
        a->sin6_addr = in6addr_loopback;
        len = sizeof(*a);
    }
    assert(bind(server, (void *)&addr, len) == 0);
    assert(getsockname(server, (void *)&addr, &len) == 0);
    assert(connect(client, (void *)&addr, len) == 0);
    DWORD timeout = 2000;
    setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    assert(send(client, "hello", 5, 0) == 5);
    char bytes[5];
    struct sockaddr_storage peer = {0};
    int plen = sizeof(peer);
    assert(recvfrom(server, bytes, 5, 0, (void *)&peer, &plen) == 5);
    assert(sendto(server, bytes, 5, 0, (void *)&peer, plen) == 5);
    assert(recv(client, bytes, 5, 0) == 5);
    closesocket(client);
    closesocket(server);
}
int main(int argc, char **argv) {
    (void)argv;
    unsigned rounds = argc == 2 ? 70 : 1;
    setvbuf(stdout, NULL, _IONBF, 0);
    WSADATA wsa;
    assert(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    assert(UDPWinStart() == ERROR_SUCCESS);
    Sleep(1000);
    for (unsigned i = 0; i < rounds; i++) {
        exchange(AF_INET);
        exchange(AF_INET6);
    }
    Sleep(2000);
    static OMINULL_EVENT events[64];
    unsigned count = 0;
    UINT64 in4 = 0, out4 = 0, in6 = 0, out6 = 0;
    for (int round = 0; round < 10; round++) {
        size_t n = UDPWinDrain(events, 64);
        for (size_t i = 0; i < n; i++) {
            OMINULL_EVENT *e = &events[i];
            if (e->ProcessId != GetCurrentProcessId())
                continue;
            assert(e->Protocol == 17);
            count++;
            if (e->IpVersion == 4) {
                in4 += e->BytesIn;
                out4 += e->BytesOut;
            } else if (e->IpVersion == 6) {
                in6 += e->BytesIn;
                out6 += e->BytesOut;
            } else
                assert(0);
        }
        Sleep(100);
    }
    char health[512];
    assert(UDPWinHealthJSON(health, sizeof(health)) > 0);
    assert(strstr(health, "\"state\":\"active\""));
    printf("UDP coverage: rows=%u v4=%llu/%llu v6=%llu/%llu health=%s trace_lost=%llu\n", count, in4, out4,
           in6, out6, health, g_UDPWinTraceLost);
    /* Other processes can emit scoped link-local traffic while this fixture
     * runs. Omission is explicit coverage, not loss of these loopback packets.
     * All other omissions, queue overflow and trace loss still fail the test. */
    assert(g_UDPWinDropped == g_UDPWinScopeOmitted && g_UDPWinSchemaOmitted == 0 && g_UDPWinTraceLost == 0 &&
           g_UDPWinBuffersLost == 0);
    UDPWinTransportLost(events, 0);
    UDPWinStop();
    printf("UDP rows=%u v4=%llu/%llu v6=%llu/%llu\n", count, in4, out4, in6, out6);
    assert(count > 0 && in4 == 10 * rounds && out4 == 10 * rounds && in6 == 10 * rounds &&
           out6 == 10 * rounds);
    if (rounds > 1)
        assert(count > 64);
    WSACleanup();
    return 0;
}
