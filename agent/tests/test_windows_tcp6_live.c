/* Native IP Helper/ESTATS probe against a dedicated IPv6 echo peer.
 * No ETW startup, policy update or telemetry upload is invoked. */
#include "../src/service.c"
#include <assert.h>
int main(int argc, char **argv) {
    assert(argc == 3 || argc == 4);
    WSADATA data;
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    struct sockaddr_in6 remote = {0};
    remote.sin6_family = AF_INET6;
    assert(inet_pton(AF_INET6, argv[1], &remote.sin6_addr) == 1);
    unsigned port = (unsigned)strtoul(argv[2], NULL, 10);
    assert(port && port <= 65535);
    remote.sin6_port = htons((u_short)port);
    if (argc == 4)
        remote.sin6_scope_id = strtoul(argv[3], NULL, 10);
    SOCKET socket6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    assert(socket6 != INVALID_SOCKET);
    u_long nonblocking = 1;
    assert(ioctlsocket(socket6, FIONBIO, &nonblocking) == 0);
    int connected =
        connect(socket6, (struct sockaddr *)&remote, sizeof(remote));
    if (connected != 0) {
        assert(WSAGetLastError() == WSAEWOULDBLOCK);
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(socket6, &writable);
        struct timeval timeout = {5, 0};
        assert(select(0, NULL, &writable, NULL, &timeout) == 1);
        int error = 0, length = sizeof(error);
        assert(getsockopt(socket6, SOL_SOCKET, SO_ERROR, (char *)&error,
                          &length) == 0 &&
               error == 0);
    }
    nonblocking = 0;
    assert(ioctlsocket(socket6, FIONBIO, &nonblocking) == 0);
    DWORD timeout = 5000;
    assert(setsockopt(socket6, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                      sizeof(timeout)) == 0);
    assert(setsockopt(socket6, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                      sizeof(timeout)) == 0);
    static OMINULL_EVENT events[MAX_FLOW_CANDIDATES_WIN];
    bool observed = false;
    for (int attempt = 0; attempt < 4 && !observed; attempt++) {
        size_t count = PollTCPObservations(events, MAX_FLOW_CANDIDATES_WIN);
        for (size_t i = 0; i < count; i++)
            if (events[i].IpVersion == 6 &&
                events[i].ProcessId == GetCurrentProcessId() &&
                events[i].RemotePort == port &&
                !memcmp(events[i].Addr.Ipv6.RemoteIp, &remote.sin6_addr, 16))
                observed = true;
    }
    assert(observed);
    char payload[4096], received[4096];
    memset(payload, 'v', sizeof(payload));
    size_t sent = 0, got = 0;
    while (sent < sizeof(payload)) {
        int n = send(socket6, payload + sent, sizeof(payload) - sent, 0);
        assert(n > 0);
        sent += n;
    }
    while (got < sizeof(received)) {
        int n = recv(socket6, received + got, sizeof(received) - got, 0);
        assert(n > 0);
        got += n;
    }
    assert(!memcmp(payload, received, sizeof(payload)));
    UINT64 bytesIn = 0, bytesOut = 0;
    unsigned measured = 0;
    for (int attempt = 0; attempt < 4; attempt++) {
        Sleep(100);
        size_t count = PollTCPObservations(events, MAX_FLOW_CANDIDATES_WIN);
        for (size_t i = 0; i < count; i++) {
            OMINULL_EVENT *e = &events[i];
            if (e->IpVersion != 6 || e->ProcessId != GetCurrentProcessId() ||
                e->RemotePort != port ||
                memcmp(e->Addr.Ipv6.RemoteIp, &remote.sin6_addr, 16))
                continue;
            assert(e->EventType == OMINULL_EVENT_FLOW_ESTABLISHED_V6);
            if (remote.sin6_scope_id)
                assert(e->RemoteScopeId == remote.sin6_scope_id &&
                       e->LocalScopeId > 0);
            assert(e->Enrichment.process_instance_id[0]);
            if (e->BytesMeasured) {
                measured++;
                bytesIn += e->BytesIn;
                bytesOut += e->BytesOut;
            }
        }
    }
    closesocket(socket6);
    printf("Native IPv6 TCP: observed=%d measured=%u bytes_in=%llu "
           "bytes_out=%llu\n",
           observed, measured, bytesIn, bytesOut);
    return measured && bytesIn == sizeof(payload) && bytesOut == sizeof(payload)
               ? 0
               : 1;
}
