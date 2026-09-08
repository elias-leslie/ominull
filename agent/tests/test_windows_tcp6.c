/* Actual collector with deterministic IP Helper rows and counters. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <assert.h>
#include <tcpestats.h>
static DWORD FixtureTable(PVOID table, PDWORD size, BOOL order, ULONG family,
                          TCP_TABLE_CLASS kind, ULONG reserved) {
    (void)order;
    (void)kind;
    (void)reserved;
    DWORD needed = family == AF_INET6 ? sizeof(MIB_TCP6TABLE_OWNER_PID)
                                      : sizeof(MIB_TCPTABLE_OWNER_PID);
    if (!table || *size < needed) {
        *size = needed;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    memset(table, 0, needed);
    if (family == AF_INET6) {
        MIB_TCP6TABLE_OWNER_PID *t = table;
        t->dwNumEntries = 1;
        MIB_TCP6ROW_OWNER_PID *r = &t->table[0];
        r->dwState = MIB_TCP_STATE_ESTAB;
        r->dwOwningPid = GetCurrentProcessId();
        r->dwLocalPort = htons(40001);
        r->dwRemotePort = htons(443);
        inet_pton(AF_INET6, "2001:db8:1234:5678::abcd", r->ucLocalAddr);
        inet_pton(AF_INET6, "2001:db8:abcd:4321::9876", r->ucRemoteAddr);
    } else {
        MIB_TCPTABLE_OWNER_PID *t = table;
        t->dwNumEntries = 1;
        t->table[0].dwState = MIB_TCP_STATE_ESTAB;
        t->table[0].dwOwningPid = GetCurrentProcessId();
        t->table[0].dwLocalPort = htons(40002);
        t->table[0].dwRemotePort = htons(443);
        t->table[0].dwLocalAddr = inet_addr("10.20.30.40");
        t->table[0].dwRemoteAddr = inet_addr("203.0.113.9");
    }
    return NO_ERROR;
}
static ULONG64 fixtureIn = 1000, fixtureOut = 2000;
static unsigned reads4, reads6;
static ULONG Read4(PMIB_TCPROW row, TCP_ESTATS_TYPE type, PUCHAR rw, ULONG rwv,
                   ULONG rws, PUCHAR ros, ULONG rosv, ULONG ross, PUCHAR rod,
                   ULONG rodv, ULONG rods) {
    (void)type;
    (void)rw;
    (void)rwv;
    (void)rws;
    (void)ros;
    (void)rosv;
    (void)ross;
    assert(row->dwLocalAddr == inet_addr("10.20.30.40") &&
           row->dwRemotePort == htons(443));
    assert(rodv == 0 && rods == sizeof(TCP_ESTATS_DATA_ROD_v0));
    TCP_ESTATS_DATA_ROD_v0 *data = (void *)rod;
    data->DataBytesIn = fixtureIn;
    data->DataBytesOut = fixtureOut;
    reads4++;
    return 0;
}
static ULONG Read6(PMIB_TCP6ROW row, TCP_ESTATS_TYPE type, PUCHAR rw, ULONG rwv,
                   ULONG rws, PUCHAR ros, ULONG rosv, ULONG ross, PUCHAR rod,
                   ULONG rodv, ULONG rods) {
    (void)type;
    (void)rw;
    (void)rwv;
    (void)rws;
    (void)ros;
    (void)rosv;
    (void)ross;
    unsigned char expected[16];
    inet_pton(AF_INET6, "2001:db8:abcd:4321::9876", expected);
    assert(!memcmp(&row->RemoteAddr, expected, 16) &&
           row->dwLocalPort == htons(40001));
    assert(rodv == 0 && rods == sizeof(TCP_ESTATS_DATA_ROD_v0));
    TCP_ESTATS_DATA_ROD_v0 *data = (void *)rod;
    data->DataBytesIn = fixtureIn;
    data->DataBytesOut = fixtureOut;
    reads6++;
    return 0;
}
static ULONG Set4(PMIB_TCPROW row, TCP_ESTATS_TYPE type, PUCHAR rw,
                  ULONG version, ULONG size, ULONG offset) {
    (void)row;
    (void)type;
    assert(!version && !offset && size == sizeof(TCP_ESTATS_DATA_RW_v0));
    assert(((TCP_ESTATS_DATA_RW_v0 *)rw)->EnableCollection);
    return 0;
}
static ULONG Set6(PMIB_TCP6ROW row, TCP_ESTATS_TYPE type, PUCHAR rw,
                  ULONG version, ULONG size, ULONG offset) {
    (void)row;
    return Set4(NULL, type, rw, version, size, offset);
}
#define GetPerTcpConnectionEStats Read4
#define GetPerTcp6ConnectionEStats Read6
#define SetPerTcpConnectionEStats Set4
#define SetPerTcp6ConnectionEStats Set6
#define GetExtendedTcpTable FixtureTable
#include "../src/service.c"
int main(void) {
    WSADATA data;
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    OMINULL_EVENT events[64];
    size_t count = PollTCPObservations(events, 64);
    unsigned v4 = 0, v6 = 0;
    for (size_t i = 0; i < count; i++) {
        if (events[i].IpVersion == 4)
            v4++;
        if (events[i].IpVersion == 6) {
            v6++;
            unsigned char expected[16];
            inet_pton(AF_INET6, "2001:db8:abcd:4321::9876", expected);
            assert(memcmp(events[i].Addr.Ipv6.RemoteIp, expected, 16) == 0);
            assert(events[i].EventType == OMINULL_EVENT_FLOW_ESTABLISHED_V6);
            assert(events[i].RemotePort == 443 && events[i].LocalPort == 40001);
            assert(events[i].ProcessId == GetCurrentProcessId());
        }
    }
    printf("TCP family rows: IPv4=%u IPv6=%u\n", v4, v6);
    assert(reads4 == 1 && reads6 == 1);
    for (size_t i = 0; i < count; i++)
        assert(!events[i].BytesMeasured && !events[i].BytesIn &&
               !events[i].BytesOut);
    fixtureIn += 7;
    fixtureOut += 11;
    count = PollTCPObservations(events, 64);
    assert(count == 2);
    for (size_t i = 0; i < count; i++)
        assert(events[i].BytesMeasured && events[i].BytesIn == 7 &&
               events[i].BytesOut == 11);
    TCP_KEY_WIN key = {0};
    key.family = 6;
    key.pid = 42;
    key.created = 100;
    key.remoteScope = 11;
    bool fresh = false;
    ESTATS_SLOT *one = EstatsSlot(&key, &fresh);
    assert(one && fresh);
    key.remoteScope = 12;
    ESTATS_SLOT *two = EstatsSlot(&key, &fresh);
    assert(two && fresh && two != one);
    key.created = 101;
    ESTATS_SLOT *three = EstatsSlot(&key, &fresh);
    assert(three && fresh && three != two);
    key.family = 4;
    ESTATS_SLOT *four = EstatsSlot(&key, &fresh);
    assert(four && fresh && four != three);
    key.local[0] = 127;
    key.remote[0] = 203;
    key.remotePort = htons(443);
    assert(!TCPAddressReportable(&key));
    puts("Both ESTATS APIs preserve deltas; family, scope and process creation "
         "separate baselines");

    char peers[4][PEER_ADDR_LEN];
    int parsed = ParseAddressArray(
        "{\"quarantined_peers\":[\"2001:db8::42\",\"203.0.113.8\"]}",
        "quarantined_peers", peers, 4);
    AGENT_CONFIG config = {0};
    strcpy(config.hub_url, "https://[2001:db8::9]:9443");
    char literal[64];
    bool hub = HubAddressLiteral(&config, literal, sizeof(literal));
    printf("Parsed peers=%d IPv6 hub=%d\n", parsed, hub);
    assert(ParseAddressArray("{\"quarantined_peers\":[\"fe80::1%11\"]}",
                             "quarantined_peers", peers, 4) == -1);
    assert(ParseAddressArray("{\"quarantined_peers\":[\"fe80::1\"]}",
                             "quarantined_peers", peers, 4) == -1);
    assert(ParseAddressArray("{\"quarantined_peers\":[\"203.0.113.1\",]}",
                             "quarantined_peers", peers, 4) == -1);

    return v4 == 1 && v6 == 1 && parsed == 2 && hub &&
                   !strcmp(literal, "2001:db8::9")
               ? 0
               : 1;
}
