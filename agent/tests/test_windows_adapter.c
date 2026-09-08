#define main ExistingJSONFixture
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "test_windows_telemetry_json.c"
#undef main
static bool ipv6Only;
static ULONG FixtureAdapters(ULONG family, ULONG flags, PVOID reserved,
                             PIP_ADAPTER_ADDRESSES adapters, PULONG size) {
    (void)reserved;
    ULONG needed = 2 * sizeof(*adapters);
    if (!adapters || *size < needed) {
        *size = needed;
        return ERROR_BUFFER_OVERFLOW;
    }
    memset(adapters, 0, needed);
    static IP_ADAPTER_UNICAST_ADDRESS unicast[2];
    static IP_ADAPTER_GATEWAY_ADDRESS gateway;
    static struct sockaddr_in addresses[2];
    static struct sockaddr_in6 address6;
    memset(unicast, 0, sizeof(unicast));
    for (int i = 0; i < 2; i++) {
        adapters[i].OperStatus = IfOperStatusUp;
        adapters[i].IfType = IF_TYPE_ETHERNET_CSMACD;
        adapters[i].PhysicalAddressLength = 6;
        adapters[i].PhysicalAddress[0] = 0x02;
        adapters[i].PhysicalAddress[5] = i + 1;
        addresses[i].sin_family = AF_INET;
        addresses[i].sin_addr.s_addr = inet_addr(i ? "10.0.0.2" : "10.0.0.1");
        unicast[i].Address.lpSockaddr = (void *)&addresses[i];
        unicast[i].Address.iSockaddrLength = sizeof(addresses[i]);
        if (!ipv6Only)
            adapters[i].FirstUnicastAddress = &unicast[i];
    }
    adapters[0].Next = &adapters[1];
    if (flags & GAA_FLAG_INCLUDE_GATEWAYS)
        adapters[0].FirstGatewayAddress = &gateway;
    if (ipv6Only && family == AF_UNSPEC) {
        address6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2001:db8::abcd", &address6.sin6_addr);
        unicast[0].Address.lpSockaddr = (void *)&address6;
        unicast[0].Address.iSockaddrLength = sizeof(address6);
        adapters[0].FirstUnicastAddress = &unicast[0];
    }
    return NO_ERROR;
}
#define GetAdaptersAddresses FixtureAdapters
#include "../src/hub_client.c"
int main(void) {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
    char ip[64], mac[64];
    int failures = 0;
    DetectPrimaryAdapter(ip, sizeof(ip), mac, sizeof(mac));
    if (strcmp(ip, "10.0.0.1") || strcmp(mac, "02:00:00:00:00:01")) {
        puts("Gateway adapter lost to secondary interface");
        failures++;
    }
    ipv6Only = true;
    DetectPrimaryAdapter(ip, sizeof(ip), mac, sizeof(mac));
    if (strcmp(ip, "2001:db8::abcd") || strcmp(mac, "02:00:00:00:00:01")) {
        puts("IPv6-only adapter identity missing");
        failures++;
    }
    printf("Primary adapter failures: %d\n", failures);
    return failures ? 1 : 0;
}
