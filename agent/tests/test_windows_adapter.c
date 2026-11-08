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
#include <winhttp.h>
/* The WinHTTP session remembers what a name resolved to, so a failed request has to
 * cost it the session or a hub that moved stays lost until that memory runs out.
 * Stand-ins just count that. */
static int sessionsOpened, sessionsClosed;
static BOOL sendWorks, requestOpens = TRUE;
#define FIXTURE_SESSION ((HINTERNET)(uintptr_t)1)
#define FIXTURE_OTHER ((HINTERNET)(uintptr_t)2)
static HINTERNET FixtureOpen(LPCWSTR a, DWORD b, LPCWSTR c, LPCWSTR d, DWORD e) {
    (void)a; (void)b; (void)c; (void)d; (void)e;
    sessionsOpened++;
    return FIXTURE_SESSION;
}
static BOOL FixtureSetTimeouts(HINTERNET h, int a, int b, int c, int d) {
    (void)h; (void)a; (void)b; (void)c; (void)d;
    return TRUE;
}
static HINTERNET FixtureConnect(HINTERNET h, LPCWSTR a, INTERNET_PORT b, DWORD c) {
    (void)h; (void)a; (void)b; (void)c;
    return FIXTURE_OTHER;
}
static HINTERNET FixtureOpenRequest(HINTERNET h, LPCWSTR a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR *e, DWORD f) {
    (void)h; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    return requestOpens ? FIXTURE_OTHER : NULL;
}
static BOOL FixtureAddHeaders(HINTERNET h, LPCWSTR a, DWORD b, DWORD c) {
    (void)h; (void)a; (void)b; (void)c;
    return TRUE;
}
static BOOL FixtureSend(HINTERNET h, LPCWSTR a, DWORD b, LPVOID c, DWORD d, DWORD e, DWORD_PTR f) {
    (void)h; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    SetLastError(ERROR_WINHTTP_CANNOT_CONNECT);
    return sendWorks;
}
static BOOL FixtureReceive(HINTERNET h, LPVOID a) {
    (void)h; (void)a;
    return TRUE;
}
static BOOL FixtureHeaders(HINTERNET h, DWORD a, LPCWSTR b, LPVOID out, LPDWORD c, LPDWORD d) {
    (void)h; (void)a; (void)b; (void)c; (void)d;
    *(DWORD *)out = 200;
    return TRUE;
}
static BOOL FixtureAvailable(HINTERNET h, LPDWORD out) {
    (void)h;
    *out = 0;
    return TRUE;
}
static BOOL FixtureClose(HINTERNET h) {
    if (h == FIXTURE_SESSION) sessionsClosed++;
    return TRUE;
}
#define WinHttpOpen FixtureOpen
#define WinHttpSetTimeouts FixtureSetTimeouts
#define WinHttpConnect FixtureConnect
#define WinHttpOpenRequest FixtureOpenRequest
#define WinHttpAddRequestHeaders FixtureAddHeaders
#define WinHttpSendRequest FixtureSend
#define WinHttpReceiveResponse FixtureReceive
#define WinHttpQueryHeaders FixtureHeaders
#define WinHttpQueryDataAvailable FixtureAvailable
#define WinHttpCloseHandle FixtureClose
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
    static AGENT_CONFIG config;
    snprintf(config.hub_url, sizeof(config.hub_url), "http://hub.example:9443");
    config.allow_plaintext = true;
    for (int path = 0; path < 2; path++) {
        for (int failure = 0; failure < 2; failure++) {
            HubHTTPEnter();
            HubHTTPDropSession();
            LeaveCriticalSection(&g_http.lock);
            int opened = sessionsOpened = 0, closed = sessionsClosed = 0;
            sendWorks = requestOpens = TRUE;
            DWORD status;
            #define FIXTURE_REQUEST() (path ? (void)Hub_PostPathData(&config, "/x", "text/plain", "{}", 2, NULL, 0) \
                                            : (void)HubPostTelemetryBody(&config, "{}", 2, false, false, NULL, 0, &status))
            FIXTURE_REQUEST();
            FIXTURE_REQUEST();
            if (sessionsOpened != opened + 1) {
                printf("Path %d: requests that work should share a session; opened %d\n", path, sessionsOpened);
                failures++;
            }
            if (failure) requestOpens = FALSE;
            else sendWorks = FALSE;
            FIXTURE_REQUEST();
            FIXTURE_REQUEST();
            /* One close for each session the failures opened and dropped. */
            if (sessionsOpened != opened + 2 || sessionsClosed != closed + 2) {
                printf("Path %d, failure %d: a failed request should close its session, or finding a moved "
                       "hub waits; opened %d, closed %d\n", path, failure, sessionsOpened, sessionsClosed);
                failures++;
            }
        }
    }
    printf("Primary adapter failures: %d\n", failures);
    return failures ? 1 : 0;
}
