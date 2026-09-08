#include <ws2tcpip.h>
#define main ExistingJSONFixture
#include "test_windows_telemetry_json.c"
#undef main
int main(void) {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
    int failures = 0;
    char host[256];
    WORD port;
    BOOL tls;
    Hub_SplitURL("https://[2001:db8:1234::9]:9443/", host, sizeof(host), &port,
                 &tls);
    if (strcmp(host, "2001:db8:1234::9") || port != 9443 || !tls) {
        puts("IPv6 hub URL parsed incorrectly");
        failures++;
    }
    OMINULL_EVENT event = {0};
    AGENT_CONFIG config = {0};
    event.IpVersion = 6;
    event.Protocol = 6;
    event.Direction = 1;
    event.LocalScopeId = 11;
    event.RemoteScopeId = 11;
    inet_pton(AF_INET6, "fe80::abcd", event.Addr.Ipv6.LocalIp);
    inet_pton(AF_INET6, "fe80::1234", event.Addr.Ipv6.RemoteIp);
    char *json = Hub_BuildTelemetryJSON(&config, &event, 1);
    if (!json || !strstr(json, "fe80::abcd%11") ||
        !strstr(json, "fe80::1234%11")) {
        puts("IPv6 interface scope discarded");
        failures++;
    }
    free(json);
    event.RemoteScopeId = 0;
    json = Hub_BuildTelemetryJSON(&config, &event, 1);
    if (json) {
        puts("Ambiguous link-local address accepted");
        failures++;
        free(json);
    }
    printf("IPv6 URL and scoped JSON failures: %d\n", failures);
    return failures ? 1 : 0;
}
