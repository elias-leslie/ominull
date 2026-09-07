#include "../include/agent.h"
char *Hub_BuildTelemetryJSON(const AGENT_CONFIG *, const OMINULL_EVENT *, size_t);
size_t Agent_CollectorHealthJSON(char *out, size_t capacity) {
    (void)out;
    (void)capacity;
    return 0;
}
const char *Agent_EnforcementStatus(void) {
    return "ok";
}
const char *Agent_LastAppliedNote(void) {
    return "";
}
bool HubAddressLiteral(const AGENT_CONFIG *config, char *out, size_t cap) {
    (void)config;
    (void)out;
    (void)cap;
    return false;
}
void Agent_DetectInstallProvenance(AGENT_CONFIG *config) {
    (void)config;
}
int main(void) {
    static AGENT_CONFIG config;
    static OMINULL_EVENT events[64];
    strcpy(config.endpoint_id, "serialization-fixture");
    for (size_t i = 0; i < 64; i++) {
        OMINULL_EVENT *e = &events[i];
        e->IpVersion = 6;
        e->Protocol = 17;
        e->Direction = 1;
        e->BytesOut = 5;
        e->Addr.Ipv6.LocalIp[0] = 0xfd;
        e->Addr.Ipv6.LocalIp[15] = 1;
        e->Addr.Ipv6.RemoteIp[0] = 0xfd;
        e->Addr.Ipv6.RemoteIp[15] = 2;
        for (int j = 0; j < 250; j++)
            e->ProcessPath[j] = L'x';
        e->ProcessPath[10] = L'\n';
        e->ProcessPath[11] = L'"';
        memset(e->Enrichment.command_line, 'a', 1000);
    }
    char *json = Hub_BuildTelemetryJSON(&config, events, 64);
    if (!json)
        return 2;
    puts(json);
    free(json);
    return 0;
}
