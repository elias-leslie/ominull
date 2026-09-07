#define _GNU_SOURCE
#define main ominull_linux_main_unused
#include "../linux/main.c"
#undef main
#include <assert.h>
int main(int argc, char **argv) {
    assert(argc == 2);
    LINUX_AGENT_CONFIG config = {0};
    snprintf(config.hub_url, sizeof(config.hub_url), "%s", argv[1]);
    config.allow_plaintext = true;
    snprintf(config.endpoint_id, sizeof(config.endpoint_id), "serializer-fixture");
    snprintf(config.hostname, sizeof(config.hostname), "serializer-fixture");
    strcpy(config.role_tag, "role\"with\ncontrols");
    LINUX_FLOW_EVENT events[64] = {0};
    for (size_t i = 0; i < 64; i++) {
        LINUX_FLOW_EVENT *f = &events[i];
        f->protocol = 17;
        f->dst_port = 9000;
        strcpy(f->src_ip, "10.0.4.20");
        strcpy(f->dst_ip, "10.0.4.21");
        strcpy(f->direction, "OUTBOUND");
        f->bytes_out = 5;
        memset(f->process_path, 1, sizeof(f->process_path) - 1);
        f->process_path[4] = '\n';
        memset(f->enrichment.command_line, 1, sizeof(f->enrichment.command_line) - 1);
    }
    SendTelemetryBatch(&config, events, 64);
    return 0;
}
