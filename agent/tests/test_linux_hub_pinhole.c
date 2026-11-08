#define _GNU_SOURCE
#include <unistd.h>
static int CaptureExec(const char *file, char *const argv[]);
#define execvp CaptureExec
#define main unused_agent_main
#include "../linux/main.c"
#undef main
#undef execvp
#include <assert.h>
static int CaptureExec(const char *file, char *const argv[]) {
    (void)file;
    char line[1024];
    size_t used = 0;
    for (size_t i = 0; argv[i]; i++)
        used += snprintf(line + used, sizeof(line) - used, "%s%s", i ? " " : "", argv[i]);
    const char *fail = getenv("OMINULL_FIXTURE_FAIL");
    const char *code = getenv("OMINULL_FIXTURE_FAIL_CODE");
    int status = fail && strstr(line, fail) ? (code ? atoi(code) : 1) : 0;
    /* Every chain the fixture "removed" is gone. */
    if (!status && strstr(line, " -C "))
        status = 1;
    FILE *out = fopen(getenv("OMINULL_FIXTURE_COMMANDS"), "a");
    if (!out)
        _exit(1);
    for (size_t i = 0; argv[i]; i++)
        fprintf(out, "%s%s", i ? " " : "", argv[i]);
    fputc('\n', out);
    fclose(out);
    _exit(status);
}
/* A swap that cannot finish building leaves the rules in force alone. */
static void RefusedStepKeepsTheOldChain(const char *path, const char *step,
                                        OMINULL_HUB_TARGETS *hub) {
    char none[1][64] = {{0}};
    char peer[1][64] = {"203.0.113.77"};
    FILE *reset = fopen(path, "w");
    assert(reset);
    fclose(reset);
    assert(setenv("OMINULL_FIXTURE_FAIL", step, 1) == 0);
    bool built = EnforcementBuild("iptables", true, hub, none, 0, peer, 1, none, 0, NULL, 0);
    unsetenv("OMINULL_FIXTURE_FAIL");
    FILE *in = fopen(path, "r");
    assert(in);
    static char data[65536];
    size_t size = fread(data, 1, sizeof(data) - 1, in);
    data[size] = 0;
    fclose(in);
    if (built || strstr(data, "-D OUTPUT -j OMINULL_ISO_OUT\n") ||
        strstr(data, "-F OMINULL_ISO_OUT\n") || strstr(data, "-E OMINULL_ISO_OUT_N")) {
        fprintf(stderr, "A refused step (%s) still touched the rules in force\n", step);
        exit(1);
    }
}
int main(void) {
    char path[] = "/tmp/ominull-pinhole-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    assert(setenv("OMINULL_FIXTURE_COMMANDS", path, 1) == 0);
    char addresses[1][64] = {{0}};
    OMINULL_HUB_TARGETS hub = {0};
    strcpy(hub.addresses[0], "2001:db8::9");
    strcpy(hub.addresses[1], "203.0.113.9");
    hub.count = 2;
    hub.port = 9443;
    assert(EnforcementBuild("ip6tables", true, &hub, addresses, 0, addresses, 0,
                            addresses, 0, NULL, 0));
    assert(EnforcementBuild("iptables", true, &hub, addresses, 0, addresses, 0,
                            addresses, 0, NULL, 0));
    FILE *in = fopen(path, "r");
    assert(in);
    char data[65536];
    size_t size = fread(data, 1, sizeof(data) - 1, in);
    data[size] = 0;
    fclose(in);
    assert(size > 0);
    bool exact = strstr(data, "-d 2001:db8::9 -p tcp --dport 9443") != NULL;
    if (!exact || !strstr(data, "-d 203.0.113.9 -p tcp --dport 9443")) {
        fputs("Linux hub permit is not restricted to its TCP port\n", stderr);
        return 1;
    }
    /* The rules in force stay until the new set is whole and hooked in. */
    const char *deny = strstr(data, "iptables -w 5 -A OMINULL_ISO_OUT_N -j DROP");
    const char *hook = deny ? strstr(deny, "iptables -w 5 -I OUTPUT -j OMINULL_ISO_OUT_N") : NULL;
    const char *unhook = hook ? strstr(hook, "iptables -w 5 -D OUTPUT -j OMINULL_ISO_OUT\n") : NULL;
    const char *rename = unhook ? strstr(unhook, "iptables -w 5 -E OMINULL_ISO_OUT_N OMINULL_ISO_OUT\n") : NULL;
    const char *flush = strstr(data, "iptables -w 5 -F OMINULL_ISO_OUT\n");
    if (!rename || flush < hook) {
        fputs("Linux rebuild touches the rules in force before the new set is hooked in\n", stderr);
        return 1;
    }
    /* A held lock on IPv6 is a refusal; a host with no IPv6 tool has nothing to keep. */
    char none[1][64] = {{0}};
    assert(setenv("OMINULL_FIXTURE_FAIL", "ip6tables", 1) == 0);
    assert(setenv("OMINULL_FIXTURE_FAIL_CODE", "127", 1) == 0);
    assert(EnforcementBuild("ip6tables", true, &hub, none, 0, none, 0, none, 0, NULL, 0));
    if (access("/proc/net/if_inet6", F_OK) == 0) {
        assert(setenv("OMINULL_FIXTURE_FAIL_CODE", "4", 1) == 0);
        assert(!EnforcementBuild("ip6tables", true, &hub, none, 0, none, 0, none, 0, NULL, 0));
    }
    unsetenv("OMINULL_FIXTURE_FAIL");
    unsetenv("OMINULL_FIXTURE_FAIL_CODE");
    RefusedStepKeepsTheOldChain(path, "-N OMINULL_ISO_IN_N", &hub);
    RefusedStepKeepsTheOldChain(path, "-A OMINULL_ISO_OUT_N -j DROP", &hub);
    RefusedStepKeepsTheOldChain(path, "-d 203.0.113.9 -p tcp --dport 9443", &hub);
    RefusedStepKeepsTheOldChain(path, "-I OUTPUT -j OMINULL_ISO_OUT_N", &hub);
    RefusedStepKeepsTheOldChain(path, "-d 203.0.113.77 -j DROP", &hub);
    unlink(path);
    puts("Linux IPv6 hub pinhole names exact TCP port; no real firewall "
         "commands "
         "executed");
    return 0;
}
