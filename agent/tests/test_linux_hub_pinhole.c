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
    FILE *out = fopen(getenv("OMINULL_FIXTURE_COMMANDS"), "a");
    if (!out)
        _exit(1);
    for (size_t i = 0; argv[i]; i++)
        fprintf(out, "%s%s", i ? " " : "", argv[i]);
    fputc('\n', out);
    fclose(out);
    _exit(0);
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
    EnforcementBuild("ip6tables", true, &hub, addresses, 0, addresses, 0,
                     addresses, 0, NULL, 0, true);
    EnforcementBuild("iptables", true, &hub, addresses, 0, addresses, 0,
                     addresses, 0, NULL, 0, true);
    FILE *in = fopen(path, "r");
    assert(in);
    char data[16384];
    size_t size = fread(data, 1, sizeof(data) - 1, in);
    data[size] = 0;
    fclose(in);
    unlink(path);
    assert(size > 0);
    bool exact = strstr(data, "-d 2001:db8::9 -p tcp --dport 9443") != NULL;
    if (!exact || !strstr(data, "-d 203.0.113.9 -p tcp --dport 9443")) {
        fputs("Linux hub permit is not restricted to its TCP port\n", stderr);
        return 1;
    }
    puts("Linux IPv6 hub pinhole names exact TCP port; no real firewall "
         "commands "
         "executed");
    return 0;
}
