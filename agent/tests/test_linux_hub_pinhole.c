#define _GNU_SOURCE
#include <unistd.h>
static int CaptureExec(const char *file, char *const argv[]);
#define execvp CaptureExec
#define main unused_agent_main
#include "../linux/main.c"
#undef main
#undef execvp
#include <assert.h>
/* A pattern ending in $ has to end the line, so one chain isn't taken for its _N. */
static bool LineMatches(const char *line, const char *pattern) {
    size_t n = strlen(pattern);
    if (n && pattern[n - 1] == '$') {
        size_t m = strlen(line);
        return m >= n - 1 && strncmp(line + m - (n - 1), pattern, n - 1) == 0;
    }
    return strstr(line, pattern) != NULL;
}
static int CaptureExec(const char *file, char *const argv[]) {
    (void)file;
    char line[1024];
    size_t used = 0;
    for (size_t i = 0; argv[i]; i++)
        used += snprintf(line + used, sizeof(line) - used, "%s%s", i ? " " : "", argv[i]);
    const char *fail = getenv("OMINULL_FIXTURE_FAIL");
    const char *code = getenv("OMINULL_FIXTURE_FAIL_CODE");
    const char *present = getenv("OMINULL_FIXTURE_PRESENT");
    int status = fail && LineMatches(line, fail) ? (code ? atoi(code) : 1) : 0;
    /* Every chain the fixture "removed" is gone, unless it says otherwise. */
    if (!status && (strstr(line, " -C ") || strstr(line, " -S ")) &&
        !(present && LineMatches(line, present)))
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
static const char *ReadCommands(const char *path) {
    static char data[65536];
    FILE *in = fopen(path, "r");
    assert(in);
    size_t size = fread(data, 1, sizeof(data) - 1, in);
    data[size] = 0;
    fclose(in);
    return data;
}
static void ResetCommands(const char *path) {
    FILE *reset = fopen(path, "w");
    assert(reset);
    fclose(reset);
    unsetenv("OMINULL_FIXTURE_FAIL");
    unsetenv("OMINULL_FIXTURE_FAIL_CODE");
    unsetenv("OMINULL_FIXTURE_PRESENT");
    g_PermitsMissing = g_PermitsRetry = false;
}
#define FLUSHED_OUT "-F OMINULL_ISO_OUT\n"
/* What a held lock or a chain that won't go must never do: empty a live chain,
 * or drop the only one in force. */
static void LockAndLeftovers(const char *path, OMINULL_HUB_TARGETS *hub) {
    char none[1][64] = {{0}};

    /* Could not tell whether the chain is hooked: nothing is touched. */
    ResetCommands(path);
    setenv("OMINULL_FIXTURE_FAIL", "-C OUTPUT -j OMINULL_ISO_OUT$", 1);
    setenv("OMINULL_FIXTURE_FAIL_CODE", "4", 1);
    assert(!EnforcementBuild("iptables", true, hub, none, 0, none, 0, none, 0, NULL, 0));
    assert(!strstr(ReadCommands(path), FLUSHED_OUT));
    assert(!strstr(ReadCommands(path), "-N OMINULL_ISO_OUT_N"));

    /* The old chain stayed hooked through the swap: it keeps its rules. */
    ResetCommands(path);
    setenv("OMINULL_FIXTURE_PRESENT", "-C OUTPUT -j OMINULL_ISO_OUT$", 1);
    assert(!EnforcementBuild("iptables", true, hub, none, 0, none, 0, none, 0, NULL, 0));
    assert(strstr(ReadCommands(path), "-I OUTPUT -j OMINULL_ISO_OUT_N"));
    assert(!strstr(ReadCommands(path), FLUSHED_OUT));

    /* The second chain is the only policy and can't take the usual name: it stays. */
    ResetCommands(path);
    setenv("OMINULL_FIXTURE_PRESENT", "-C OUTPUT -j OMINULL_ISO_OUT_N$", 1);
    setenv("OMINULL_FIXTURE_FAIL", "-E OMINULL_ISO_OUT_N OMINULL_ISO_OUT$", 1);
    assert(!EnforcementBuild("iptables", true, hub, none, 0, none, 0, none, 0, NULL, 0));
    assert(!strstr(ReadCommands(path), "-D OUTPUT -j OMINULL_ISO_OUT_N"));

    /* Teardown reports a chain that would not go, or a hook it can't see past. */
    ResetCommands(path);
    assert(EnforcementTeardown("iptables"));
    setenv("OMINULL_FIXTURE_PRESENT", "-S OMINULL_ISO_IN$", 1);
    assert(!EnforcementTeardown("iptables"));
    ResetCommands(path);
    setenv("OMINULL_FIXTURE_FAIL", "-C INPUT -j OMINULL_ISO_IN$", 1);
    setenv("OMINULL_FIXTURE_FAIL_CODE", "4", 1);
    assert(!EnforcementTeardown("iptables"));
    assert(!strstr(ReadCommands(path), "-F OMINULL_ISO_IN\n"));

    /* A restart finds the default deny still in force, in either family or chain. */
    ResetCommands(path);
    appliedIsolated = false;
    g_RulesAdopted = false;
    AdoptRulesInForce();
    assert(!appliedIsolated && g_RulesAdopted);
    g_RulesAdopted = false;
    setenv("OMINULL_FIXTURE_PRESENT", "ip6tables -w 5 -C OMINULL_ISO_OUT -j DROP$", 1);
    AdoptRulesInForce();
    assert(appliedIsolated && g_RulesAdopted);
    appliedIsolated = false;
    g_RulesAdopted = false;
    setenv("OMINULL_FIXTURE_PRESENT", " -C OMINULL_ISO_OUT_N -j DROP$", 1);
    AdoptRulesInForce();
    assert(appliedIsolated);
    /* A held lock is no answer: it asks again. */
    ResetCommands(path);
    appliedIsolated = false;
    g_RulesAdopted = false;
    setenv("OMINULL_FIXTURE_FAIL", " -C OMINULL_ISO_OUT -j DROP$", 1);
    setenv("OMINULL_FIXTURE_FAIL_CODE", "4", 1);
    AdoptRulesInForce();
    assert(!g_RulesAdopted);
    ResetCommands(path);
    AdoptRulesInForce();
    assert(g_RulesAdopted);

    /* The dead-man timer takes out the default deny and nothing else, restart or
     * no restart, and keeps at it until the rule is really gone. */
    ResetCommands(path);
    appliedIsolated = true;
    setenv("OMINULL_FIXTURE_FAIL", "iptables -w 5 -C OMINULL_ISO_OUT -j DROP$", 1);
    setenv("OMINULL_FIXTURE_FAIL_CODE", "4", 1);
    for (int i = 0; i < 200; i++) HubContact(false);
    assert(appliedIsolated && strstr(g_ApplyNote, "not applied"));
    ResetCommands(path);
    HubContact(false);
    assert(!appliedIsolated && !g_ApplyNote[0]);
    const char *data = ReadCommands(path);
    assert(strstr(data, "iptables -w 5 -D OMINULL_ISO_OUT -j DROP\n"));
    assert(strstr(data, "ip6tables -w 5 -D OMINULL_ISO_IN -j DROP\n") ||
           access("/proc/net/if_inet6", F_OK) != 0);
    assert(!strstr(data, " -F ") && !strstr(data, " -X ") && !strstr(data, " -D OUTPUT"));
    HubContact(true);
    g_ApplyRefused = false;
}
/* Loopback and DHCP hold the swap back; other permits only report. */
static void Permits(const char *path, OMINULL_HUB_TARGETS *hub) {
    char none[1][64] = {{0}};
    char allow[1][64] = {"198.51.100.5"};
    BASELINE_RULE rules[2];
    memset(rules, 0, sizeof(rules));
    strcpy(rules[0].service, "dhcp"); strcpy(rules[0].destination, "198.51.100.2");
    strcpy(rules[0].protocol, "udp"); rules[0].port = 67;
    strcpy(rules[1].service, "ntp"); strcpy(rules[1].destination, "198.51.100.3");
    strcpy(rules[1].protocol, "udp"); rules[1].port = 123;

    ResetCommands(path);
    setenv("OMINULL_FIXTURE_FAIL", "-i lo -j RETURN", 1);
    assert(!EnforcementBuild("iptables", true, hub, allow, 1, none, 0, none, 0, rules, 2));
    assert(!strstr(ReadCommands(path), FLUSHED_OUT));

    ResetCommands(path);
    setenv("OMINULL_FIXTURE_FAIL", "-d 198.51.100.2", 1);
    assert(!EnforcementBuild("iptables", true, hub, allow, 1, none, 0, none, 0, rules, 2));
    assert(!strstr(ReadCommands(path), FLUSHED_OUT));

    ResetCommands(path);
    assert(EnforcementBuild("iptables", true, hub, allow, 1, none, 0, none, 0, rules, 2));
    assert(!g_PermitsMissing);

    /* Refused for good: reported, not retried. A held lock: retried too. */
    ResetCommands(path);
    setenv("OMINULL_FIXTURE_FAIL", "-d 198.51.100.5", 1);
    assert(EnforcementBuild("iptables", true, hub, allow, 1, none, 0, none, 0, rules, 2));
    assert(g_PermitsMissing && !g_PermitsRetry);
    ResetCommands(path);
    setenv("OMINULL_FIXTURE_FAIL", "-d 198.51.100.3", 1);
    setenv("OMINULL_FIXTURE_FAIL_CODE", "4", 1);
    assert(EnforcementBuild("iptables", true, hub, allow, 1, none, 0, none, 0, rules, 2));
    assert(g_PermitsMissing && g_PermitsRetry);

    /* The DHCPv6 reply comes from the server's link-local address. */
    ResetCommands(path);
    strcpy(rules[0].destination, "ff02::1:2"); rules[0].port = 547;
    assert(EnforcementBuild("ip6tables", true, hub, none, 0, none, 0, none, 0, rules, 1));
    assert(strstr(ReadCommands(path), "-d ff02::1:2 --dport 547"));
    assert(strstr(ReadCommands(path), "-s fe80::/10 --sport 547"));
    ResetCommands(path);
}
/* An isolated host follows a hub that moved, keeping everything else it enforces. */
static void FollowsAMovedHub(const char *path) {
    LINUX_AGENT_CONFIG config;
    memset(&config, 0, sizeof(config));
    strcpy(config.hub_url, "https://198.51.100.9:443");
    memset(&appliedHubTargets, 0, sizeof(appliedHubTargets));
    strcpy(appliedHubTargets.addresses[0], "198.51.100.8");
    appliedHubTargets.count = 1;
    appliedHubTargets.port = 443;
    strcpy(appliedPeers[0], "203.0.113.77");
    appliedPeerCount = 1;
    strcpy(appliedAllow[0], "198.51.100.5");
    appliedAllowCount = 1;
    strcpy(appliedThreats[0], "203.0.113.88");
    appliedThreatCount = 1;
    memset(&appliedBaseline[0], 0, sizeof(appliedBaseline[0]));
    strcpy(appliedBaseline[0].destination, "198.51.100.53");
    strcpy(appliedBaseline[0].protocol, "udp");
    strcpy(appliedBaseline[0].service, "dns");
    appliedBaseline[0].port = 53;
    appliedBaselineCount = 1;

    known = false;
    appliedIsolated = true;
    ResetCommands(path);
    FollowHubAddress(&config);
    assert(!ReadCommands(path)[0] && !strcmp(appliedHubTargets.addresses[0], "198.51.100.8"));
    known = true;
    appliedIsolated = false;
    FollowHubAddress(&config);
    assert(!ReadCommands(path)[0]);
    appliedIsolated = true;

    /* Refused: the hole stays recorded where it was and the next beat tries again. */
    g_ForgetApplied = false;
    assert(setenv("OMINULL_FIXTURE_FAIL", "-j DROP$", 1) == 0);
    FollowHubAddress(&config);
    unsetenv("OMINULL_FIXTURE_FAIL");
    assert(!strcmp(appliedHubTargets.addresses[0], "198.51.100.8") && appliedHubTargets.count == 1 && g_FollowPending.count == 2);

    ResetCommands(path);
    FollowHubAddress(&config);
    const char *data = ReadCommands(path);
    /* The new address is the agent's alone; the old hole stays as it was. */
    assert(strstr(data, "-d 198.51.100.9 -p tcp --dport 443 -m owner --uid-owner "));
    assert(strstr(data, "-s 198.51.100.9 -p tcp --sport 443 ! --syn -j RETURN"));
    assert(!strstr(data, "-d 198.51.100.9 -p tcp --dport 443 -j RETURN"));
    assert(strstr(data, "-d 198.51.100.8 -p tcp --dport 443 -j RETURN"));
    assert(strstr(data, "-d 203.0.113.77 -j DROP") && strstr(data, "-d 198.51.100.5 -j RETURN"));
    assert(strstr(data, "-d 203.0.113.88 -j DROP") && strstr(data, "-d 198.51.100.53 "));
    assert(strstr(data, "-A OMINULL_ISO_OUT_N -j DROP"));
    assert(appliedHubTargets.count == 2 && appliedHubTargets.agent_only[1] && appliedIsolated);
    /* Below the blocks, so a lying answer can't name a quarantined address. */
    assert(strstr(data, "-d 203.0.113.88 -j DROP") < strstr(data, "-d 198.51.100.9 "));
    /* A reply doesn't promote it: the agent is all that needs it. */
    assert(!g_ForgetApplied);
    /* The agent's calls to it are still its own, not a flow to report. */
    {
        FLOW_CANDIDATE own;
        memset(&own, 0, sizeof(own));
        strcpy(own.dst_ip, "198.51.100.9");
        own.dst_port = 443;
        g_SelfPid = 7;
        g_HubPeerPort = 443;
        assert(IsOwnHubFlow(&own, 7) && !IsOwnHubFlow(&own, 8));
        g_HubPeerPort = 0;
    }

    ResetCommands(path);
    FollowHubAddress(&config);
    assert(!ReadCommands(path)[0]);
    strcpy(config.hub_url, "ftp://host");
    FollowHubAddress(&config);
    assert(!ReadCommands(path)[0] && appliedHubTargets.count == 2);

    /* A permit lost to a held lock is tried again next beat, with the hub still silent,
     * even when it was the one the lookup needs. */
    strcpy(config.hub_url, "https://198.51.100.10:443");
    assert(setenv("OMINULL_FIXTURE_FAIL", "198.51.100.53", 1) == 0 && setenv("OMINULL_FIXTURE_FAIL_CODE", "4", 1) == 0);
    FollowHubAddress(&config);
    unsetenv("OMINULL_FIXTURE_FAIL");
    unsetenv("OMINULL_FIXTURE_FAIL_CODE");
    assert(appliedHubTargets.count == 2 && g_FollowPending.count == 3);
    strcpy(config.hub_url, "ftp://host");
    ResetCommands(path);
    FollowHubAddress(&config);
    data = ReadCommands(path);
    assert(strstr(data, "198.51.100.53") && strstr(data, "198.51.100.10") && appliedHubTargets.count == 3);
    assert(!g_FollowPending.count && !g_ForgetApplied);

    known = false;
    appliedIsolated = false;
    appliedPeerCount = appliedAllowCount = appliedThreatCount = appliedBaselineCount = 0;
    memset(&appliedHubTargets, 0, sizeof(appliedHubTargets));
    g_PermitsMissing = g_PermitsRetry = false;
}
int main(void) {
    char path[] = "/tmp/ominull-pinhole-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    assert(setenv("OMINULL_FIXTURE_COMMANDS", path, 1) == 0);
    FollowsAMovedHub(path);
    /* The error permit is for isolated hosts only: its match turns on connection
     * tracking for the whole family, and a busy host with a peer or threat block
     * must not start tracking every flow for it. It sits below the blocks. */
    {
        char none[1][64] = {{0}}, peer[1][64] = {"203.0.113.77"};
        OMINULL_HUB_TARGETS held = {0};
        strcpy(held.addresses[0], "198.51.100.8");
        held.count = 1;
        held.port = 443;
        ResetCommands(path);
        assert(EnforcementBuild("iptables", false, &held, none, 0, peer, 1, none, 0, NULL, 0));
        assert(!strstr(ReadCommands(path), "conntrack"));
        ResetCommands(path);
        assert(EnforcementBuild("iptables", true, &held, none, 0, peer, 1, none, 0, NULL, 0));
        const char *rules = ReadCommands(path);
        const char *blocked = strstr(rules, "-d 203.0.113.77 -j DROP"), *error = strstr(rules, "--icmp-type 3 -m conntrack --ctstate RELATED");
        assert(blocked && error && blocked < error);
        assert(!strstr(rules, "--icmp-type 5 "));
    }
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
    LockAndLeftovers(path, &hub);
    Permits(path, &hub);
    unlink(path);
    puts("Linux IPv6 hub pinhole names exact TCP port; no real firewall "
         "commands "
         "executed");
    return 0;
}
