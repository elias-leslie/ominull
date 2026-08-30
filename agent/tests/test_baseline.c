/* Unit tests for the baseline isolation policy as the Linux agent receives it.
 *
 * The parser here turns a hub reply into arguments for iptables on a host that
 * is about to be cut off the network. A rule that is dropped when it should be
 * kept strands the host; a rule that is kept when it should be dropped is a hole
 * in the isolation. Neither failure announces itself, so both are tested.
 *
 * main.c is compiled in with its entry point renamed - the functions under test
 * are static, which is the right visibility for them. */
#define main ominull_agent_main_unused
#include "../linux/main.c"
#undef main

#include <assert.h>

static int failures = 0;

static void check(bool cond, const char* what) {
    printf("  %s %s\n", cond ? "[+]" : "[-]", what);
    if (!cond) failures++;
}

int main(void) {
    printf("[*] Baseline isolation policy - Linux agent parser\n");

    /* A hub that says nothing about a baseline is a hub too old to have one.
     * That has to be distinguishable from a hub whose baseline is empty: the
     * first keeps the built-in permits, the second means hub and loopback only,
     * and confusing them either strands a fleet or leaves the hole open. */
    {
        BASELINE_RULE r[MAX_BASELINE_RULES];
        int n = ParseBaselineRules("{\"status\":\"ok\",\"is_isolated\":false}", r, MAX_BASELINE_RULES);
        check(n == -1, "a reply with no baseline key reports \"absent\", not \"empty\"");

        n = ParseBaselineRules("{\"isolation_baseline\":[]}", r, MAX_BASELINE_RULES);
        check(n == 0, "an empty baseline reports zero rules, not \"absent\"");
    }

    /* The ordinary case. */
    {
        const char* reply =
            "{\"status\":\"ok\",\"isolation_baseline\":["
            "{\"service\":\"dns\",\"destination\":\"10.0.0.1\",\"protocol\":\"udp\",\"port\":53},"
            "{\"service\":\"dhcp\",\"destination\":\"10.0.0.1\",\"protocol\":\"udp\",\"port\":67},"
            "{\"service\":\"custom\",\"destination\":\"10.0.0.4\",\"protocol\":\"tcp\",\"port\":88}"
            "],\"is_isolated\":true}";
        BASELINE_RULE r[MAX_BASELINE_RULES];
        int n = ParseBaselineRules(reply, r, MAX_BASELINE_RULES);
        check(n == 3, "three rules parse out of a well-formed reply");
        check(n == 3 && strcmp(r[0].service, "dns") == 0 && strcmp(r[0].destination, "10.0.0.1") == 0
              && strcmp(r[0].protocol, "udp") == 0 && r[0].port == 53, "the DNS rule keeps all four fields");
        check(n == 3 && r[2].port == 88 && strcmp(r[2].protocol, "tcp") == 0,
              "a custom TCP rule keeps its own protocol and port");
    }

    /* Everything in a rule becomes an argument to iptables. A hub that sends
     * something else is either running a build that does not validate its own
     * policy or is not the hub. */
    {
        const char* hostile =
            "{\"isolation_baseline\":["
            "{\"service\":\"dns\",\"destination\":\"10.0.0.1 -j ACCEPT\",\"protocol\":\"udp\",\"port\":53},"
            "{\"service\":\"dns\",\"destination\":\"example.com\",\"protocol\":\"udp\",\"port\":53},"
            "{\"service\":\"dns\",\"destination\":\"10.0.0.2\",\"protocol\":\"icmp\",\"port\":53},"
            "{\"service\":\"dns\",\"destination\":\"10.0.0.3\",\"protocol\":\"udp\",\"port\":99999},"
            "{\"service\":\"dns\",\"destination\":\"10.0.0.4\",\"protocol\":\"udp\",\"port\":0},"
            "{\"service\":\"dns\",\"destination\":\"10.0.0.9\",\"protocol\":\"udp\",\"port\":53}"
            "]}";
        BASELINE_RULE r[MAX_BASELINE_RULES];
        int n = ParseBaselineRules(hostile, r, MAX_BASELINE_RULES);
        check(n == 1, "five malformed rules are dropped and the good one survives");
        check(n == 1 && strcmp(r[0].destination, "10.0.0.9") == 0,
              "the surviving rule is the well-formed one, so a bad entry does not shift the list");
    }

    /* A hub answering with more rules than this agent has room for must fill the
     * array and stop, not walk off the end of it. */
    {
        char big[16384];
        int off = snprintf(big, sizeof(big), "{\"isolation_baseline\":[");
        for (int i = 0; i < MAX_BASELINE_RULES + 20; i++) {
            off += snprintf(big + off, sizeof(big) - off,
                            "%s{\"service\":\"dns\",\"destination\":\"10.0.1.%d\",\"protocol\":\"udp\",\"port\":53}",
                            i ? "," : "", i % 250);
        }
        snprintf(big + off, sizeof(big) - off, "]}");

        BASELINE_RULE r[MAX_BASELINE_RULES];
        int n = ParseBaselineRules(big, r, MAX_BASELINE_RULES);
        check(n == MAX_BASELINE_RULES, "an over-long baseline is capped at the array size");
    }

    /* IsIPLiteral is what stands between a hub reply and an iptables argument. */
    {
        check(IsIPLiteral("10.0.0.1"), "a v4 literal is accepted");
        check(IsIPLiteral("fe80::1"), "a v6 literal is accepted");
        check(!IsIPLiteral("10.0.0.1;reboot"), "a literal with a shell metacharacter is refused");
        check(!IsIPLiteral(""), "an empty destination is refused");
    }

    if (failures) {
        printf("[-] %d check(s) failed\n", failures);
        return 1;
    }
    printf("[+] All baseline parser checks passed\n");
    return 0;
}
