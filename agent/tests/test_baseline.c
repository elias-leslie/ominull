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

    /* Isolation exceptions are read whole or not at all: they arrive inside
     * the signed isolation (agent_trust.h Trust_ParseRules) or, once, in the
     * bootstrap answer. */
    {
        TrustRule r[TRUST_MAX_RULES];
        const char* empty = "[]";
        check(Trust_ParseRules(empty, empty + 2, r, TRUST_MAX_RULES) == 0, "an empty list reads as zero rules");
        const char* ok = "[{\"destination\":\"10.0.0.1\",\"port\":53,\"protocol\":\"udp\",\"service\":\"dns\"},"
                         "{\"destination\":\"10.0.0.1\",\"port\":67,\"protocol\":\"udp\",\"service\":\"dhcp\"},"
                         "{\"destination\":\"10.0.0.4\",\"port\":88,\"protocol\":\"tcp\",\"service\":\"custom\"}]";
        int n = Trust_ParseRules(ok, ok + strlen(ok), r, TRUST_MAX_RULES);
        check(n == 3, "three rules parse out of a well-formed list");
        check(n == 3 && strcmp(r[0].service, "dns") == 0 && strcmp(r[0].destination, "10.0.0.1") == 0
              && strcmp(r[0].protocol, "udp") == 0 && r[0].port == 53, "the DNS rule keeps all four fields");
        check(n == 3 && r[2].port == 88 && strcmp(r[2].protocol, "tcp") == 0, "a custom TCP rule keeps its own protocol and port");
        const char* hostile[] = {
            "[{\"destination\":\"10.0.0.1 -j ACCEPT\",\"port\":53,\"protocol\":\"udp\",\"service\":\"dns\"}]",
            "[{\"destination\":\"example.com\",\"port\":53,\"protocol\":\"udp\",\"service\":\"dns\"}]",
            "[{\"destination\":\"10.0.0.2\",\"port\":53,\"protocol\":\"icmp\",\"service\":\"dns\"}]",
            "[{\"destination\":\"10.0.0.3\",\"port\":99999,\"protocol\":\"udp\",\"service\":\"dns\"}]",
            "[{\"destination\":\"10.0.0.4\",\"port\":0,\"protocol\":\"udp\",\"service\":\"dns\"}]",
            "[{\"destination\":\"0.0.0.0/0\",\"port\":443,\"protocol\":\"tcp\",\"service\":\"custom\"}]",
            "[{\"destination\":\"10.0.0.5\",\"port\":53,\"protocol\":\"udp\",\"service\":\"d n s\"}]",
            "[{\"destination\":\"10.0.0.5\",\"port\":53,\"protocol\":\"udp\",\"service\":\"dns\",\"Service\":\"x\"}]",
        };
        for (size_t i = 0; i < sizeof(hostile) / sizeof(hostile[0]); i++)
            check(Trust_ParseRules(hostile[i], hostile[i] + strlen(hostile[i]), r, TRUST_MAX_RULES) == -1, "a malformed rule refuses the whole list");
        char big[16384];
        int off = snprintf(big, sizeof(big), "[");
        for (int i = 0; i < TRUST_MAX_RULES + 1; i++)
            off += snprintf(big + off, sizeof(big) - off, "%s{\"destination\":\"10.0.1.%d\",\"port\":53,\"protocol\":\"udp\",\"service\":\"dns\"}",
                            i ? "," : "", i % 250);
        snprintf(big + off, sizeof(big) - off, "]");
        check(Trust_ParseRules(big, big + strlen(big), r, TRUST_MAX_RULES) == -1, "a list longer than the agent can hold is refused, not cut");
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
