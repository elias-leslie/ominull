/* Holding an agent session's block rules: which sessions a rule may hold on and
 * what reaches the firewall, over a fake /proc and cgroup tree. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];
static char g_proc[300];
static char g_cg[300];
#define OMINULL_PROC_ROOT g_proc
#define OMINULL_CGROUP_ROOT g_cg
#include "../include/session_block_linux.h"

static int g_fail = 0;
static void check(bool ok, const char* what) {
    printf("%s %s\n", ok ? "[+]" : "[-] FAIL:", what);
    if (!ok) g_fail = 1;
}

static char g_cmds[64][400];
static int g_cmdCount = 0;
static int g_failOn = -1;
static int fake_run(const char* const argv[]) {
    char line[400] = {0};
    for (int i = 0; argv[i]; i++) {
        strncat(line, argv[i], sizeof(line) - strlen(line) - 2);
        strcat(line, " ");
    }
    int at = g_cmdCount;
    if (g_cmdCount < 64) snprintf(g_cmds[g_cmdCount++], sizeof(g_cmds[0]), "%s", line);
    return at == g_failOn ? 1 : 0;
}
static int g_drops = 0;
static bool g_dropFails = false;
static bool fake_drop(const char* tool, const char* hook, const char* chain) {
    (void)tool; (void)hook; (void)chain;
    g_drops++;
    return !g_dropFails;
}
static bool fake_public(const char* a) { return strncmp(a, "10.", 3) != 0 && strncmp(a, "fd", 2) != 0; }
static bool fake_no_v6(const char* tool) { return strcmp(tool, "ip6tables") == 0; }
static bool fake_both(const char* tool) { (void)tool; return false; }
static SESSION_BLOCK_OPS g_ops = { fake_run, fake_drop, fake_public, fake_both };

static bool cmd_has(const char* a, const char* b) {
    for (int i = 0; i < g_cmdCount; i++)
        if (strstr(g_cmds[i], a) && (!b || strstr(g_cmds[i], b))) return true;
    return false;
}
static void reset_fw(void) { g_cmdCount = 0; g_drops = 0; g_failOn = -1; g_dropFails = false; }

static void put(const char* dir, const char* name, const char* content, size_t len) {
    char path[700];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE* f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }
    fwrite(content, 1, len, f);
    fclose(f);
}
static void mkdirs(const char* path) {
    char cmd[800];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", path);
    if (system(cmd) != 0) exit(1);
}
/* One process: its parent, its binary, its Aico window and its cgroup. */
static void proc_add(int pid, int ppid, const char* exe, const char* widget, const char* group) {
    char dir[400], buf[800];
    snprintf(dir, sizeof(dir), "%s/%d", g_proc, pid);
    mkdirs(dir);
    int n = snprintf(buf, sizeof(buf), "%d (x) S %d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 %d 0 0\n", pid, ppid, 1000 + pid);
    put(dir, "stat", buf, (size_t)n);
    n = snprintf(buf, sizeof(buf), "Name:\tx\nUid:\t1000\t1000\t1000\t1000\n");
    put(dir, "status", buf, (size_t)n);
    n = snprintf(buf, sizeof(buf), "0::/%s\n", group);
    put(dir, "cgroup", buf, (size_t)n);
    n = widget ? snprintf(buf, sizeof(buf), "AICO_WIDGET_ID=%s%cHOME=/x%c", widget, 0, 0) : snprintf(buf, sizeof(buf), "HOME=/x%c", 0);
    put(dir, "environ", buf, (size_t)n);
    snprintf(buf, sizeof(buf), "%s/exe", dir);
    unlink(buf);
    if (symlink(exe, buf) != 0) { perror("symlink"); exit(1); }
}
static void group_procs(const char* group, const char* pids) {
    char dir[500];
    snprintf(dir, sizeof(dir), "%s/%s", g_cg, group);
    mkdirs(dir);
    put(dir, "cgroup.procs", pids, strlen(pids));
}
static void reset_tree(void) {
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s/proc' '%s/cg'", g_root, g_root);
    if (system(cmd) != 0) exit(1);
    mkdirs(g_proc);
    mkdirs(g_cg);
    ProcessLineage_ResetCache();
    g_SessionBlockChain = NULL;
    g_SessionBlockSig = 0;
    g_SessionBlockCleared = true;
    g_SessionBlockStale[0] = g_SessionBlockStale[1] = false;
}

#define CLAUDE "/home/u/.local/share/claude/versions/2.1.30"
#define CODEX "/usr/local/bin/codex"

static void test_parse(void) {
    SESSION_BLOCK_ENTRY e;
    check(SessionBlock_ParseEntry(&g_ops, "claude|1b16ad8d|8.8.8.0/24|443", &e) && e.port == 443 && strcmp(e.window, "1b16ad8d") == 0, "a whole entry parses");
    check(SessionBlock_ParseEntry(&g_ops, "*|*|2001:4860::/32|0", &e) && e.port == 0, "any tool, any window, all ports, IPv6");
    check(!SessionBlock_ParseEntry(&g_ops, "claude|1b16ad8d|10.0.0.0/24|443", &e), "a private range is refused");
    check(!SessionBlock_ParseEntry(&g_ops, "claude|1b16ad8d|8.0.0.0/4|443", &e), "a range wider than /8 is refused");
    check(!SessionBlock_ParseEntry(&g_ops, "claude|XYZ|8.8.8.8|443", &e), "a window that isn't hex is refused");
    check(!SessionBlock_ParseEntry(&g_ops, "cl aude|1b16|8.8.8.8|443", &e), "a tool with odd characters is refused");
    check(!SessionBlock_ParseEntry(&g_ops, "claude|1b16|8.8.8.8|99999", &e), "a port out of range is refused");
    check(!SessionBlock_ParseEntry(&g_ops, "claude|1b16|8.8.8.8", &e), "a short entry is refused");
    check(!SessionBlock_ParseEntry(&g_ops, "claude|1b16|8.8.8.8|4|4", &e), "a long entry is refused");
    char longest[64];
    memset(longest, 'a', 63);
    longest[63] = '\0';
    memcpy(longest, "claude|1b16|", 12);
    check(!SessionBlock_ParseEntry(&g_ops, longest, &e), "an entry at the parser's limit may have lost its tail");
}

static SESSION_BLOCK_ENTRY entry(const char* tool, const char* window, const char* cidr, int port) {
    SESSION_BLOCK_ENTRY e;
    memset(&e, 0, sizeof(e));
    snprintf(e.tool, sizeof(e.tool), "%s", tool);
    snprintf(e.window, sizeof(e.window), "%s", window);
    snprintf(e.cidr, sizeof(e.cidr), "%s", cidr);
    e.port = port;
    return e;
}

static void test_session_of(void) {
    reset_tree();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "a.scope");
    proc_add(101, 100, "/usr/bin/bash", "1b16ad8d", "a.scope");
    proc_add(102, 101, "/usr/bin/curl", "1b16ad8d", "a.scope");
    proc_add(200, 1, "/usr/bin/pi", "2c27be9e", "b.scope");
    proc_add(300, 1, "/usr/bin/sshd", NULL, "c.scope");
    char s[100];
    ProcessLineage_SessionOf(100, s, sizeof(s));
    check(strcmp(s, "claude:1b16ad8d") == 0, "the agent's own process is its session");
    ProcessLineage_SessionOf(102, s, sizeof(s));
    check(strcmp(s, "claude:1b16ad8d") == 0, "what the agent ran is its session");
    ProcessLineage_SessionOf(200, s, sizeof(s));
    check(strcmp(s, "aico:2c27be9e") == 0, "an unknown runtime in an Aico window is that window");
    ProcessLineage_SessionOf(300, s, sizeof(s));
    check(s[0] == '\0', "anything else has no session");
}

static void test_holds_on_a_pure_group(void) {
    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "user.slice/a.scope");
    proc_add(101, 100, "/usr/bin/curl", "1b16ad8d", "user.slice/a.scope");
    group_procs("user.slice/a.scope", "100\n101\n");
    SESSION_BLOCK_ENTRY e[] = { entry("claude", "1b16ad8d", "8.8.8.0/24", 443), entry("*", "*", "2001:4860::/32", 0), entry("codex", "*", "9.9.9.9", 0) };
    char note[SESSION_BLOCK_NOTE_MAX];
    SessionBlock_Sync(&g_ops, e, 3, note, sizeof(note));
    check(note[0] == '\0', "nothing to report");
    check(cmd_has("iptables -N OMINULL_SESS_A", NULL) && cmd_has("iptables -I OUTPUT 1 -j OMINULL_SESS_A", NULL), "IPv4 chain created and hooked");
    check(cmd_has("--path user.slice/a.scope -d 8.8.8.0/24 -p tcp --dport 443 -j REJECT", NULL), "the rule holds TCP on the session's cgroup, with no leading slash");
    check(cmd_has("--path user.slice/a.scope -d 8.8.8.0/24 -p udp --dport 443 -j REJECT", NULL), "and UDP, which carries QUIC");
    check(cmd_has("ip6tables -A OMINULL_SESS_A", "-d 2001:4860::/32 -j REJECT"), "an all-ports IPv6 rule goes in ip6tables");
    check(!cmd_has("9.9.9.9", NULL), "another tool's rule is not held");

    int before = g_cmdCount;
    SessionBlock_Sync(&g_ops, e, 3, note, sizeof(note));
    check(g_cmdCount == before, "an unchanged set touches nothing");

    reset_fw();
    SESSION_BLOCK_ENTRY two[] = { entry("claude", "1b16ad8d", "1.1.1.1", 0) };
    SessionBlock_Sync(&g_ops, two, 1, note, sizeof(note));
    check(cmd_has("iptables -N OMINULL_SESS_B", NULL) && g_drops == 2, "a change builds the other chain, then drops the old one");

    reset_fw();
    g_failOn = 2;
    SESSION_BLOCK_ENTRY three[] = { entry("claude", "1b16ad8d", "1.0.0.1", 0) };
    SessionBlock_Sync(&g_ops, three, 1, note, sizeof(note));
    check(strstr(note, "refused") != NULL && strcmp(g_SessionBlockChain, SESSION_BLOCK_CHAIN_B) == 0, "a refused set leaves the rules in force and says so");

    reset_fw();
    SessionBlock_Sync(&g_ops, NULL, 0, note, sizeof(note));
    check(g_drops == 4 && g_SessionBlockChain == NULL, "no entries lifts everything");
    reset_fw();
    SessionBlock_Sync(&g_ops, NULL, 0, note, sizeof(note));
    check(g_cmdCount == 0 && g_drops == 0, "no entries and nothing held costs nothing");
}

static void test_refuses_shared_groups(void) {
    SESSION_BLOCK_ENTRY e[] = { entry("claude", "*", "8.8.8.8", 0) };
    char note[SESSION_BLOCK_NOTE_MAX];

    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "session-3.scope");
    proc_add(50, 1, "/usr/sbin/sshd", NULL, "session-3.scope");
    group_procs("session-3.scope", "50\n100\n");
    SessionBlock_Sync(&g_ops, e, 1, note, sizeof(note));
    check(strstr(note, "holds other processes") && strstr(note, "claude:1b16ad8d") && g_cmdCount == 0, "a group shared with anything else is refused and named");

    reset_tree();
    reset_fw();
    proc_add(90, 1, "/usr/bin/bash", "1b16ad8d", "pane.scope");
    proc_add(100, 90, CLAUDE, "1b16ad8d", "pane.scope");
    group_procs("pane.scope", "90\n100\n");
    SessionBlock_Sync(&g_ops, e, 1, note, sizeof(note));
    check(note[0] == '\0' && cmd_has("--path pane.scope", NULL), "the shell a window runs its agent from is that window's session");

    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "x.scope");
    proc_add(200, 1, CLAUDE, "2c27be9e", "x.scope");
    group_procs("x.scope", "100\n200\n");
    SessionBlock_Sync(&g_ops, e, 1, note, sizeof(note));
    check(strstr(note, "holds other processes") && g_cmdCount == 0, "two sessions in one group are refused");

    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "");
    SessionBlock_Sync(&g_ops, e, 1, note, sizeof(note));
    check(strstr(note, "no cgroup of its own") && g_cmdCount == 0, "the root cgroup is refused: the match would cover the machine");

    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "y.scope");
    group_procs("y.scope", "100\n");
    group_procs("y.scope/child", "");
    SessionBlock_Sync(&g_ops, e, 1, note, sizeof(note));
    check(strstr(note, "child groups") && g_cmdCount == 0, "the match covers child groups, so a group with any is refused");

    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "z.scope");
    SessionBlock_Sync(&g_ops, e, 1, note, sizeof(note));
    check(strstr(note, "could not be read") && g_cmdCount == 0, "an unreadable group is refused");
}

static void test_clears_an_earlier_run(void) {
    reset_tree();
    reset_fw();
    g_SessionBlockCleared = false;
    char note[SESSION_BLOCK_NOTE_MAX];
    SessionBlock_Sync(&g_ops, NULL, 0, note, sizeof(note));
    check(g_drops == 4, "the first pass clears what an earlier run left, in both families");
    g_ops.no_table = fake_no_v6;
    reset_fw();
    g_SessionBlockCleared = false;
    SessionBlock_Sync(&g_ops, NULL, 0, note, sizeof(note));
    check(g_drops == 2, "a host without IPv6 clears IPv4 only");
    g_ops.no_table = fake_both;
}

static void test_window_with_no_known_binary(void) {
    char note[SESSION_BLOCK_NOTE_MAX];
    reset_tree();
    reset_fw();
    proc_add(200, 1, "/usr/bin/pi", "2c27be9e", "pi.scope");
    proc_add(300, 1, "/usr/sbin/sshd", NULL, "sshd.scope");
    group_procs("pi.scope", "200\n");
    group_procs("sshd.scope", "300\n");
    SESSION_BLOCK_ENTRY e[] = { entry("aico", "2c27be9e", "8.8.8.8", 0) };
    SessionBlock_Sync(&g_ops, e, 1, note, sizeof(note));
    check(note[0] == '\0' && cmd_has("--path pi.scope", "-d 8.8.8.8"), "a window running no known binary can be blocked");
    check(!cmd_has("sshd.scope", NULL), "a process with no window is not");

    reset_tree();
    reset_fw();
    proc_add(200, 1, "/usr/bin/pi", "2c27be9e", "pi.scope");
    group_procs("pi.scope", "200\n");
    SESSION_BLOCK_ENTRY any[] = { entry("*", "2c27be9e", "8.8.4.4", 0) };
    SessionBlock_Sync(&g_ops, any, 1, note, sizeof(note));
    check(note[0] == '\0' && cmd_has("--path pi.scope", "-d 8.8.4.4"), "so can a rule naming only the window");
}

static void test_two_tools_in_one_window(void) {
    char note[SESSION_BLOCK_NOTE_MAX];
    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "w.scope");
    proc_add(200, 100, CODEX, "1b16ad8d", "w.scope");
    group_procs("w.scope", "100\n200\n");
    SESSION_BLOCK_ENTRY e[] = { entry("claude", "1b16ad8d", "1.1.1.1", 0), entry("codex", "1b16ad8d", "2.2.2.2", 0) };
    SessionBlock_Sync(&g_ops, e, 2, note, sizeof(note));
    check(strstr(note, "not held for 1") && strstr(note, "another agent") && g_cmdCount == 0, "a rule naming one tool is refused where it would also hit another, once per window");

    reset_fw();
    SESSION_BLOCK_ENTRY w[] = { entry("*", "1b16ad8d", "1.1.1.1", 0), entry("*", "1b16ad8d", "2.2.2.2", 443) };
    SessionBlock_Sync(&g_ops, w, 2, note, sizeof(note));
    check(note[0] == '\0' && cmd_has("-d 1.1.1.1", NULL) && cmd_has("-d 2.2.2.2", NULL), "a rule naming the window holds on all of it");
    int rules = 0;
    for (int i = 0; i < g_cmdCount; i++) rules += strstr(g_cmds[i], "-d 1.1.1.1") != NULL;
    check(rules == 1, "and each rule goes in once, however many processes it covers");
    int before = g_cmdCount;
    proc_add(90, 1, CODEX, "1b16ad8d", "w.scope");
    group_procs("w.scope", "90\n100\n200\n");
    SessionBlock_Sync(&g_ops, w, 2, note, sizeof(note));
    check(g_cmdCount == before, "another process in the window changes nothing");
}

static void test_a_chain_that_will_not_drop(void) {
    char note[SESSION_BLOCK_NOTE_MAX];
    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "a.scope");
    group_procs("a.scope", "100\n");
    SESSION_BLOCK_ENTRY one[] = { entry("claude", "1b16ad8d", "1.1.1.1", 0) };
    SESSION_BLOCK_ENTRY two[] = { entry("claude", "1b16ad8d", "1.0.0.1", 0) };
    SessionBlock_Sync(&g_ops, one, 1, note, sizeof(note));

    g_dropFails = true;
    SessionBlock_Sync(&g_ops, two, 1, note, sizeof(note));
    check(strcmp(g_SessionBlockChain, SESSION_BLOCK_CHAIN_B) == 0 && strstr(note, "still held"), "an old chain that won't drop is reported");
    g_dropFails = false;
    g_drops = 0;
    g_cmdCount = 0;
    SessionBlock_Sync(&g_ops, two, 1, note, sizeof(note));
    check(g_drops == 2 && note[0] == '\0' && g_cmdCount == 0, "and tried again next beat, with the set unchanged");

    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "a.scope");
    group_procs("a.scope", "100\n");
    g_failOn = 1;
    g_dropFails = true;
    SessionBlock_Sync(&g_ops, one, 1, note, sizeof(note));
    check(g_SessionBlockChain == NULL && g_SessionBlockStale[0], "a half-built chain that won't drop is remembered");
    g_failOn = -1;
    SessionBlock_Sync(&g_ops, NULL, 0, note, sizeof(note));
    check(strstr(note, "still held") != NULL, "and reported when the hub lifts the rule, though nothing is in force");
    g_dropFails = false;
    g_drops = 0;
    SessionBlock_Sync(&g_ops, NULL, 0, note, sizeof(note));
    check(g_drops == 2 && !g_SessionBlockStale[0] && note[0] == '\0', "and dropped once the firewall lets it");
}

static void test_recreated_group(void) {
    char note[SESSION_BLOCK_NOTE_MAX], old[500], fresh[500];
    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "a.scope");
    group_procs("a.scope", "100\n");
    SESSION_BLOCK_ENTRY e[] = { entry("claude", "1b16ad8d", "1.1.1.1", 0) };
    SessionBlock_Sync(&g_ops, e, 1, note, sizeof(note));
    check(strcmp(g_SessionBlockChain, SESSION_BLOCK_CHAIN_A) == 0, "first set in chain A");
    /* New directory while the old exists, so it can't reuse the inode. */
    group_procs("a.new", "100\n");
    snprintf(old, sizeof(old), "%s/a.scope", g_cg);
    snprintf(fresh, sizeof(fresh), "%s/a.new", g_cg);
    char cmd[1600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s' && mv '%s' '%s'", old, fresh, old);
    if (system(cmd) != 0) exit(1);
    SessionBlock_Sync(&g_ops, e, 1, note, sizeof(note));
    check(strcmp(g_SessionBlockChain, SESSION_BLOCK_CHAIN_B) == 0, "a group recreated under the same name gets its rules again");
}

static void test_group_holding_this_agent(void) {
    char note[SESSION_BLOCK_NOTE_MAX], pids[64];
    reset_tree();
    reset_fw();
    proc_add(100, 1, CLAUDE, "1b16ad8d", "a.scope");
    snprintf(pids, sizeof(pids), "100\n%d\n", (int)getpid());
    group_procs("a.scope", pids);
    SESSION_BLOCK_ENTRY e[] = { entry("claude", "1b16ad8d", "1.1.1.1", 0) };
    SessionBlock_Sync(&g_ops, e, 1, note, sizeof(note));
    check(strstr(note, "Ominull agent") && g_cmdCount == 0, "a group holding the Ominull agent itself is refused");
}

int main(void) {
    snprintf(g_root, sizeof(g_root), "%s/session-block-test-%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
    snprintf(g_proc, sizeof(g_proc), "%s/proc", g_root);
    snprintf(g_cg, sizeof(g_cg), "%s/cg", g_root);
    test_parse();
    test_session_of();
    test_holds_on_a_pure_group();
    test_refuses_shared_groups();
    test_clears_an_earlier_run();
    test_window_with_no_known_binary();
    test_two_tools_in_one_window();
    test_a_chain_that_will_not_drop();
    test_recreated_group();
    test_group_holding_this_agent();
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
    if (system(cmd) != 0) g_fail = 1;
    printf(g_fail ? "[-] session block tests FAILED\n" : "[+] session block tests passed\n");
    return g_fail;
}
