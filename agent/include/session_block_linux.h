/*
 * Ominull Linux: holding an agent session's block rules.
 *
 * The hub names sessions and public address ranges; the kernel only knows
 * sockets. A session's sockets are told apart by cgroup, so a rule holds only
 * where a session has a cgroup of its own: every process in it, and no child
 * group, belongs to that session. Anything else is refused and reported, because
 * blocking a shared cgroup would cut off whatever else lives in it.
 *
 * With no entries there is no /proc scan and no firewall call after the first
 * pass, which clears what an earlier run left.
 *
 * Limits: a session started since the last beat is not covered until the next;
 * a process moved out of the cgroup (systemd-run, docker) escapes; the cgroup
 * match uses the cgroup a socket was created in.
 */

#ifndef OMINULL_SESSION_BLOCK_LINUX_H
#define OMINULL_SESSION_BLOCK_LINUX_H

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "process_lineage_linux.h"

#ifndef OMINULL_CGROUP_ROOT
#define OMINULL_CGROUP_ROOT "/sys/fs/cgroup"
#endif

#define SESSION_BLOCK_MAX_ENTRIES 32
#define SESSION_BLOCK_MAX_GROUPS 16
#define SESSION_BLOCK_MAX_RULES 256
#define SESSION_BLOCK_NOTE_MAX 200
#define SESSION_BLOCK_CHAIN_A "OMINULL_SESS_A"
#define SESSION_BLOCK_CHAIN_B "OMINULL_SESS_B"

typedef struct {
    char tool[33];
    char window[65];
    char cidr[48];
    int port;
} SESSION_BLOCK_ENTRY;

typedef struct {
    int (*run)(const char* const argv[]);                                 /* a firewall command; 0 is success */
    bool (*drop_chain)(const char* tool, const char* hook, const char* chain); /* true once it is gone */
    bool (*is_public)(const char* address);
    bool (*no_table)(const char* tool);                                   /* this family has no firewall here */
} SESSION_BLOCK_OPS;

typedef struct {
    char group[512];  /* relative to the cgroup root */
    char cidr[48];
    int port;
    bool v6;
    uint64_t identity;  /* of the cgroup when the rule was made */
} SESSION_BLOCK_RULE;

static const char* g_SessionBlockChain = NULL;  /* the chain in force */
static uint64_t g_SessionBlockSig = 0;
static bool g_SessionBlockCleared = false;      /* what an earlier run left is gone */
static bool g_SessionBlockStale[2] = {false, false};  /* chain A, B: not in force, but wouldn't drop */

static inline bool SessionBlock_Field(const char* s, size_t n, char* out, size_t outLen) {
    if (n == 0 || n >= outLen) return false;
    memcpy(out, s, n);
    out[n] = '\0';
    return true;
}

/* One "tool|window|range|port" from the hub. Refuses a token at the parser's
 * length limit, which may have lost its tail: a shortened port is another port. */
static inline bool SessionBlock_ParseEntry(const SESSION_BLOCK_OPS* ops, const char* s, SESSION_BLOCK_ENTRY* e) {
    if (strlen(s) >= 63) return false;
    const char* a = strchr(s, '|');
    const char* b = a ? strchr(a + 1, '|') : NULL;
    const char* c = b ? strchr(b + 1, '|') : NULL;
    if (!c || strchr(c + 1, '|')) return false;
    if (!SessionBlock_Field(s, (size_t)(a - s), e->tool, sizeof(e->tool)) ||
        !SessionBlock_Field(a + 1, (size_t)(b - a - 1), e->window, sizeof(e->window)) ||
        !SessionBlock_Field(b + 1, (size_t)(c - b - 1), e->cidr, sizeof(e->cidr))) return false;

    if (strcmp(e->tool, "*") != 0) {
        for (const char* p = e->tool; *p; p++)
            if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return false;
    }
    if (strcmp(e->window, "*") != 0) {
        size_t len = strlen(e->window);
        if (len < 4) return false;
        for (const char* p = e->window; *p; p++)
            if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return false;
    }

    char* end = NULL;
    long port = strtol(c + 1, &end, 10);
    if (!end || *end || end == c + 1 || port < 0 || port > 65535) return false;
    e->port = (int)port;

    char addr[48];
    snprintf(addr, sizeof(addr), "%s", e->cidr);
    bool v6 = strchr(addr, ':') != NULL;
    char* slash = strchr(addr, '/');
    if (slash) {
        *slash = '\0';
        long bits = strtol(slash + 1, &end, 10);
        if (!end || *end || end == slash + 1 || bits < (v6 ? 32 : 8) || bits > (v6 ? 128 : 32)) return false;
    }
    return ops->is_public(addr);
}

/* A process's cgroup, relative to the root; false for the root or when unread. */
static inline bool SessionBlock_GroupOf(uint32_t pid, char* out, size_t outLen) {
    char buf[1024];
    if (!ProcessLineage_ReadSmall(pid, "cgroup", buf, sizeof(buf), NULL)) return false;
    char* line = strncmp(buf, "0::", 3) == 0 ? buf : strstr(buf, "\n0::");
    if (!line) return false;
    char* cg = line + (line[0] == '\n' ? 4 : 3);
    cg[strcspn(cg, "\n")] = '\0';
    while (*cg == '/') cg++;
    if (!*cg || strlen(cg) >= outLen || strstr(cg, "..")) return false;
    snprintf(out, outLen, "%s", cg);
    return true;
}

/* Whether two session keys are one session: the same key, or the same Aico
 * window, since the shell a window runs its agent from is "aico:<window>". */
static inline bool SessionBlock_SameSession(const char* a, const char* b) {
    if (strcmp(a, b) == 0) return true;
    const char* wa = strchr(a, ':');
    const char* wb = strchr(b, ':');
    return wa && wb && wa[1] && strcmp(wa, wb) == 0;
}

/* NULL when the group holds this session alone, else why not. */
static inline const char* SessionBlock_GroupImpure(const char* group, const char* session) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", OMINULL_CGROUP_ROOT, group);
    DIR* dir = opendir(path);
    if (!dir) return "its cgroup could not be read";
    struct dirent* d;
    bool children = false;
    while ((d = readdir(dir)) != NULL) {
        if (d->d_type == DT_DIR && strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0) children = true;
    }
    closedir(dir);
    if (children) return "its cgroup has child groups";

    snprintf(path, sizeof(path), "%s/%s/cgroup.procs", OMINULL_CGROUP_ROOT, group);
    FILE* f = fopen(path, "r");
    if (!f) return "its cgroup could not be read";
    const char* why = NULL;
    unsigned pid;
    while (!why && fscanf(f, "%u", &pid) == 1) {
        if ((pid_t)pid == getpid()) {  /* a block here could cut this agent off its hub */
            why = "the Ominull agent runs in its cgroup";
            break;
        }
        unsigned long long start = 0;
        uint32_t ppid = 0;
        if (!ProcessLineage_ReadStat(pid, &start, &ppid)) continue;  /* it has exited */
        char other[100];
        ProcessLineage_SessionOf(pid, other, sizeof(other));
        if (!SessionBlock_SameSession(other, session)) why = "its cgroup holds other processes";
    }
    fclose(f);
    return why;
}

static inline bool SessionBlock_Covers(const SESSION_BLOCK_ENTRY* e, const char* tool, const char* window) {
    return (strcmp(e->tool, "*") == 0 || strcmp(e->tool, tool) == 0) &&
           (strcmp(e->window, "*") == 0 || strcmp(e->window, window) == 0);
}

/* Whether the group runs an agent other than tool. A cgroup match covers the
 * whole group, so a rule naming one tool would hit the other. */
static inline bool SessionBlock_HoldsOtherTool(const char* group, const char* tool) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s/cgroup.procs", OMINULL_CGROUP_ROOT, group);
    FILE* f = fopen(path, "r");
    if (!f) return true;
    bool other = false;
    unsigned pid;
    while (!other && fscanf(f, "%u", &pid) == 1) {
        const char* running = ProcessLineage_AgentTool(pid);
        other = running && strcmp(running, tool) != 0;
    }
    fclose(f);
    return other;
}

/* The match binds the cgroup itself, not its path, so a group recreated under
 * the same name needs its rules put in again. */
static inline uint64_t SessionBlock_GroupIdentity(const char* group) {
    char path[1024];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", OMINULL_CGROUP_ROOT, group);
    return stat(path, &st) == 0 ? (uint64_t)st.st_ino : 0;
}

static inline int SessionBlock_RuleOrder(const void* a, const void* b) {
    const SESSION_BLOCK_RULE* x = a;
    const SESSION_BLOCK_RULE* y = b;
    int c = strcmp(x->group, y->group);
    if (c == 0) c = strcmp(x->cidr, y->cidr);
    return c ? c : x->port - y->port;
}

typedef struct {
    int count;
    const char* why;
    char session[100];
} SESSION_BLOCK_REFUSALS;

static inline void SessionBlock_Refuse(SESSION_BLOCK_REFUSALS* r, const char* why, const char* session) {
    if (r->count++ == 0) {
        r->why = why;
        snprintf(r->session, sizeof(r->session), "%s", session);
    }
}

/* The rules the running sessions call for, sorted so that the order processes
 * happen to be listed in doesn't read as a change. A process carrying a window
 * with no agent binary is "aico", as ProcessLineage_SessionOf names it. A session
 * the entries cover but no rule can hold goes in the note. */
static inline int SessionBlock_Rules(const SESSION_BLOCK_ENTRY* entries, int n, SESSION_BLOCK_RULE* rules, char* note, size_t noteLen) {
    struct {
        char name[512];
        bool held;
        bool toolRefused;
    } groups[SESSION_BLOCK_MAX_GROUPS];
    int groupCount = 0, ruleCount = 0;
    SESSION_BLOCK_REFUSALS refused = { 0, NULL, {0} };

    DIR* proc = opendir(OMINULL_PROC_ROOT);
    if (!proc) {
        snprintf(note, noteLen, "agent session rules not held: running processes could not be read");
        return 0;
    }
    struct dirent* d;
    while ((d = readdir(proc)) != NULL) {
        char* end = NULL;
        unsigned long pid = strtoul(d->d_name, &end, 10);
        if (!end || *end || pid == 0) continue;
        char window[65];
        const char* tool = ProcessLineage_AgentTool((uint32_t)pid);
        ProcessLineage_ReadWidget((uint32_t)pid, window, sizeof(window));
        if (!tool) {
            if (!window[0]) continue;
            tool = "aico";
        }
        bool covered = false;
        for (int i = 0; i < n && !covered; i++) covered = SessionBlock_Covers(&entries[i], tool, window);
        if (!covered) continue;

        char session[100], group[512];
        snprintf(session, sizeof(session), "%s:%s", tool, window);
        if (!SessionBlock_GroupOf((uint32_t)pid, group, sizeof(group))) {
            SessionBlock_Refuse(&refused, "it has no cgroup of its own", session);
            continue;
        }
        int g = 0;
        while (g < groupCount && strcmp(groups[g].name, group) != 0) g++;
        if (g == groupCount) {
            if (groupCount == SESSION_BLOCK_MAX_GROUPS) {
                SessionBlock_Refuse(&refused, "too many sessions to hold", session);
                continue;
            }
            const char* why = SessionBlock_GroupImpure(group, session);
            if (why) SessionBlock_Refuse(&refused, why, session);
            snprintf(groups[g].name, sizeof(groups[g].name), "%s", group);
            groups[g].held = why == NULL;
            groups[g].toolRefused = false;
            groupCount++;
        }
        if (!groups[g].held) continue;

        for (int i = 0; i < n; i++) {
            if (!SessionBlock_Covers(&entries[i], tool, window)) continue;
            if (strcmp(entries[i].tool, "*") != 0 && SessionBlock_HoldsOtherTool(group, entries[i].tool)) {
                if (!groups[g].toolRefused) SessionBlock_Refuse(&refused, "its window also runs another agent, so the rule must name the window", session);
                groups[g].toolRefused = true;
                continue;
            }
            bool have = false;
            for (int k = 0; k < ruleCount && !have; k++)
                have = rules[k].port == entries[i].port && strcmp(rules[k].cidr, entries[i].cidr) == 0 && strcmp(rules[k].group, group) == 0;
            if (have) continue;
            if (ruleCount >= SESSION_BLOCK_MAX_RULES) {
                SessionBlock_Refuse(&refused, "too many rules to hold", session);
                break;
            }
            SESSION_BLOCK_RULE* r = &rules[ruleCount++];
            snprintf(r->group, sizeof(r->group), "%s", group);
            snprintf(r->cidr, sizeof(r->cidr), "%s", entries[i].cidr);
            r->port = entries[i].port;
            r->v6 = strchr(r->cidr, ':') != NULL;
            r->identity = SessionBlock_GroupIdentity(group);
        }
    }
    closedir(proc);
    qsort(rules, (size_t)ruleCount, sizeof(*rules), SessionBlock_RuleOrder);
    if (refused.count) snprintf(note, noteLen, "agent session rules not held for %d: %s: %s", refused.count, refused.session, refused.why);
    return ruleCount;
}

static inline uint64_t SessionBlock_Signature(const SESSION_BLOCK_RULE* rules, int n) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < n; i++) {
        char line[660];
        int len = snprintf(line, sizeof(line), "%s|%llu|%s|%d;", rules[i].group, (unsigned long long)rules[i].identity, rules[i].cidr, rules[i].port);
        for (int c = 0; c < len && c < (int)sizeof(line); c++) h = (h ^ (unsigned char)line[c]) * 1099511628211ULL;
    }
    return h;
}

static inline bool SessionBlock_AddRule(const SESSION_BLOCK_OPS* ops, const char* tool, const char* chain, const SESSION_BLOCK_RULE* r) {
    if (r->port == 0) {
        const char* all[] = { tool, "-A", chain, "-m", "cgroup", "--path", r->group, "-d", r->cidr, "-j", "REJECT", NULL };
        return ops->run(all) == 0;
    }
    char port[8];
    snprintf(port, sizeof(port), "%d", r->port);
    const char* tcp[] = { tool, "-A", chain, "-m", "cgroup", "--path", r->group, "-d", r->cidr, "-p", "tcp", "--dport", port, "-j", "REJECT", NULL };
    const char* udp[] = { tool, "-A", chain, "-m", "cgroup", "--path", r->group, "-d", r->cidr, "-p", "udp", "--dport", port, "-j", "REJECT", NULL };
    return ops->run(tcp) == 0 && ops->run(udp) == 0;
}

/* One family's new chain, complete, then hooked in ahead of everything. */
static inline bool SessionBlock_Install(const SESSION_BLOCK_OPS* ops, const char* tool, const char* chain, const SESSION_BLOCK_RULE* rules, int n) {
    bool v6 = strcmp(tool, "ip6tables") == 0;
    bool any = false;
    for (int i = 0; i < n; i++) any = any || rules[i].v6 == v6;
    if (!any) return true;
    if (ops->no_table(tool)) return true;
    const char* create[] = { tool, "-N", chain, NULL };
    if (ops->run(create) != 0) return false;
    for (int i = 0; i < n; i++) {
        if (rules[i].v6 == v6 && !SessionBlock_AddRule(ops, tool, chain, &rules[i])) return false;
    }
    const char* hook[] = { tool, "-I", "OUTPUT", "1", "-j", chain, NULL };
    return ops->run(hook) == 0;
}

static inline bool SessionBlock_DropEverywhere(const SESSION_BLOCK_OPS* ops, const char* chain) {
    bool gone = true;
    const char* tools[] = { "iptables", "ip6tables" };
    for (int i = 0; i < 2; i++) {
        if (!ops->no_table(tools[i])) gone = ops->drop_chain(tools[i], "OUTPUT", chain) && gone;
    }
    return gone;
}

/* Removes every session block; true once they are gone. */
static inline bool SessionBlock_Clear(const SESSION_BLOCK_OPS* ops) {
    bool gone = SessionBlock_DropEverywhere(ops, SESSION_BLOCK_CHAIN_A);
    gone = SessionBlock_DropEverywhere(ops, SESSION_BLOCK_CHAIN_B) && gone;
    if (gone) {
        g_SessionBlockChain = NULL;
        g_SessionBlockSig = 0;
        g_SessionBlockCleared = true;
        g_SessionBlockStale[0] = g_SessionBlockStale[1] = false;
    }
    return gone;
}

/* A chain out of use that won't drop keeps rejecting, so it is tried again every
 * beat, whatever else is asked for. */
static inline void SessionBlock_Retire(const SESSION_BLOCK_OPS* ops, const char* chain) {
    g_SessionBlockStale[strcmp(chain, SESSION_BLOCK_CHAIN_A) == 0 ? 0 : 1] = !SessionBlock_DropEverywhere(ops, chain);
}

static inline void SessionBlock_NoteStale(char* note, size_t noteLen) {
    if (!note[0] && (g_SessionBlockStale[0] || g_SessionBlockStale[1]))
        snprintf(note, noteLen, "agent session rules still held: the firewall would not remove them");
}

/* Brings the firewall to what the entries call for. The rules in force stay
 * until the new set is whole. note says what could not be held. */
static inline void SessionBlock_Sync(const SESSION_BLOCK_OPS* ops, const SESSION_BLOCK_ENTRY* entries, int n, char* note, size_t noteLen) {
    note[0] = '\0';
    if (!g_SessionBlockCleared && !SessionBlock_Clear(ops)) {
        snprintf(note, noteLen, "agent session rules not held: the firewall would not clear the last set");
        return;
    }
    if (g_SessionBlockStale[0]) SessionBlock_Retire(ops, SESSION_BLOCK_CHAIN_A);
    if (g_SessionBlockStale[1]) SessionBlock_Retire(ops, SESSION_BLOCK_CHAIN_B);
    if (n == 0) {
        if (g_SessionBlockChain && !SessionBlock_Clear(ops))
            snprintf(note, noteLen, "agent session rules still held: the firewall would not remove them");
        SessionBlock_NoteStale(note, noteLen);
        return;
    }

    SESSION_BLOCK_RULE* rules = calloc(SESSION_BLOCK_MAX_RULES, sizeof(*rules));
    if (!rules) {
        snprintf(note, noteLen, "agent session rules not held: out of memory");
        return;
    }
    int count = SessionBlock_Rules(entries, n, rules, note, noteLen);
    uint64_t sig = SessionBlock_Signature(rules, count);
    if (count == 0) {
        if (g_SessionBlockChain && !SessionBlock_Clear(ops) && !note[0])
            snprintf(note, noteLen, "agent session rules still held: the firewall would not remove them");
    } else if (!g_SessionBlockChain || sig != g_SessionBlockSig) {
        const char* next = g_SessionBlockChain && strcmp(g_SessionBlockChain, SESSION_BLOCK_CHAIN_A) == 0 ? SESSION_BLOCK_CHAIN_B : SESSION_BLOCK_CHAIN_A;
        const char* old = g_SessionBlockChain;
        bool ok = SessionBlock_Install(ops, "iptables", next, rules, count) && SessionBlock_Install(ops, "ip6tables", next, rules, count);
        if (ok) {
            if (old) SessionBlock_Retire(ops, old);
            g_SessionBlockChain = next;
            g_SessionBlockSig = sig;
        } else {
            SessionBlock_Retire(ops, next);
            snprintf(note, noteLen, "agent session rules not held: the firewall refused them");
        }
    }
    free(rules);
    SessionBlock_NoteStale(note, noteLen);
}

#endif
