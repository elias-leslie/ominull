/*
 * Ominull data inventory: Linux walker, sandbox and scheduling.
 *
 * What it does. On a hub-configured cadence the agent walks the hub-configured
 * roots and reports metadata only: per store (a directory at store_depth below
 * a root) counts, bytes, times, permission counts, owners, an extension
 * histogram and marker hints; per file only verdicts (rule ids) for secret
 * candidates, private keys, key/credential files and encrypted containers.
 * File contents and matched strings never leave the scanning child. A few host
 * facts (at-rest encryption of each root, listening sockets, ufw, pending
 * updates, sshd login settings) ride along.
 *
 * Read-only by construction. The scan runs in a forked child that, before it
 * touches any scanned path:
 *   - drops every capability except CAP_DAC_READ_SEARCH (read anything) and
 *     CAP_FOWNER (only so O_NOATIME works on files it does not own), clears the
 *     bounding and ambient sets and sets no_new_privs;
 *   - sets RLIMIT_FSIZE 0, RLIMIT_CORE 0, a CPU and address-space limit;
 *   - installs a seccomp filter that kills the process on any syscall outside a
 *     short read-only list. openat must carry O_NOFOLLOW and none of
 *     O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND/O_TMPFILE; write is allowed only
 *     to the result pipe; mmap/mprotect never with PROT_EXEC. There is no
 *     syscall in the list that writes, renames, unlinks, chmods, executes, forks
 *     or opens a socket.
 *   - runs at nice 19, SCHED_IDLE and the idle I/O class, and dies with the
 *     agent (PR_SET_PDEATHSIG).
 * Walks never follow symlinks (fstatat AT_SYMLINK_NOFOLLOW, openat O_NOFOLLOW
 * per component, inode re-checked on the open descriptor), never open anything
 * but regular files and directories, never cross into network, FUSE or pseudo
 * filesystems, and skip canary paths by path before any stat or open, so a
 * scan can never trip one. Caches and regenerable trees are skipped by rule
 * (CACHEDIR.TAG, node_modules, .cache, virtualenvs, ...).
 *
 * Budgets and cursor. Each run stops at max_files or max_seconds; reading
 * content stops at content_budget_bytes. Stores are visited in a fixed order
 * and the cursor (the last store reported) is saved only after the hub
 * accepted the run, so the next run resumes there. A cycle is one pass over
 * every store. Content is re-read only for files changed since the store's
 * last complete content scan, except on a full cycle (every full_every_days, or
 * when DI_RULES_VERSION or the policy changed).
 *
 * The parent (the agent's main loop) only fetches the policy, forks the child,
 * drains its pipe without blocking telemetry, posts the result and writes the
 * agent's own state file after an HTTP 200.
 */

#ifndef OMINULL_DATA_INVENTORY_LINUX_H
#define OMINULL_DATA_INVENTORY_LINUX_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "data_inventory_core.h"

#define DI_POLICY_HEADER "ominull-data-policy/1"
#define DI_STATE_HEADER "ominull-data-state/1"
#define DI_SCHEMA "ominull.data-inventory/1"
#define DI_DEFAULT_STATE_PATH "/var/lib/ominull/data-inventory.state"
#define DI_STATE_SEP "\n\x1eOMINULL-DATA-STATE\n"
#define DI_END_MARK "\x1eOMINULL-DATA-END\n"

#define DI_PATH_CAP 1024
#define DI_MAX_ROOTS 16
#define DI_MAX_EXCLUDES 64
#define DI_MAX_CANARIES 256
#define DI_MAX_DEPTH 48
#define DI_MAX_DIR_ENTRIES 100000
#define DI_EXT_SLOTS 64
#define DI_UID_SLOTS 16
#define DI_MAX_LISTENERS 64
#define DI_OUT_CAP (12u << 20)
#define DI_STATE_CAP (4u << 20)

/* ---------------------------------------------------------------------------
 * Policy (served by the hub at /api/v1/data/policy; line format, see
 * hub/pkg/server/data_inventory.go)
 * ------------------------------------------------------------------------- */

typedef struct {
    int version;
    bool enabled;
    int nroots, nexcludes, ncanaries;
    char roots[DI_MAX_ROOTS][DI_PATH_CAP];
    char excludes[DI_MAX_EXCLUDES][256];
    char canaries[DI_MAX_CANARIES][DI_PATH_CAP];
    int store_depth;
    long max_files;
    int max_seconds;
    long content_max_bytes;
    long long content_budget_bytes;
    int interval_hours;
    int resume_minutes;
    int full_every_days;
    bool one_filesystem;
    int max_stores;
    int max_items;
} DataInvPolicy;

static inline void DataInv_PolicyDefaults(DataInvPolicy* p) {
    memset(p, 0, sizeof(*p));
    p->store_depth = 2;
    p->max_files = 300000;
    p->max_seconds = 900;
    p->content_max_bytes = 256 * 1024;
    p->content_budget_bytes = 256LL << 20;
    p->interval_hours = 24;
    p->resume_minutes = 60;
    p->full_every_days = 7;
    p->one_filesystem = true;
    p->max_stores = 3000;
    p->max_items = 1000;
}

/* An absolute, normalised path: no "." or ".." components, no "//", no
 * control bytes, shorter than DI_PATH_CAP. */
static inline bool DataInv_AbsPathOK(const char* s) {
    size_t n = strlen(s);
    if (n == 0 || n >= DI_PATH_CAP || s[0] != '/') return false;
    if (n > 1 && s[n - 1] == '/') return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if (*p < 0x20 || *p == 0x7f) return false;
        if (*p == '/' && (p[1] == '/' || (p[1] == '.' && (p[2] == '/' || p[2] == '\0')) ||
                          (p[1] == '.' && p[2] == '.' && (p[3] == '/' || p[3] == '\0'))))
            return false;
    }
    return true;
}

static inline bool DataInv_ParseLong(const char* s, long long lo, long long hi, long long* out) {
    if (!*s) return false;
    char* end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno || *end || v < lo || v > hi) return false;
    *out = v;
    return true;
}

/* Parses the whole policy or nothing: an unknown key is ignored (a newer hub),
 * a known key out of range, a missing header or a missing "end" line rejects
 * it, and a rejected policy means no scan. */
static inline bool DataInv_ParsePolicy(const char* text, DataInvPolicy* p, char* why, size_t whycap) {
    DataInv_PolicyDefaults(p);
    const char* line = text;
    bool header = false, ended = false;
    char buf[DI_PATH_CAP + 64];
    while (*line) {
        const char* nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        if (len >= sizeof(buf)) { snprintf(why, whycap, "policy line too long"); return false; }
        memcpy(buf, line, len);
        buf[len] = '\0';
        if (len && buf[len - 1] == '\r') buf[--len] = '\0';
        line = nl ? nl + 1 : line + len;
        if (!header) {
            if (strcmp(buf, DI_POLICY_HEADER) != 0) { snprintf(why, whycap, "not an %s document", DI_POLICY_HEADER); return false; }
            header = true;
            continue;
        }
        if (ended) { snprintf(why, whycap, "data after end"); return false; }
        if (!strcmp(buf, "end")) { ended = true; continue; }
        if (!buf[0]) continue;
        char* val = strchr(buf, ' ');
        if (!val) { snprintf(why, whycap, "policy line without a value"); return false; }
        *val++ = '\0';
        long long v = 0;
#define DI_NUM(key, lo, hi, field)                                                       \
        if (!strcmp(buf, key)) {                                                         \
            if (!DataInv_ParseLong(val, lo, hi, &v)) {                                   \
                snprintf(why, whycap, "policy %s out of range", key);                    \
                return false;                                                            \
            }                                                                            \
            p->field = v;                                                                \
            continue;                                                                    \
        }
        DI_NUM("version", 0, 2000000000LL, version)
        DI_NUM("store_depth", 1, 6, store_depth)
        DI_NUM("max_files", 1000, 5000000, max_files)
        DI_NUM("max_seconds", 30, 14400, max_seconds)
        DI_NUM("content_max_bytes", 0, 4 << 20, content_max_bytes)
        DI_NUM("content_budget_bytes", 0, 8LL << 30, content_budget_bytes)
        DI_NUM("interval_hours", 1, 720, interval_hours)
        DI_NUM("resume_minutes", 5, 1440, resume_minutes)
        DI_NUM("full_every_days", 1, 90, full_every_days)
        DI_NUM("max_stores", 10, 20000, max_stores)
        DI_NUM("max_items", 10, 5000, max_items)
#undef DI_NUM
        if (!strcmp(buf, "enabled") || !strcmp(buf, "one_filesystem")) {
            if (strcmp(val, "0") && strcmp(val, "1")) { snprintf(why, whycap, "policy %.20s must be 0 or 1", buf); return false; }
            if (buf[0] == 'e') p->enabled = val[0] == '1';
            else p->one_filesystem = val[0] == '1';
            continue;
        }
        if (!strcmp(buf, "root") || !strcmp(buf, "canary")) {
            if (!DataInv_AbsPathOK(val)) { snprintf(why, whycap, "policy %.20s is not an absolute normalised path", buf); return false; }
            if (buf[0] == 'r') {
                if (p->nroots >= DI_MAX_ROOTS) { snprintf(why, whycap, "too many roots"); return false; }
                snprintf(p->roots[p->nroots++], DI_PATH_CAP, "%s", val);
            } else {
                if (p->ncanaries >= DI_MAX_CANARIES) { snprintf(why, whycap, "too many canaries"); return false; }
                snprintf(p->canaries[p->ncanaries++], DI_PATH_CAP, "%s", val);
            }
            continue;
        }
        if (!strcmp(buf, "exclude")) {
            if (p->nexcludes >= DI_MAX_EXCLUDES || strlen(val) >= 256 || val[0] == '\0') {
                snprintf(why, whycap, "bad or too many excludes");
                return false;
            }
            snprintf(p->excludes[p->nexcludes++], 256, "%s", val);
            continue;
        }
        /* unknown key: a newer hub; ignored */
    }
    if (!header || !ended) { snprintf(why, whycap, "policy incomplete (no end line)"); return false; }
    if (p->enabled && p->nroots == 0) { snprintf(why, whycap, "policy enabled without roots"); return false; }
    return true;
}

/* ---------------------------------------------------------------------------
 * State (the agent's own file; written by the parent only)
 * ------------------------------------------------------------------------- */

typedef struct {
    long long ms;
    char cycle[33];
    char* path;
} DataInvMark;

typedef struct {
    unsigned long long dev, ino;
    long long size, mtime_ns;
    uint64_t rules;
    char cycle[33];
    char* store;
    char* path;
} DataInvVerdict;

typedef struct {
    bool has_cycle;
    char cycle_id[33];
    long long cycle_started;
    bool cycle_full, cycle_done;
    int cycle_policy, cycle_rules;
    bool has_cursor;
    char cursor[DI_PATH_CAP];
    long long last_run, last_done, last_full;
    DataInvMark* marks;
    size_t nmarks, capmarks;
    DataInvVerdict* verdicts;
    size_t nverdicts, capverdicts;
} DataInvState;

static inline void DataInv_StateFree(DataInvState* s) {
    for (size_t i = 0; i < s->nmarks; i++) free(s->marks[i].path);
    for (size_t i = 0; i < s->nverdicts; i++) {
        free(s->verdicts[i].store);
        free(s->verdicts[i].path);
    }
    free(s->marks);
    free(s->verdicts);
    memset(s, 0, sizeof(*s));
}

static inline bool DataInv_CycleIdOK(const char* s) {
    size_t n = strlen(s);
    if (n < 8 || n > 32) return false;
    for (size_t i = 0; i < n; i++) {
        if (DataInv_Hex(s[i]) < 0 || (s[i] >= 'A' && s[i] <= 'F')) return false;
    }
    return true;
}

static int DataInv_MarkCmp(const void* a, const void* b) {
    return DataInv_PathCmp(((const DataInvMark*)a)->path, ((const DataInvMark*)b)->path);
}
static int DataInv_VerdictCmp(const void* a, const void* b) {
    return DataInv_PathCmp(((const DataInvVerdict*)a)->path, ((const DataInvVerdict*)b)->path);
}

/* Parses a state document. Any malformed line rejects the whole file: the
 * scan then starts a fresh full cycle, which only costs I/O. */
static inline bool DataInv_ParseState(const char* text, DataInvState* s) {
    memset(s, 0, sizeof(*s));
    if (strncmp(text, DI_STATE_HEADER "\n", strlen(DI_STATE_HEADER) + 1) != 0) return false;
    const char* line = text + strlen(DI_STATE_HEADER) + 1;
    bool ended = false;
    char* buf = (char*)malloc(DI_PATH_CAP * 4);
    if (!buf) return false;
    while (*line && !ended) {
        const char* nl = strchr(line, '\n');
        if (!nl) goto bad;
        size_t len = (size_t)(nl - line);
        if (len >= DI_PATH_CAP * 4) goto bad;
        memcpy(buf, line, len);
        buf[len] = '\0';
        line = nl + 1;
        if (!strcmp(buf, "end")) { ended = true; break; }
        char* f[10] = {0};
        int nf = 0;
        for (char* tok = strtok(buf, " "); tok && nf < 10; tok = strtok(NULL, " ")) f[nf++] = tok;
        if (nf == 0) goto bad;
        long long a = 0, b = 0, c = 0, d = 0;
        if (!strcmp(f[0], "cycle") && nf == 7) {
            if (!DataInv_CycleIdOK(f[1]) || !DataInv_ParseLong(f[2], 0, 1LL << 50, &a) || !DataInv_ParseLong(f[3], 0, 1, &b) ||
                !DataInv_ParseLong(f[4], 0, 1, &c) || !DataInv_ParseLong(f[5], 0, 2000000000LL, &d))
                goto bad;
            long long r = 0;
            if (!DataInv_ParseLong(f[6], 0, 1000000, &r)) goto bad;
            s->has_cycle = true;
            snprintf(s->cycle_id, sizeof(s->cycle_id), "%s", f[1]);
            s->cycle_started = a;
            s->cycle_full = b == 1;
            s->cycle_done = c == 1;
            s->cycle_policy = (int)d;
            s->cycle_rules = (int)r;
        } else if (!strcmp(f[0], "cursor") && nf == 2) {
            if (!DataInv_DecodeStatePath(f[1]) || !DataInv_AbsPathOK(f[1])) goto bad;
            snprintf(s->cursor, sizeof(s->cursor), "%s", f[1]);
            s->has_cursor = true;
        } else if ((!strcmp(f[0], "last_run") || !strcmp(f[0], "last_done") || !strcmp(f[0], "last_full")) && nf == 2) {
            if (!DataInv_ParseLong(f[1], 0, 1LL << 50, &a)) goto bad;
            if (f[0][5] == 'r') s->last_run = a;
            else if (f[0][5] == 'd') s->last_done = a;
            else s->last_full = a;
        } else if (!strcmp(f[0], "wm") && nf == 4) {
            if (!DataInv_ParseLong(f[1], 0, 1LL << 50, &a) || !DataInv_CycleIdOK(f[2]) || !DataInv_DecodeStatePath(f[3]) ||
                !DataInv_AbsPathOK(f[3]))
                goto bad;
            if (s->nmarks == s->capmarks) {
                size_t nc = s->capmarks ? s->capmarks * 2 : 64;
                DataInvMark* m = (DataInvMark*)realloc(s->marks, nc * sizeof(*m));
                if (!m) goto bad;
                s->marks = m;
                s->capmarks = nc;
            }
            DataInvMark* m = &s->marks[s->nmarks];
            m->ms = a;
            snprintf(m->cycle, sizeof(m->cycle), "%s", f[2]);
            m->path = strdup(f[3]);
            if (!m->path) goto bad;
            s->nmarks++;
        } else if (!strcmp(f[0], "v") && nf == 9) {
            unsigned long long dev = 0, ino = 0;
            char* e1 = NULL;
            char* e2 = NULL;
            char* e3 = NULL;
            errno = 0;
            dev = strtoull(f[1], &e1, 10);
            ino = strtoull(f[2], &e2, 10);
            uint64_t rules = strtoull(f[5], &e3, 16);
            if (errno || *e1 || *e2 || *e3 || !DataInv_ParseLong(f[3], 0, 1LL << 50, &a) ||
                !DataInv_ParseLong(f[4], -(1LL << 62), 1LL << 62, &b) || !DataInv_CycleIdOK(f[6]) ||
                !DataInv_DecodeStatePath(f[7]) || !DataInv_AbsPathOK(f[7]) || !DataInv_DecodeStatePath(f[8]) ||
                !DataInv_AbsPathOK(f[8]))
                goto bad;
            if (s->nverdicts == s->capverdicts) {
                size_t nc = s->capverdicts ? s->capverdicts * 2 : 64;
                DataInvVerdict* v = (DataInvVerdict*)realloc(s->verdicts, nc * sizeof(*v));
                if (!v) goto bad;
                s->verdicts = v;
                s->capverdicts = nc;
            }
            DataInvVerdict* v = &s->verdicts[s->nverdicts];
            v->dev = dev;
            v->ino = ino;
            v->size = a;
            v->mtime_ns = b;
            v->rules = rules;
            snprintf(v->cycle, sizeof(v->cycle), "%s", f[6]);
            v->store = strdup(f[7]);
            v->path = strdup(f[8]);
            if (!v->store || !v->path) { free(v->store); free(v->path); goto bad; }
            s->nverdicts++;
        } else {
            goto bad;
        }
    }
    if (!ended || *line) goto bad;
    free(buf);
    if (s->nmarks > 1) qsort(s->marks, s->nmarks, sizeof(*s->marks), DataInv_MarkCmp);
    if (s->nverdicts > 1) qsort(s->verdicts, s->nverdicts, sizeof(*s->verdicts), DataInv_VerdictCmp);
    return true;
bad:
    free(buf);
    DataInv_StateFree(s);
    return false;
}

static inline const DataInvMark* DataInv_FindMark(const DataInvState* s, const char* path) {
    size_t lo = 0, hi = s->nmarks;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = DataInv_PathCmp(s->marks[mid].path, path);
        if (c == 0) return &s->marks[mid];
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

static inline const DataInvVerdict* DataInv_FindVerdict(const DataInvState* s, const char* path) {
    size_t lo = 0, hi = s->nverdicts;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = DataInv_PathCmp(s->verdicts[mid].path, path);
        if (c == 0) return &s->verdicts[mid];
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

/* Reads a small file of the agent's own (state) into a malloc'd string. */
static inline char* DataInv_ReadSmallFile(const char* path, size_t cap) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (size_t)st.st_size >= cap) { close(fd); return NULL; }
    char* buf = (char*)malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    buf[got] = '\0';
    return buf;
}

/* ---------------------------------------------------------------------------
 * Schedule
 * ------------------------------------------------------------------------- */

/* A cycle left open (budget hit) resumes after resume_minutes; a finished
 * cycle is followed by the next after interval_hours. */
static inline bool DataInv_Due(const DataInvPolicy* p, const DataInvState* s, long long now_ms) {
    if (!p->enabled || p->nroots == 0) return false;
    if (!s->has_cycle) return true;
    if (s->cycle_policy != p->version || s->cycle_rules != DI_RULES_VERSION) return true;
    if (!s->cycle_done) return now_ms - s->last_run >= (long long)p->resume_minutes * 60000;
    return now_ms - s->last_done >= (long long)p->interval_hours * 3600000;
}

/* ---------------------------------------------------------------------------
 * Sandbox (child only)
 * ------------------------------------------------------------------------- */

#if defined(__x86_64__)
#define DI_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define DI_AUDIT_ARCH AUDIT_ARCH_AARCH64
#endif

#define DI_IOPRIO_WHO_PROCESS 1
#define DI_IOPRIO_CLASS_IDLE 3
#define DI_IOPRIO_CLASS_SHIFT 13
#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif
/* The kernel's O_TMPFILE bit alone: glibc's __O_TMPFILE also carries
 * O_DIRECTORY, which the walk needs. */
#define DI_O_TMPFILE_BIT 020000000

#define DI_ARG_LO(n) (offsetof(struct seccomp_data, args) + (n) * sizeof(uint64_t))

/* Lowest priority and resource caps. Returns false only when a limit that
 * the read-only guarantee depends on could not be set. */
static inline bool DataInv_LowerPriority(const DataInvPolicy* p) {
    (void)setpriority(PRIO_PROCESS, 0, 19);
    struct sched_param sp = {0};
    (void)sched_setscheduler(0, SCHED_IDLE, &sp);
    (void)syscall(SYS_ioprio_set, DI_IOPRIO_WHO_PROCESS, 0, DI_IOPRIO_CLASS_IDLE << DI_IOPRIO_CLASS_SHIFT);
    struct rlimit zero = {0, 0};
    if (setrlimit(RLIMIT_FSIZE, &zero) != 0 || setrlimit(RLIMIT_CORE, &zero) != 0) return false;
    struct rlimit cpu = {(rlim_t)p->max_seconds + 60, (rlim_t)p->max_seconds + 60};
    (void)setrlimit(RLIMIT_CPU, &cpu);
    struct rlimit as = {(rlim_t)2 << 30, (rlim_t)2 << 30};
    (void)setrlimit(RLIMIT_AS, &as);
    struct rlimit nofile = {256, 256};
    (void)setrlimit(RLIMIT_NOFILE, &nofile);
    return true;
}

/* Keeps at most CAP_DAC_READ_SEARCH and CAP_FOWNER (only those the process
 * already has: an unprivileged test run keeps none), empties the bounding and
 * ambient sets where the process may, and sets no_new_privs. */
static inline bool DataInv_DropCapabilities(void) {
    struct __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct cur[2];
    memset(cur, 0, sizeof(cur));
    if (syscall(SYS_capget, &hdr, cur) != 0) return false;
    bool setpcap = (cur[0].effective & (1u << CAP_SETPCAP)) != 0;
    for (int cap = 0; cap < 64; cap++) {
        if (cap == CAP_DAC_READ_SEARCH || cap == CAP_FOWNER) continue;
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && errno != EINVAL && (setpcap || errno != EPERM)) return false;
    }
    (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof(data));
    uint32_t keep = ((1u << CAP_DAC_READ_SEARCH) | (1u << CAP_FOWNER)) & cur[0].permitted;
    data[0].effective = keep;
    data[0].permitted = keep;
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall(SYS_capset, &hdr, data) != 0) return false;
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
}

static inline bool DataInv_InstallSeccomp(int outfd) {
#ifndef DI_AUDIT_ARCH
    (void)outfd;
    return false; /* unknown architecture: no scan */
#else
    const uint32_t forbidden_open = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND | DI_O_TMPFILE_BIT;
#define DI_ALLOW(nr) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, DI_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1), /* x32 ABI */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
        /* write: the result pipe only */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, DI_ARG_LO(0)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)outfd, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* openat: read-only, never following a symlink */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, DI_ARG_LO(2)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, forbidden_open, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, O_NOFOLLOW, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* mmap / mprotect: never executable */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, DI_ARG_LO(2)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, DI_ARG_LO(2)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        DI_ALLOW(__NR_read),
        DI_ALLOW(__NR_pread64),
        DI_ALLOW(__NR_close),
        DI_ALLOW(__NR_fstat),
        DI_ALLOW(__NR_newfstatat),
#ifdef __NR_statx
        DI_ALLOW(__NR_statx),
#endif
        DI_ALLOW(__NR_lseek),
        DI_ALLOW(__NR_getdents64),
        DI_ALLOW(__NR_fstatfs),
        DI_ALLOW(__NR_brk),
        DI_ALLOW(__NR_munmap),
        DI_ALLOW(__NR_mremap),
        DI_ALLOW(__NR_madvise),
        DI_ALLOW(__NR_clock_gettime),
        DI_ALLOW(__NR_gettimeofday),
        DI_ALLOW(__NR_getrandom),
        DI_ALLOW(__NR_sysinfo),
        DI_ALLOW(__NR_futex),
        DI_ALLOW(__NR_rt_sigprocmask),
        DI_ALLOW(__NR_rt_sigreturn),
        DI_ALLOW(__NR_getpid),
        DI_ALLOW(__NR_gettid),
        DI_ALLOW(__NR_exit),
        DI_ALLOW(__NR_exit_group),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
#undef DI_ALLOW
    struct sock_fprog prog = {(unsigned short)(sizeof(filter) / sizeof(filter[0])), filter};
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == 0 ||
           prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0;
#endif
}

/* ---------------------------------------------------------------------------
 * Walker (child only)
 * ------------------------------------------------------------------------- */

typedef struct {
    char ext[16];
    long long n, bytes;
} DataInvExt;

typedef struct {
    char path[DI_PATH_CAP];
    const char* root;
    bool shallow, partial, content_partial, truncated;
    long long files, dirs, bytes, newest_ms, oldest_ms;
    long long world_readable, group_readable, world_writable, setid, symlinks, special;
    long long skipped_regenerable, skipped_excluded, skipped_mounts, errors;
    unsigned uid[DI_UID_SLOTS];
    long long uid_n[DI_UID_SLOTS];
    int nuid;
    bool uid_overflow;
    DataInvExt ext[DI_EXT_SLOTS];
    int next;
    long long ext_other_n, ext_other_bytes;
    uint32_t hints;
    long long items;
} DataInvStore;

enum {
    DI_H_GIT = 0, DI_H_PYTHON, DI_H_NODE, DI_H_VENV, DI_H_RUST, DI_H_GO, DI_H_DOCKER, DI_H_RESTIC, DI_H_SYNCTHING,
    DI_H_OBSIDIAN, DI_H_MAILDIR, DI_H_SQLITE, DI_H_HOME, DI_H_COUNT
};
static const char* const DI_HINT_NAMES[DI_H_COUNT] = {"git", "python", "node", "venv", "rust", "go", "docker",
                                                      "restic_repo", "syncthing", "obsidian", "maildir", "sqlite", "home"};

typedef struct {
    const DataInvPolicy* pol;
    const DataInvState* old;
    bool full;
    char cycle_id[33];
    long long start_ms, deadline_ms;
    char cursor[DI_PATH_CAP];
    bool has_cursor;
    char last_store[DI_PATH_CAP];
    bool any_store;
    /* run totals */
    long long files, dirs, bytes, content_files, content_bytes, skipped_canary, skipped_regenerable, skipped_excluded,
        skipped_mounts, skipped_depth, errors, stores, items, items_dropped, stores_dropped;
    const char* stop; /* NULL, "files", "time", "stores" */
    bool content_exhausted;
    DataInvBuf* stores_buf;
    DataInvBuf* items_buf;
    DataInvBuf* state_buf; /* wm and v lines of this run */
    char** visited;        /* stores reported this run, in walk (PathCmp) order */
    size_t nvisited, capvisited;
    char path[DI_PATH_CAP * 2];
    dev_t root_dev;
    long root_ftype;
    char root_src[256]; /* mount source of the root's filesystem (btrfs one-filesystem check) */
    char* mountinfo;    /* read once, lazily */
} DataInvWalk;

static inline long long DataInv_NowMs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static inline long long DataInv_MonoMs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static inline bool DataInv_IsCanary(const DataInvPolicy* p, const char* path) {
    for (int i = 0; i < p->ncanaries; i++) {
        if (DataInv_Under(path, p->canaries[i])) return true;
    }
    return false;
}

/* Policy exclusions (fnmatch over the full path; '*' also matches '/'). */
static inline bool DataInv_Excluded(const DataInvPolicy* p, const char* path) {
    for (int i = 0; i < p->nexcludes; i++) {
        if (fnmatch(p->excludes[i], path, 0) == 0) return true;
    }
    return false;
}

/* Directories that are caches or regenerable by name. */
static inline bool DataInv_RegenerableDir(const char* name, const char* parent) {
    static const char* const names[] = {
        ".cache", "node_modules", "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
        ".gradle", ".npm", ".pnpm-store", ".yarn", ".rustup", ".terraform", ".next", ".nuxt", ".parcel-cache",
        ".turbo", ".angular", "bower_components", ".vscode-server", ".cursor-server", ".windsurf-server",
        ".snapshots", "lost+found", ".Trash", ".ccache", ".sccache", ".nv", ".thumbnails", NULL,
    };
    for (size_t i = 0; names[i]; i++) {
        if (!strcmp(name, names[i])) return true;
    }
    if (!strncmp(name, ".Trash-", 7)) return true;
    if (!strcmp(parent, ".cargo") && (!strcmp(name, "registry") || !strcmp(name, "git"))) return true;
    if (!strcmp(parent, "share") && !strcmp(name, "Trash")) return true;
    if (!strcmp(parent, "share") && !strcmp(name, "containers")) return true;
    if (!strcmp(parent, ".m2") && !strcmp(name, "repository")) return true;
    if (!strcmp(parent, "pkg") && !strcmp(name, "mod")) return true;
    if (!strcmp(parent, ".ollama") && !strcmp(name, "models")) return true;
    if (!strcmp(parent, ".local") && !strcmp(name, "lib")) return true;
    return false;
}

/* Filesystem types the walk may enter: local disk filesystems only. */
static inline bool DataInv_LocalFsType(long t) {
    switch ((unsigned long)t) {
    case 0xEF53UL:     /* ext2/3/4 */
    case 0x9123683EUL: /* btrfs */
    case 0x58465342UL: /* xfs */
    case 0x2FC12FC1UL: /* zfs */
    case 0xF2F52010UL: /* f2fs */
    case 0x4D44UL:     /* vfat */
    case 0x2011BAB0UL: /* exfat */
    case 0x5346544EUL: /* ntfs */
    case 0x7366746EUL: /* ntfs3 */
    case 0x3153464AUL: /* jfs */
    case 0x52654973UL: /* reiserfs */
        return true;
    default:
        return false;
    }
}

static inline void DataInv_StoreInit(DataInvStore* s, const char* path, const char* root, bool shallow) {
    memset(s, 0, sizeof(*s));
    snprintf(s->path, sizeof(s->path), "%.1023s", path);
    s->root = root;
    s->shallow = shallow;
}

static inline void DataInv_StoreUid(DataInvStore* s, unsigned uid) {
    for (int i = 0; i < s->nuid; i++) {
        if (s->uid[i] == uid) { s->uid_n[i]++; return; }
    }
    if (s->nuid < DI_UID_SLOTS) {
        s->uid[s->nuid] = uid;
        s->uid_n[s->nuid++] = 1;
    } else {
        s->uid_overflow = true;
    }
}

static inline void DataInv_StoreExt(DataInvStore* s, const char* name, long long size) {
    char ext[16];
    DataInv_Extension(name, ext, sizeof(ext));
    for (int i = 0; i < s->next; i++) {
        if (!strcmp(s->ext[i].ext, ext)) { s->ext[i].n++; s->ext[i].bytes += size; return; }
    }
    if (s->next < DI_EXT_SLOTS) {
        snprintf(s->ext[s->next].ext, sizeof(s->ext[s->next].ext), "%s", ext);
        s->ext[s->next].n = 1;
        s->ext[s->next].bytes = size;
        s->next++;
    } else {
        s->ext_other_n++;
        s->ext_other_bytes += size;
    }
    if (!strcmp(ext, "sqlite") || !strcmp(ext, "sqlite3") || !strcmp(ext, "db")) s->hints |= 1u << DI_H_SQLITE;
}

static inline void DataInv_StoreHintName(DataInvStore* s, const char* name, bool is_dir) {
    static const struct { const char* name; int dir; int hint; } marks[] = {
        {".git", 1, DI_H_GIT}, {"pyproject.toml", 0, DI_H_PYTHON}, {"setup.py", 0, DI_H_PYTHON},
        {"requirements.txt", 0, DI_H_PYTHON}, {"package.json", 0, DI_H_NODE}, {"pyvenv.cfg", 0, DI_H_VENV},
        {"Cargo.toml", 0, DI_H_RUST}, {"go.mod", 0, DI_H_GO}, {"docker-compose.yml", 0, DI_H_DOCKER},
        {"docker-compose.yaml", 0, DI_H_DOCKER}, {"compose.yaml", 0, DI_H_DOCKER}, {"compose.yml", 0, DI_H_DOCKER},
        {"Dockerfile", 0, DI_H_DOCKER}, {".stfolder", 1, DI_H_SYNCTHING}, {".obsidian", 1, DI_H_OBSIDIAN},
        {"cur", 1, DI_H_MAILDIR}, {".bashrc", 0, DI_H_HOME}, {".profile", 0, DI_H_HOME},
    };
    for (size_t i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
        if ((int)is_dir == marks[i].dir && !strcmp(name, marks[i].name)) s->hints |= 1u << marks[i].hint;
    }
}

static inline int DataInv_ExtCmp(const void* a, const void* b) {
    const DataInvExt* x = (const DataInvExt*)a;
    const DataInvExt* y = (const DataInvExt*)b;
    if (x->n != y->n) return x->n > y->n ? -1 : 1;
    return strcmp(x->ext, y->ext);
}

static inline void DataInv_EmitStore(DataInvWalk* w, DataInvStore* s) {
    DataInvBuf* b = w->stores_buf;
    if (w->stores > 0) DataInv_PutS(b, ",");
    DataInv_PutS(b, "{\"path\":");
    DataInv_PutJSONPath(b, s->path);
    DataInv_PutS(b, ",\"root\":");
    DataInv_PutJSONPath(b, s->root);
    DataInv_PutS(b, s->shallow ? ",\"shallow\":true" : ",\"shallow\":false");
    DataInv_PutS(b, s->partial ? ",\"partial\":true" : ",\"partial\":false");
    DataInv_PutS(b, s->content_partial ? ",\"content_partial\":true" : ",\"content_partial\":false");
    DataInv_PutS(b, s->truncated ? ",\"truncated\":true" : ",\"truncated\":false");
    DataInv_PutF(b, ",\"files\":%lld", s->files);
    DataInv_PutF(b, ",\"dirs\":%lld", s->dirs);
    DataInv_PutF(b, ",\"bytes\":%lld", s->bytes);
    DataInv_PutF(b, ",\"newest_mtime\":%lld", s->newest_ms);
    DataInv_PutF(b, ",\"oldest_mtime\":%lld", s->oldest_ms);
    DataInv_PutF(b, ",\"world_readable\":%lld", s->world_readable);
    DataInv_PutF(b, ",\"group_readable\":%lld", s->group_readable);
    DataInv_PutF(b, ",\"world_writable\":%lld", s->world_writable);
    DataInv_PutF(b, ",\"setid\":%lld", s->setid);
    DataInv_PutF(b, ",\"symlinks\":%lld", s->symlinks);
    DataInv_PutF(b, ",\"special\":%lld", s->special);
    DataInv_PutF(b, ",\"skipped_regenerable\":%lld", s->skipped_regenerable);
    DataInv_PutF(b, ",\"skipped_excluded\":%lld", s->skipped_excluded);
    DataInv_PutF(b, ",\"skipped_mounts\":%lld", s->skipped_mounts);
    DataInv_PutF(b, ",\"errors\":%lld", s->errors);
    DataInv_PutF(b, ",\"items\":%lld", s->items);
    int dom = -1;
    for (int i = 0; i < s->nuid; i++) {
        if (dom < 0 || s->uid_n[i] > s->uid_n[dom]) dom = i;
    }
    DataInv_PutF(b, ",\"owner_uid\":%lld", dom < 0 ? -1LL : (long long)s->uid[dom]);
    DataInv_PutF(b, ",\"owners\":%lld", s->uid_overflow ? (long long)DI_UID_SLOTS + 1 : (long long)s->nuid);
    qsort(s->ext, (size_t)s->next, sizeof(s->ext[0]), DataInv_ExtCmp);
    DataInv_PutS(b, ",\"ext\":[");
    int shown = s->next < 8 ? s->next : 8;
    for (int i = 0; i < shown; i++) {
        DataInv_PutS(b, i ? ",[" : "[");
        DataInv_PutJSONString(b, s->ext[i].ext);
        DataInv_PutF(b, ",%lld", s->ext[i].n);
        DataInv_PutF(b, ",%lld]", s->ext[i].bytes);
    }
    DataInv_PutS(b, "],\"hints\":[");
    bool first = true;
    for (int h = 0; h < DI_H_COUNT; h++) {
        if (s->hints & (1u << h)) {
            if (!first) DataInv_PutS(b, ",");
            DataInv_PutJSONString(b, DI_HINT_NAMES[h]);
            first = false;
        }
    }
    DataInv_PutS(b, "]}");
    w->stores++;
}

static inline void DataInv_EmitItem(DataInvWalk* w, DataInvStore* s, const char* path, const struct stat* st, uint64_t rules) {
    s->items++;
    if (w->items >= w->pol->max_items) { w->items_dropped++; return; }
    DataInvBuf* b = w->items_buf;
    if (w->items > 0) DataInv_PutS(b, ",");
    DataInv_PutS(b, "{\"path\":");
    DataInv_PutJSONPath(b, path);
    DataInv_PutS(b, ",\"store\":");
    DataInv_PutJSONPath(b, s->path);
    DataInv_PutS(b, ",\"kind\":");
    DataInv_PutJSONString(b, DataInv_ItemKind(rules));
    DataInv_PutS(b, ",\"rules\":[");
    bool first = true;
    for (int r = 0; r < DI_RULE_COUNT; r++) {
        if (rules & DI_BIT(r)) {
            if (!first) DataInv_PutS(b, ",");
            DataInv_PutJSONString(b, DI_RULE_NAMES[r]);
            first = false;
        }
    }
    DataInv_PutF(b, "],\"mode\":%lld", (long long)(st->st_mode & 07777));
    DataInv_PutF(b, ",\"uid\":%lld", (long long)st->st_uid);
    DataInv_PutF(b, ",\"size\":%lld", (long long)st->st_size);
    long long mt = (long long)st->st_mtim.tv_sec * 1000 + st->st_mtim.tv_nsec / 1000000;
    DataInv_PutF(b, ",\"mtime\":%lld}", mt < 0 ? 0 : mt);
    w->items++;
}

/* One state line per cached verdict (content rules only, so a name-only key
 * file is not cached: its rules are recomputed from the name each run). */
static inline void DataInv_StateVerdict(DataInvWalk* w, const char* store, const char* path, const struct stat* st,
                                        uint64_t content_rules) {
    if (!content_rules) return;
    DataInvBuf* b = w->state_buf;
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "v %llu %llu %lld %lld %llx ", (unsigned long long)st->st_dev, (unsigned long long)st->st_ino,
             (long long)st->st_size, (long long)st->st_mtim.tv_sec * 1000000000LL + st->st_mtim.tv_nsec,
             (unsigned long long)content_rules);
    DataInv_PutS(b, tmp);
    DataInv_PutS(b, w->cycle_id);
    DataInv_PutS(b, " ");
    DataInv_PutStatePath(b, store);
    DataInv_PutS(b, " ");
    DataInv_PutStatePath(b, path);
    DataInv_PutS(b, "\n");
}

/* Opens name below dirfd read-only, never following a symlink, and checks the
 * descriptor is the same regular file or directory fstatat saw. */
static inline int DataInv_OpenChecked(int dirfd, const char* name, const struct stat* seen, bool dir) {
    int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOCTTY | (dir ? O_DIRECTORY : 0);
    int fd = openat(dirfd, name, flags | O_NOATIME);
    if (fd < 0 && errno == EPERM) fd = openat(dirfd, name, flags);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_dev != seen->st_dev || st.st_ino != seen->st_ino ||
        (dir ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))) {
        close(fd);
        errno = ESTALE;
        return -1;
    }
    return fd;
}

/* Content rules of one regular file: from the verdict cache when the file is
 * unchanged since the store's last complete content scan, else read. Sets
 * *read_ok false when the content budget stopped the read. */
static inline uint64_t DataInv_FileContent(DataInvWalk* w, DataInvStore* s, int dirfd, const char* name, const char* path,
                                           const struct stat* st, uint64_t name_rules, long long mark_ms, bool* skipped) {
    *skipped = false;
    char ext[16];
    DataInv_Extension(name, ext, sizeof(ext));
    bool container_ext = !ext[0] || !strcmp(ext, "img") || !strcmp(ext, "bin") || !strcmp(ext, "dat") ||
                         !strcmp(ext, "luks") || !strcmp(ext, "enc") || !strcmp(ext, "vault") || (name_rules & DI_CONTAINER_MASK);
    /* Text candidates larger than content_max_bytes: the head of a config-like
     * file is read; bulk text (logs, dumps, data) that large is not. */
    bool bulk = !strcmp(ext, "log") || !strcmp(ext, "csv") || !strcmp(ext, "sql") || !strcmp(ext, "txt") ||
                !strcmp(ext, "md") || !strcmp(ext, "json") || !strcmp(ext, "xml");
    bool text = DataInv_ContentCandidate(name, name_rules) && (st->st_size <= w->pol->content_max_bytes || !bulk || name_rules);
    bool magic = container_ext && st->st_size >= 16;
    if (!text && !magic) return 0;
    if (w->pol->content_max_bytes == 0) return 0;
    long long ctime_ms = (long long)st->st_ctim.tv_sec * 1000 + st->st_ctim.tv_nsec / 1000000;
    long long mtime_ms = (long long)st->st_mtim.tv_sec * 1000 + st->st_mtim.tv_nsec / 1000000;
    if (!w->full && mark_ms > 0 && mtime_ms < mark_ms && ctime_ms < mark_ms) {
        const DataInvVerdict* v = DataInv_FindVerdict(w->old, path);
        if (v && v->dev == (unsigned long long)st->st_dev && v->ino == (unsigned long long)st->st_ino && v->size == st->st_size &&
            v->mtime_ns == (long long)st->st_mtim.tv_sec * 1000000000LL + st->st_mtim.tv_nsec)
            return v->rules;
        if (!v) return 0; /* unchanged and had no verdict */
    }
    size_t want = text ? (size_t)(st->st_size < w->pol->content_max_bytes ? st->st_size : w->pol->content_max_bytes) : 64;
    if (want == 0) return 0;
    /* Not read this time (budget, open or memory): the last verdict stands, so
     * a known secret is never dropped because a run ran out of budget. */
    const DataInvVerdict* last = DataInv_FindVerdict(w->old, path);
    uint64_t kept = last ? last->rules : 0;
    if (w->content_bytes + (long long)want > w->pol->content_budget_bytes) {
        w->content_exhausted = true;
        *skipped = true;
        return kept;
    }
    int fd = DataInv_OpenChecked(dirfd, name, st, false);
    if (fd < 0) { s->errors++; w->errors++; *skipped = true; return kept; }
    unsigned char* buf = (unsigned char*)malloc(want + 1);
    if (!buf) { close(fd); *skipped = true; return kept; }
    size_t got = 0;
    while (got < want) {
        ssize_t n = read(fd, buf + got, want - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    w->content_files++;
    w->content_bytes += (long long)got;
    uint64_t r = text ? DataInv_ContentRules(buf, got) : DataInv_MagicRules(buf, got);
    free(buf);
    return r;
}

static inline bool DataInv_OverBudget(DataInvWalk* w) {
    if (w->stop) return true;
    if (w->files >= w->pol->max_files) w->stop = "files";
    else if (DataInv_MonoMs() >= w->deadline_ms) w->stop = "time";
    return w->stop != NULL;
}

/* Lists a directory's entry names, sorted by strcmp. Returns a malloc'd
 * array of pointers into one malloc'd arena (*arena); NULL on error. */
static inline char** DataInv_ListDir(int fd, size_t* count, char** arena, bool* truncated) {
    *count = 0;
    *arena = NULL;
    *truncated = false;
    size_t acap = 16384, alen = 0, ncap = 256;
    char* a = (char*)malloc(acap);
    size_t* offs = (size_t*)malloc(ncap * sizeof(size_t));
    if (!a || !offs) { free(a); free(offs); return NULL; }
    char dbuf[32768];
    for (;;) {
        long n = syscall(SYS_getdents64, fd, dbuf, sizeof(dbuf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { free(a); free(offs); return NULL; }
        if (n == 0) break;
        for (long off = 0; off < n;) {
            unsigned short reclen;
            memcpy(&reclen, dbuf + off + 16, sizeof(reclen));
            const char* name = dbuf + off + 19;
            off += reclen;
            if (reclen == 0) { free(a); free(offs); return NULL; }
            if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
            if (*count >= DI_MAX_DIR_ENTRIES) { *truncated = true; continue; }
            size_t len = strlen(name) + 1;
            if (alen + len > acap) {
                while (alen + len > acap) acap *= 2;
                char* na = (char*)realloc(a, acap);
                if (!na) { free(a); free(offs); return NULL; }
                a = na;
            }
            if (*count == ncap) {
                ncap *= 2;
                size_t* no = (size_t*)realloc(offs, ncap * sizeof(size_t));
                if (!no) { free(a); free(offs); return NULL; }
                offs = no;
            }
            memcpy(a + alen, name, len);
            offs[(*count)++] = alen;
            alen += len;
        }
    }
    char** names = (char**)malloc((*count ? *count : 1) * sizeof(char*));
    if (!names) { free(a); free(offs); return NULL; }
    for (size_t i = 0; i < *count; i++) names[i] = a + offs[i];
    free(offs);
    *arena = a;
    return names;
}

static int DataInv_NameCmp(const void* a, const void* b) { return strcmp(*(char* const*)a, *(char* const*)b); }

/* Appends "/name" to w->path; returns the old length or -1 when too long. */
static inline int DataInv_PushPath(DataInvWalk* w, const char* name) {
    size_t len = strlen(w->path);
    size_t base = (len == 1 && w->path[0] == '/') ? 0 : len;
    size_t n = strlen(name);
    if (base + 1 + n >= DI_PATH_CAP) return -1;
    w->path[base] = '/';
    memcpy(w->path + base + 1, name, n + 1);
    return (int)len;
}

static inline void DataInv_PopPath(DataInvWalk* w, int old_len) { w->path[old_len] = '\0'; }

/* Mount checks for a directory about to be entered. */
static inline ssize_t DataInv_ReadPath(const char* path, char* buf, size_t cap);

/* The mount source (the " - fstype source" field) of the mount whose
 * major:minor is dev; false when no mount has it. */
static inline bool DataInv_MountSourceOf(const char* mi, dev_t dev, char* out, size_t cap) {
    for (const char* line = mi; line && *line;) {
        const char* nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        char l[1024];
        if (len < sizeof(l)) {
            memcpy(l, line, len);
            l[len] = '\0';
            unsigned maj = 0, min = 0;
            char src[256];
            const char* sep = strstr(l, " - ");
            if (sep && sscanf(l, "%*u %*u %u:%u", &maj, &min) == 2 && sscanf(sep + 3, "%*s %255s", src) == 1 &&
                maj == major(dev) && min == minor(dev)) {
                snprintf(out, cap, "%s", src);
                return true;
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    return false;
}

/* The source of the mount a path lies under (longest mount point prefix). */
static inline void DataInv_RootMountSource(const char* mi, const char* root, char* out, size_t cap) {
    size_t best = 0;
    out[0] = '\0';
    for (const char* line = mi; line && *line;) {
        const char* nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        char l[1024];
        if (len < sizeof(l)) {
            memcpy(l, line, len);
            l[len] = '\0';
            char mp[512], src[256];
            const char* sep = strstr(l, " - ");
            if (sep && sscanf(l, "%*u %*u %*s %*s %511s", mp) == 1 && sscanf(sep + 3, "%*s %255s", src) == 1 &&
                DataInv_Under(root, mp) && strlen(mp) >= best) {
                best = strlen(mp);
                snprintf(out, cap, "%s", src);
            }
        }
        line = nl ? nl + 1 : NULL;
    }
}

static inline const char* DataInv_MountInfo(DataInvWalk* w) {
    if (!w->mountinfo) {
        w->mountinfo = (char*)malloc(1 << 20);
        if (w->mountinfo && DataInv_ReadPath("/proc/self/mountinfo", w->mountinfo, 1 << 20) <= 0) w->mountinfo[0] = '\0';
    }
    return w->mountinfo ? w->mountinfo : "";
}

static inline bool DataInv_MayEnter(DataInvWalk* w, int fd, const struct stat* st) {
    struct statfs sf;
    if (fstatfs(fd, &sf) != 0 || !DataInv_LocalFsType((long)sf.f_type)) return false;
    if (!w->pol->one_filesystem || st->st_dev == w->root_dev) return true;
    /* btrfs gives every subvolume its own st_dev. A subvolume of the root's
     * filesystem is either not a mount of its own or a mount of the same
     * source; a different btrfs filesystem mounted below is a mount of another
     * source, and is not entered. */
    if ((unsigned long)sf.f_type != 0x9123683EUL || (unsigned long)w->root_ftype != 0x9123683EUL) return false;
    char src[256];
    if (!DataInv_MountSourceOf(DataInv_MountInfo(w), st->st_dev, src, sizeof(src))) return true;
    return w->root_src[0] && !strcmp(src, w->root_src);
}

static void DataInv_WalkStoreDir(DataInvWalk* w, DataInvStore* s, int fd, int depth, bool store_top);

/* One regular file, a symlink or something else, inside a store. */
static inline void DataInv_Entry(DataInvWalk* w, DataInvStore* s, int dirfd, const char* name, const char* parent,
                                 const struct stat* st, long long mark_ms) {
    if (S_ISLNK(st->st_mode)) { s->symlinks++; return; }
    if (!S_ISREG(st->st_mode)) { s->special++; return; }
    s->files++;
    w->files++;
    s->bytes += st->st_size;
    w->bytes += st->st_size;
    long long m = (long long)st->st_mtim.tv_sec * 1000 + st->st_mtim.tv_nsec / 1000000;
    if (m < 0) m = 0; /* dated before 1970 (archives, touch -d): the contract's times are >= 0 */
    if (m > s->newest_ms) s->newest_ms = m;
    if (s->files == 1 || m < s->oldest_ms) s->oldest_ms = m;
    if (st->st_mode & S_IROTH) s->world_readable++;
    if (st->st_mode & S_IRGRP) s->group_readable++;
    if (st->st_mode & S_IWOTH) s->world_writable++;
    if (st->st_mode & (S_ISUID | S_ISGID)) s->setid++;
    DataInv_StoreUid(s, (unsigned)st->st_uid);
    DataInv_StoreExt(s, name, st->st_size);
    uint64_t name_rules = DataInv_NameRules(name, parent);
    bool skipped = false;
    uint64_t content = DataInv_FileContent(w, s, dirfd, name, w->path, st, name_rules, mark_ms, &skipped);
    if (skipped) s->content_partial = true;
    uint64_t rules = name_rules | content;
    /* A .pem that holds only certificates is not a key file. */
    char ext[16];
    DataInv_Extension(name, ext, sizeof(ext));
    if (!strcmp(ext, "pem") && !skipped && !(content & (DI_BIT(DI_R_PRIVATE_KEY) | DI_BIT(DI_R_PRIVATE_KEY_ENCRYPTED))))
        rules &= ~DI_BIT(DI_K_KEY_FILE);
    if (rules) DataInv_EmitItem(w, s, w->path, st, rules);
    DataInv_StateVerdict(w, s->path, w->path, st, content);
}

/* Checks a directory entry against canaries, exclusions and rules; returns
 * true when it should be visited and fills *st. */
static inline bool DataInv_Admit(DataInvWalk* w, DataInvStore* s, int dirfd, const char* name, const char* parent,
                                 struct stat* st, bool count_dirs) {
    if (DataInv_IsCanary(w->pol, w->path)) { /* before any stat or open */
        if (count_dirs) w->skipped_canary++;
        return false;
    }
    if (DataInv_Excluded(w->pol, w->path)) {
        if (count_dirs) {
            w->skipped_excluded++;
            if (s) s->skipped_excluded++;
        }
        return false;
    }
    if (fstatat(dirfd, name, st, AT_SYMLINK_NOFOLLOW) != 0) {
        w->errors++;
        if (s) s->errors++;
        return false;
    }
    if (S_ISDIR(st->st_mode) && DataInv_RegenerableDir(name, parent)) {
        if (count_dirs) {
            w->skipped_regenerable++;
            if (s) s->skipped_regenerable++;
        }
        return false;
    }
    return true;
}

/* Opens a subdirectory for walking, applying the mount and cache-tag rules.
 * Returns the descriptor or -1 (counted). */
static inline int DataInv_EnterDir(DataInvWalk* w, DataInvStore* s, int dirfd, const char* name, const struct stat* st) {
    int fd = DataInv_OpenChecked(dirfd, name, st, true);
    if (fd < 0) { w->errors++; if (s) s->errors++; return -1; }
    if (!DataInv_MayEnter(w, fd, st)) {
        close(fd);
        w->skipped_mounts++;
        if (s) s->skipped_mounts++;
        return -1;
    }
    struct stat tag;
    if (fstatat(fd, "CACHEDIR.TAG", &tag, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(tag.st_mode)) {
        close(fd);
        w->skipped_regenerable++;
        if (s) s->skipped_regenerable++;
        return -1;
    }
    struct stat cfg;
    if (fstatat(fd, "pyvenv.cfg", &cfg, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(cfg.st_mode)) {
        close(fd); /* a virtualenv is regenerable */
        w->skipped_regenerable++;
        if (s) {
            s->hints |= 1u << DI_H_VENV;
            s->skipped_regenerable++;
        }
        return -1;
    }
    return fd;
}

static inline const char* DataInv_BaseName(const char* path) {
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* .git is not walked (objects are regenerable from the remote or are the
 * repository itself); only its config is checked, for credentials in URLs. */
static inline void DataInv_GitDir(DataInvWalk* w, DataInvStore* s, int dirfd, const struct stat* gst, long long mark_ms) {
    s->hints |= 1u << DI_H_GIT;
    int gfd = DataInv_OpenChecked(dirfd, ".git", gst, true);
    if (gfd < 0) return;
    struct stat cst;
    int old = DataInv_PushPath(w, "config");
    if (old >= 0 && !DataInv_IsCanary(w->pol, w->path) && fstatat(gfd, "config", &cst, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(cst.st_mode)) {
        bool skipped = false;
        uint64_t content = DataInv_FileContent(w, s, gfd, "config", w->path, &cst, 0, mark_ms, &skipped);
        content &= DI_BIT(DI_R_URL_CREDENTIALS) | DI_BIT(DI_R_GITHUB_TOKEN) | DI_BIT(DI_R_GITLAB_TOKEN);
        if (content) DataInv_EmitItem(w, s, w->path, &cst, content);
        DataInv_StateVerdict(w, s->path, w->path, &cst, content);
    }
    if (old >= 0) DataInv_PopPath(w, old);
    close(gfd);
}

static void DataInv_WalkStoreDir(DataInvWalk* w, DataInvStore* s, int fd, int depth, bool store_top) {
    if (DataInv_OverBudget(w)) return;
    if (depth > DI_MAX_DEPTH) { w->skipped_depth++; s->truncated = true; return; }
    size_t n = 0;
    char* arena = NULL;
    bool trunc = false;
    char** names = DataInv_ListDir(fd, &n, &arena, &trunc);
    if (!names) { w->errors++; s->errors++; return; }
    if (trunc) s->truncated = true;
    qsort(names, n, sizeof(char*), DataInv_NameCmp);
    char parent[256];
    snprintf(parent, sizeof(parent), "%.255s", DataInv_BaseName(w->path));
    const DataInvMark* mk = DataInv_FindMark(w->old, s->path);
    long long mark_ms = mk ? mk->ms : 0;
    for (size_t i = 0; i < n && !DataInv_OverBudget(w); i++) {
        int old = DataInv_PushPath(w, names[i]);
        if (old < 0) { w->errors++; s->errors++; s->truncated = true; continue; }
        struct stat st;
        if (DataInv_Admit(w, s, fd, names[i], parent, &st, true)) {
            if (store_top) DataInv_StoreHintName(s, names[i], S_ISDIR(st.st_mode));
            if (S_ISDIR(st.st_mode)) {
                if (!strcmp(names[i], ".git")) {
                    DataInv_GitDir(w, s, fd, &st, mark_ms);
                } else {
                    int cfd = DataInv_EnterDir(w, s, fd, names[i], &st);
                    if (cfd >= 0) {
                        s->dirs++;
                        w->dirs++;
                        DataInv_WalkStoreDir(w, s, cfd, depth + 1, false);
                        close(cfd);
                    }
                }
            } else {
                DataInv_Entry(w, s, fd, names[i], parent, &st, mark_ms);
            }
        }
        DataInv_PopPath(w, old);
    }
    free(names);
    free(arena);
}

/* Finishes a store: reports it, records its watermark and moves the cursor.
 * A store cut short by the budget is reported (partial) only when it is the
 * first of the run, so one huge store cannot stall the cycle; otherwise it is
 * dropped and the next run starts with it. */
static inline bool DataInv_FinishStore(DataInvWalk* w, DataInvStore* s, long long run_start_ms) {
    if (w->stop) {
        if (w->any_store) return false;
        s->partial = true;
    }
    if (w->stores >= w->pol->max_stores) {
        w->stores_dropped++;
        w->stop = "stores";
        return false;
    }
    DataInv_EmitStore(w, s);
    snprintf(w->last_store, sizeof(w->last_store), "%.1023s", s->path);
    w->any_store = true;
    if (w->nvisited == w->capvisited) {
        size_t nc = w->capvisited ? w->capvisited * 2 : 256;
        char** nv = (char**)realloc(w->visited, nc * sizeof(char*));
        if (nv) {
            w->visited = nv;
            w->capvisited = nc;
        }
    }
    if (w->nvisited < w->capvisited) w->visited[w->nvisited++] = strdup(s->path);
    /* A store whose content was fully checked gets a new watermark; one cut
     * short keeps its old mark, so the files not read are read next time. */
    const DataInvMark* mk = DataInv_FindMark(w->old, s->path);
    long long ms = (!s->content_partial && !s->partial) ? run_start_ms : (mk ? mk->ms : 0);
    if (ms > 0) {
        DataInv_PutF(w->state_buf, "wm %lld ", ms);
        DataInv_PutS(w->state_buf, w->cycle_id);
        DataInv_PutS(w->state_buf, " ");
        DataInv_PutStatePath(w->state_buf, s->path);
        DataInv_PutS(w->state_buf, "\n");
    }
    return true;
}

/* Rewinds the verdict lines a dropped store wrote. */
static inline void DataInv_RewindState(DataInvWalk* w, size_t len) {
    w->state_buf->len = len;
    if (w->state_buf->data) w->state_buf->data[len] = '\0';
}

static inline void DataInv_RewindItems(DataInvWalk* w, size_t len, long long items) {
    w->items_buf->len = len;
    if (w->items_buf->data) w->items_buf->data[len] = '\0';
    w->items = items;
}

/* Visits one store root (a directory at store_depth). */
static inline void DataInv_Store(DataInvWalk* w, int fd, const char* root, long long run_start_ms) {
    DataInvStore* s = (DataInvStore*)calloc(1, sizeof(DataInvStore));
    if (!s) { w->errors++; return; }
    DataInv_StoreInit(s, w->path, root, false);
    size_t state_len = w->state_buf->len, items_len = w->items_buf->len;
    long long items = w->items;
    DataInv_WalkStoreDir(w, s, fd, 0, true);
    if (!DataInv_FinishStore(w, s, run_start_ms)) {
        DataInv_RewindState(w, state_len);
        DataInv_RewindItems(w, items_len, items);
    }
    free(s);
}

/* Directories above store depth: their own files form a shallow store
 * (reported first, keyed by the directory), then each subdirectory is a
 * store or is walked further. */
static void DataInv_Upper(DataInvWalk* w, int fd, int depth, const char* root, long long run_start_ms) {
    if (DataInv_OverBudget(w)) return;
    size_t n = 0;
    char* arena = NULL;
    bool trunc = false;
    char** names = DataInv_ListDir(fd, &n, &arena, &trunc);
    if (!names) { w->errors++; return; }
    qsort(names, n, sizeof(char*), DataInv_NameCmp);
    char parent[256];
    snprintf(parent, sizeof(parent), "%.255s", DataInv_BaseName(w->path));
    bool shallow_due = !w->has_cursor || DataInv_PathCmp(w->path, w->cursor) > 0;
    if (shallow_due) {
        DataInvStore* s = (DataInvStore*)calloc(1, sizeof(DataInvStore));
        if (s) {
            DataInv_StoreInit(s, w->path, root, true);
            s->truncated = trunc;
            size_t state_len = w->state_buf->len, items_len = w->items_buf->len;
            long long items = w->items;
            const DataInvMark* mk = DataInv_FindMark(w->old, s->path);
            long long mark_ms = mk ? mk->ms : 0;
            for (size_t i = 0; i < n && !DataInv_OverBudget(w); i++) {
                int old = DataInv_PushPath(w, names[i]);
                if (old < 0) { w->errors++; continue; }
                struct stat st;
                if (DataInv_Admit(w, s, fd, names[i], parent, &st, false)) {
                    DataInv_StoreHintName(s, names[i], S_ISDIR(st.st_mode));
                    if (S_ISDIR(st.st_mode)) {
                        if (!strcmp(names[i], ".git")) DataInv_GitDir(w, s, fd, &st, mark_ms);
                    } else {
                        DataInv_Entry(w, s, fd, names[i], parent, &st, mark_ms);
                    }
                }
                DataInv_PopPath(w, old);
            }
            if (s->files > 0 || s->items > 0) {
                if (!DataInv_FinishStore(w, s, run_start_ms)) {
                    DataInv_RewindState(w, state_len);
                    DataInv_RewindItems(w, items_len, items);
                }
            }
            free(s);
        }
    }
    for (size_t i = 0; i < n && !DataInv_OverBudget(w); i++) {
        if (!strcmp(names[i], ".git")) continue;
        int old = DataInv_PushPath(w, names[i]);
        if (old < 0) { w->errors++; continue; }
        /* Whole subtree already done in this cycle: skip without a stat. */
        if (w->has_cursor && DataInv_PathCmp(w->path, w->cursor) <= 0 && !DataInv_Under(w->cursor, w->path)) {
            DataInv_PopPath(w, old);
            continue;
        }
        struct stat st;
        if (DataInv_IsCanary(w->pol, w->path)) {
            w->skipped_canary++;
        } else if (DataInv_Excluded(w->pol, w->path)) {
            w->skipped_excluded++;
        } else if (fstatat(fd, names[i], &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode)) {
            if (DataInv_RegenerableDir(names[i], parent)) {
                w->skipped_regenerable++;
            } else if (depth + 1 >= w->pol->store_depth) {
                if (!w->has_cursor || DataInv_PathCmp(w->path, w->cursor) > 0) {
                    int cfd = DataInv_EnterDir(w, NULL, fd, names[i], &st);
                    if (cfd >= 0) {
                        DataInv_Store(w, cfd, root, run_start_ms);
                        close(cfd);
                    }
                }
            } else {
                int cfd = DataInv_EnterDir(w, NULL, fd, names[i], &st);
                if (cfd >= 0) {
                    DataInv_Upper(w, cfd, depth + 1, root, run_start_ms);
                    close(cfd);
                }
            }
        }
        DataInv_PopPath(w, old);
    }
    free(names);
    free(arena);
}

static inline int DataInv_RootCmp(const void* a, const void* b) {
    return DataInv_PathCmp(*(char* const*)a, *(char* const*)b);
}

/* Opens an absolute root one component at a time, never following a symlink. */
static inline int DataInv_OpenRoot(const char* root) {
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[DI_PATH_CAP];
    snprintf(buf, sizeof(buf), "%s", root);
    for (char* tok = strtok(buf, "/"); tok; tok = strtok(NULL, "/")) {
        int next = openat(fd, tok, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        close(fd);
        if (next < 0) return -1;
        fd = next;
    }
    return fd;
}

static inline void DataInv_WalkRoots(DataInvWalk* w, long long run_start_ms) {
    const char* roots[DI_MAX_ROOTS];
    int n = 0;
    for (int i = 0; i < w->pol->nroots; i++) roots[n++] = w->pol->roots[i];
    qsort(roots, (size_t)n, sizeof(char*), DataInv_RootCmp);
    for (int i = 0; i < n && !DataInv_OverBudget(w); i++) {
        bool nested = false;
        for (int j = 0; j < n; j++) {
            if (j != i && DataInv_Under(roots[i], roots[j]) && strcmp(roots[i], roots[j])) nested = true;
            if (j < i && !strcmp(roots[i], roots[j])) nested = true;
        }
        if (nested) continue;
        if (w->has_cursor && DataInv_PathCmp(roots[i], w->cursor) < 0 && !DataInv_Under(w->cursor, roots[i])) continue;
        if (DataInv_IsCanary(w->pol, roots[i])) { w->skipped_canary++; continue; }
        int fd = DataInv_OpenRoot(roots[i]);
        if (fd < 0) { w->errors++; continue; }
        struct stat st;
        struct statfs sf;
        if (fstat(fd, &st) != 0 || fstatfs(fd, &sf) != 0 || !DataInv_LocalFsType((long)sf.f_type)) {
            w->skipped_mounts++;
            close(fd);
            continue;
        }
        w->root_dev = st.st_dev;
        w->root_ftype = (long)sf.f_type;
        DataInv_RootMountSource(DataInv_MountInfo(w), roots[i], w->root_src, sizeof(w->root_src));
        snprintf(w->path, sizeof(w->path), "%.1023s", roots[i]);
        DataInv_Upper(w, fd, 0, roots[i], run_start_ms);
        close(fd);
    }
}

/* ---------------------------------------------------------------------------
 * Host facts (child only; all reads)
 * ------------------------------------------------------------------------- */

static inline ssize_t DataInv_ReadPath(const char* path, char* buf, size_t cap) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got + 1 < cap) {
        ssize_t n = read(fd, buf + got, cap - 1 - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    buf[got] = '\0';
    return (ssize_t)got;
}

/* Whether block device maj:min is, or sits on top of, a dm-crypt mapping. */
static inline int DataInv_CryptDev(unsigned maj, unsigned min, int depth) {
    if (depth > 6) return 0;
    char path[128], buf[256];
    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/dm/uuid", maj, min);
    if (DataInv_ReadPath(path, buf, sizeof(buf)) > 0 && !strncmp(buf, "CRYPT-", 6)) return 1;
    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/slaves", maj, min);
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    size_t n = 0;
    char* arena = NULL;
    bool trunc = false;
    char** names = DataInv_ListDir(fd, &n, &arena, &trunc);
    close(fd);
    int found = 0;
    for (size_t i = 0; names && i < n && !found; i++) {
        snprintf(path, sizeof(path), "/sys/class/block/%.64s/dev", names[i]);
        unsigned a = 0, b = 0;
        if (DataInv_ReadPath(path, buf, sizeof(buf)) > 0 && sscanf(buf, "%u:%u", &a, &b) == 2) found = DataInv_CryptDev(a, b, depth + 1);
    }
    free(names);
    free(arena);
    return found;
}

/* The block device behind the mount that holds path, from mountinfo: the
 * longest mount point that is a prefix of path. "unknown" for btrfs/zfs
 * devices that are not plain block devices. */
static inline const char* DataInv_RootEncryption(const char* root, const char* mountinfo) {
    size_t best = 0;
    unsigned bmaj = 0, bmin = 0;
    char bsrc[256] = {0};
    const char* line = mountinfo;
    while (line && *line) {
        const char* nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        char l[1024];
        if (len < sizeof(l)) {
            memcpy(l, line, len);
            l[len] = '\0';
            unsigned maj = 0, min = 0;
            char mp[512], src[256];
            const char* sep = strstr(l, " - ");
            if (sep && sscanf(l, "%*u %*u %u:%u %*s %511s", &maj, &min, mp) == 3 &&
                sscanf(sep + 3, "%*s %255s", src) == 1) {
                size_t m = strlen(mp);
                if (DataInv_Under(root, mp) && m >= best) {
                    best = m;
                    bmaj = maj;
                    bmin = min;
                    snprintf(bsrc, sizeof(bsrc), "%s", src);
                }
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    if (!best) return "unknown";
    if (bmaj != 0) return DataInv_CryptDev(bmaj, bmin, 0) ? "dm-crypt" : "none";
    if (!strncmp(bsrc, "/dev/", 5)) {
        struct stat st;
        if (fstatat(AT_FDCWD, bsrc, &st, 0) == 0 && S_ISBLK(st.st_mode))
            return DataInv_CryptDev(major(st.st_rdev), minor(st.st_rdev), 0) ? "dm-crypt" : "none";
    }
    return "unknown";
}

static inline void DataInv_Listeners(DataInvBuf* b) {
    static const struct { const char* path; const char* proto; bool v6; const char* state; } tables[] = {
        {"/proc/net/tcp", "tcp", false, "0A"}, {"/proc/net/tcp6", "tcp", true, "0A"},
        {"/proc/net/udp", "udp", false, "07"}, {"/proc/net/udp6", "udp", true, "07"},
    };
    char* buf = (char*)malloc(1 << 20);
    if (!buf) return;
    int shown = 0;
    struct { char proto[4]; char scope[10]; unsigned port; } seen[DI_MAX_LISTENERS];
    bool first = true;
    for (size_t t = 0; t < 4; t++) {
        if (DataInv_ReadPath(tables[t].path, buf, 1 << 20) <= 0) continue;
        char* line = strchr(buf, '\n');
        while (line && *++line) {
            char* nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            char local[64], rem[64], st[8];
            if (sscanf(line, "%*d: %63s %63s %7s", local, rem, st) == 3 && !strcmp(st, tables[t].state)) {
                char* colon = strrchr(local, ':');
                char* rcolon = strrchr(rem, ':');
                bool remote_zero = rcolon && !strcmp(rcolon + 1, "0000");
                if (colon && (tables[t].proto[0] == 't' || remote_zero)) {
                    *colon = '\0';
                    unsigned port = (unsigned)strtoul(colon + 1, NULL, 16);
                    const char* scope = "addr";
                    if (strspn(local, "0") == strlen(local)) scope = "any";
                    else if (!tables[t].v6 && strlen(local) == 8 && local[6] == '7' && local[7] == 'F') scope = "loopback";
                    else if (tables[t].v6 && !strcmp(local, "00000000000000000000000001000000")) scope = "loopback";
                    else if (tables[t].v6 && !strncmp(local, "0000000000000000FFFF0000", 24) && !strcmp(local + 30, "7F"))
                        scope = "loopback";
                    bool dup = false;
                    for (int i = 0; i < shown; i++) {
                        if (seen[i].port == port && !strcmp(seen[i].proto, tables[t].proto) && !strcmp(seen[i].scope, scope)) dup = true;
                    }
                    if (!dup && shown < DI_MAX_LISTENERS) {
                        snprintf(seen[shown].proto, sizeof(seen[shown].proto), "%s", tables[t].proto);
                        snprintf(seen[shown].scope, sizeof(seen[shown].scope), "%s", scope);
                        seen[shown].port = port;
                        shown++;
                        DataInv_PutS(b, first ? "[\"" : ",[\"");
                        DataInv_PutS(b, tables[t].proto);
                        DataInv_PutS(b, "\",\"");
                        DataInv_PutS(b, scope);
                        DataInv_PutF(b, "\",%lld]", (long long)port);
                        first = false;
                    }
                }
            }
            line = nl;
        }
    }
    free(buf);
}

/* First value of an sshd option across sshd_config.d/ (sorted, as Include
 * at the top reads them) and sshd_config: sshd uses the first one it sees. */
static inline void DataInv_SshdOption(const char* key, char* out, size_t cap) {
    snprintf(out, cap, "default");
    char* buf = (char*)malloc(65536);
    if (!buf) return;
    char paths[33][320];
    int np = 0;
    int dfd = open("/etc/ssh/sshd_config.d", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd >= 0) {
        size_t n = 0;
        char* arena = NULL;
        bool trunc = false;
        char** names = DataInv_ListDir(dfd, &n, &arena, &trunc);
        close(dfd);
        if (names) {
            qsort(names, n, sizeof(char*), DataInv_NameCmp);
            for (size_t i = 0; i < n && np < 32; i++) {
                if (DataInv_EndsWithCI(names[i], ".conf")) snprintf(paths[np++], sizeof(paths[0]), "/etc/ssh/sshd_config.d/%.256s", names[i]);
            }
        }
        free(names);
        free(arena);
    }
    snprintf(paths[np++], sizeof(paths[0]), "/etc/ssh/sshd_config");
    for (int i = 0; i < np; i++) {
        if (DataInv_ReadPath(paths[i], buf, 65536) <= 0) continue;
        for (char* line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
            while (*line == ' ' || *line == '\t') line++;
            if (!strncasecmp(line, "Match", 5)) break; /* options after Match are conditional */
            size_t kl = strlen(key);
            if (!strncasecmp(line, key, kl) && (line[kl] == ' ' || line[kl] == '\t' || line[kl] == '=')) {
                char* v = line + kl;
                while (*v == ' ' || *v == '\t' || *v == '=') v++;
                char val[24];
                size_t j = 0;
                while (v[j] && v[j] != ' ' && v[j] != '\t' && v[j] != '\r' && j < sizeof(val) - 1) {
                    val[j] = DataInv_Lower(v[j]);
                    j++;
                }
                val[j] = '\0';
                if (!strcmp(val, "yes") || !strcmp(val, "no") || !strcmp(val, "prohibit-password") ||
                    !strcmp(val, "without-password") || !strcmp(val, "forced-commands-only"))
                    snprintf(out, cap, "%s", val);
                else
                    snprintf(out, cap, "other");
                free(buf);
                return;
            }
        }
    }
    free(buf);
}

static inline void DataInv_HostFacts(DataInvWalk* w, DataInvBuf* b) {
    char* mi = (char*)malloc(1 << 20);
    DataInv_PutS(b, "{\"roots\":[");
    if (mi && DataInv_ReadPath("/proc/self/mountinfo", mi, 1 << 20) <= 0) mi[0] = '\0';
    for (int i = 0; i < w->pol->nroots; i++) {
        DataInv_PutS(b, i ? ",{\"path\":" : "{\"path\":");
        DataInv_PutJSONPath(b, w->pol->roots[i]);
        DataInv_PutS(b, ",\"encryption\":");
        DataInv_PutJSONString(b, mi ? DataInv_RootEncryption(w->pol->roots[i], mi) : "unknown");
        DataInv_PutS(b, "}");
    }
    free(mi);
    DataInv_PutS(b, "],\"listeners\":[");
    DataInv_Listeners(b);
    DataInv_PutS(b, "]");
    char buf[4096];
    const char* ufw = "absent";
    if (DataInv_ReadPath("/etc/ufw/ufw.conf", buf, sizeof(buf)) > 0) ufw = strstr(buf, "\nENABLED=yes") || !strncmp(buf, "ENABLED=yes", 11) ? "enabled" : "disabled";
    DataInv_PutS(b, ",\"ufw\":");
    DataInv_PutJSONString(b, ufw);
    long long upd = -1, sec = -1;
    if (DataInv_ReadPath("/var/lib/update-notifier/updates-available", buf, sizeof(buf)) > 0) {
        for (char* line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
            long long v = 0;
            if (strstr(line, "can be applied immediately") && sscanf(line, "%lld", &v) == 1) upd = v;
            if (strstr(line, "security update") && sscanf(line, "%lld", &v) == 1) sec = v;
        }
        if (upd < 0) upd = 0;
        if (sec < 0) sec = 0;
    }
    DataInv_PutF(b, ",\"updates\":%lld", upd);
    DataInv_PutF(b, ",\"security_updates\":%lld", sec);
    char v1[24], v2[24], v3[24];
    DataInv_SshdOption("PasswordAuthentication", v1, sizeof(v1));
    DataInv_SshdOption("PermitRootLogin", v2, sizeof(v2));
    DataInv_SshdOption("KbdInteractiveAuthentication", v3, sizeof(v3));
    struct stat sst;
    bool sshd = fstatat(AT_FDCWD, "/etc/ssh/sshd_config", &sst, AT_SYMLINK_NOFOLLOW) == 0;
    DataInv_PutS(b, ",\"sshd\":");
    if (!sshd) {
        DataInv_PutS(b, "null");
    } else {
        DataInv_PutS(b, "{\"password_authentication\":");
        DataInv_PutJSONString(b, v1);
        DataInv_PutS(b, ",\"permit_root_login\":");
        DataInv_PutJSONString(b, v2);
        DataInv_PutS(b, ",\"kbd_interactive\":");
        DataInv_PutJSONString(b, v3);
        DataInv_PutS(b, "}");
    }
    DataInv_PutS(b, "}");
}

/* ---------------------------------------------------------------------------
 * Child entry point
 * ------------------------------------------------------------------------- */

static inline bool DataInv_WriteAll(int fd, const char* data, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        data += n;
        len -= (size_t)n;
    }
    return true;
}

static inline bool DataInv_Visited(const DataInvWalk* w, const char* store) {
    size_t lo = 0, hi = w->nvisited;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = DataInv_PathCmp(w->visited[mid], store);
        if (c == 0) return true;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

/* Runs the scan and writes "<json>" DI_STATE_SEP "<state>" DI_END_MARK to
 * outfd. With sandbox false (tests only) the sandbox is not installed. */
static inline int DataInv_ChildRun(int outfd, const DataInvPolicy* pol, const char* old_state_text, const char* endpoint_id,
                                   const char* new_cycle_id, long long now_ms, bool sandbox) {
    long long real_start_ms = DataInv_NowMs();
    DataInvState old;
    if (!old_state_text || !DataInv_ParseState(old_state_text, &old)) memset(&old, 0, sizeof(old));
    if (sandbox) {
        if (!DataInv_LowerPriority(pol) || !DataInv_DropCapabilities() || !DataInv_InstallSeccomp(outfd)) {
            static const char msg[] = "\x1eOMINULL-DATA-ABORT sandbox\n";
            (void)DataInv_WriteAll(outfd, msg, sizeof(msg) - 1);
            return 3;
        }
    }
    DataInvWalk* w = (DataInvWalk*)calloc(1, sizeof(DataInvWalk));
    DataInvBuf stores = {(char*)malloc(DI_OUT_CAP / 2), DI_OUT_CAP / 2, 0, true};
    DataInvBuf items = {(char*)malloc(DI_OUT_CAP / 4), DI_OUT_CAP / 4, 0, true};
    DataInvBuf state = {(char*)malloc(DI_STATE_CAP), DI_STATE_CAP, 0, true};
    DataInvBuf host = {(char*)malloc(65536), 65536, 0, true};
    DataInvBuf out = {(char*)malloc(DI_OUT_CAP), DI_OUT_CAP, 0, true};
    int rc = 0;
    DataInvBuf st = {NULL, 0, 0, false};
    if (!w || !stores.data || !items.data || !state.data || !host.data || !out.data) { rc = 4; goto done; }
    stores.data[0] = items.data[0] = state.data[0] = host.data[0] = '\0';
    w->pol = pol;
    w->old = &old;
    w->stores_buf = &stores;
    w->items_buf = &items;
    w->state_buf = &state;
    w->start_ms = now_ms;
    w->deadline_ms = DataInv_MonoMs() + (long long)pol->max_seconds * 1000;

    /* Continue the open cycle, or start a new one (full when due, or when the
     * rules or the policy changed). */
    bool resume = old.has_cycle && !old.cycle_done && old.cycle_policy == pol->version && old.cycle_rules == DI_RULES_VERSION;
    bool full;
    long long cycle_started;
    if (resume) {
        snprintf(w->cycle_id, sizeof(w->cycle_id), "%s", old.cycle_id);
        full = old.cycle_full;
        cycle_started = old.cycle_started;
        if (old.has_cursor) {
            snprintf(w->cursor, sizeof(w->cursor), "%s", old.cursor);
            w->has_cursor = true;
        }
    } else {
        snprintf(w->cycle_id, sizeof(w->cycle_id), "%s", new_cycle_id);
        full = !old.has_cycle || old.cycle_rules != DI_RULES_VERSION || old.cycle_policy != pol->version ||
               now_ms - old.last_full >= (long long)pol->full_every_days * 86400000LL;
        cycle_started = now_ms;
    }
    w->full = full;

    DataInv_HostFacts(w, &host);
    DataInv_WalkRoots(w, now_ms);
    bool complete = w->stop == NULL;
    long long finished = now_ms + (DataInv_NowMs() - real_start_ms);

    /* New state: header, cycle, cursor, times, this run's marks and verdicts,
     * then the old ones this run did not replace (only those of this cycle
     * once the cycle completes, so removed stores and files age out). */
    st = (DataInvBuf){(char*)malloc(DI_STATE_CAP), DI_STATE_CAP, 0, true};
    if (!st.data) { rc = 4; goto done; }
    st.data[0] = '\0';
    DataInv_PutS(&st, DI_STATE_HEADER "\ncycle ");
    DataInv_PutS(&st, w->cycle_id);
    DataInv_PutF(&st, " %lld", cycle_started);
    DataInv_PutF(&st, " %lld", full ? 1LL : 0LL);
    DataInv_PutF(&st, " %lld", complete ? 1LL : 0LL);
    DataInv_PutF(&st, " %lld", (long long)pol->version);
    DataInv_PutF(&st, " %lld\n", (long long)DI_RULES_VERSION);
    if (!complete && (w->any_store || w->has_cursor)) {
        DataInv_PutS(&st, "cursor ");
        DataInv_PutStatePath(&st, w->any_store ? w->last_store : w->cursor);
        DataInv_PutS(&st, "\n");
    }
    DataInv_PutF(&st, "last_run %lld\n", finished);
    DataInv_PutF(&st, "last_done %lld\n", complete ? finished : old.last_done);
    DataInv_PutF(&st, "last_full %lld\n", (complete && full) ? cycle_started : old.last_full);
    DataInv_Put(&st, state.data, state.len);
    /* Old marks and verdicts of stores this run did not report carry over (a
     * reported store wrote its own lines above); once the cycle completes,
     * only those refreshed in this cycle, so removed stores and files age out. */
    for (size_t i = 0; i < old.nmarks; i++) {
        const DataInvMark* m = &old.marks[i];
        if (DataInv_Visited(w, m->path)) continue;
        if (complete && strcmp(m->cycle, w->cycle_id) != 0) continue;
        DataInv_PutF(&st, "wm %lld ", m->ms);
        DataInv_PutS(&st, m->cycle);
        DataInv_PutS(&st, " ");
        DataInv_PutStatePath(&st, m->path);
        DataInv_PutS(&st, "\n");
    }
    for (size_t i = 0; i < old.nverdicts; i++) {
        const DataInvVerdict* v = &old.verdicts[i];
        if (DataInv_Visited(w, v->store)) continue;
        if (complete && strcmp(v->cycle, w->cycle_id) != 0) continue;
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "v %llu %llu %lld %lld %llx ", v->dev, v->ino, v->size, v->mtime_ns, (unsigned long long)v->rules);
        DataInv_PutS(&st, tmp);
        DataInv_PutS(&st, v->cycle);
        DataInv_PutS(&st, " ");
        DataInv_PutStatePath(&st, v->store);
        DataInv_PutS(&st, " ");
        DataInv_PutStatePath(&st, v->path);
        DataInv_PutS(&st, "\n");
    }
    DataInv_PutS(&st, "end\n");

    /* The document. */
    DataInv_PutS(&out, "{\"schema\":\"" DI_SCHEMA "\",\"endpoint_id\":");
    DataInv_PutJSONString(&out, endpoint_id ? endpoint_id : "");
    DataInv_PutS(&out, ",\"platform\":\"linux\",\"run\":{\"cycle_id\":");
    DataInv_PutJSONString(&out, w->cycle_id);
    DataInv_PutS(&out, ",\"mode\":");
    DataInv_PutJSONString(&out, full ? "full" : "incremental");
    DataInv_PutF(&out, ",\"started_at\":%lld", now_ms);
    DataInv_PutF(&out, ",\"finished_at\":%lld", finished);
    DataInv_PutF(&out, ",\"cycle_started_at\":%lld", cycle_started);
    DataInv_PutS(&out, complete ? ",\"cycle_complete\":true" : ",\"cycle_complete\":false");
    DataInv_PutS(&out, ",\"resumed_from\":");
    if (w->has_cursor) DataInv_PutJSONPath(&out, w->cursor);
    else DataInv_PutS(&out, "null");
    DataInv_PutS(&out, ",\"budget_hit\":");
    DataInv_PutJSONString(&out, w->stop ? w->stop : (w->content_exhausted ? "content" : "none"));
    DataInv_PutF(&out, ",\"files\":%lld", w->files);
    DataInv_PutF(&out, ",\"dirs\":%lld", w->dirs);
    DataInv_PutF(&out, ",\"bytes\":%lld", w->bytes);
    DataInv_PutF(&out, ",\"content_files\":%lld", w->content_files);
    DataInv_PutF(&out, ",\"content_bytes\":%lld", w->content_bytes);
    DataInv_PutF(&out, ",\"skipped_canary\":%lld", w->skipped_canary);
    DataInv_PutF(&out, ",\"skipped_regenerable\":%lld", w->skipped_regenerable);
    DataInv_PutF(&out, ",\"skipped_excluded\":%lld", w->skipped_excluded);
    DataInv_PutF(&out, ",\"skipped_mounts\":%lld", w->skipped_mounts);
    DataInv_PutF(&out, ",\"skipped_depth\":%lld", w->skipped_depth);
    DataInv_PutF(&out, ",\"errors\":%lld", w->errors);
    DataInv_PutF(&out, ",\"stores\":%lld", w->stores);
    DataInv_PutF(&out, ",\"items\":%lld", w->items);
    DataInv_PutF(&out, ",\"items_dropped\":%lld", w->items_dropped);
    DataInv_PutF(&out, ",\"stores_dropped\":%lld", w->stores_dropped);
    DataInv_PutF(&out, ",\"policy_version\":%lld", (long long)pol->version);
    DataInv_PutF(&out, ",\"rules_version\":%lld", (long long)DI_RULES_VERSION);
    DataInv_PutS(&out, sandbox ? ",\"sandboxed\":true}" : ",\"sandboxed\":false}");
    DataInv_PutS(&out, ",\"host\":");
    DataInv_Put(&out, host.data, host.len);
    DataInv_PutS(&out, ",\"stores\":[");
    DataInv_Put(&out, stores.data, stores.len);
    DataInv_PutS(&out, "],\"items\":[");
    DataInv_Put(&out, items.data, items.len);
    DataInv_PutS(&out, "]}");
    bool ok = out.ok && stores.ok && items.ok && host.ok && state.ok && st.ok;
    if (!ok) {
        static const char msg[] = "\x1eOMINULL-DATA-ABORT overflow\n";
        (void)DataInv_WriteAll(outfd, msg, sizeof(msg) - 1);
        rc = 5;
        goto done;
    }
    if (!DataInv_WriteAll(outfd, out.data, out.len) || !DataInv_WriteAll(outfd, DI_STATE_SEP, strlen(DI_STATE_SEP)) ||
        !DataInv_WriteAll(outfd, st.data, st.len) || !DataInv_WriteAll(outfd, DI_END_MARK, strlen(DI_END_MARK)))
        rc = 6;
done:
    /* The child exits right after; freeing keeps in-process runs (tests) clean. */
    if (w) {
        for (size_t i = 0; i < w->nvisited; i++) free(w->visited[i]);
        free(w->visited);
        free(w->mountinfo);
        free(w);
    }
    free(stores.data);
    free(items.data);
    free(state.data);
    free(host.data);
    free(out.data);
    free(st.data);
    DataInv_StateFree(&old);
    return rc;
}

/* ---------------------------------------------------------------------------
 * Parent side: start, drain, finish
 * ------------------------------------------------------------------------- */

typedef struct {
    bool active;
    pid_t pid;
    int fd;
    char* buf;
    size_t len, cap;
    long long started_mono, kill_after_mono;
    bool overflow;
} DataInvRun;

/* Splits a finished child's output into the document and the new state.
 * Returns false (with why) when the child aborted or the output is not whole. */
static inline bool DataInv_SplitOutput(char* buf, size_t len, char** doc, char** state, char* why, size_t whycap) {
    *doc = *state = NULL;
    if (len == 0) { snprintf(why, whycap, "scan produced nothing (killed by the sandbox or a limit?)"); return false; }
    buf[len] = '\0';
    char* abort_mark = strstr(buf, "\x1eOMINULL-DATA-ABORT ");
    if (abort_mark) {
        snprintf(why, whycap, "scan aborted: %.40s", abort_mark + 20);
        char* nl = strchr(why, '\n');
        if (nl) *nl = '\0';
        return false;
    }
    size_t el = strlen(DI_END_MARK);
    if (len < el || memcmp(buf + len - el, DI_END_MARK, el) != 0) { snprintf(why, whycap, "scan output incomplete"); return false; }
    char* sep = strstr(buf, DI_STATE_SEP);
    if (!sep) { snprintf(why, whycap, "scan output has no state section"); return false; }
    *sep = '\0';
    *doc = buf;
    *state = sep + strlen(DI_STATE_SEP);
    buf[len - el] = '\0';
    if (strncmp(*state, DI_STATE_HEADER "\n", strlen(DI_STATE_HEADER) + 1) != 0 || strlen(*state) < 5 ||
        strcmp(*state + strlen(*state) - 4, "end\n") != 0) {
        snprintf(why, whycap, "scan state section malformed");
        return false;
    }
    if ((*doc)[0] != '{') { snprintf(why, whycap, "scan document malformed"); return false; }
    return true;
}

/* Writes the agent's state file atomically (temp file, fsync, rename). */
static inline bool DataInv_WriteState(const char* path, const char* text) {
    char tmp[512];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return false;
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t len = strlen(text);
    bool ok = DataInv_WriteAll(fd, text, len) && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    if (!ok || rename(tmp, path) != 0) { unlink(tmp); return false; }
    return true;
}

/* Forks the scanning child. The parent keeps only the pipe. */
static inline bool DataInv_Start(DataInvRun* run, const DataInvPolicy* pol, const char* state_path, const char* endpoint_id) {
    if (run->active) return false;
    char* old = DataInv_ReadSmallFile(state_path, DI_STATE_CAP);
    unsigned char rnd[8] = {0};
    if (syscall(SYS_getrandom, rnd, sizeof(rnd), 0) != (long)sizeof(rnd)) {
        long long t = DataInv_NowMs();
        memcpy(rnd, &t, sizeof(rnd));
    }
    char cycle[33];
    for (int i = 0; i < 8; i++) snprintf(cycle + i * 2, 3, "%02x", rnd[i]);
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) { free(old); return false; }
    (void)fcntl(fds[0], F_SETPIPE_SZ, 1 << 20);
    long long now = DataInv_NowMs();
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        free(old);
        return false;
    }
    if (pid == 0) {
        (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        signal(SIGPIPE, SIG_DFL);
        close(fds[0]);
        /* Close everything inherited except the pipe and stdio: hub sockets,
         * BPF maps and the agent's own files are not the scanner's business. */
#ifdef SYS_close_range
        bool closed = (fds[1] <= 3 || syscall(SYS_close_range, 3, (unsigned)fds[1] - 1, 0) == 0) &&
                      syscall(SYS_close_range, (unsigned)fds[1] + 1, ~0u, 0) == 0;
#else
        bool closed = false;
#endif
        if (!closed) {
            int max = (int)sysconf(_SC_OPEN_MAX);
            if (max < 0 || max > 65536) max = 65536;
            for (int fd = 3; fd < max; fd++) {
                if (fd != fds[1]) close(fd);
            }
        }
        int rc = DataInv_ChildRun(fds[1], pol, old, endpoint_id, cycle, now, true);
        _exit(rc);
    }
    free(old);
    close(fds[1]);
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    run->active = true;
    run->pid = pid;
    run->fd = fds[0];
    run->cap = DI_OUT_CAP + DI_STATE_CAP + 4096;
    run->buf = (char*)malloc(run->cap + 1);
    run->len = 0;
    run->overflow = run->buf == NULL;
    run->started_mono = DataInv_MonoMs();
    run->kill_after_mono = run->started_mono + ((long long)pol->max_seconds + 120) * 1000;
    return true;
}

/* Drains whatever the child has written. Returns true once the child has
 * closed the pipe (finished, aborted or killed); the result is in run->buf. */
static inline bool DataInv_Drain(DataInvRun* run) {
    if (!run->active) return false;
    for (;;) {
        char tmp[65536];
        ssize_t n = read(run->fd, tmp, sizeof(tmp));
        if (n > 0) {
            if (!run->overflow && run->len + (size_t)n <= run->cap) {
                memcpy(run->buf + run->len, tmp, (size_t)n);
                run->len += (size_t)n;
            } else {
                run->overflow = true;
            }
            continue;
        }
        if (n == 0) {
            close(run->fd);
            run->fd = -1;
            /* SIGCHLD may be ignored (auto-reap); waitpid then fails, which is fine. */
            (void)waitpid(run->pid, NULL, WNOHANG);
            run->pid = 0; /* gone: never signal a reused pid */
            return true;
        }
        if (errno == EINTR) continue;
        break; /* EAGAIN: nothing more now */
    }
    if (DataInv_MonoMs() > run->kill_after_mono) {
        kill(run->pid, SIGKILL);
        run->overflow = true;
    }
    return false;
}

static inline void DataInv_Reset(DataInvRun* run) {
    if (run->fd >= 0 && run->active) close(run->fd);
    free(run->buf);
    memset(run, 0, sizeof(*run));
    run->fd = -1;
}

/* Stops a running scan (agent shutdown). */
static inline void DataInv_Abort(DataInvRun* run) {
    if (run->active && run->pid > 0) kill(run->pid, SIGKILL);
    DataInv_Reset(run);
}

#endif /* OMINULL_DATA_INVENTORY_LINUX_H */
