#ifndef OMINULL_SCRIPT_SUPERVISOR_H
#define OMINULL_SCRIPT_SUPERVISOR_H

/*
 * Script job supervisor: the platform-neutral half (docs/RESPONSE_SUPERVISOR.md).
 *
 * Both workers (script_exec_linux.h, script_exec_windows.h) feed this the
 * job's output and a sample of its process tree every few seconds; it parses
 * `::progress::` lines, keeps the activity clock, picks the phase (running,
 * stalled, needs_hands), decides when a heartbeat is due and builds its body
 * for POST /api/v1/response/jobs/progress. Nothing here touches the network,
 * the clock or the process table: callers pass the time and the numbers in,
 * so the whole thing is unit-tested from the Linux test binary.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SUPERVISOR_PROGRESS_PREFIX     "::progress::"
#define SUPERVISOR_TEXT_MAX            200      /* message and window title, bytes */
#define SUPERVISOR_LINE_MAX            512      /* kept of one output line while parsing */
#define SUPERVISOR_CPU_ACTIVITY_MS     200
#define SUPERVISOR_IO_ACTIVITY_BYTES   65536

typedef enum {
    SUPERVISOR_PHASE_RUNNING = 0,
    SUPERVISOR_PHASE_STALLED = 1,
    SUPERVISOR_PHASE_NEEDS_HANDS = 2,
} ScriptSupervisorPhase;

/* Timings in milliseconds; tests shorten them. */
typedef struct {
    int64_t idle_threshold_ms;      /* no activity this long: stalled or needs_hands */
    int64_t sample_interval_ms;     /* process tree sample */
    int64_t heartbeat_interval_ms;  /* plain heartbeat */
    int64_t min_post_gap_ms;        /* at most one change-driven post per gap */
} ScriptSupervisorSettings;

static inline ScriptSupervisorSettings Supervisor_DefaultSettings(void) {
    ScriptSupervisorSettings s = { 180000, 5000, 30000, 5000 };
    return s;
}

/* Where heartbeats go. post() gets a complete JSON body; it must come back
 * within a few seconds (a helper thread, or a short transport timeout) and its
 * failures are ignored. cancel_requested() reports a hub cancel seen on any
 * reply so far. Either may be NULL. */
typedef struct {
    ScriptSupervisorSettings settings;
    const char* job_id;
    const char* lease_id;
    void (*post)(void* ctx, const char* body);
    bool (*cancel_requested)(void* ctx);
    void* ctx;
} ScriptSupervisorHooks;

typedef struct {
    bool truncated;
    bool timed_out;
    bool cancelled;
    int64_t duration_ms;
} ScriptRunResult;

typedef struct {
    bool present;
    char title[SUPERVISOR_TEXT_MAX + 1];
    char process[SUPERVISOR_TEXT_MAX + 1];
    uint32_t pid;
    uint32_t session;
} ScriptSupervisorWindow;

typedef struct {
    uint64_t cpu_ms;
    uint64_t io_bytes;
    uint32_t processes;
} ScriptTreeSample;

typedef struct {
    ScriptSupervisorSettings settings;

    int64_t last_activity_ms;
    int64_t last_sample_ms;
    int64_t last_post_ms;
    bool posted_once;

    bool have_sample;
    uint64_t prev_cpu_ms;
    uint64_t prev_io_bytes;
    ScriptTreeSample last;

    ScriptSupervisorPhase phase;
    ScriptSupervisorPhase posted_phase;
    ScriptSupervisorWindow window;

    int progress_pct;               /* -1 unknown */
    char message[SUPERVISOR_TEXT_MAX + 1];
    bool progress_dirty;

    char line[SUPERVISOR_LINE_MAX];
    size_t line_len;
} ScriptSupervisor;

/* ---------------------------------------------------------------------------
 * Text helpers
 * ------------------------------------------------------------------------- */

/* Copies src (len bytes) into dst without control characters, at most max
 * bytes, never ending inside a UTF-8 sequence. */
static inline void Supervisor_CleanText(const char* src, size_t len, char* dst, size_t max) {
    size_t d = 0;
    for (size_t s = 0; s < len && d < max; s++) {
        unsigned char c = (unsigned char)src[s];
        if (c < 0x20 || c == 0x7f) continue;
        dst[d++] = (char)c;
    }
    /* Back off a multi-byte sequence the cap cut short. */
    if (d > 0) {
        size_t start = d;
        while (start > 0 && (((unsigned char)dst[start - 1]) & 0xC0) == 0x80) start--;
        if (start > 0) {
            unsigned char lead = (unsigned char)dst[start - 1];
            size_t need = (lead & 0xE0) == 0xC0 ? 2 : (lead & 0xF0) == 0xE0 ? 3 : (lead & 0xF8) == 0xF0 ? 4 : 1;
            if (lead >= 0xC0 && d - (start - 1) < need) d = start - 1;
        }
    }
    while (d > 0 && dst[d - 1] == ' ') d--;
    dst[d] = '\0';
}

/* Appends "str" as a JSON string literal; returns the new length, or cap when
 * it did not fit. */
static inline size_t Supervisor_AppendJSONString(char* buf, size_t len, size_t cap, const char* str) {
    if (len >= cap) return cap;
    if (len + 1 >= cap) return cap;
    buf[len++] = '"';
    for (const unsigned char* p = (const unsigned char*)str; *p; p++) {
        char esc[8];
        size_t n = 0;
        if (*p == '"') { esc[0] = '\\'; esc[1] = '"'; n = 2; }
        else if (*p == '\\') { esc[0] = '\\'; esc[1] = '\\'; n = 2; }
        else if (*p < 0x20 || *p == 0x7f) { n = (size_t)snprintf(esc, sizeof(esc), "\\u%04x", *p); }
        else { esc[0] = (char)*p; n = 1; }
        if (len + n + 2 > cap) return cap;
        memcpy(buf + len, esc, n);
        len += n;
    }
    buf[len++] = '"';
    buf[len] = '\0';
    return len;
}

/* ---------------------------------------------------------------------------
 * Progress lines
 * ------------------------------------------------------------------------- */

/* Parses one complete output line (no newline). Returns true for a progress
 * line; *pct is 0-100, or -1 when the line names none. */
static inline bool Supervisor_ParseProgressLine(const char* line, size_t len, int* pct, char* msg, size_t msg_cap) {
    size_t plen = sizeof(SUPERVISOR_PROGRESS_PREFIX) - 1;
    if (len < plen || memcmp(line, SUPERVISOR_PROGRESS_PREFIX, plen) != 0) return false;
    size_t i = plen;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    *pct = -1;
    size_t j = i;
    int value = 0;
    while (j < len && j - i < 3 && line[j] >= '0' && line[j] <= '9') value = value * 10 + (line[j++] - '0');
    if (j > i && j < len && line[j] == '%' && value <= 100) {
        *pct = value;
        i = j + 1;
        while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    }
    size_t cap = msg_cap > 0 ? msg_cap - 1 : 0;
    if (cap > SUPERVISOR_TEXT_MAX) cap = SUPERVISOR_TEXT_MAX;
    if (msg_cap > 0) Supervisor_CleanText(line + i, len - i, msg, cap);
    return true;
}

/* ---------------------------------------------------------------------------
 * State machine
 * ------------------------------------------------------------------------- */

static inline void Supervisor_Init(ScriptSupervisor* s, const ScriptSupervisorSettings* settings, int64_t now_ms) {
    memset(s, 0, sizeof(*s));
    s->settings = settings ? *settings : Supervisor_DefaultSettings();
    if (s->settings.idle_threshold_ms <= 0) s->settings.idle_threshold_ms = 180000;
    if (s->settings.sample_interval_ms <= 0) s->settings.sample_interval_ms = 5000;
    if (s->settings.heartbeat_interval_ms <= 0) s->settings.heartbeat_interval_ms = 30000;
    if (s->settings.min_post_gap_ms < 0) s->settings.min_post_gap_ms = 0;
    s->last_activity_ms = now_ms;
    s->last_sample_ms = now_ms;
    s->progress_pct = -1;
    s->phase = SUPERVISOR_PHASE_RUNNING;
    s->posted_phase = SUPERVISOR_PHASE_RUNNING;
}

static inline void Supervisor_MarkActive(ScriptSupervisor* s, int64_t now_ms) {
    s->last_activity_ms = now_ms;
    if (s->phase != SUPERVISOR_PHASE_RUNNING) {
        s->phase = SUPERVISOR_PHASE_RUNNING;
        s->window.present = false;
    }
}

static inline void Supervisor_EndLine(ScriptSupervisor* s) {
    size_t len = s->line_len;
    if (len > 0 && s->line[len - 1] == '\r') len--;
    int pct = -1;
    char msg[SUPERVISOR_TEXT_MAX + 1];
    if (Supervisor_ParseProgressLine(s->line, len, &pct, msg, sizeof(msg))) {
        if (pct >= 0) s->progress_pct = pct;
        memcpy(s->message, msg, sizeof(s->message));
        s->progress_dirty = true;
    }
    s->line_len = 0;
}

/* New output bytes: activity, and progress lines parsed across reads. */
static inline void Supervisor_FeedOutput(ScriptSupervisor* s, const char* data, size_t n, int64_t now_ms) {
    if (n == 0) return;
    Supervisor_MarkActive(s, now_ms);
    for (size_t i = 0; i < n; i++) {
        char c = data[i];
        if (c == '\n') {
            Supervisor_EndLine(s);
        } else if (s->line_len < sizeof(s->line)) {
            s->line[s->line_len++] = c;
        }
    }
}

static inline bool Supervisor_SampleDue(const ScriptSupervisor* s, int64_t now_ms) {
    return now_ms - s->last_sample_ms >= s->settings.sample_interval_ms;
}

static inline int64_t Supervisor_IdleMs(const ScriptSupervisor* s, int64_t now_ms) {
    int64_t idle = now_ms - s->last_activity_ms;
    return idle < 0 ? 0 : idle;
}

/* Takes a tree sample. Returns true when the job is idle past the threshold:
 * the caller then looks for a window (or not) and calls Supervisor_SetIdlePhase. */
static inline bool Supervisor_ApplySample(ScriptSupervisor* s, int64_t now_ms, const ScriptTreeSample* sample) {
    s->last_sample_ms = now_ms;
    if (s->have_sample) {
        /* Totals only fall when a process leaves the tree; restart the baseline. */
        bool cpu_up = sample->cpu_ms >= s->prev_cpu_ms && sample->cpu_ms - s->prev_cpu_ms >= SUPERVISOR_CPU_ACTIVITY_MS;
        bool io_up = sample->io_bytes >= s->prev_io_bytes && sample->io_bytes - s->prev_io_bytes >= SUPERVISOR_IO_ACTIVITY_BYTES;
        if (cpu_up || io_up) Supervisor_MarkActive(s, now_ms);
    }
    s->have_sample = true;
    s->prev_cpu_ms = sample->cpu_ms;
    s->prev_io_bytes = sample->io_bytes;
    s->last = *sample;
    if (Supervisor_IdleMs(s, now_ms) >= s->settings.idle_threshold_ms) return true;
    if (s->phase != SUPERVISOR_PHASE_RUNNING) {
        s->phase = SUPERVISOR_PHASE_RUNNING;
        s->window.present = false;
    }
    return false;
}

/* Idle past the threshold: needs_hands with a window, else stalled. */
static inline void Supervisor_SetIdlePhase(ScriptSupervisor* s, const ScriptSupervisorWindow* window) {
    if (window && window->present) {
        s->phase = SUPERVISOR_PHASE_NEEDS_HANDS;
        s->window = *window;
    } else {
        s->phase = SUPERVISOR_PHASE_STALLED;
        s->window.present = false;
    }
}

static inline const char* Supervisor_PhaseName(ScriptSupervisorPhase phase) {
    switch (phase) {
        case SUPERVISOR_PHASE_STALLED: return "stalled";
        case SUPERVISOR_PHASE_NEEDS_HANDS: return "needs_hands";
        default: return "running";
    }
}

/* First beat at once; then every heartbeat interval, or sooner (at most one
 * per gap) when the phase changed or a progress line arrived. */
static inline bool Supervisor_ShouldPost(const ScriptSupervisor* s, int64_t now_ms) {
    if (!s->posted_once) return true;
    int64_t since = now_ms - s->last_post_ms;
    if (since >= s->settings.heartbeat_interval_ms) return true;
    bool changed = s->phase != s->posted_phase || s->progress_dirty;
    return changed && since >= s->settings.min_post_gap_ms;
}

/* Builds the progress body and records it as posted. Returns its length, 0
 * when it did not fit. */
static inline size_t Supervisor_BuildPost(ScriptSupervisor* s, const char* job_id, const char* lease_id,
                                          int64_t now_ms, char* buf, size_t cap) {
    if (!buf || cap < 64) return 0;
    size_t len = 0;
    len += (size_t)snprintf(buf, cap, "{\"job_id\":");
    len = Supervisor_AppendJSONString(buf, len, cap, job_id ? job_id : "");
    if (len + 16 >= cap) return 0;
    len += (size_t)snprintf(buf + len, cap - len, ",\"lease_id\":");
    len = Supervisor_AppendJSONString(buf, len, cap, lease_id ? lease_id : "");
    if (len >= cap) return 0;
    int w = snprintf(buf + len, cap - len, ",\"phase\":\"%s\",\"progress_pct\":%d",
                     Supervisor_PhaseName(s->phase), s->progress_pct);
    if (w < 0 || (size_t)w >= cap - len) return 0;
    len += (size_t)w;
    if (s->message[0]) {
        if (len + 12 >= cap) return 0;
        len += (size_t)snprintf(buf + len, cap - len, ",\"message\":");
        len = Supervisor_AppendJSONString(buf, len, cap, s->message);
        if (len >= cap) return 0;
    }
    w = snprintf(buf + len, cap - len, ",\"cpu_ms\":%llu,\"io_bytes\":%llu,\"idle_seconds\":%lld,\"processes\":%u",
                 (unsigned long long)s->last.cpu_ms, (unsigned long long)s->last.io_bytes,
                 (long long)(Supervisor_IdleMs(s, now_ms) / 1000), (unsigned)s->last.processes);
    if (w < 0 || (size_t)w >= cap - len) return 0;
    len += (size_t)w;
    if (s->phase == SUPERVISOR_PHASE_NEEDS_HANDS && s->window.present) {
        if (len + 24 >= cap) return 0;
        len += (size_t)snprintf(buf + len, cap - len, ",\"window\":{\"title\":");
        len = Supervisor_AppendJSONString(buf, len, cap, s->window.title);
        if (len + 16 >= cap) return 0;
        len += (size_t)snprintf(buf + len, cap - len, ",\"process\":");
        len = Supervisor_AppendJSONString(buf, len, cap, s->window.process);
        if (len >= cap) return 0;
        w = snprintf(buf + len, cap - len, ",\"pid\":%u,\"session\":%u}", (unsigned)s->window.pid, (unsigned)s->window.session);
        if (w < 0 || (size_t)w >= cap - len) return 0;
        len += (size_t)w;
    }
    if (len + 2 > cap) return 0;
    buf[len++] = '}';
    buf[len] = '\0';

    s->posted_once = true;
    s->last_post_ms = now_ms;
    s->posted_phase = s->phase;
    s->progress_dirty = false;
    return len;
}

/* Builds and hands a heartbeat to hooks->post when one is due. */
static inline void Supervisor_MaybePost(ScriptSupervisor* s, const ScriptSupervisorHooks* hooks, int64_t now_ms) {
    if (!hooks || !hooks->post || !Supervisor_ShouldPost(s, now_ms)) return;
    char body[1536];
    if (Supervisor_BuildPost(s, hooks->job_id, hooks->lease_id, now_ms, body, sizeof(body)) > 0)
        hooks->post(hooks->ctx, body);
}

static inline bool Supervisor_CancelRequested(const ScriptSupervisorHooks* hooks) {
    return hooks && hooks->cancel_requested && hooks->cancel_requested(hooks->ctx);
}

/* The hub's reply {"ok":true,"cancel":true}: true when it asks for a cancel. */
static inline bool Supervisor_ReplyCancels(const char* reply) {
    if (!reply) return false;
    const char* p = strstr(reply, "\"cancel\"");
    if (!p) return false;
    p += 8;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != ':') return false;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return strncmp(p, "true", 4) == 0;
}

#endif /* OMINULL_SCRIPT_SUPERVISOR_H */
