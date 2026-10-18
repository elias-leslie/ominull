#ifndef OMINULL_SCRIPT_EXEC_LINUX_H
#define OMINULL_SCRIPT_EXEC_LINUX_H

/*
 * Ominull Linux Endpoint Script Execution Worker (Slice 5B).
 *
 * Implements:
 * - Strict interpreter allowlisting (/bin/sh, /bin/bash, pwsh).
 * - Bounded payload parsing (source up to 64 KiB, parameters up to 16 KiB).
 * - In-process SHA-256 verification of script source against signed script_digest.
 * - Parameter delivery via private file and sanitized environment (ZERO textual template substitution).
 * - Contained worker execution:
 *     - Dedicated process group (setpgid) for complete tree termination.
 *     - File descriptor isolation (close fd > 2).
 *     - Sanitized environment (clearenv).
 *     - Explicit safe working directory.
 *     - CPU resource bounding (RLIMIT_CPU).
 *     - Hard deadline timeout monitoring with SIGTERM -> SIGKILL escalation.
 * - Bounded stdout/stderr capture with honest truncation tracking.
 * - Complete automatic cleanup of temporary execution and parameter files.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>

#include <dirent.h>

#include "response_dispatcher.h"
#include "script_supervisor.h"

/* Where job scripts and their parameters are written: root-owned, never /tmp.
 * Tests point it at a private directory of their own. */
#ifndef OMINULL_SCRIPT_STATE_DIR
#define OMINULL_SCRIPT_STATE_DIR "/var/lib/ominull"
#endif
static const char* g_script_exec_state_dir = OMINULL_SCRIPT_STATE_DIR;

#define SCRIPT_EXEC_MAX_SOURCE_BYTES  65536  // 64 KiB
#define SCRIPT_EXEC_MAX_PARAMS_BYTES  16384  // 16 KiB
#define SCRIPT_EXEC_DEFAULT_TIMEOUT   60     // 60 seconds
#define SCRIPT_EXEC_MAX_TIMEOUT       3600   // 1 hour (hub: scripts.MaxTimeoutSeconds)
#define SCRIPT_EXEC_DEFAULT_MAX_OUT   1048576 // 1 MiB
#define SCRIPT_EXEC_MAX_MAX_OUT       5242880 // 5 MiB
#define SCRIPT_EXEC_MAX_PARAM_COUNT   64

typedef struct {
    char name[64];
    char value[2048];
} ScriptParamEntry;

typedef struct {
    char script_id[64];
    int  script_version;
    char script_digest[65];
    char interpreter[128];
    char source[SCRIPT_EXEC_MAX_SOURCE_BYTES];
    size_t source_len;
    char parameters_json[SCRIPT_EXEC_MAX_PARAMS_BYTES];
    size_t parameters_len;
    ScriptParamEntry params[SCRIPT_EXEC_MAX_PARAM_COUNT];
    size_t param_count;
    int  timeout_seconds;
    size_t max_output_bytes;
} ScriptExecParams;

/* ---------------------------------------------------------------------------
 * Interpreter Allowlist
 * ------------------------------------------------------------------------- */

static inline bool ScriptExec_IsAllowedInterpreter(const char* interpreter) {
    if (!interpreter || interpreter[0] == '\0') return false;
    if (strcmp(interpreter, "/bin/sh") == 0) return true;
    if (strcmp(interpreter, "/bin/bash") == 0) return true;
    if (strcmp(interpreter, "/usr/bin/sh") == 0) return true;
    if (strcmp(interpreter, "/usr/bin/bash") == 0) return true;
    if (strcmp(interpreter, "pwsh") == 0) return true;
    if (strcmp(interpreter, "/usr/bin/pwsh") == 0) return true;
    return false;
}

/* ---------------------------------------------------------------------------
 * JSON String & Parameter Parser Helpers
 * ------------------------------------------------------------------------- */

static inline bool ScriptExec_UnescapeJSONString(const char* src, size_t src_len, char* dst, size_t dst_cap, size_t* out_len) {
    size_t d = 0;
    for (size_t s = 0; s < src_len && d + 1 < dst_cap; s++) {
        if (src[s] == '\\' && s + 1 < src_len) {
            s++;
            switch (src[s]) {
                case '\"': dst[d++] = '\"'; break;
                case '\\': dst[d++] = '\\'; break;
                case '/':  dst[d++] = '/';  break;
                case 'b':  dst[d++] = '\b'; break;
                case 'f':  dst[d++] = '\f'; break;
                case 'n':  dst[d++] = '\n'; break;
                case 'r':  dst[d++] = '\r'; break;
                case 't':  dst[d++] = '\t'; break;
                case 'u': {
                    if (s + 4 < src_len) {
                        char hex_buf[5] = { src[s+1], src[s+2], src[s+3], src[s+4], '\0' };
                        unsigned int codepoint = 0;
                        if (sscanf(hex_buf, "%x", &codepoint) == 1) {
                            s += 4;
                            if (codepoint < 0x80) {
                                dst[d++] = (char)codepoint;
                            } else if (codepoint < 0x800 && d + 2 < dst_cap) {
                                dst[d++] = (char)(0xC0 | (codepoint >> 6));
                                dst[d++] = (char)(0x80 | (codepoint & 0x3F));
                            } else if (d + 3 < dst_cap) {
                                dst[d++] = (char)(0xE0 | (codepoint >> 12));
                                dst[d++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
                                dst[d++] = (char)(0x80 | (codepoint & 0x3F));
                            }
                        } else {
                            dst[d++] = src[s];
                        }
                    } else {
                        dst[d++] = src[s];
                    }
                    break;
                }
                default:
                    dst[d++] = src[s];
                    break;
            }
        } else {
            dst[d++] = src[s];
        }
    }
    dst[d] = '\0';
    if (out_len) *out_len = d;
    return true;
}

static inline void ScriptExec_ParseParametersObject(const char* json_obj, ScriptParamEntry* entries, size_t max_entries, size_t* out_count) {
    if (!json_obj || !entries || !out_count) return;
    *out_count = 0;

    const char* p = strchr(json_obj, '{');
    if (!p) return;
    p++;

    while (*p && *p != '}' && *out_count < max_entries) {
        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
        if (*p != '\"') break;
        p++;

        // Read parameter key
        const char* key_start = p;
        while (*p && *p != '\"') p++;
        if (*p != '\"') break;
        size_t key_len = p - key_start;
        p++; // skip closing quote

        while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;

        // Read parameter value
        char val_buf[2048] = {0};
        size_t val_len = 0;
        if (*p == '\"') {
            p++;
            const char* val_start = p;
            while (*p && !(*p == '\"' && *(p - 1) != '\\')) p++;
            size_t raw_len = p - val_start;
            if (*p == '\"') p++;
            ScriptExec_UnescapeJSONString(val_start, raw_len, val_buf, sizeof(val_buf), &val_len);
        } else {
            // number or boolean
            const char* val_start = p;
            while (*p && *p != ',' && *p != '}' && !isspace((unsigned char)*p)) p++;
            val_len = p - val_start;
            if (val_len >= sizeof(val_buf)) val_len = sizeof(val_buf) - 1;
            strncpy(val_buf, val_start, val_len);
            val_buf[val_len] = '\0';
        }

        if (key_len > 0 && key_len < sizeof(entries[*out_count].name)) {
            snprintf(entries[*out_count].name, sizeof(entries[*out_count].name), "%.*s", (int)key_len, key_start);
            snprintf(entries[*out_count].value, sizeof(entries[*out_count].value), "%s", val_buf);
            (*out_count)++;
        }

        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
    }
}

/* ---------------------------------------------------------------------------
 * Payload Parser
 * ------------------------------------------------------------------------- */

static inline bool ScriptExec_ParsePayload(const char* json, ScriptExecParams* out) {
    if (!json || !out) return false;
    memset(out, 0, sizeof(*out));
    out->timeout_seconds = SCRIPT_EXEC_DEFAULT_TIMEOUT;
    out->max_output_bytes = SCRIPT_EXEC_DEFAULT_MAX_OUT;
    strncpy(out->interpreter, "/bin/sh", sizeof(out->interpreter) - 1);

    // 1. script_id
    const char* p = strstr(json, "\"script_id\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '\"');
            if (p) {
                p++;
                const char* end = strchr(p, '\"');
                if (end && (size_t)(end - p) < sizeof(out->script_id)) {
                    strncpy(out->script_id, p, end - p);
                    out->script_id[end - p] = '\0';
                }
            }
        }
    }

    // 2. script_version
    p = strstr(json, "\"script_version\"");
    if (!p) p = strstr(json, "\"version\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            out->script_version = atoi(p + 1);
        }
    }

    // 3. script_digest
    p = strstr(json, "\"script_digest\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '\"');
            if (p) {
                p++;
                const char* end = strchr(p, '\"');
                if (end && (size_t)(end - p) < sizeof(out->script_digest)) {
                    strncpy(out->script_digest, p, end - p);
                    out->script_digest[end - p] = '\0';
                }
            }
        }
    }

    // 4. interpreter
    p = strstr(json, "\"interpreter\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '\"');
            if (p) {
                p++;
                const char* end = strchr(p, '\"');
                if (end && (size_t)(end - p) < sizeof(out->interpreter)) {
                    strncpy(out->interpreter, p, end - p);
                    out->interpreter[end - p] = '\0';
                }
            }
        }
    }

    // 5. source (escaped string)
    p = strstr(json, "\"source\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '\"');
            if (p) {
                p++;
                const char* s = p;
                while (*s) {
                    if (*s == '\"' && *(s - 1) != '\\') break;
                    s++;
                }
                if (*s == '\"') {
                    size_t raw_len = s - p;
                    ScriptExec_UnescapeJSONString(p, raw_len, out->source, sizeof(out->source), &out->source_len);
                }
            }
        }
    }

    // 6. parameters
    p = strstr(json, "\"parameters\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p++;
            while (*p && isspace((unsigned char)*p)) p++;
            if (*p == '{') {
                const char* obj_start = p;
                int depth = 0;
                while (*p) {
                    if (*p == '{') depth++;
                    else if (*p == '}') {
                        depth--;
                        if (depth == 0) {
                            p++;
                            break;
                        }
                    }
                    p++;
                }
                size_t obj_len = p - obj_start;
                if (obj_len < sizeof(out->parameters_json)) {
                    strncpy(out->parameters_json, obj_start, obj_len);
                    out->parameters_json[obj_len] = '\0';
                    out->parameters_len = obj_len;
                    ScriptExec_ParseParametersObject(out->parameters_json, out->params, SCRIPT_EXEC_MAX_PARAM_COUNT, &out->param_count);
                }
            }
        }
    }

    // 7. timeout_seconds
    p = strstr(json, "\"timeout_seconds\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            int t = atoi(p + 1);
            if (t > 0 && t <= SCRIPT_EXEC_MAX_TIMEOUT) out->timeout_seconds = t;
        }
    }

    // 8. max_output_bytes
    p = strstr(json, "\"max_output_bytes\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            long long mb = atoll(p + 1);
            if (mb > 0 && (size_t)mb <= SCRIPT_EXEC_MAX_MAX_OUT) out->max_output_bytes = (size_t)mb;
        }
    }

    return (out->source_len > 0);
}

/* ---------------------------------------------------------------------------
 * JSON Escaping Helper
 * ------------------------------------------------------------------------- */

static inline char* ScriptExec_EscapeJSON(const char* str) {
    if (!str) return strdup("");
    size_t len = strlen(str);
    size_t cap = len * 4 + 16;
    char* buf = (char*)malloc(cap);
    if (!buf) return NULL;

    size_t d = 0;
    for (size_t s = 0; s < len; s++) {
        unsigned char c = (unsigned char)str[s];
        if (c == '\"') {
            buf[d++] = '\\'; buf[d++] = '\"';
        } else if (c == '\\') {
            buf[d++] = '\\'; buf[d++] = '\\';
        } else if (c == '\b') {
            buf[d++] = '\\'; buf[d++] = 'b';
        } else if (c == '\f') {
            buf[d++] = '\\'; buf[d++] = 'f';
        } else if (c == '\n') {
            buf[d++] = '\\'; buf[d++] = 'n';
        } else if (c == '\r') {
            buf[d++] = '\\'; buf[d++] = 'r';
        } else if (c == '\t') {
            buf[d++] = '\\'; buf[d++] = 't';
        } else if (c < 0x20) {
            d += snprintf(buf + d, cap - d, "\\u%04x", c);
        } else {
            buf[d++] = (char)c;
        }
        if (d + 8 >= cap) {
            cap *= 2;
            char* new_buf = (char*)realloc(buf, cap);
            if (!new_buf) {
                free(buf);
                return NULL;
            }
            buf = new_buf;
        }
    }
    buf[d] = '\0';
    return buf;
}

/* ---------------------------------------------------------------------------
 * Process tree sampling (/proc) for the supervisor (script_supervisor.h)
 * ------------------------------------------------------------------------- */

static inline int64_t ScriptExec_NowMs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Reads the process group, state and CPU ticks (own + reaped children) of one
 * process. */
static inline bool ScriptExec_ReadProcStat(const char* pid, long* pgrp, char* state, uint64_t* ticks) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/stat", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    /* The command name may hold spaces and parentheses: fields start after
     * the last ')'. Field 3 is state, 5 pgrp, 14-17 utime stime cutime cstime. */
    char* p = strrchr(buf, ')');
    if (!p) return false;
    p++;
    char st = 0;
    long ppid = 0, grp = 0, session = 0, tty = 0, tpgid = 0;
    unsigned long flags = 0, minflt = 0, cminflt = 0, majflt = 0, cmajflt = 0;
    unsigned long long utime = 0, stime = 0;
    long long cutime = 0, cstime = 0;
    if (sscanf(p, " %c %ld %ld %ld %ld %ld %lu %lu %lu %lu %lu %llu %llu %lld %lld",
               &st, &ppid, &grp, &session, &tty, &tpgid, &flags, &minflt, &cminflt, &majflt, &cmajflt,
               &utime, &stime, &cutime, &cstime) != 15)
        return false;
    *pgrp = grp;
    *state = st;
    *ticks = utime + stime + (uint64_t)(cutime > 0 ? cutime : 0) + (uint64_t)(cstime > 0 ? cstime : 0);
    return true;
}

/* read_bytes + write_bytes from /proc/<pid>/io (rchar + wchar when those are
 * missing); 0 when unreadable. */
static inline uint64_t ScriptExec_ReadProcIO(const char* pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/io", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    unsigned long long rchar = 0, wchar = 0, rb = 0, wb = 0;
    bool have_rb = false, have_wb = false;
    for (char* line = buf; line && *line; ) {
        char* next = strchr(line, '\n');
        if (next) *next++ = '\0';
        if (sscanf(line, "rchar: %llu", &rchar) == 1) {}
        else if (sscanf(line, "wchar: %llu", &wchar) == 1) {}
        else if (sscanf(line, "read_bytes: %llu", &rb) == 1) have_rb = true;
        else if (sscanf(line, "write_bytes: %llu", &wb) == 1) have_wb = true;
        line = next;
    }
    if (have_rb || have_wb) return rb + wb;
    return rchar + wchar;
}

/* Sums the job's process group: every /proc entry whose pgrp is pgid. Zombies
 * count toward CPU but not as live processes. */
static inline void ScriptExec_SampleTree(pid_t pgid, ScriptTreeSample* out) {
    memset(out, 0, sizeof(*out));
    static long tick_hz = 0;
    if (tick_hz <= 0) tick_hz = sysconf(_SC_CLK_TCK);
    if (tick_hz <= 0) tick_hz = 100;
    DIR* dir = opendir("/proc");
    if (!dir) return;
    uint64_t ticks_total = 0;
    struct dirent* de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        long grp = 0;
        char state = 0;
        uint64_t ticks = 0;
        if (!ScriptExec_ReadProcStat(de->d_name, &grp, &state, &ticks) || grp != (long)pgid) continue;
        ticks_total += ticks;
        if (state != 'Z' && state != 'X') {
            out->processes++;
            out->io_bytes += ScriptExec_ReadProcIO(de->d_name);
        }
    }
    closedir(dir);
    out->cpu_ms = ticks_total * 1000 / (uint64_t)tick_hz;
}

/* Ends every process left in the group: SIGTERM, up to 250 ms for them to go,
 * then SIGKILL. The leader must still be unreaped (a zombie keeps the group id
 * from being reused). */
static inline void ScriptExec_KillGroup(pid_t pgid) {
    ScriptTreeSample s;
    ScriptExec_SampleTree(pgid, &s);
    if (s.processes == 0) return;
    if (kill(-pgid, SIGTERM) != 0) return;
    for (int i = 0; i < 10; i++) {
        usleep(25000);
        ScriptExec_SampleTree(pgid, &s);
        if (s.processes == 0) return;
    }
    kill(-pgid, SIGKILL);
}

/* Appends one read to the capture (up to limit bytes) and to the supervisor. */
static inline void ScriptExec_TakeOutput(const char* chunk, size_t n, char* output_buf, size_t* bytes_read,
                                         size_t limit, bool* truncated, ScriptSupervisor* sup, int64_t now_ms) {
    if (*bytes_read + n <= limit) {
        memcpy(output_buf + *bytes_read, chunk, n);
        *bytes_read += n;
    } else {
        size_t room = limit > *bytes_read ? limit - *bytes_read : 0;
        if (room > 0) {
            memcpy(output_buf + *bytes_read, chunk, room);
            *bytes_read += room;
        }
        *truncated = true;
    }
    Supervisor_FeedOutput(sup, chunk, n, now_ms);
}

/* Reads what the pipe holds now. Returns false once it is at EOF or broken. */
static inline bool ScriptExec_DrainReady(int fd, char* output_buf, size_t* bytes_read, size_t limit,
                                         bool* truncated, ScriptSupervisor* sup) {
    char chunk[4096];
    for (;;) {
        ssize_t n = read(fd, chunk, sizeof(chunk));
        if (n > 0) {
            ScriptExec_TakeOutput(chunk, (size_t)n, output_buf, bytes_read, limit, truncated, sup, ScriptExec_NowMs());
            continue;
        }
        if (n == 0) return false;
        if (errno == EINTR) continue;
        return errno == EAGAIN || errno == EWOULDBLOCK;
    }
}

/* ---------------------------------------------------------------------------
 * Contained Worker Execution
 * ------------------------------------------------------------------------- */

/* Runs one script job under the supervisor: heartbeats through hooks (NULL:
 * none), hang detection, cancel, and the whole process group cleaned up
 * however it ends. Returns the exit code (124 timed out, 130 cancelled). */
static inline int ScriptExec_RunSupervised(
    const ScriptExecParams* params,
    const char* job_id,
    char* output_buf,
    size_t output_cap,
    const ScriptSupervisorHooks* hooks,
    ScriptRunResult* result
) {
    if (result) memset(result, 0, sizeof(*result));
    if (!params || !job_id || !output_buf || output_cap == 0) return -1;
    output_buf[0] = '\0';

    // 1. Verify interpreter allowlist
    if (!ScriptExec_IsAllowedInterpreter(params->interpreter)) {
        snprintf(output_buf, output_cap, "Error: interpreter '%s' is not in allowlist", params->interpreter);
        return 126;
    }

    // 2. In-Process SHA-256 Digest Verification
    if (params->script_digest[0] != '\0') {
        uint8_t hash[32];
        char hex[65];
        Response_SHA256_Sum((const uint8_t*)params->source, params->source_len, hash);
        Response_BytesToHex(hash, 32, hex);
        if (strcasecmp(hex, params->script_digest) != 0) {
            snprintf(output_buf, output_cap, "Error: script source digest mismatch (expected %s, got %s)", params->script_digest, hex);
            return 125;
        }
    }

    // 3. The state directory. There is no fallback: /tmp is writable by every
    // account, and a planted symlink there would turn this root write into a
    // clobber of any file. A missing or loose directory fails the job.
    const char* state_dir = g_script_exec_state_dir;
    struct stat st;
    if (lstat(state_dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        snprintf(output_buf, output_cap, "Error: script state directory %s is missing or not private to this agent", state_dir);
        return 1;
    }

    // 4. Create secure script file (mode 0700). A stale file from a crashed
    // job is removed; the new one is created exclusively and never followed.
    char script_path[256];
    snprintf(script_path, sizeof(script_path), "%s/ominull_script_%s.sh", state_dir, job_id);
    unlink(script_path);
    int sfd = open(script_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0700);
    if (sfd < 0) {
        snprintf(output_buf, output_cap, "Error: failed to create temporary script file: %s", strerror(errno));
        return 1;
    }
    ssize_t written = write(sfd, params->source, params->source_len);
    close(sfd);
    if (written < 0 || (size_t)written != params->source_len) {
        unlink(script_path);
        snprintf(output_buf, output_cap, "Error: failed to write script content: %s", strerror(errno));
        return 1;
    }

    // 5. Create secure parameter file (mode 0600)
    char params_path[256];
    snprintf(params_path, sizeof(params_path), "%s/ominull_params_%s.json", state_dir, job_id);
    unlink(params_path);
    int pfd = open(params_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (pfd >= 0) {
        const char* pcontent = params->parameters_len > 0 ? params->parameters_json : "{}";
        ssize_t pw = write(pfd, pcontent, strlen(pcontent));
        (void)pw;
        close(pfd);
    }

    // 6. Setup stdout/stderr capture pipe
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        unlink(script_path);
        unlink(params_path);
        snprintf(output_buf, output_cap, "Error: pipe() failed: %s", strerror(errno));
        return 1;
    }

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    // Save and temporarily restore SIGCHLD default handler
    struct sigaction sa_old, sa_dfl;
    memset(&sa_dfl, 0, sizeof(sa_dfl));
    sa_dfl.sa_handler = SIG_DFL;
    sigaction(SIGCHLD, &sa_dfl, &sa_old);

    // 7. Fork contained worker process
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        close(pipefd[0]);

        // Redirect stdout & stderr to pipe
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        // Dedicated process group for tree-containment
        setpgid(0, 0);

        // Close inherited descriptors > 2
        for (int fd = 3; fd < 1024; fd++) {
            close(fd);
        }

        // Sanitized environment
        clearenv();
        setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", 1);
        setenv("HOME", state_dir, 1);
        setenv("USER", "root", 1);
        setenv("LANG", "C.UTF-8", 1);
        setenv("OMINULL_JOB_ID", job_id, 1);
        setenv("OMINULL_SCRIPT_ID", params->script_id, 1);
        char ver_buf[32];
        snprintf(ver_buf, sizeof(ver_buf), "%d", params->script_version);
        setenv("OMINULL_SCRIPT_VERSION", ver_buf, 1);
        setenv("OMINULL_PARAMS_FILE", params_path, 1);

        // Export individual parameters as OMINULL_PARAM_<NAME>, OMINULL_PARAM_<UPPER_NAME>, and <NAME>
        for (size_t i = 0; i < params->param_count; i++) {
            char env_name[128];
            snprintf(env_name, sizeof(env_name), "OMINULL_PARAM_%s", params->params[i].name);
            setenv(env_name, params->params[i].value, 1);
            char upper_name[64];
            size_t k = 0;
            for (; k < sizeof(upper_name) - 1 && params->params[i].name[k]; k++) {
                upper_name[k] = (char)toupper((unsigned char)params->params[i].name[k]);
            }
            upper_name[k] = '\0';
            char upper_env[128];
            snprintf(upper_env, sizeof(upper_env), "OMINULL_PARAM_%s", upper_name);
            setenv(upper_env, params->params[i].value, 1);
            setenv(params->params[i].name, params->params[i].value, 1);
        }

        // Safe working directory
        if (chdir(state_dir) != 0) {
            if (chdir("/tmp") != 0) {
                if (chdir("/") != 0) {}
            }
        }

        // CPU limit bounding
        struct rlimit rl;
        rl.rlim_cur = params->timeout_seconds + 5;
        rl.rlim_max = params->timeout_seconds + 5;
        setrlimit(RLIMIT_CPU, &rl);

        // Execute script
        execl(params->interpreter, params->interpreter, script_path, (char*)NULL);
        _exit(127);
    }

    if (pid < 0) {
        sigaction(SIGCHLD, &sa_old, NULL);
        close(pipefd[0]);
        close(pipefd[1]);
        unlink(script_path);
        unlink(params_path);
        snprintf(output_buf, output_cap, "Error: fork() failed: %s", strerror(errno));
        return 1;
    }

    // Parent process
    close(pipefd[1]);
    /* Also from this side, so the group exists before the first sample. */
    setpgid(pid, pid);

    // Set non-blocking on pipe read end
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    size_t bytes_read = 0;
    size_t limit = params->max_output_bytes < output_cap ? params->max_output_bytes : output_cap - 1;
    bool truncated = false;
    bool timed_out = false;
    bool cancelled = false;
    bool pipe_open = true;

    int64_t loop_start = ScriptExec_NowMs();
    int64_t timeout_ms = (int64_t)params->timeout_seconds * 1000;
    ScriptSupervisor sup;
    Supervisor_Init(&sup, hooks ? &hooks->settings : NULL, loop_start);
    if (hooks && hooks->post) {
        ScriptTreeSample first;
        ScriptExec_SampleTree(pid, &first);
        Supervisor_ApplySample(&sup, loop_start, &first);
    }
    Supervisor_MaybePost(&sup, hooks, loop_start);

    /* Runs until the script exits, times out or is cancelled. The script
     * closing its output is not the end: the deadline and a cancel still
     * apply while it runs on with stdout gone. */
    for (;;) {
        int64_t now = ScriptExec_NowMs();
        if (now - loop_start >= timeout_ms) {
            timed_out = true;
            break;
        }
        if (Supervisor_CancelRequested(hooks)) {
            cancelled = true;
            break;
        }

        int wait_ms = (int)(timeout_ms - (now - loop_start));
        if (wait_ms > 100) wait_ms = 100;
        if (wait_ms <= 0) wait_ms = 1;
        if (pipe_open) {
            struct pollfd pfd_in = { .fd = pipefd[0], .events = POLLIN, .revents = 0 };
            int pr = poll(&pfd_in, 1, wait_ms);
            if (pr > 0)
                pipe_open = ScriptExec_DrainReady(pipefd[0], output_buf, &bytes_read, limit, &truncated, &sup);
        } else {
            usleep((useconds_t)wait_ms * 1000);
        }

        /* Exited? Looked at without reaping: the zombie holds the group id
         * until the leftovers in the group are killed below. */
        siginfo_t si;
        memset(&si, 0, sizeof(si));
        if (waitid(P_PID, (id_t)pid, &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == pid)
            break;

        now = ScriptExec_NowMs();
        if (Supervisor_SampleDue(&sup, now)) {
            ScriptTreeSample sample;
            ScriptExec_SampleTree(pid, &sample);
            if (Supervisor_ApplySample(&sup, now, &sample))
                Supervisor_SetIdlePhase(&sup, NULL);   /* no windows on Linux */
        }
        Supervisor_MaybePost(&sup, hooks, now);
    }

    /* Whatever is still ready, then the rest of the group (background
     * children of a finished script, or the whole tree on timeout/cancel),
     * then the pipe to EOF with a deadline: a process that left the group
     * could hold it open for ever. */
    if (pipe_open)
        pipe_open = ScriptExec_DrainReady(pipefd[0], output_buf, &bytes_read, limit, &truncated, &sup);
    ScriptExec_KillGroup(pid);
    int64_t drain_deadline = ScriptExec_NowMs() + 1000;
    while (pipe_open && ScriptExec_NowMs() < drain_deadline) {
        struct pollfd pfd_in = { .fd = pipefd[0], .events = POLLIN, .revents = 0 };
        if (poll(&pfd_in, 1, 50) > 0)
            pipe_open = ScriptExec_DrainReady(pipefd[0], output_buf, &bytes_read, limit, &truncated, &sup);
    }

    close(pipefd[0]);
    output_buf[bytes_read] = '\0';

    int status = 0;
    int exit_code = 1;
    pid_t reaped;
    while ((reaped = waitpid(pid, &status, 0)) < 0 && errno == EINTR) { }
    if (timed_out) {
        exit_code = 124; // standard command timeout exit status
    } else if (cancelled) {
        exit_code = 130;
    } else if (reaped == pid) {
        if (WIFEXITED(status)) {
            exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            exit_code = 128 + WTERMSIG(status);
        }
    }
    sigaction(SIGCHLD, &sa_old, NULL);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    int64_t duration_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000 +
                          (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000;
    if (duration_ms < 0) duration_ms = 0;

    // Append truncation marker if needed
    if (truncated) {
        static const char trunc_msg[] = "\n[... output truncated at byte limit ...]\n";
        if (bytes_read + sizeof(trunc_msg) < output_cap) {
            strcat(output_buf, trunc_msg);
        }
    }
    if (result) {
        result->truncated = truncated;
        result->timed_out = timed_out;
        result->cancelled = cancelled;
        result->duration_ms = duration_ms;
    }

    // Unlink temporary execution files
    unlink(script_path);
    unlink(params_path);

    return exit_code;
}

/* The unsupervised form: no heartbeats, default timings. */
static inline int ScriptExec_RunContained(
    const ScriptExecParams* params,
    const char* job_id,
    char* output_buf,
    size_t output_cap,
    bool* out_truncated,
    bool* out_timed_out,
    int64_t* out_duration_ms
) {
    ScriptRunResult r;
    int code = ScriptExec_RunSupervised(params, job_id, output_buf, output_cap, NULL, &r);
    if (out_truncated) *out_truncated = r.truncated;
    if (out_timed_out) *out_timed_out = r.timed_out;
    if (out_duration_ms) *out_duration_ms = r.duration_ms;
    return code;
}

#endif /* OMINULL_SCRIPT_EXEC_LINUX_H */
