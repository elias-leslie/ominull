/*
 * Ominull Linux Endpoint Process Lineage, Boot Identity, & Executable Hashing
 *
 * Implements bounded /proc inspection, boot identity binding, process instance ID
 * generation, command line extraction, and in-process executable hashing with LRU caching.
 */

#ifndef OMINULL_PROCESS_LINEAGE_LINUX_H
#define OMINULL_PROCESS_LINEAGE_LINUX_H

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "response_dispatcher.h"

#ifndef OMINULL_PROC_ROOT
#define OMINULL_PROC_ROOT "/proc"
#endif

#define LINUX_HASH_CACHE_CAP 512
#define LINUX_MAX_HASH_BYTES (64 * 1024 * 1024) // 64 MiB max hash cap

typedef struct {
    uint32_t pid;
    uint32_t ppid;
    char process_instance_id[128];
    char parent_process_instance_id[128];
    char command_line[1024];
    char user_identity[64];
    char executable_sha256[65];
    char attribution_status[32]; // authoritative, inferred_cached, race_suspected, permission_denied, unknown
    int64_t observed_at;
} PROCESS_ENRICHMENT;

typedef struct {
    dev_t dev;
    ino_t ino;
    off_t size;
    time_t mtime;
    char sha256_hex[65];
    uint64_t last_used;
    bool valid;
} LINUX_HASH_CACHE_ENTRY;

static LINUX_HASH_CACHE_ENTRY g_LinuxHashCache[LINUX_HASH_CACHE_CAP];
static uint64_t g_LinuxHashAccessCounter = 0;
static char g_LinuxCachedBootID[64] = {0};

/* Formats a path under OMINULL_PROC_ROOT */
static inline void ProcessLineage_ProcPath(char* out, size_t outLen, const char* suffix) {
    snprintf(out, outLen, "%s/%s", OMINULL_PROC_ROOT, suffix);
}

/* Captures or returns the system boot UUID */
static inline const char* ProcessLineage_GetBootID(void) {
    if (g_LinuxCachedBootID[0] != '\0') {
        return g_LinuxCachedBootID;
    }

    // 1. Try /proc/sys/kernel/random/boot_id
    char bootPath[256];
    ProcessLineage_ProcPath(bootPath, sizeof(bootPath), "sys/kernel/random/boot_id");
    int fd = open(bootPath, O_RDONLY);
    if (fd < 0 && strcmp(OMINULL_PROC_ROOT, "/proc") != 0) {
        // Fallback to real system boot_id if fixture didn't mock sys
        fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    }

    if (fd >= 0) {
        char buf[64] = {0};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            // Trim whitespace/newlines
            for (ssize_t i = n - 1; i >= 0 && (buf[i] == '\n' || buf[i] == '\r' || buf[i] == ' '); i--) {
                buf[i] = '\0';
            }
            if (strlen(buf) > 0) {
                snprintf(g_LinuxCachedBootID, sizeof(g_LinuxCachedBootID), "%s", buf);
                return g_LinuxCachedBootID;
            }
        }
    }

    // 2. Fallback: Parse btime from /proc/stat
    char statPath[256];
    ProcessLineage_ProcPath(statPath, sizeof(statPath), "stat");
    FILE* fp = fopen(statPath, "r");
    if (!fp && strcmp(OMINULL_PROC_ROOT, "/proc") != 0) {
        fp = fopen("/proc/stat", "r");
    }
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "btime ", 6) == 0) {
                unsigned long btime = 0;
                if (sscanf(line + 6, "%lu", &btime) == 1 && btime > 0) {
                    snprintf(g_LinuxCachedBootID, sizeof(g_LinuxCachedBootID), "btime-%lu", btime);
                    fclose(fp);
                    return g_LinuxCachedBootID;
                }
            }
        }
        fclose(fp);
    }

    // 3. Fallback: Host root inode stat
    struct stat rootSt;
    if (stat("/", &rootSt) == 0) {
        snprintf(g_LinuxCachedBootID, sizeof(g_LinuxCachedBootID), "root-%lu-%lu", (unsigned long)rootSt.st_dev, (unsigned long)rootSt.st_ino);
        return g_LinuxCachedBootID;
    }

    snprintf(g_LinuxCachedBootID, sizeof(g_LinuxCachedBootID), "boot-unknown");
    return g_LinuxCachedBootID;
}

/* Reads process starttime (field 22) and PPID (field 4) from /proc/<pid>/stat */
static inline bool ProcessLineage_ReadStat(uint32_t pid, unsigned long long* outStartTime, uint32_t* outPPID) {
    if (!outStartTime || !outPPID) return false;
    *outStartTime = 0;
    *outPPID = 0;

    char statSuffix[64];
    char statPath[256];
    snprintf(statSuffix, sizeof(statSuffix), "%u/stat", pid);
    ProcessLineage_ProcPath(statPath, sizeof(statPath), statSuffix);

    FILE* fp = fopen(statPath, "r");
    if (!fp) return false;

    char line[1024];
    bool ok = fgets(line, sizeof(line), fp) != NULL;
    fclose(fp);
    if (!ok) return false;

    // The comm field is enclosed in parentheses and may contain spaces or ')'.
    // The last ')' is the canonical delimiter.
    char* fields = strrchr(line, ')');
    if (!fields) return false;
    fields++;

    char* save = NULL;
    char* token = strtok_r(fields, " ", &save);
    int field = 3; // field 1 = pid, field 2 = comm, field 3 = state
    bool gotPPID = false;
    bool gotStart = false;

    while (token) {
        if (field == 4) { // field 4 = ppid
            char* end = NULL;
            unsigned long ppidVal = strtoul(token, &end, 10);
            if (end != token && ppidVal <= UINT32_MAX) {
                *outPPID = (uint32_t)ppidVal;
                gotPPID = true;
            }
        } else if (field == 22) { // field 22 = starttime
            char* end = NULL;
            unsigned long long startVal = strtoull(token, &end, 10);
            if (end != token) {
                *outStartTime = startVal;
                gotStart = true;
                break;
            }
        }
        field++;
        token = strtok_r(NULL, " ", &save);
    }

    return gotStart && gotPPID;
}

/* Reads space-separated arguments from /proc/<pid>/cmdline */
static inline bool ProcessLineage_ReadCmdline(uint32_t pid, char* outCmdline, size_t maxLen) {
    if (!outCmdline || maxLen == 0) return false;
    outCmdline[0] = '\0';

    char cmdSuffix[64];
    char cmdPath[256];
    snprintf(cmdSuffix, sizeof(cmdSuffix), "%u/cmdline", pid);
    ProcessLineage_ProcPath(cmdPath, sizeof(cmdPath), cmdSuffix);

    int fd = open(cmdPath, O_RDONLY);
    if (fd < 0) return false;

    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return false;
    }
    buf[n] = '\0';

    // Replace interior '\0' bytes with ' '
    size_t outPos = 0;
    for (ssize_t i = 0; i < n && outPos < maxLen - 1; i++) {
        if (buf[i] == '\0') {
            if (i + 1 < n && buf[i + 1] != '\0') {
                outCmdline[outPos++] = ' ';
            }
        } else {
            outCmdline[outPos++] = buf[i];
        }
    }
    outCmdline[outPos] = '\0';
    return true;
}

/* Reads process user identity from /proc/<pid>/status */
static inline bool ProcessLineage_ReadUser(uint32_t pid, char* outUser, size_t maxLen) {
    if (!outUser || maxLen == 0) return false;
    outUser[0] = '\0';

    char statusSuffix[64];
    char statusPath[256];
    snprintf(statusSuffix, sizeof(statusSuffix), "%u/status", pid);
    ProcessLineage_ProcPath(statusPath, sizeof(statusPath), statusSuffix);

    FILE* fp = fopen(statusPath, "r");
    if (!fp) return false;

    char line[256];
    uid_t uid = (uid_t)-1;
    bool foundUID = false;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            unsigned int realUID = 0;
            if (sscanf(line + 4, "%u", &realUID) == 1) {
                uid = (uid_t)realUID;
                foundUID = true;
                break;
            }
        }
    }
    fclose(fp);

    if (!foundUID) return false;

    if (uid == 0) {
        snprintf(outUser, maxLen, "root");
        return true;
    }

    // Lookup username via getpwuid_r
    struct passwd pwd;
    struct passwd* result = NULL;
    char pwdBuf[1024];
    if (getpwuid_r(uid, &pwd, pwdBuf, sizeof(pwdBuf), &result) == 0 && result && result->pw_name) {
        snprintf(outUser, maxLen, "%s", result->pw_name);
        return true;
    }

    snprintf(outUser, maxLen, "UID:%u", (unsigned int)uid);
    return true;
}

/* Reset hash cache (useful for test teardown) */
static inline void ProcessLineage_ResetCache(void) {
    memset(g_LinuxHashCache, 0, sizeof(g_LinuxHashCache));
    g_LinuxHashAccessCounter = 0;
    g_LinuxCachedBootID[0] = '\0';
}

/* Sets a mock boot ID for deterministic testing */
static inline void ProcessLineage_SetBootIDForTesting(const char* bootID) {
    if (!bootID) {
        g_LinuxCachedBootID[0] = '\0';
    } else {
        snprintf(g_LinuxCachedBootID, sizeof(g_LinuxCachedBootID), "%s", bootID);
    }
}

/* Computes or looks up executable SHA-256 with LRU caching and size bounding */
static inline bool ProcessLineage_HashExecutable(uint32_t pid, char* outHex, size_t maxLen, char* outStatus, size_t statusLen) {
    if (!outHex || maxLen < 65 || !outStatus || statusLen == 0) return false;
    outHex[0] = '\0';
    snprintf(outStatus, statusLen, "unknown");

    char exeSuffix[64];
    char exePath[256];
    snprintf(exeSuffix, sizeof(exeSuffix), "%u/exe", pid);
    ProcessLineage_ProcPath(exePath, sizeof(exePath), exeSuffix);

    // Safely open executable without following symlinks where possible
    int fd = open(exePath, O_RDONLY);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) {
            snprintf(outStatus, statusLen, "permission_denied");
        } else if (errno == ENOENT) {
            snprintf(outStatus, statusLen, "race_suspected");
        } else {
            snprintf(outStatus, statusLen, "unknown");
        }
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        snprintf(outStatus, statusLen, "unknown");
        return false;
    }

    if ((uint64_t)st.st_size > LINUX_MAX_HASH_BYTES) {
        close(fd);
        snprintf(outStatus, statusLen, "unknown");
        return false;
    }

    // 1. Check LRU Cache by dev + ino + size + mtime
    uint64_t nowAccess = ++g_LinuxHashAccessCounter;
    for (size_t i = 0; i < LINUX_HASH_CACHE_CAP; i++) {
        LINUX_HASH_CACHE_ENTRY* entry = &g_LinuxHashCache[i];
        if (entry->valid && entry->dev == st.st_dev && entry->ino == st.st_ino &&
            entry->size == st.st_size && entry->mtime == st.st_mtime) {
            close(fd);
            entry->last_used = nowAccess;
            snprintf(outHex, maxLen, "%s", entry->sha256_hex);
            snprintf(outStatus, statusLen, "inferred_cached");
            return true;
        }
    }

    // 2. Cache Miss: Compute SHA-256 over file contents up to LINUX_MAX_HASH_BYTES
    ResponseSHA256Context ctx;
    Response_SHA256_Init(&ctx);

    size_t totalRead = 0;
    char chunk[16384];
    ssize_t n = 0;

    while ((n = read(fd, chunk, sizeof(chunk))) > 0) {
        if (totalRead + (size_t)n > LINUX_MAX_HASH_BYTES) {
            close(fd);
            snprintf(outStatus, statusLen, "unknown");
            return false;
        }
        Response_SHA256_Update(&ctx, (const uint8_t*)chunk, (size_t)n);
        totalRead += (size_t)n;
    }
    close(fd);

    if (n < 0 || (st.st_size > 0 && totalRead != (size_t)st.st_size)) {
        snprintf(outStatus, statusLen, "race_suspected");
        return false;
    }

    uint8_t hash[32];
    Response_SHA256_Final(&ctx, hash);
    Response_BytesToHex(hash, 32, outHex);

    // 3. Store in LRU Cache
    size_t targetSlot = 0;
    uint64_t oldest = UINT64_MAX;
    bool foundEmpty = false;

    for (size_t i = 0; i < LINUX_HASH_CACHE_CAP; i++) {
        if (!g_LinuxHashCache[i].valid) {
            targetSlot = i;
            foundEmpty = true;
            break;
        }
        if (g_LinuxHashCache[i].last_used < oldest) {
            oldest = g_LinuxHashCache[i].last_used;
            targetSlot = i;
        }
    }
    (void)foundEmpty;

    LINUX_HASH_CACHE_ENTRY* slot = &g_LinuxHashCache[targetSlot];
    slot->valid = true;
    slot->dev = st.st_dev;
    slot->ino = st.st_ino;
    slot->size = st.st_size;
    slot->mtime = st.st_mtime;
    snprintf(slot->sha256_hex, sizeof(slot->sha256_hex), "%s", outHex);
    slot->last_used = nowAccess;

    snprintf(outStatus, statusLen, "authoritative");
    return true;
}

/* Enriches a process with full lineage and executable hashing */
static inline bool ProcessLineage_InspectProcess(uint32_t pid, PROCESS_ENRICHMENT* outEnrichment) {
    if (!outEnrichment) return false;
    memset(outEnrichment, 0, sizeof(*outEnrichment));
    outEnrichment->pid = pid;
    outEnrichment->observed_at = (int64_t)time(NULL);

    if (pid == 0) {
        snprintf(outEnrichment->user_identity, sizeof(outEnrichment->user_identity), "root");
        snprintf(outEnrichment->attribution_status, sizeof(outEnrichment->attribution_status), "unknown");
        return true;
    }

    const char* bootID = ProcessLineage_GetBootID();

    unsigned long long startTime = 0;
    uint32_t ppid = 0;
    if (ProcessLineage_ReadStat(pid, &startTime, &ppid)) {
        outEnrichment->ppid = ppid;
        snprintf(outEnrichment->process_instance_id, sizeof(outEnrichment->process_instance_id),
                 "%s:%u:%llu", bootID, pid, startTime);

        if (ppid > 0) {
            unsigned long long parentStart = 0;
            uint32_t grandparent = 0;
            if (ProcessLineage_ReadStat(ppid, &parentStart, &grandparent)) {
                snprintf(outEnrichment->parent_process_instance_id, sizeof(outEnrichment->parent_process_instance_id),
                         "%s:%u:%llu", bootID, ppid, parentStart);
            }
        }
    } else {
        snprintf(outEnrichment->attribution_status, sizeof(outEnrichment->attribution_status), "race_suspected");
    }

    (void)ProcessLineage_ReadCmdline(pid, outEnrichment->command_line, sizeof(outEnrichment->command_line));
    (void)ProcessLineage_ReadUser(pid, outEnrichment->user_identity, sizeof(outEnrichment->user_identity));

    char hashStatus[32] = {0};
    if (ProcessLineage_HashExecutable(pid, outEnrichment->executable_sha256, sizeof(outEnrichment->executable_sha256), hashStatus, sizeof(hashStatus))) {
        snprintf(outEnrichment->attribution_status, sizeof(outEnrichment->attribution_status), "%s", hashStatus);
    } else {
        if (outEnrichment->attribution_status[0] == '\0') {
            snprintf(outEnrichment->attribution_status, sizeof(outEnrichment->attribution_status), "%s", hashStatus[0] ? hashStatus : "unknown");
        }
    }

    return true;
}

/* Escapes a string for safe embedding into JSON without malloc */
static inline size_t ProcessLineage_EscapeJSON(const char* in, char* out, size_t outLen) {
    if (!out || outLen == 0) return 0;
    if (!in) {
        out[0] = '\0';
        return 0;
    }

    size_t o = 0;
    for (size_t i = 0; in[i] && o < outLen - 2; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            if (o + 2 >= outLen) break;
            out[o++] = '\\';
            out[o++] = c;
        } else if (c == '\n') {
            if (o + 2 >= outLen) break;
            out[o++] = '\\';
            out[o++] = 'n';
        } else if (c == '\r') {
            if (o + 2 >= outLen) break;
            out[o++] = '\\';
            out[o++] = 'r';
        } else if (c == '\t') {
            if (o + 2 >= outLen) break;
            out[o++] = '\\';
            out[o++] = 't';
        } else if (c < 32) {
            // Control character
            if (o + 6 >= outLen) break;
            snprintf(out + o, 7, "\\u%04x", c);
            o += 6;
        } else {
            out[o++] = c;
        }
    }
    out[o] = '\0';
    return o;
}

#endif /* OMINULL_PROCESS_LINEAGE_LINUX_H */
