/*
 * Ominull Linux Endpoint Process Lineage & Executable Hashing Unit Test Suite
 *
 * Verifies:
 * - Boot ID capture and caching
 * - /proc/<pid>/stat parsing with normal and complex/escaped comm names
 * - /proc/<pid>/cmdline parsing and argument separation
 * - /proc/<pid>/status UID parsing and username resolution
 * - Executable SHA-256 hashing and user-space LRU cache hits/evictions
 * - PID reuse isolation and boot transition uniqueness
 * - Rapid process exit / race handling (race_suspected)
 * - Permission denial handling (permission_denied)
 * - Safe size-bounding (unknown on excessive binary size)
 * - Zero-allocation JSON escaping
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char g_mock_proc_dir[256] = {0};
#define OMINULL_PROC_ROOT g_mock_proc_dir

#include "../include/process_lineage_linux.h"

static int g_failures = 0;

static void check(bool condition, const char* name, const char* detail) {
    if (!condition) {
        printf("  [-] FAIL: %s (%s)\n", name, detail ? detail : "unspecified error");
        g_failures++;
    } else {
        printf("  [+] PASS: %s\n", name);
    }
}

static int remove_tree_cb(const char* path, const struct stat* st, int type, struct FTW* state) {
    (void)st; (void)type; (void)state;
    return remove(path);
}

static void cleanup_mock_proc(void) {
    if (g_mock_proc_dir[0] != '\0') {
        nftw(g_mock_proc_dir, remove_tree_cb, 16, FTW_DEPTH | FTW_PHYS);
        g_mock_proc_dir[0] = '\0';
    }
}

static void init_mock_proc(void) {
    cleanup_mock_proc();
    char templatePath[] = "/tmp/ominull-proc-test-XXXXXX";
    char* res = mkdtemp(templatePath);
    if (!res) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(g_mock_proc_dir, sizeof(g_mock_proc_dir), "%s", res);
}

static void mock_path(char* out, size_t outLen, const char* rel) {
    snprintf(out, outLen, "%s/%s", g_mock_proc_dir, rel);
}

static void create_file(const char* relPath, const void* data, size_t len) {
    char full[512];
    mock_path(full, sizeof(full), relPath);

    char* slash = strrchr(full, '/');
    if (slash && slash != full) {
        *slash = '\0';
        mkdir(full, 0755);
        *slash = '/';
    }

    FILE* fp = fopen(full, "wb");
    if (!fp) {
        perror(full);
        exit(1);
    }
    if (len > 0) {
        if (fwrite(data, 1, len, fp) != len) {
            perror("fwrite");
            exit(1);
        }
    }
    fclose(fp);
}

static void make_mock_exe(const char* pidStr, const char* targetPath) {
    char dir[512];
    mock_path(dir, sizeof(dir), pidStr);
    mkdir(dir, 0755);

    char linkPath[1024];
    snprintf(linkPath, sizeof(linkPath), "%s/exe", dir);
    unlink(linkPath);
    if (symlink(targetPath, linkPath) != 0) {
        perror("symlink");
    }
}

static void test_boot_id(void) {
    printf("[*] Testing Boot ID Resolution & Caching...\n");
    ProcessLineage_ResetCache();

    const char* realBoot = ProcessLineage_GetBootID();
    check(realBoot != NULL && strlen(realBoot) > 0, "Boot ID is non-empty", realBoot);

    const char* cachedBoot = ProcessLineage_GetBootID();
    check(strcmp(realBoot, cachedBoot) == 0, "Boot ID returns cached value", cachedBoot);

    ProcessLineage_SetBootIDForTesting("custom-boot-uuid-12345");
    check(strcmp(ProcessLineage_GetBootID(), "custom-boot-uuid-12345") == 0,
          "Boot ID override works", ProcessLineage_GetBootID());

    ProcessLineage_ResetCache();
    check(strcmp(ProcessLineage_GetBootID(), "custom-boot-uuid-12345") != 0,
          "Cache reset clears boot ID override", NULL);
}

static void test_stat_parsing(void) {
    printf("[*] Testing /proc/<pid>/stat Parsing...\n");
    init_mock_proc();

    // 1. Normal stat
    const char* normalStat = "100 (normal_proc) S 1 100 100 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 987654321 12345 678 0 0 0\n";
    create_file("100/stat", normalStat, strlen(normalStat));

    unsigned long long startTime = 0;
    uint32_t ppid = 0;
    bool ok = ProcessLineage_ReadStat(100, &startTime, &ppid);
    check(ok, "Normal stat parsed successfully", NULL);
    check(ppid == 1, "Normal stat PPID matches", NULL);
    check(startTime == 987654321ULL, "Normal stat starttime matches", NULL);

    // 2. Stat with spaces in comm
    const char* spaceStat = "200 (Web Content Helper) R 100 200 200 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 1122334455 12345 678 0 0 0\n";
    create_file("200/stat", spaceStat, strlen(spaceStat));
    ok = ProcessLineage_ReadStat(200, &startTime, &ppid);
    check(ok, "Stat with spaces in comm parsed successfully", NULL);
    check(ppid == 100, "Spaced comm stat PPID matches", NULL);
    check(startTime == 1122334455ULL, "Spaced comm stat starttime matches", NULL);

    // 3. Stat with parentheses in comm
    const char* parenStat = "300 (nested (paren) comm) D 200 300 300 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 5566778899 12345 678 0 0 0\n";
    create_file("300/stat", parenStat, strlen(parenStat));
    ok = ProcessLineage_ReadStat(300, &startTime, &ppid);
    check(ok, "Stat with parentheses in comm parsed successfully", NULL);
    check(ppid == 200, "Paren comm stat PPID matches", NULL);
    check(startTime == 5566778899ULL, "Paren comm stat starttime matches", NULL);

    // 4. Init process with PPID 0
    const char* initStat = "1 (systemd) S 0 1 1 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 1 12345 678 0 0 0\n";
    create_file("1/stat", initStat, strlen(initStat));
    ok = ProcessLineage_ReadStat(1, &startTime, &ppid);
    check(ok, "Init stat parsed successfully", NULL);
    check(ppid == 0, "Init PPID is 0", NULL);
    check(startTime == 1ULL, "Init starttime matches", NULL);

    // 5. Truncated stat (< 22 fields)
    const char* truncStat = "400 (broken) S 1 400 400 0 -1 4194304\n";
    create_file("400/stat", truncStat, strlen(truncStat));
    ok = ProcessLineage_ReadStat(400, &startTime, &ppid);
    check(!ok, "Truncated stat is rejected", NULL);

    // 6. Non-existent PID
    ok = ProcessLineage_ReadStat(99999, &startTime, &ppid);
    check(!ok, "Missing stat file returns false", NULL);
}

static void test_cmdline_parsing(void) {
    printf("[*] Testing /proc/<pid>/cmdline Parsing...\n");
    init_mock_proc();

    // 1. Multi-argument null-separated command line
    const char rawCmd[] = "/usr/bin/python3\0-u\0/opt/app/server.py\0--port\08080\0";
    create_file("100/cmdline", rawCmd, sizeof(rawCmd));

    char cmdBuf[1024];
    bool ok = ProcessLineage_ReadCmdline(100, cmdBuf, sizeof(cmdBuf));
    check(ok, "Multi-arg cmdline read successfully", cmdBuf);
    check(strcmp(cmdBuf, "/usr/bin/python3 -u /opt/app/server.py --port 8080") == 0,
          "Null bytes converted to spaces accurately", cmdBuf);

    // 2. Single-argument command line
    const char rawSingle[] = "kthreadd\0";
    create_file("101/cmdline", rawSingle, sizeof(rawSingle));
    ok = ProcessLineage_ReadCmdline(101, cmdBuf, sizeof(cmdBuf));
    check(ok, "Single-arg cmdline read successfully", cmdBuf);
    check(strcmp(cmdBuf, "kthreadd") == 0, "Single-arg matches verbatim", cmdBuf);

    // 3. Empty cmdline (kernel threads)
    create_file("102/cmdline", "", 0);
    ok = ProcessLineage_ReadCmdline(102, cmdBuf, sizeof(cmdBuf));
    check(!ok, "Empty cmdline returns false", NULL);
    check(cmdBuf[0] == '\0', "Output buffer is empty string", NULL);

    // 4. Missing cmdline
    ok = ProcessLineage_ReadCmdline(99999, cmdBuf, sizeof(cmdBuf));
    check(!ok, "Missing cmdline returns false", NULL);
}

static void test_user_reading(void) {
    printf("[*] Testing /proc/<pid>/status User Resolution...\n");
    init_mock_proc();

    // 1. Root user (UID 0)
    const char* statusRoot = "Name:\troot_daemon\nState:\tS (sleeping)\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
    create_file("100/status", statusRoot, strlen(statusRoot));

    char userBuf[64];
    bool ok = ProcessLineage_ReadUser(100, userBuf, sizeof(userBuf));
    check(ok, "Root status read successfully", userBuf);
    check(strcmp(userBuf, "root") == 0, "UID 0 maps to 'root'", userBuf);

    // 2. Current user's UID
    uid_t myUid = getuid();
    char statusSelf[256];
    snprintf(statusSelf, sizeof(statusSelf), "Name:\tself\nUid:\t%u\t%u\t%u\t%u\n",
             (unsigned int)myUid, (unsigned int)myUid, (unsigned int)myUid, (unsigned int)myUid);
    create_file("101/status", statusSelf, strlen(statusSelf));

    ok = ProcessLineage_ReadUser(101, userBuf, sizeof(userBuf));
    check(ok, "Current user status read successfully", userBuf);
    check(strlen(userBuf) > 0, "Current username resolved and non-empty", userBuf);

    // 3. Unresolvable high UID (fallback to UID:<num>)
    const char* statusHighUid = "Name:\tanon\nUid:\t987654\t987654\t987654\t987654\n";
    create_file("102/status", statusHighUid, strlen(statusHighUid));
    ok = ProcessLineage_ReadUser(102, userBuf, sizeof(userBuf));
    check(ok, "High UID status read successfully", userBuf);
    check(strcmp(userBuf, "UID:987654") == 0, "High UID formatted as UID:987654", userBuf);

    // 4. Missing status
    ok = ProcessLineage_ReadUser(99999, userBuf, sizeof(userBuf));
    check(!ok, "Missing status returns false", NULL);
}

static void test_executable_hashing_and_lru(void) {
    printf("[*] Testing Executable Hashing & LRU Cache...\n");
    init_mock_proc();
    ProcessLineage_ResetCache();

    // Create a mock executable binary
    char binPath[512];
    mock_path(binPath, sizeof(binPath), "sample_bin");
    FILE* fp = fopen(binPath, "wb");
    if (!fp) { perror("fopen sample_bin"); exit(1); }
    const char binContent[] = "OMINULL_TEST_EXECUTABLE_BINARY_PAYLOAD_V1";
    fwrite(binContent, 1, sizeof(binContent), fp);
    fclose(fp);

    // Compute expected SHA-256 in test
    ResponseSHA256Context expectedCtx;
    Response_SHA256_Init(&expectedCtx);
    Response_SHA256_Update(&expectedCtx, (const uint8_t*)binContent, sizeof(binContent));
    uint8_t expectedHash[32];
    Response_SHA256_Final(&expectedCtx, expectedHash);
    char expectedHex[65];
    Response_BytesToHex(expectedHash, 32, expectedHex);

    // Link mock proc /100/exe to sample_bin
    make_mock_exe("100", binPath);

    // 1. Initial Hash (Cache Miss -> authoritative)
    char outHex[65] = {0};
    char outStatus[32] = {0};
    bool ok = ProcessLineage_HashExecutable(100, outHex, sizeof(outHex), outStatus, sizeof(outStatus));
    check(ok, "Initial executable hash succeeded", outHex);
    check(strcmp(outStatus, "authoritative") == 0, "Initial status is 'authoritative'", outStatus);
    check(strcmp(outHex, expectedHex) == 0, "Computed SHA-256 matches expected digest", outHex);

    // 2. Second Hash (Cache Hit -> inferred_cached)
    char hitHex[65] = {0};
    char hitStatus[32] = {0};
    ok = ProcessLineage_HashExecutable(100, hitHex, sizeof(hitHex), hitStatus, sizeof(hitStatus));
    check(ok, "Cached executable hash succeeded", hitHex);
    check(strcmp(hitStatus, "inferred_cached") == 0, "Subsequent status is 'inferred_cached'", hitStatus);
    check(strcmp(hitHex, expectedHex) == 0, "Cached SHA-256 matches expected digest", hitHex);

    // 3. Missing Executable (race_suspected)
    char raceHex[65] = {0};
    char raceStatus[32] = {0};
    ok = ProcessLineage_HashExecutable(99999, raceHex, sizeof(raceHex), raceStatus, sizeof(raceStatus));
    check(!ok, "Missing executable fails", NULL);
    check(strcmp(raceStatus, "race_suspected") == 0, "Missing executable status is 'race_suspected'", raceStatus);

    // 4. Permission Denial (permission_denied)
    if (getuid() != 0) { // Only testable when not running as root
        char noPermBin[512];
        mock_path(noPermBin, sizeof(noPermBin), "noperm_bin");
        FILE* np = fopen(noPermBin, "wb");
        if (np) {
            fwrite("NO_PERM", 1, 7, np);
            fchmod(fileno(np), 0000);

            make_mock_exe("105", noPermBin);

            char permHex[65] = {0};
            char permStatus[32] = {0};
            ok = ProcessLineage_HashExecutable(105, permHex, sizeof(permHex), permStatus, sizeof(permStatus));
            check(!ok, "Unreadable executable fails", NULL);
            check(strcmp(permStatus, "permission_denied") == 0,
                  "Unreadable executable status is 'permission_denied'", permStatus);

            fchmod(fileno(np), 0644); // restore the same open fixture for cleanup
            fclose(np);
        }
    } else {
        printf("  [*] Skipping permission_denied check (running as root)\n");
    }

    // 5. Huge File Exceeding LINUX_MAX_HASH_BYTES (sparse 65 MiB file)
    char hugeBin[512];
    mock_path(hugeBin, sizeof(hugeBin), "huge_bin");
    int hugeFd = open(hugeBin, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (hugeFd >= 0) {
        if (ftruncate(hugeFd, (off_t)LINUX_MAX_HASH_BYTES + 1024) == 0) {
            close(hugeFd);
            make_mock_exe("106", hugeBin);

            char hugeHex[65] = {0};
            char hugeStatus[32] = {0};
            ok = ProcessLineage_HashExecutable(106, hugeHex, sizeof(hugeHex), hugeStatus, sizeof(hugeStatus));
            check(!ok, "Oversized binary hashing is skipped", NULL);
            check(strcmp(hugeStatus, "unknown") == 0, "Oversized binary status is 'unknown'", hugeStatus);
        } else {
            close(hugeFd);
        }
    }

    // 6. Cache Eviction: Fill cache to capacity (512 items) and verify oldest is evicted
    ProcessLineage_ResetCache();
    for (size_t i = 0; i < LINUX_HASH_CACHE_CAP; i++) {
        g_LinuxHashCache[i].valid = true;
        g_LinuxHashCache[i].dev = 1;
        g_LinuxHashCache[i].ino = (ino_t)(1000 + i);
        g_LinuxHashCache[i].size = 100;
        g_LinuxHashCache[i].mtime = 12345;
        snprintf(g_LinuxHashCache[i].sha256_hex, sizeof(g_LinuxHashCache[i].sha256_hex), "%064zx", i);
        g_LinuxHashCache[i].last_used = (uint64_t)(i + 1);
    }
    g_LinuxHashAccessCounter = LINUX_HASH_CACHE_CAP;

    char evictHex[65] = {0};
    char evictStatus[32] = {0};
    ok = ProcessLineage_HashExecutable(100, evictHex, sizeof(evictHex), evictStatus, sizeof(evictStatus));
    check(ok, "Hash insertion under full cache succeeds", NULL);
    check(strcmp(evictStatus, "authoritative") == 0, "Inserted entry is authoritative", evictStatus);

    check(g_LinuxHashCache[0].ino != 1000, "Oldest cache entry (index 0) was evicted", NULL);
    check(strcmp(g_LinuxHashCache[0].sha256_hex, expectedHex) == 0,
          "Slot 0 now holds the newly hashed binary", NULL);
}

static void test_process_lineage_and_pid_reuse(void) {
    printf("[*] Testing Process Lineage & PID Reuse Handling...\n");
    init_mock_proc();
    ProcessLineage_ResetCache();
    ProcessLineage_SetBootIDForTesting("boot-uuid-test-2026");

    char binPath[512];
    mock_path(binPath, sizeof(binPath), "daemon_bin");
    FILE* fp = fopen(binPath, "wb");
    if (fp) {
        fwrite("DAEMON_PAYLOAD", 1, 14, fp);
        fclose(fp);
    }

    // Process 400 (Parent): ppid 1, starttime 1000000
    const char* parentStat = "400 (parent_srv) S 1 400 400 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 1000000 12345 678 0 0 0\n";
    create_file("400/stat", parentStat, strlen(parentStat));
    create_file("400/cmdline", "/usr/bin/parent_srv\0", 20);
    create_file("400/status", "Name:\tparent_srv\nUid:\t0\t0\t0\t0\n", 35);
    make_mock_exe("400", binPath);

    // Process 500 (Child): ppid 400, starttime 2000000
    const char* childStat = "500 (child_worker) S 400 400 400 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 2000000 12345 678 0 0 0\n";
    create_file("500/stat", childStat, strlen(childStat));
    create_file("500/cmdline", "/usr/bin/child_worker\0--job\042\0", 30);
    create_file("500/status", "Name:\tchild_worker\nUid:\t0\t0\t0\t0\n", 37);
    make_mock_exe("500", binPath);

    // 1. Inspect Child Process with Living Parent
    PROCESS_ENRICHMENT childEnr;
    bool ok = ProcessLineage_InspectProcess(500, &childEnr);
    check(ok, "Inspect child process succeeded", NULL);
    check(childEnr.pid == 500, "Child PID is 500", NULL);
    check(childEnr.ppid == 400, "Child PPID is 400", NULL);
    check(strcmp(childEnr.process_instance_id, "boot-uuid-test-2026:500:2000000") == 0,
          "Child process_instance_id incorporates boot ID, PID, and starttime", childEnr.process_instance_id);
    check(strcmp(childEnr.parent_process_instance_id, "boot-uuid-test-2026:400:1000000") == 0,
          "Parent process_instance_id incorporates parent starttime", childEnr.parent_process_instance_id);
    check(strcmp(childEnr.attribution_status, "authoritative") == 0,
          "Attribution status is authoritative", childEnr.attribution_status);

    // 2. PID Reuse Simulation: Same PID 500 restarted with starttime 3000000
    const char* childReusedStat = "500 (child_worker_v2) S 400 400 400 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 3000000 12345 678 0 0 0\n";
    create_file("500/stat", childReusedStat, strlen(childReusedStat));

    PROCESS_ENRICHMENT reusedEnr;
    ok = ProcessLineage_InspectProcess(500, &reusedEnr);
    check(ok, "Inspect reused PID process succeeded", NULL);
    check(strcmp(reusedEnr.process_instance_id, "boot-uuid-test-2026:500:3000000") == 0,
          "Reused PID generates distinct process_instance_id", reusedEnr.process_instance_id);
    check(strcmp(childEnr.process_instance_id, reusedEnr.process_instance_id) != 0,
          "PID reuse conflict is prevented by starttime disambiguation", NULL);

    // 3. Boot Transition Simulation: Different boot UUID generates different instance ID
    ProcessLineage_SetBootIDForTesting("boot-uuid-rebooted-9999");
    PROCESS_ENRICHMENT rebootEnr;
    ok = ProcessLineage_InspectProcess(500, &rebootEnr);
    check(ok, "Inspect process under new boot ID succeeded", NULL);
    check(strcmp(rebootEnr.process_instance_id, "boot-uuid-rebooted-9999:500:3000000") == 0,
          "Boot transition modifies process_instance_id namespace", rebootEnr.process_instance_id);
    check(strcmp(reusedEnr.process_instance_id, rebootEnr.process_instance_id) != 0,
          "Reboot collision is prevented by boot UUID prefix", NULL);

    // 4. Dead Parent (ppid 400 exited before child inspection)
    char parentStatPath[512];
    mock_path(parentStatPath, sizeof(parentStatPath), "400/stat");
    unlink(parentStatPath);

    PROCESS_ENRICHMENT orphanEnr;
    ok = ProcessLineage_InspectProcess(500, &orphanEnr);
    check(ok, "Inspect process with dead parent succeeded", NULL);
    check(orphanEnr.ppid == 400, "PPID is preserved", NULL);
    check(orphanEnr.parent_process_instance_id[0] == '\0',
          "Parent process_instance_id is empty when parent cannot be verified (zero invention)",
          orphanEnr.parent_process_instance_id);

    // 5. Dead Process (Rapid Exit)
    char childStatPath[512];
    mock_path(childStatPath, sizeof(childStatPath), "500/stat");
    unlink(childStatPath);
    char childExePath[512];
    mock_path(childExePath, sizeof(childExePath), "500/exe");
    unlink(childExePath);

    PROCESS_ENRICHMENT deadEnr;
    ok = ProcessLineage_InspectProcess(500, &deadEnr);
    check(ok, "Inspect dead process returns graceful struct", NULL);
    check(strcmp(deadEnr.attribution_status, "race_suspected") == 0,
          "Dead process attribution status is 'race_suspected'", deadEnr.attribution_status);
    check(deadEnr.process_instance_id[0] == '\0',
          "Dead process does not synthesize false process_instance_id", NULL);

    // 6. PID 0 (Kernel/System)
    PROCESS_ENRICHMENT sysEnr;
    ok = ProcessLineage_InspectProcess(0, &sysEnr);
    check(ok, "Inspect PID 0 succeeded", NULL);
    check(sysEnr.pid == 0, "PID 0 preserved", NULL);
    check(strcmp(sysEnr.user_identity, "root") == 0, "PID 0 user is root", sysEnr.user_identity);
    check(strcmp(sysEnr.attribution_status, "unknown") == 0, "PID 0 attribution status is unknown", sysEnr.attribution_status);
}

static void test_json_escaping(void) {
    printf("[*] Testing JSON Escaping...\n");
    char out[256];

    // Plain text
    size_t len = ProcessLineage_EscapeJSON("/usr/bin/curl", out, sizeof(out));
    check(strcmp(out, "/usr/bin/curl") == 0 && len == strlen(out),
          "Plain string escaped without alteration", out);

    // Quotes and Backslashes
    len = ProcessLineage_EscapeJSON("foo \"bar\" \\ baz", out, sizeof(out));
    check(strcmp(out, "foo \\\"bar\\\" \\\\ baz") == 0 && len == strlen(out),
          "Quotes and backslashes escaped with backslashes", out);

    // Newlines, Carriage Returns, and Tabs
    len = ProcessLineage_EscapeJSON("line1\nline2\rline3\tline4", out, sizeof(out));
    check(strcmp(out, "line1\\nline2\\rline3\\tline4") == 0 && len == strlen(out),
          "Newlines, tabs, and carriage returns escaped", out);

    // Control Characters (< 32)
    char rawCtrl[] = "alert\007bell";
    len = ProcessLineage_EscapeJSON(rawCtrl, out, sizeof(out));
    check(strcmp(out, "alert\\u0007bell") == 0 && len == strlen(out),
          "ASCII control char escaped to \\u0007", out);

    // Buffer Truncation Safety
    char smallOut[8];
    len = ProcessLineage_EscapeJSON("a \"very\" long string", smallOut, sizeof(smallOut));
    check(len < sizeof(smallOut) && strlen(smallOut) < sizeof(smallOut),
          "Small buffer does not overflow and stays null-terminated", smallOut);

    // NULL input
    len = ProcessLineage_EscapeJSON(NULL, out, sizeof(out));
    check(len == 0 && out[0] == '\0', "NULL input handled safely", NULL);
}

int main(void) {
    printf("=== Ominull Linux Endpoint Process Lineage & Hashing Test Suite ===\n");

    test_boot_id();
    test_stat_parsing();
    test_cmdline_parsing();
    test_user_reading();
    test_executable_hashing_and_lru();
    test_process_lineage_and_pid_reuse();
    test_json_escaping();

    cleanup_mock_proc();

    if (g_failures > 0) {
        fprintf(stderr, "\n[-] Test suite FAILED with %d failure(s)\n", g_failures);
        return 1;
    }

    printf("\n[+] All Linux process lineage, boot identity, & executable hashing tests PASSED cleanly.\n");
    return 0;
}
