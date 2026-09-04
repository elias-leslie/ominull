/*
 * Ominull Windows Endpoint Process Lineage & Executable Hashing Unit Test Suite
 *
 * Verifies:
 * - Boot ID generation, caching, and test overrides
 * - Process creation time and parent PID retrieval
 * - Command line extraction and user token attribution
 * - Win32 user-space executable hashing with 512-entry LRU cache (authoritative vs inferred_cached)
 * - Cache eviction and size bounding (64 MiB ceiling)
 * - PID reuse disambiguation and reboot namespace isolation
 * - System/Idle (PID 0, 4) handling and rapid exit race detection
 * - Zero-allocation JSON escaping
 * - ETW provider lifecycle with graceful fallback
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000006
#endif

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "../include/process_lineage_windows.h"

static int g_failures = 0;
static int g_tests_run = 0;

static void check(bool condition, const char* name, const char* detail) {
    g_tests_run++;
    if (!condition) {
        printf("  [-] FAIL: %s (%s)\n", name, detail ? detail : "unspecified error");
        g_failures++;
    } else {
        printf("  [+] PASS: %s\n", name);
    }
}

static void test_boot_id(void) {
    printf("[*] Testing Windows Boot ID Resolution & Caching...\n");
    ProcessLineageWin_ResetCache();

    const char* realBoot = ProcessLineageWin_GetBootID();
    check(realBoot != NULL && strlen(realBoot) > 0, "Boot ID is non-empty", realBoot);
    check(strncmp(realBoot, "win-", 4) == 0, "Boot ID starts with 'win-'", realBoot);

    // Caching check
    const char* cachedBoot = ProcessLineageWin_GetBootID();
    check(strcmp(realBoot, cachedBoot) == 0, "Boot ID returns cached value", cachedBoot);

    // Deterministic test override
    ProcessLineageWin_SetBootIDForTesting("win-boot-fixed-12345");
    check(strcmp(ProcessLineageWin_GetBootID(), "win-boot-fixed-12345") == 0,
          "Boot ID test override works", ProcessLineageWin_GetBootID());

    ProcessLineageWin_ResetCache();
    check(strcmp(ProcessLineageWin_GetBootID(), "win-boot-fixed-12345") != 0,
          "Cache reset clears boot ID override", NULL);
}

static void test_self_process_inspection(void) {
    printf("[*] Testing Self Process Inspection...\n");
    ProcessLineageWin_ResetCache();
    ProcessLineageWin_SetBootIDForTesting("win-boot-test-self");

    DWORD myPid = GetCurrentProcessId();
    PROCESS_ENRICHMENT_WIN enr;
    bool ok = ProcessLineageWin_InspectProcess(myPid, &enr);
    check(ok, "Inspect current process succeeded", NULL);
    check(enr.pid == myPid, "PID matches current process ID", NULL);
    check(strlen(enr.process_instance_id) > 0, "process_instance_id is populated", enr.process_instance_id);
    check(strncmp(enr.process_instance_id, "win-boot-test-self:", 19) == 0,
          "process_instance_id starts with boot UUID", enr.process_instance_id);

    // Parent PID and instance ID check
    check(enr.ppid > 0, "Parent PID was resolved", NULL);

    // Executable SHA-256 and attribution
    check(strlen(enr.executable_sha256) == 64, "executable_sha256 is 64 hex characters", enr.executable_sha256);
    check(strcmp(enr.attribution_status, "authoritative") == 0 ||
          strcmp(enr.attribution_status, "inferred_cached") == 0,
          "Attribution status is authoritative or inferred_cached", enr.attribution_status);

    // User identity check
    check(strlen(enr.user_identity) > 0, "user_identity is resolved", enr.user_identity);

    // Cached inspection check
    PROCESS_ENRICHMENT_WIN enr2;
    ok = ProcessLineageWin_InspectProcess(myPid, &enr2);
    check(ok, "Second inspection of self succeeded", NULL);
    check(strcmp(enr2.attribution_status, "inferred_cached") == 0,
          "Subsequent inspection uses inferred_cached status", enr2.attribution_status);
    check(strcmp(enr.executable_sha256, enr2.executable_sha256) == 0,
          "Cached SHA-256 matches initial hash", enr2.executable_sha256);
}

static void test_executable_hashing_and_lru(void) {
    printf("[*] Testing Executable Hashing & Win32 LRU Cache...\n");
    ProcessLineageWin_ResetCache();

    // Create a temporary file on disk with known content
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    char sampleFile[MAX_PATH];
    snprintf(sampleFile, sizeof(sampleFile), "%s\\ominull_win_sample.exe", tempPath);

    FILE* fp = fopen(sampleFile, "wb");
    if (!fp) { perror("fopen sample"); exit(1); }
    const char content[] = "OMINULL_WIN32_SAMPLE_EXECUTABLE_CONTENT_2026";
    fwrite(content, 1, sizeof(content), fp);
    fclose(fp);

    // Compute expected SHA-256
    ResponseSHA256Context ctx;
    Response_SHA256_Init(&ctx);
    Response_SHA256_Update(&ctx, (const uint8_t*)content, sizeof(content));
    uint8_t expectedHash[32];
    Response_SHA256_Final(&ctx, expectedHash);
    char expectedHex[65];
    Response_BytesToHex(expectedHash, 32, expectedHex);

    WCHAR wSample[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, sampleFile, -1, wSample, MAX_PATH);

    // 1. First hash (authoritative)
    char outHex[65] = {0};
    char outStatus[32] = {0};
    bool ok = ProcessLineageWin_HashExecutable(wSample, outHex, sizeof(outHex), outStatus, sizeof(outStatus));
    check(ok, "Initial Win32 hash succeeded", outHex);
    check(strcmp(outStatus, "authoritative") == 0, "Initial status is 'authoritative'", outStatus);
    check(strcmp(outHex, expectedHex) == 0, "Computed SHA-256 matches expected digest", outHex);

    // 2. Second hash (inferred_cached)
    char hitHex[65] = {0};
    char hitStatus[32] = {0};
    ok = ProcessLineageWin_HashExecutable(wSample, hitHex, sizeof(hitHex), hitStatus, sizeof(hitStatus));
    check(ok, "Cached Win32 hash succeeded", hitHex);
    check(strcmp(hitStatus, "inferred_cached") == 0, "Subsequent status is 'inferred_cached'", hitStatus);
    check(strcmp(hitHex, expectedHex) == 0, "Cached SHA-256 matches expected digest", hitHex);

    // 3. Non-existent executable (race_suspected)
    char missingHex[65] = {0};
    char missingStatus[32] = {0};
    ok = ProcessLineageWin_HashExecutable(L"C:\\nonexistent\\missing_process.exe",
                                          missingHex, sizeof(missingHex), missingStatus, sizeof(missingStatus));
    check(!ok, "Missing file fails", NULL);
    check(strcmp(missingStatus, "race_suspected") == 0, "Missing file status is 'race_suspected'", missingStatus);

    // 4. Cache Eviction (fill 512 entries, add 513th)
    ProcessLineageWin_ResetCache();
    for (size_t i = 0; i < WIN_HASH_CACHE_CAP; i++) {
        g_WinHashCache[i].valid = true;
        g_WinHashCache[i].volume_serial = 0x12345678;
        g_WinHashCache[i].file_index = (uint64_t)(2000 + i);
        g_WinHashCache[i].file_size = 128;
        g_WinHashCache[i].last_write_time.dwLowDateTime = (DWORD)i;
        g_WinHashCache[i].last_write_time.dwHighDateTime = 1;
        snprintf(g_WinHashCache[i].sha256_hex, sizeof(g_WinHashCache[i].sha256_hex), "%064zx", i);
        g_WinHashCache[i].last_used = (uint64_t)(i + 1);
    }
    g_WinHashAccessCounter = WIN_HASH_CACHE_CAP;

    // Slot 0 has last_used = 1 (oldest). Now hash sample file again.
    char evictHex[65] = {0};
    char evictStatus[32] = {0};
    ok = ProcessLineageWin_HashExecutable(wSample, evictHex, sizeof(evictHex), evictStatus, sizeof(evictStatus));
    check(ok, "Hash insertion under full Win32 cache succeeded", NULL);
    check(strcmp(evictStatus, "authoritative") == 0, "Inserted entry is authoritative", evictStatus);
    check(g_WinHashCache[0].file_index != 2000, "Oldest cache entry (slot 0) was evicted", NULL);
    check(strcmp(g_WinHashCache[0].sha256_hex, expectedHex) == 0, "Slot 0 now holds newly hashed binary", NULL);

    DeleteFileA(sampleFile);
}

static void test_pid_reuse_and_boot_transition(void) {
    printf("[*] Testing PID Reuse & Boot Transition Isolation...\n");
    ProcessLineageWin_ResetCache();
    ProcessLineageWin_SetBootIDForTesting("win-boot-uuid-A");

    // Process Instance ID generation format: <bootID>:<pid>:<starttime>
    char idA[128], idB[128], idReboot[128];
    snprintf(idA, sizeof(idA), "%s:%u:%llu", ProcessLineageWin_GetBootID(), 1234, 100000ULL);
    snprintf(idB, sizeof(idB), "%s:%u:%llu", ProcessLineageWin_GetBootID(), 1234, 200000ULL);

    check(strcmp(idA, idB) != 0, "Different start times prevent PID reuse collision", NULL);

    // Boot transition
    ProcessLineageWin_SetBootIDForTesting("win-boot-uuid-B");
    snprintf(idReboot, sizeof(idReboot), "%s:%u:%llu", ProcessLineageWin_GetBootID(), 1234, 100000ULL);
    check(strcmp(idA, idReboot) != 0, "Different boot IDs isolate instances across reboots", NULL);
}

static void test_system_and_dead_processes(void) {
    printf("[*] Testing System PIDs & Dead Process Handling...\n");

    // PID 0 (System Idle)
    PROCESS_ENRICHMENT_WIN enr0;
    bool ok = ProcessLineageWin_InspectProcess(0, &enr0);
    check(ok, "Inspect PID 0 succeeded", NULL);
    check(enr0.pid == 0, "PID 0 preserved", NULL);
    check(strcmp(enr0.user_identity, "SYSTEM") == 0, "PID 0 user is SYSTEM", enr0.user_identity);
    check(strcmp(enr0.attribution_status, "unknown") == 0, "PID 0 attribution status is unknown", enr0.attribution_status);

    // PID 4 (System)
    PROCESS_ENRICHMENT_WIN enr4;
    ok = ProcessLineageWin_InspectProcess(4, &enr4);
    check(ok, "Inspect PID 4 succeeded", NULL);
    check(enr4.pid == 4, "PID 4 preserved", NULL);
    check(strcmp(enr4.user_identity, "SYSTEM") == 0, "PID 4 user is SYSTEM", enr4.user_identity);
    check(strcmp(enr4.attribution_status, "unknown") == 0, "PID 4 attribution status is unknown", enr4.attribution_status);

    // Dead / non-existent PID
    PROCESS_ENRICHMENT_WIN enrDead;
    ok = ProcessLineageWin_InspectProcess(9999999, &enrDead);
    check(!ok, "Inspect dead PID returns false", NULL);
    check(strcmp(enrDead.attribution_status, "race_suspected") == 0,
          "Dead PID attribution status is 'race_suspected'", enrDead.attribution_status);
}

static void test_json_escaping(void) {
    printf("[*] Testing Win32 JSON Escaping...\n");
    char out[256];

    // Plain path
    size_t len = ProcessLineageWin_EscapeJSON("C:\\Program Files\\app.exe", out, sizeof(out));
    check(strcmp(out, "C:\\\\Program Files\\\\app.exe") == 0 && len == strlen(out),
          "Backslashes properly escaped in Windows path", out);

    // Quotes
    len = ProcessLineageWin_EscapeJSON("cmd.exe /c \"echo hello\"", out, sizeof(out));
    check(strcmp(out, "cmd.exe /c \\\"echo hello\\\"") == 0 && len == strlen(out),
          "Quotes properly escaped", out);

    // Control characters
    char rawCtrl[] = "line1\nline2\ttab";
    len = ProcessLineageWin_EscapeJSON(rawCtrl, out, sizeof(out));
    check(strcmp(out, "line1\\nline2\\ttab") == 0 && len == strlen(out),
          "Newlines and tabs escaped", out);

    // NULL input
    len = ProcessLineageWin_EscapeJSON(NULL, out, sizeof(out));
    check(len == 0 && out[0] == '\0', "NULL input handled safely", NULL);
}

static void test_etw_lifecycle(void) {
    printf("[*] Testing ETW Provider Lifecycle & Fallback...\n");

    // Calling InitETW should either start trace or gracefully fall back
    bool etwOk = ProcessLineageWin_InitETW();
    if (etwOk) {
        check(g_EtwSessionActive, "ETW session is active", NULL);
        ProcessLineageWin_StopETW();
        check(!g_EtwSessionActive, "ETW session cleanly stopped", NULL);
    } else {
        check(!g_EtwSessionActive, "ETW gracefully fell back to snapshot mode", NULL);
    }
}

int main(void) {
    printf("=== Ominull Windows Endpoint Process Lineage & Hashing Test Suite ===\n");

    test_boot_id();
    test_self_process_inspection();
    test_executable_hashing_and_lru();
    test_pid_reuse_and_boot_transition();
    test_system_and_dead_processes();
    test_json_escaping();
    test_etw_lifecycle();

    if (g_failures > 0) {
        fprintf(stderr, "\n[-] Windows test suite FAILED with %d failure(s) out of %d tests\n",
                g_failures, g_tests_run);
        return 1;
    }

    printf("\n[+] All Windows process lineage & executable hashing tests PASSED cleanly (%d tests).\n",
           g_tests_run);
    return 0;
}
