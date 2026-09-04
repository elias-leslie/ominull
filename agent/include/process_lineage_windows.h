/*
 * Ominull Windows Endpoint Process Lineage, Boot Identity, ETW Provider, & Executable Hashing
 *
 * Implements:
 * - Boot identity binding and process instance ID generation (<boot_id>:<pid>:<starttime>)
 * - Parent PID and parent instance ID tracking without false tree invention
 * - Command line extraction via NtQueryInformationProcess (ProcessCommandLineInformation)
 * - User token identity resolution (OpenProcessToken, LookupAccountSidA)
 * - 512-entry user-space LRU executable SHA-256 cache keyed on (volume_serial, file_index, file_size, last_write_time)
 * - Real-time ETW Process Provider initialization with graceful snapshot fallback
 * - Explicit attribution status semantics (authoritative, inferred_cached, race_suspected, permission_denied, unknown)
 * - Zero-allocation JSON escaping helper
 */

#ifndef OMINULL_PROCESS_LINEAGE_WINDOWS_H
#define OMINULL_PROCESS_LINEAGE_WINDOWS_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000006
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "response_dispatcher.h"

#define WIN_HASH_CACHE_CAP 512
#define WIN_MAX_HASH_BYTES (64 * 1024 * 1024) // 64 MiB maximum file hashing ceiling

#ifndef WIN_LINEAGE_MAX_PATH
#define WIN_LINEAGE_MAX_PATH 512
#endif

typedef struct {
    DWORD pid;
    DWORD ppid;
    char process_instance_id[128];
    char parent_process_instance_id[128];
    char command_line[1024];
    char user_identity[64];
    char executable_sha256[65];
    char attribution_status[32]; // authoritative, inferred_cached, race_suspected, permission_denied, unknown
    int64_t observed_at;
} PROCESS_ENRICHMENT_WIN;

typedef struct {
    DWORD volume_serial;
    uint64_t file_index;
    uint64_t file_size;
    FILETIME last_write_time;
    char sha256_hex[65];
    uint64_t last_used;
    bool valid;
} WIN_HASH_CACHE_ENTRY;

static WIN_HASH_CACHE_ENTRY g_WinHashCache[WIN_HASH_CACHE_CAP];
static uint64_t g_WinHashAccessCounter = 0;
static char g_WinCachedBootID[64] = {0};
static bool g_EtwSessionActive = false;
static TRACEHANDLE g_EtwSessionHandle = 0;

/* Native NT data structures for dynamic lookup */
typedef struct _OMINULL_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} OMINULL_UNICODE_STRING;

typedef struct _OMINULL_PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} OMINULL_PROCESS_BASIC_INFORMATION;

typedef LONG (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

static inline pfnNtQueryInformationProcess ProcessLineageWin_GetNtQuery(void) {
    static pfnNtQueryInformationProcess s_pfn = NULL;
    static bool s_probed = false;
    if (!s_probed) {
        HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
        if (hNtDll) {
            s_pfn = (pfnNtQueryInformationProcess)(void*)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        }
        s_probed = true;
    }
    return s_pfn;
}

/* Reset hash cache and boot ID (useful for test teardown) */
static inline void ProcessLineageWin_ResetCache(void) {
    memset(g_WinHashCache, 0, sizeof(g_WinHashCache));
    g_WinHashAccessCounter = 0;
    g_WinCachedBootID[0] = '\0';
}

/* Override boot ID for deterministic testing */
static inline void ProcessLineageWin_SetBootIDForTesting(const char* bootID) {
    if (!bootID) {
        g_WinCachedBootID[0] = '\0';
    } else {
        snprintf(g_WinCachedBootID, sizeof(g_WinCachedBootID), "%s", bootID);
    }
}

/* Captures or returns cached system boot identity */
static inline const char* ProcessLineageWin_GetBootID(void) {
    if (g_WinCachedBootID[0] != '\0') {
        return g_WinCachedBootID;
    }

    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);

    ULONGLONG uptimeSec = GetTickCount64() / 1000;
    ULONGLONG bootTime = (ULONGLONG)time(NULL) - uptimeSec;

    snprintf(g_WinCachedBootID, sizeof(g_WinCachedBootID), "win-%08lx-%llu",
             (unsigned long)serial, (unsigned long long)bootTime);
    return g_WinCachedBootID;
}

/* Reads process creation time in 100-nanosecond ticks */
static inline bool ProcessLineageWin_GetProcessTimes(HANDLE hProc, ULONGLONG* outStartTimeTicks) {
    if (!outStartTimeTicks) return false;
    *outStartTimeTicks = 0;

    FILETIME created, exited, kernel, user;
    if (GetProcessTimes(hProc, &created, &exited, &kernel, &user)) {
        *outStartTimeTicks = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
        return true;
    }
    return false;
}

/* Reads parent PID using ProcessBasicInformation with Toolhelp snapshot fallback */
static inline bool ProcessLineageWin_ReadParentPid(HANDLE hProc, DWORD pid, DWORD* outParentPid) {
    if (!outParentPid) return false;
    *outParentPid = 0;

    pfnNtQueryInformationProcess pfn = ProcessLineageWin_GetNtQuery();
    if (pfn && hProc) {
        OMINULL_PROCESS_BASIC_INFORMATION pbi;
        memset(&pbi, 0, sizeof(pbi));
        ULONG retLen = 0;
        LONG status = pfn(hProc, 0, &pbi, sizeof(pbi), &retLen);
        if (status >= 0) {
            *outParentPid = (DWORD)pbi.InheritedFromUniqueProcessId;
            return true;
        }
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    *outParentPid = pe.th32ParentProcessID;
                    CloseHandle(hSnap);
                    return true;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return false;
}

/* Reads command line via ProcessCommandLineInformation (class 60) */
static inline bool ProcessLineageWin_ReadCmdline(HANDLE hProc, char* outCmdline, size_t maxLen) {
    if (!outCmdline || maxLen == 0) return false;
    outCmdline[0] = '\0';

    pfnNtQueryInformationProcess pfn = ProcessLineageWin_GetNtQuery();
    if (pfn && hProc) {
        ULONG bufSize = 4096;
        BYTE* buf = (BYTE*)malloc(bufSize);
        if (buf) {
            ULONG retLen = 0;
            LONG status = pfn(hProc, 60, buf, bufSize, &retLen);
            if (status >= 0 && retLen >= sizeof(OMINULL_UNICODE_STRING)) {
                OMINULL_UNICODE_STRING* us = (OMINULL_UNICODE_STRING*)buf;
                if (us->Buffer && us->Length > 0) {
                    int chars = us->Length / sizeof(WCHAR);
                    int converted = WideCharToMultiByte(CP_UTF8, 0, us->Buffer, chars, outCmdline, (int)maxLen - 1, NULL, NULL);
                    if (converted > 0) {
                        outCmdline[converted] = '\0';
                        free(buf);
                        return true;
                    }
                }
            }
            free(buf);
        }
    }

    // Fallback: QueryFullProcessImageNameA
    DWORD pLen = (DWORD)maxLen;
    if (QueryFullProcessImageNameA(hProc, 0, outCmdline, &pLen)) {
        return true;
    }

    return false;
}

/* Reads user identity (DOMAIN\User or User) from process token */
static inline bool ProcessLineageWin_ReadUser(HANDLE hProc, DWORD pid, char* outUser, size_t maxLen) {
    if (!outUser || maxLen == 0) return false;
    outUser[0] = '\0';

    if (pid <= 4) {
        snprintf(outUser, maxLen, "SYSTEM");
        return true;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        return false;
    }

    DWORD reqLen = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &reqLen);
    if (reqLen == 0) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_USER* pTokenUser = (TOKEN_USER*)malloc(reqLen);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return false;
    }

    bool ok = false;
    if (GetTokenInformation(hToken, TokenUser, pTokenUser, reqLen, &reqLen)) {
        char name[128] = {0};
        DWORD nameLen = sizeof(name);
        char domain[128] = {0};
        DWORD domainLen = sizeof(domain);
        SID_NAME_USE sidType;

        if (LookupAccountSidA(NULL, pTokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
            if (domain[0] != '\0') {
                snprintf(outUser, maxLen, "%s\\%s", domain, name);
            } else {
                snprintf(outUser, maxLen, "%s", name);
            }
            ok = true;
        }
    }

    free(pTokenUser);
    CloseHandle(hToken);
    return ok;
}

/* Computes or looks up executable SHA-256 with 512-entry LRU cache */
static inline bool ProcessLineageWin_HashExecutable(const WCHAR* wExePath, char* outHex, size_t maxLen, char* outStatus, size_t statusLen) {
    if (!outHex || maxLen < 65 || !outStatus || statusLen == 0) return false;
    outHex[0] = '\0';
    snprintf(outStatus, statusLen, "unknown");

    if (!wExePath || wExePath[0] == L'\0') {
        return false;
    }

    HANDLE hFile = CreateFileW(wExePath, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION) {
            snprintf(outStatus, statusLen, "permission_denied");
        } else if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            snprintf(outStatus, statusLen, "race_suspected");
        } else {
            snprintf(outStatus, statusLen, "unknown");
        }
        return false;
    }

    BY_HANDLE_FILE_INFORMATION fi;
    if (!GetFileInformationByHandle(hFile, &fi)) {
        CloseHandle(hFile);
        snprintf(outStatus, statusLen, "unknown");
        return false;
    }

    uint64_t fileSize = ((uint64_t)fi.nFileSizeHigh << 32) | fi.nFileSizeLow;
    uint64_t fileIndex = ((uint64_t)fi.nFileIndexHigh << 32) | fi.nFileIndexLow;

    if (fileSize > WIN_MAX_HASH_BYTES) {
        CloseHandle(hFile);
        snprintf(outStatus, statusLen, "unknown");
        return false;
    }

    // 1. Check LRU Cache
    uint64_t nowAccess = ++g_WinHashAccessCounter;
    for (size_t i = 0; i < WIN_HASH_CACHE_CAP; i++) {
        WIN_HASH_CACHE_ENTRY* entry = &g_WinHashCache[i];
        if (entry->valid && entry->volume_serial == fi.dwVolumeSerialNumber &&
            entry->file_index == fileIndex && entry->file_size == fileSize &&
            entry->last_write_time.dwLowDateTime == fi.ftLastWriteTime.dwLowDateTime &&
            entry->last_write_time.dwHighDateTime == fi.ftLastWriteTime.dwHighDateTime) {
            CloseHandle(hFile);
            entry->last_used = nowAccess;
            snprintf(outHex, maxLen, "%s", entry->sha256_hex);
            snprintf(outStatus, statusLen, "inferred_cached");
            return true;
        }
    }

    // 2. Cache Miss: Compute SHA-256 over file contents
    ResponseSHA256Context ctx;
    Response_SHA256_Init(&ctx);

    size_t totalRead = 0;
    char chunk[16384];
    DWORD bytesRead = 0;

    while (ReadFile(hFile, chunk, sizeof(chunk), &bytesRead, NULL) && bytesRead > 0) {
        if (totalRead + bytesRead > WIN_MAX_HASH_BYTES) {
            CloseHandle(hFile);
            snprintf(outStatus, statusLen, "unknown");
            return false;
        }
        Response_SHA256_Update(&ctx, (const uint8_t*)chunk, bytesRead);
        totalRead += bytesRead;
    }
    CloseHandle(hFile);

    if (fileSize > 0 && totalRead != fileSize) {
        snprintf(outStatus, statusLen, "race_suspected");
        return false;
    }

    uint8_t hash[32];
    Response_SHA256_Final(&ctx, hash);
    Response_BytesToHex(hash, 32, outHex);

    // 3. Store in LRU Cache
    size_t targetSlot = 0;
    uint64_t oldest = UINT64_MAX;
    for (size_t i = 0; i < WIN_HASH_CACHE_CAP; i++) {
        if (!g_WinHashCache[i].valid) {
            targetSlot = i;
            break;
        }
        if (g_WinHashCache[i].last_used < oldest) {
            oldest = g_WinHashCache[i].last_used;
            targetSlot = i;
        }
    }

    WIN_HASH_CACHE_ENTRY* slot = &g_WinHashCache[targetSlot];
    slot->valid = true;
    slot->volume_serial = fi.dwVolumeSerialNumber;
    slot->file_index = fileIndex;
    slot->file_size = fileSize;
    slot->last_write_time = fi.ftLastWriteTime;
    snprintf(slot->sha256_hex, sizeof(slot->sha256_hex), "%s", outHex);
    slot->last_used = nowAccess;

    snprintf(outStatus, statusLen, "authoritative");
    return true;
}

/* Enriches a process with full lineage and executable hashing */
static inline bool ProcessLineageWin_InspectProcess(DWORD pid, PROCESS_ENRICHMENT_WIN* outEnrichment) {
    if (!outEnrichment) return false;
    memset(outEnrichment, 0, sizeof(*outEnrichment));
    outEnrichment->pid = pid;
    outEnrichment->observed_at = (int64_t)time(NULL);

    if (pid <= 4) {
        snprintf(outEnrichment->user_identity, sizeof(outEnrichment->user_identity), "SYSTEM");
        snprintf(outEnrichment->attribution_status, sizeof(outEnrichment->attribution_status), "unknown");
        return true;
    }

    const char* bootID = ProcessLineageWin_GetBootID();

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            snprintf(outEnrichment->attribution_status, sizeof(outEnrichment->attribution_status), "permission_denied");
        } else {
            snprintf(outEnrichment->attribution_status, sizeof(outEnrichment->attribution_status), "race_suspected");
        }
        return false;
    }

    ULONGLONG startTimeTicks = 0;
    if (ProcessLineageWin_GetProcessTimes(hProc, &startTimeTicks)) {
        snprintf(outEnrichment->process_instance_id, sizeof(outEnrichment->process_instance_id),
                 "%s:%lu:%llu", bootID, (unsigned long)pid, (unsigned long long)startTimeTicks);

        DWORD ppid = 0;
        if (ProcessLineageWin_ReadParentPid(hProc, pid, &ppid) && ppid > 0) {
            outEnrichment->ppid = ppid;
            HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
            if (hParent) {
                ULONGLONG pStartTicks = 0;
                if (ProcessLineageWin_GetProcessTimes(hParent, &pStartTicks)) {
                    snprintf(outEnrichment->parent_process_instance_id, sizeof(outEnrichment->parent_process_instance_id),
                             "%s:%lu:%llu", bootID, (unsigned long)ppid, (unsigned long long)pStartTicks);
                }
                CloseHandle(hParent);
            }
        }
    } else {
        snprintf(outEnrichment->attribution_status, sizeof(outEnrichment->attribution_status), "race_suspected");
    }

    (void)ProcessLineageWin_ReadCmdline(hProc, outEnrichment->command_line, sizeof(outEnrichment->command_line));
    (void)ProcessLineageWin_ReadUser(hProc, pid, outEnrichment->user_identity, sizeof(outEnrichment->user_identity));

    WCHAR wPath[WIN_LINEAGE_MAX_PATH] = {0};
    DWORD pathLen = WIN_LINEAGE_MAX_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, wPath, &pathLen)) {
        char hashStatus[32] = {0};
        if (ProcessLineageWin_HashExecutable(wPath, outEnrichment->executable_sha256, sizeof(outEnrichment->executable_sha256), hashStatus, sizeof(hashStatus))) {
            snprintf(outEnrichment->attribution_status, sizeof(outEnrichment->attribution_status), "%s", hashStatus);
        } else {
            if (outEnrichment->attribution_status[0] == '\0') {
                snprintf(outEnrichment->attribution_status, sizeof(outEnrichment->attribution_status), "%s", hashStatus[0] ? hashStatus : "unknown");
            }
        }
    }

    CloseHandle(hProc);
    return true;
}

/* Zero-allocation JSON escaping helper */
static inline size_t ProcessLineageWin_EscapeJSON(const char* in, char* out, size_t outLen) {
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

/* Optional real-time ETW process provider initialization with graceful fallback */
static inline bool ProcessLineageWin_InitETW(void) {
    if (g_EtwSessionActive) return true;

    // Kernel-Process Provider GUID: {22fb2cd6-0e7b-4226-a0f7-2d4c022a0044}
    static const GUID KERNEL_PROCESS_GUID =
        { 0x22fb2cd6, 0x0e7b, 0x4226, { 0xa0, 0xf7, 0x2d, 0x4c, 0x02, 0x2a, 0x00, 0x44 } };

    size_t propSize = sizeof(EVENT_TRACE_PROPERTIES) + 256;
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(propSize);
    if (!props) return false;
    memset(props, 0, propSize);

    props->Wnode.BufferSize = (ULONG)propSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; // QPC
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    TRACEHANDLE hSession = 0;
    ULONG status = StartTraceW(&hSession, L"OminullProcessTrace", props);
    if (status == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, L"OminullProcessTrace", props, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceW(&hSession, L"OminullProcessTrace", props);
    }

    if (status == ERROR_SUCCESS) {
        status = EnableTraceEx2(hSession, &KERNEL_PROCESS_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, 0x10, 0, 0, NULL);
        if (status == ERROR_SUCCESS) {
            g_EtwSessionHandle = hSession;
            g_EtwSessionActive = true;
            free(props);
            return true;
        }
        ControlTraceW(hSession, L"OminullProcessTrace", props, EVENT_TRACE_CONTROL_STOP);
    }

    free(props);
    // Graceful fallback to on-demand snapshot inspection
    g_EtwSessionActive = false;
    return false;
}

static inline void ProcessLineageWin_StopETW(void) {
    if (!g_EtwSessionActive) return;

    size_t propSize = sizeof(EVENT_TRACE_PROPERTIES) + 256;
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(propSize);
    if (props) {
        memset(props, 0, propSize);
        props->Wnode.BufferSize = (ULONG)propSize;
        ControlTraceW(g_EtwSessionHandle, L"OminullProcessTrace", props, EVENT_TRACE_CONTROL_STOP);
        free(props);
    }
    g_EtwSessionActive = false;
    g_EtwSessionHandle = 0;
}

#endif /* OMINULL_PROCESS_LINEAGE_WINDOWS_H */
