#ifndef OMINULL_TERMINAL_WINDOWS_H
#define OMINULL_TERMINAL_WINDOWS_H

/*
 * Ominull Windows ConPTY Pseudoconsole Worker (Slice 3B.2)
 *
 * Enforces Windows ConPTY Terminal Invariants:
 * 1. Build baseline: Requires NTDDI_VERSION >= 0x0A000006 and _WIN32_WINNT >= 0x0A00.
 * 2. Supported OS floor: Windows 10 Version 1809 (Build 17763) / Windows Server 2019+.
 * 3. Fixed executable allowlist: cmd.exe, powershell.exe, and pwsh.exe only.
 * 4. Pseudoconsole allocation via CreatePseudoConsole.
 * 5. Process creation with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE.
 * 6. Hard containment inside a Windows Job Object (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
 * 7. Minimal sanitized environment (PATH, SYSTEMROOT, COMSPEC).
 * 8. Full-duplex WebSocket relay via WinHTTP WebSocket API (WinHttpWebSocket*).
 * 9. Real-time window resize propagation (ResizePseudoConsole).
 * 10. Fail-closed child-tree termination (TerminateJobObject).
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000006
#endif

#include <winsock2.h>
#include <windows.h>
#include <wincon.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "agent.h"
#include "terminal_frame.h"

#define WIN_TERMINAL_MAX_FRAME_SIZE 65536
#define WIN_TERMINAL_MAX_MESSAGE 1048576   /* largest reassembled incoming message */
#define WIN_TERMINAL_STDOUT_CHUNK 32768    /* console bytes per stdout message */

/* ---------------------------------------------------------------------------
 * Executable Allowlist Validation
 * ------------------------------------------------------------------------- */

static inline bool Terminal_IsAllowedProgramWindows(const char* program, char* out_canonical, size_t out_max) {
    if (!program || program[0] == '\0' || !out_canonical || out_max < 64) return false;
    out_canonical[0] = '\0';

    // Disallow arguments, slashes that indicate subshell flags, or pipe characters
    if (strchr(program, ' ') != NULL || strchr(program, '\t') != NULL ||
        strchr(program, ';') != NULL || strchr(program, '&') != NULL ||
        strchr(program, '|') != NULL) {
        return false;
    }

    char sysDir[MAX_PATH];
    if (GetSystemDirectoryA(sysDir, sizeof(sysDir)) == 0) {
        strncpy(sysDir, "C:\\Windows\\System32", sizeof(sysDir) - 1);
        sysDir[sizeof(sysDir) - 1] = '\0';
    }

    // 1. cmd.exe
    if (_stricmp(program, "cmd.exe") == 0 || _stricmp(program, "cmd") == 0) {
        snprintf(out_canonical, out_max, "%s\\cmd.exe", sysDir);
        return (GetFileAttributesA(out_canonical) != INVALID_FILE_ATTRIBUTES);
    }
    if (_strnicmp(program, sysDir, strlen(sysDir)) == 0 && _stricmp(program + strlen(sysDir), "\\cmd.exe") == 0) {
        strncpy(out_canonical, program, out_max - 1);
        out_canonical[out_max - 1] = '\0';
        return (GetFileAttributesA(out_canonical) != INVALID_FILE_ATTRIBUTES);
    }

    // 2. powershell.exe
    char psPath[MAX_PATH];
    snprintf(psPath, sizeof(psPath), "%s\\WindowsPowerShell\\v1.0\\powershell.exe", sysDir);
    if (_stricmp(program, "powershell.exe") == 0 || _stricmp(program, "powershell") == 0) {
        strncpy(out_canonical, psPath, out_max - 1);
        out_canonical[out_max - 1] = '\0';
        return (GetFileAttributesA(out_canonical) != INVALID_FILE_ATTRIBUTES);
    }
    if (_stricmp(program, psPath) == 0) {
        strncpy(out_canonical, psPath, out_max - 1);
        out_canonical[out_max - 1] = '\0';
        return (GetFileAttributesA(out_canonical) != INVALID_FILE_ATTRIBUTES);
    }

    // 3. pwsh.exe (PowerShell Core, if installed)
    if (_stricmp(program, "pwsh.exe") == 0 || _stricmp(program, "pwsh") == 0) {
        const char* candidate7 = "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
        if (GetFileAttributesA(candidate7) != INVALID_FILE_ATTRIBUTES) {
            strncpy(out_canonical, candidate7, out_max - 1);
            out_canonical[out_max - 1] = '\0';
            return true;
        }
        return false;
    }

    return false;
}

typedef struct {
    char session_id[64];
    char program[64];
    char canonical_program[MAX_PATH];
    char connect_token[128];
} TerminalSessionParamsWin;

static inline bool Terminal_ParsePayloadWindows(const char* json, TerminalSessionParamsWin* out) {
    if (!json || !out) return false;
    memset(out, 0, sizeof(*out));
    if (!TermPayload_Parse(json, out->session_id, sizeof(out->session_id), out->program, sizeof(out->program),
                           out->connect_token, sizeof(out->connect_token))) {
        return false;
    }

    if (out->session_id[0] == '\0' || out->connect_token[0] == '\0') {
        return false;
    }

    if (out->program[0] == '\0') {
        strncpy(out->program, "cmd.exe", sizeof(out->program) - 1);
    }

    return Terminal_IsAllowedProgramWindows(out->program, out->canonical_program, sizeof(out->canonical_program));
}

/* ---------------------------------------------------------------------------
 * Base64 Encoding & Decoding for Windows
 * ------------------------------------------------------------------------- */

static inline size_t Terminal_Base64EncodeWin(const unsigned char* in, size_t in_len, char* out, size_t out_max) {
    return TermB64_Encode(in, in_len, out, out_max);
}

static inline size_t Terminal_Base64DecodeWin(const char* in, size_t in_len, unsigned char* out, size_t out_max) {
    return TermB64_Decode(in, in_len, out, out_max);
}

/* ---------------------------------------------------------------------------
 * Windows ConPTY Worker Execution
 * ------------------------------------------------------------------------- */

typedef struct {
    HANDLE hPipeOutRead;
    HINTERNET hWS;
    volatile bool running;
} TerminalWinStdoutThreadCtx;

static inline DWORD WINAPI Terminal_StdoutThreadProc(LPVOID lpParam) {
    TerminalWinStdoutThreadCtx* ctx = (TerminalWinStdoutThreadCtx*)lpParam;
    static const char pre[] = "{\"type\":\"stdout\",\"data\":\"";
    const size_t pl = sizeof(pre) - 1;
    const size_t frame_cap = TermB64_EncodedLen(WIN_TERMINAL_STDOUT_CHUNK) + pl + 8;
    unsigned char* raw_buf = (unsigned char*)malloc(WIN_TERMINAL_STDOUT_CHUNK);
    char* frame_json = (char*)malloc(frame_cap);
    if (!raw_buf || !frame_json) {
        free(raw_buf);
        free(frame_json);
        ctx->running = false;
        return 0;
    }
    memcpy(frame_json, pre, pl);

    while (ctx->running) {
        DWORD bytesRead = 0;
        /* ReadFile returns what the pipe holds now, up to the chunk: output is
         * coalesced under load and still sent at once when the console is idle. */
        if (!ReadFile(ctx->hPipeOutRead, raw_buf, WIN_TERMINAL_STDOUT_CHUNK, &bytesRead, NULL) || bytesRead == 0) {
            break;
        }
        size_t b64_len = TermB64_Encode(raw_buf, bytesRead, frame_json + pl, frame_cap - pl - 3);
        if (b64_len == 0) break;
        frame_json[pl + b64_len] = '"';
        frame_json[pl + b64_len + 1] = '}';
        DWORD err = WinHttpWebSocketSend(ctx->hWS, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                         frame_json, (DWORD)(pl + b64_len + 2));
        if (err != ERROR_SUCCESS) {
            break;
        }
    }
    free(raw_buf);
    free(frame_json);
    ctx->running = false;
    return 0;
}

/* Grows *buf to hold need bytes, up to WIN_TERMINAL_MAX_MESSAGE + 1. */
static inline bool Terminal_WinReserve(unsigned char** buf, size_t* cap, size_t need) {
    if (need > WIN_TERMINAL_MAX_MESSAGE + 1) return false;
    if (need <= *cap) return true;
    size_t ncap = *cap ? *cap : 16384;
    while (ncap < need) ncap *= 2;
    if (ncap > WIN_TERMINAL_MAX_MESSAGE + 1) ncap = WIN_TERMINAL_MAX_MESSAGE + 1;
    unsigned char* nb = (unsigned char*)realloc(*buf, ncap);
    if (!nb) return false;
    *buf = nb;
    *cap = ncap;
    return true;
}

/* Writes the whole buffer to the console input pipe. */
static inline bool Terminal_WinWriteAll(HANDLE h, const unsigned char* p, size_t n) {
    while (n > 0) {
        DWORD chunk = n > 65536 ? 65536 : (DWORD)n;
        DWORD written = 0;
        if (!WriteFile(h, p, chunk, &written, NULL) || written == 0) return false;
        p += written;
        n -= written;
    }
    return true;
}

/* Applies one complete incoming message. Returns false when the session should end. */
static inline bool Terminal_WinHandleMessage(const char* json, size_t len, HANDLE hPipeInWrite, HPCON hPC) {
    TermInFrame f;
    if (!TermFrame_Parse(json, len, &f)) return true;
    if (strcmp(f.type, "stdin") == 0) {
        if (f.data_len == 0) return true;
        size_t cap = f.data_len / 4 * 3 + 3;
        unsigned char* dec = (unsigned char*)malloc(cap);
        if (!dec) return false;
        size_t n = TermB64_Decode(f.data, f.data_len, dec, cap);
        bool ok = (n == 0) || Terminal_WinWriteAll(hPipeInWrite, dec, n);
        free(dec);
        return ok;
    }
    if (strcmp(f.type, "resize") == 0) {
        if (hPC && f.rows > 0 && f.rows <= 500 && f.cols > 0 && f.cols <= 500) {
            COORD newSize = {(SHORT)f.cols, (SHORT)f.rows};
            ResizePseudoConsole(hPC, newSize);
        }
        return true;
    }
    if (strcmp(f.type, "close") == 0) return false;
    return true;
}

static inline int Terminal_RunWindowsWorker(
    const AGENT_CONFIG* config,
    const char* session_id,
    const char* token,
    const char* program
) {
    if (!config) return -1;
    const char* hub_url = config->hub_url;
    const char* endpoint_id = config->endpoint_id;
    bool is_https = Hub_UsesTLS(config);

    char canonical_cmd[MAX_PATH];
    if (!Terminal_IsAllowedProgramWindows(program, canonical_cmd, sizeof(canonical_cmd))) {
        return -1;
    }

    // 1. Create anonymous pipes for pseudoconsole
    HANDLE hPipeInRead = NULL, hPipeInWrite = NULL;
    HANDLE hPipeOutRead = NULL, hPipeOutWrite = NULL;

    if (!CreatePipe(&hPipeInRead, &hPipeInWrite, NULL, 0)) return -1;
    if (!CreatePipe(&hPipeOutRead, &hPipeOutWrite, NULL, 0)) {
        CloseHandle(hPipeInRead);
        CloseHandle(hPipeInWrite);
        return -1;
    }

    // 2. Create pseudoconsole (80x24 default)
    COORD consoleSize = {80, 24};
    HPCON hPC = NULL;
    HRESULT hr = CreatePseudoConsole(consoleSize, hPipeInRead, hPipeOutWrite, 0, &hPC);
    // PseudoConsole takes ownership of read-in and write-out handles
    CloseHandle(hPipeInRead);
    CloseHandle(hPipeOutWrite);

    if (FAILED(hr) || !hPC) {
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        return -1;
    }

    // 3. Create Windows Job Object for containment
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) {
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        return -1;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
    ZeroMemory(&jeli, sizeof(jeli));
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));

    // 4. Configure process creation with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
    STARTUPINFOEXA siEx;
    ZeroMemory(&siEx, sizeof(siEx));
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    siEx.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)malloc(attrSize);
    if (!siEx.lpAttributeList) {
        CloseHandle(hJob);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        return -1;
    }

    if (!InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, &attrSize)) {
        free(siEx.lpAttributeList);
        CloseHandle(hJob);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        return -1;
    }

    if (!UpdateProcThreadAttribute(siEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hPC, sizeof(HPCON), NULL, NULL)) {
        DeleteProcThreadAttributeList(siEx.lpAttributeList);
        free(siEx.lpAttributeList);
        CloseHandle(hJob);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        return -1;
    }

    // Minimal sanitized environment
    const char envBlock[] = "PATH=C:\\Windows\\System32;C:\\Windows\0SYSTEMROOT=C:\\Windows\0COMSPEC=C:\\Windows\\System32\\cmd.exe\0\0";

    CreateDirectoryA("C:\\ProgramData", NULL);
    CreateDirectoryA("C:\\ProgramData\\Ominull", NULL);
    const char* workDir = "C:\\ProgramData\\Ominull";
    DWORD attr = GetFileAttributesA(workDir);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        workDir = "C:\\Windows\\System32";
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL created = CreateProcessA(
        NULL,
        canonical_cmd,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB,
        (LPVOID)envBlock,
        workDir,
        &siEx.StartupInfo,
        &pi
    );

    DeleteProcThreadAttributeList(siEx.lpAttributeList);
    free(siEx.lpAttributeList);

    if (!created) {
        CloseHandle(hJob);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        return -1;
    }

    if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hJob);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        return -1;
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    // 5. Connect WebSocket via WinHTTP
    // Parse host and port
    char hostA[128] = {0};
    int port = is_https ? 443 : 80;
    const char* p = hub_url;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        port = 80;
    } else if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        port = 443;
    }
    const char* slash = strchr(p, '/');
    size_t host_len = slash ? (size_t)(slash - p) : strlen(p);
    if (host_len >= sizeof(hostA)) host_len = sizeof(hostA) - 1;
    strncpy(hostA, p, host_len);
    hostA[host_len] = '\0';

    char* colon = strchr(hostA, ':');
    if (colon) {
        *colon = '\0';
        port = atoi(colon + 1);
    }

    WCHAR hostW[128];
    MultiByteToWideChar(CP_UTF8, 0, hostA, -1, hostW, sizeof(hostW)/sizeof(hostW[0]));

    HINTERNET hSession = WinHttpOpen(L"OminullAgent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        TerminateJobObject(hJob, 1);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        CloseHandle(pi.hProcess);
        CloseHandle(hJob);
        return -1;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, hostW, (INTERNET_PORT)port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        TerminateJobObject(hJob, 1);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        CloseHandle(pi.hProcess);
        CloseHandle(hJob);
        return -1;
    }

    char pathA[512];
    snprintf(pathA, sizeof(pathA), "/api/v1/terminal/ws/agent?session_id=%s&endpoint_id=%s&token=%s",
             session_id, endpoint_id, token);
    WCHAR pathW[512];
    MultiByteToWideChar(CP_UTF8, 0, pathA, -1, pathW, sizeof(pathW)/sizeof(pathW[0]));

    DWORD flags = is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", pathW, NULL, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        TerminateJobObject(hJob, 1);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        CloseHandle(pi.hProcess);
        CloseHandle(hJob);
        return -1;
    }

    // Set WebSocket Upgrade option
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        TerminateJobObject(hJob, 1);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        CloseHandle(pi.hProcess);
        CloseHandle(hJob);
        return -1;
    }

    char hdrsA[512];
    snprintf(hdrsA, sizeof(hdrsA),
        "X-Device-Endpoint-ID: %s\r\nX-Terminal-Token: %s\r\n",
        endpoint_id, token);
    WCHAR hdrsW[512];
    MultiByteToWideChar(CP_UTF8, 0, hdrsA, -1, hdrsW, sizeof(hdrsW)/sizeof(hdrsW[0]));

    Hub_AttachClientCert(hRequest, config);

    BOOL bSend = WinHttpSendRequest(hRequest, hdrsW, -1L, NULL, 0, 0, 0);
    if (!bSend && Hub_RetryWithoutClientCert(hRequest, GetLastError())) {
        bSend = WinHttpSendRequest(hRequest, hdrsW, -1L, NULL, 0, 0, 0);
    }

    if (!bSend || !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        TerminateJobObject(hJob, 1);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        CloseHandle(pi.hProcess);
        CloseHandle(hJob);
        return -1;
    }

    if (!Hub_VerifyRequestPin(hRequest, config)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        TerminateJobObject(hJob, 1);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        CloseHandle(pi.hProcess);
        CloseHandle(hJob);
        return -1;
    }

    HINTERNET hWS = WinHttpWebSocketCompleteUpgrade(hRequest, 0);
    WinHttpCloseHandle(hRequest);
    if (!hWS) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        TerminateJobObject(hJob, 1);
        ClosePseudoConsole(hPC);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        CloseHandle(pi.hProcess);
        CloseHandle(hJob);
        return -1;
    }

    // 6. Launch stdout forwarder thread
    TerminalWinStdoutThreadCtx stdoutCtx = {
        .hPipeOutRead = hPipeOutRead,
        .hWS = hWS,
        .running = true,
    };
    HANDLE hStdoutThread = CreateThread(NULL, 0, Terminal_StdoutThreadProc, &stdoutCtx, 0, NULL);

    // 7. Stdin & Control loop: fragments are reassembled into whole messages (up to 1 MiB) before parsing.
    unsigned char* msg = NULL;
    size_t msg_len = 0, msg_cap = 0;
    while (stdoutCtx.running) {
        if (msg_len >= WIN_TERMINAL_MAX_MESSAGE) break; /* message over the cap */
        size_t need = msg_len + 16384 + 1;
        if (need > WIN_TERMINAL_MAX_MESSAGE + 1) need = WIN_TERMINAL_MAX_MESSAGE + 1;
        if (!Terminal_WinReserve(&msg, &msg_cap, need)) break;
        DWORD bytesRead = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE bufferType;
        DWORD room = (DWORD)(msg_cap - 1 - msg_len);
        DWORD err = WinHttpWebSocketReceive(hWS, msg + msg_len, room, &bytesRead, &bufferType);
        if (err != ERROR_SUCCESS) {
            break;
        }
        if (bufferType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            break;
        }
        msg_len += bytesRead;
        if (bufferType == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE ||
            bufferType == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE) {
            continue;
        }
        bool keep = true;
        if (bufferType == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
            msg[msg_len] = '\0';
            keep = Terminal_WinHandleMessage((const char*)msg, msg_len, hPipeInWrite, hPC);
        }
        msg_len = 0;
        if (!keep) break;
    }
    free(msg);

    stdoutCtx.running = false;

    // 8. Fail-closed teardown & child-tree kill
    TerminateJobObject(hJob, 1);
    ClosePseudoConsole(hPC);
    CloseHandle(hPipeInWrite);
    CloseHandle(hPipeOutRead);

    if (hStdoutThread) {
        WaitForSingleObject(hStdoutThread, 1000);
        CloseHandle(hStdoutThread);
    }

    WinHttpWebSocketClose(hWS, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
    WinHttpCloseHandle(hWS);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(hJob);

    return (int)exitCode;
}

#endif /* OMINULL_TERMINAL_WINDOWS_H */
