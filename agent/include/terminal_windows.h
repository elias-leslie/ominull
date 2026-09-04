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

#define WIN_TERMINAL_MAX_FRAME_SIZE 65536

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

    // Bounded search for session_id
    const char* s_id = strstr(json, "\"session_id\"");
    if (s_id) {
        const char* val = strchr(s_id, ':');
        if (val) {
            val++;
            while (*val == ' ' || *val == '\t' || *val == '"') val++;
            size_t len = 0;
            while (val[len] && val[len] != '"' && val[len] != ',' && val[len] != '}' && len < sizeof(out->session_id) - 1) {
                out->session_id[len] = val[len];
                len++;
            }
            out->session_id[len] = '\0';
        }
    }

    // Bounded search for program
    const char* s_pr = strstr(json, "\"program\"");
    if (s_pr) {
        const char* val = strchr(s_pr, ':');
        if (val) {
            val++;
            while (*val == ' ' || *val == '\t' || *val == '"') val++;
            size_t len = 0;
            while (val[len] && val[len] != '"' && val[len] != ',' && val[len] != '}' && len < sizeof(out->program) - 1) {
                out->program[len] = val[len];
                len++;
            }
            out->program[len] = '\0';
        }
    }

    // Bounded search for connect_token
    const char* s_tok = strstr(json, "\"connect_token\"");
    if (s_tok) {
        const char* val = strchr(s_tok, ':');
        if (val) {
            val++;
            while (*val == ' ' || *val == '\t' || *val == '"') val++;
            size_t len = 0;
            while (val[len] && val[len] != '"' && val[len] != ',' && val[len] != '}' && len < sizeof(out->connect_token) - 1) {
                out->connect_token[len] = val[len];
                len++;
            }
            out->connect_token[len] = '\0';
        }
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

static const char b64_table_win[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline size_t Terminal_Base64EncodeWin(const unsigned char* in, size_t in_len, char* out, size_t out_max) {
    size_t out_len = 4 * ((in_len + 2) / 3);
    if (out_len + 1 > out_max) return 0;

    size_t i = 0, j = 0;
    while (i < in_len) {
        size_t rem = in_len - i;
        uint32_t oct_a = in[i++];
        uint32_t oct_b = (rem > 1) ? in[i++] : 0;
        uint32_t oct_c = (rem > 2) ? in[i++] : 0;
        uint32_t triple = (oct_a << 16) | (oct_b << 8) | oct_c;

        out[j++] = b64_table_win[(triple >> 18) & 0x3F];
        out[j++] = b64_table_win[(triple >> 12) & 0x3F];
        out[j++] = (rem > 1) ? b64_table_win[(triple >> 6) & 0x3F] : '=';
        out[j++] = (rem > 2) ? b64_table_win[triple & 0x3F] : '=';
    }
    out[j] = '\0';
    return j;
}

static inline int b64_val_win(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static inline size_t Terminal_Base64DecodeWin(const char* in, size_t in_len, unsigned char* out, size_t out_max) {
    size_t i = 0, j = 0;
    while (i < in_len && j < out_max) {
        while (i < in_len && (in[i] == ' ' || in[i] == '\r' || in[i] == '\n' || in[i] == '\t')) i++;
        if (i >= in_len) break;

        int a = b64_val_win(in[i++]);
        int b = (i < in_len) ? b64_val_win(in[i++]) : -1;
        int c = (i < in_len) ? b64_val_win(in[i++]) : -1;
        int d = (i < in_len) ? b64_val_win(in[i++]) : -1;

        if (a < 0 || b < 0) break;
        uint32_t triple = (a << 18) | (b << 12) | ((c < 0 ? 0 : c) << 6) | (d < 0 ? 0 : d);

        out[j++] = (triple >> 16) & 0xFF;
        if (c >= 0 && j < out_max) out[j++] = (triple >> 8) & 0xFF;
        if (d >= 0 && j < out_max) out[j++] = triple & 0xFF;
    }
    return j;
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
    unsigned char raw_buf[4096];

    while (ctx->running) {
        DWORD bytesRead = 0;
        if (!ReadFile(ctx->hPipeOutRead, raw_buf, sizeof(raw_buf), &bytesRead, NULL) || bytesRead == 0) {
            break;
        }

        char b64[8192];
        size_t b64_len = Terminal_Base64EncodeWin(raw_buf, bytesRead, b64, sizeof(b64));
        if (b64_len > 0) {
            char frame_json[9000];
            int jlen = snprintf(frame_json, sizeof(frame_json),
                "{\"type\":\"stdout\",\"data\":\"%s\"}", b64);
            if (jlen > 0) {
                DWORD err = WinHttpWebSocketSend(ctx->hWS, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                                 frame_json, (DWORD)jlen);
                if (err != ERROR_SUCCESS) {
                    break;
                }
            }
        }
    }
    ctx->running = false;
    return 0;
}

static inline int Terminal_RunWindowsWorker(
    const char* hub_url,
    bool is_https,
    const char* endpoint_id,
    const char* session_id,
    const char* token,
    const char* program
) {
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

    if (!WinHttpSendRequest(hRequest, hdrsW, -1L, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
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

    // 7. Stdin & Control loop
    unsigned char wsBuf[8192];
    while (stdoutCtx.running) {
        DWORD bytesRead = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE bufferType;
        DWORD err = WinHttpWebSocketReceive(hWS, wsBuf, sizeof(wsBuf) - 1, &bytesRead, &bufferType);
        if (err != ERROR_SUCCESS || bytesRead == 0) {
            break;
        }

        if (bufferType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            break;
        }

        if (bufferType == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE ||
            bufferType == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE) {
            wsBuf[bytesRead] = '\0';
            const char* f_json = (const char*)wsBuf;

            if (strstr(f_json, "\"type\":\"stdin\"") || strstr(f_json, "\"type\": \"stdin\"")) {
                const char* d_pos = strstr(f_json, "\"data\"");
                if (d_pos) {
                    const char* col = strchr(d_pos, ':');
                    if (col) {
                        col++;
                        while (*col == ' ' || *col == '\t' || *col == '"') col++;
                        size_t dlen = 0;
                        while (col[dlen] && col[dlen] != '"' && col[dlen] != '}' && col[dlen] != ',') dlen++;
                        if (dlen > 0) {
                            unsigned char dec[4096];
                            size_t declen = Terminal_Base64DecodeWin(col, dlen, dec, sizeof(dec));
                            if (declen > 0) {
                                DWORD written = 0;
                                WriteFile(hPipeInWrite, dec, (DWORD)declen, &written, NULL);
                            }
                        }
                    }
                }
            } else if (strstr(f_json, "\"type\":\"resize\"") || strstr(f_json, "\"type\": \"resize\"")) {
                int rows = 0, cols = 0;
                const char* r_pos = strstr(f_json, "\"rows\"");
                if (r_pos) {
                    const char* r_val = strchr(r_pos, ':');
                    if (r_val) rows = atoi(r_val + 1);
                }
                const char* c_pos = strstr(f_json, "\"cols\"");
                if (c_pos) {
                    const char* c_val = strchr(c_pos, ':');
                    if (c_val) cols = atoi(c_val + 1);
                }
                if (rows > 0 && rows <= 500 && cols > 0 && cols <= 500) {
                    COORD newSize = {(SHORT)cols, (SHORT)rows};
                    ResizePseudoConsole(hPC, newSize);
                }
            } else if (strstr(f_json, "\"type\":\"close\"") || strstr(f_json, "\"type\": \"close\"")) {
                break;
            }
        }
    }

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
