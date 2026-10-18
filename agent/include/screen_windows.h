#ifndef OMINULL_SCREEN_WINDOWS_H
#define OMINULL_SCREEN_WINDOWS_H

/*
 * Ominull Windows Screen Session Launcher & Byte Relay (Track a).
 *
 * The agent runs as SYSTEM in session 0 and cannot capture pixels or inject
 * input in the interactive desktop from there (REMOTE_SCREEN.md §6). So, unlike
 * the in-process ConPTY terminal worker, screen work is done by a separate Rust
 * helper (ominull-screen-helper.exe) launched into the *active console session*.
 * This header is the C side and does TWO things only:
 *
 *   1. Launch the helper in the console session with a duplicated SYSTEM token
 *      whose TokenSessionId is set to the active console session, STARTUPINFO
 *      lpDesktop = "winsta0\\default", a per-session environment block, and a
 *      Job Object (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) so a dead agent tears the
 *      helper down (§6.1, §6.5).
 *   2. Relay bytes between the single hub WebSocket (WinHTTP, dial-out, like the
 *      ConPTY worker) and the helper's stdio over anonymous pipes, as
 *      length-prefixed frames: u8 kind (0=text, 1=binary) + u32le len + bytes
 *      (§6.5). A WS text message becomes a kind=0 frame to the helper; a WS
 *      binary message a kind=1 frame; and vice versa on the way back.
 *
 * The C side does NO message parsing beyond this length-prefix framing: the
 * screen frame/input JSON schema (§4) is owned by the Rust helper's `wire`
 * module. There is deliberately no C screen_frame.h parser (§4.4). The connect
 * token stays in the agent and never reaches the helper (§6.5).
 *
 * The pure framing helpers (ScreenFrame_*) are below the Windows guard so a
 * host build (Linux gcc) can unit-test the round trip without windows.h; the
 * launcher and relay compile only under _WIN32 (mingw cross build).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * §6.5 pipe framing: u8 kind + u32le len + len bytes. Pure, host-testable.
 * ------------------------------------------------------------------------- */

#define SCREEN_FRAME_KIND_TEXT    0u
#define SCREEN_FRAME_KIND_BINARY  1u
/* A helper->agent "service request" (§6.4/§6.5): the agent (a real Windows
 * service) acts on it itself and never forwards it to the WebSocket. The
 * payload is a single opcode byte. */
#define SCREEN_FRAME_KIND_SERVICE 2u
#define SCREEN_FRAME_HEADER_LEN   5u
/* Service-request opcode: Ctrl+Alt+Del (the SAS only a real service may send). */
#define SCREEN_SERVICE_OP_SAS     1u
/* One frame carries one WebSocket message. The relay cap is 1 MiB
 * agent->operator (§4.3); a single 256x256 JPEG tile is far under it. The same
 * cap bounds a frame the agent reassembles from the helper, so a corrupt length
 * can never make the relay allocate without bound. */
#define SCREEN_FRAME_MAX_PAYLOAD (1024u * 1024u)

/* Writes the 5-byte header (kind, then little-endian length) into out. */
static inline void ScreenFrame_EncodeHeader(uint8_t kind, uint32_t len, unsigned char out[SCREEN_FRAME_HEADER_LEN]) {
    out[0] = kind;
    out[1] = (unsigned char)(len & 0xFFu);
    out[2] = (unsigned char)((len >> 8) & 0xFFu);
    out[3] = (unsigned char)((len >> 16) & 0xFFu);
    out[4] = (unsigned char)((len >> 24) & 0xFFu);
}

/* Reads a 5-byte header. Rejects an unknown kind or a length over the cap, so
 * the caller never trusts an out-of-contract frame. */
static inline bool ScreenFrame_DecodeHeader(const unsigned char in[SCREEN_FRAME_HEADER_LEN], uint8_t* kind, uint32_t* len) {
    uint8_t k = in[0];
    if (k != SCREEN_FRAME_KIND_TEXT && k != SCREEN_FRAME_KIND_BINARY && k != SCREEN_FRAME_KIND_SERVICE) return false;
    uint32_t n = (uint32_t)in[1] | ((uint32_t)in[2] << 8) | ((uint32_t)in[3] << 16) | ((uint32_t)in[4] << 24);
    if (n > SCREEN_FRAME_MAX_PAYLOAD) return false;
    if (kind) *kind = k;
    if (len) *len = n;
    return true;
}

/* Encodes a whole frame (header + payload) into buf. Returns the total byte
 * count, or 0 if it would not fit or the payload is over the cap. */
static inline size_t ScreenFrame_EncodeInto(unsigned char* buf, size_t buf_cap, uint8_t kind,
                                            const unsigned char* payload, uint32_t len) {
    if (kind != SCREEN_FRAME_KIND_TEXT && kind != SCREEN_FRAME_KIND_BINARY && kind != SCREEN_FRAME_KIND_SERVICE) return 0;
    if (len > SCREEN_FRAME_MAX_PAYLOAD) return 0;
    size_t total = (size_t)SCREEN_FRAME_HEADER_LEN + (size_t)len;
    if (total > buf_cap) return 0;
    ScreenFrame_EncodeHeader(kind, len, buf);
    if (len) memcpy(buf + SCREEN_FRAME_HEADER_LEN, payload, len);
    return total;
}

/* Decodes a whole frame from buf. On success sets *kind, *payload (into buf),
 * *len, and *consumed (header+len). Returns false if buf does not yet hold a
 * complete frame or the header is out of contract. */
static inline bool ScreenFrame_DecodeFrom(const unsigned char* buf, size_t buf_len, uint8_t* kind,
                                          const unsigned char** payload, uint32_t* len, size_t* consumed) {
    if (buf_len < SCREEN_FRAME_HEADER_LEN) return false;
    uint8_t k = 0;
    uint32_t n = 0;
    if (!ScreenFrame_DecodeHeader(buf, &k, &n)) return false;
    if (buf_len < (size_t)SCREEN_FRAME_HEADER_LEN + (size_t)n) return false;
    if (kind) *kind = k;
    if (payload) *payload = buf + SCREEN_FRAME_HEADER_LEN;
    if (len) *len = n;
    if (consumed) *consumed = (size_t)SCREEN_FRAME_HEADER_LEN + (size_t)n;
    return true;
}

#ifdef _WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000006
#endif

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <stdio.h>
#include <stdlib.h>

#include "agent.h"
/* Response_SHA256_* (helper digest pin) and TermJson (bounded offer parsing).
 * Both are header-only and already pulled in by response_windows.c; the guard
 * makes a second include here harmless. */
#include "response_dispatcher.h"

#define SCREEN_HELPER_EXE_NAME "ominull-screen-helper.exe"

/* Bumped by the service (service.c) on SERVICE_CONTROL_SESSIONCHANGE; a live
 * screen worker watches it and respawns the helper into the new active console
 * session (§6.1). Defined once in response_windows.c. */
extern volatile LONG g_ScreenSessionEpoch;

/* The offer payload the hub writes for a screen session (§3 step 4):
 * {"session_id","mode","connect_token","operator"[,"unattended":true][,"ask_first":true]}.
 * mode is "control" or "view". unattended/ask_first (§7) and operator (display
 * only) are passed to the helper on its command line; session_id and the
 * connect token stay in the agent and never reach the helper (§6.5). */
typedef struct {
    char session_id[64];
    char mode[16];
    char connect_token[128];
    bool unattended;
    bool ask_first;
    char operator_name[65];   /* sanitized: printable ASCII, <=64 chars, no quote/backslash */
} ScreenSessionParamsWin;

/* ---------------------------------------------------------------------------
 * Pipe frame I/O over the helper's stdio handles.
 * ------------------------------------------------------------------------- */

static inline bool Screen_PipeReadAll(HANDLE h, unsigned char* p, size_t n) {
    while (n > 0) {
        DWORD chunk = n > 0x10000 ? 0x10000 : (DWORD)n;
        DWORD got = 0;
        if (!ReadFile(h, p, chunk, &got, NULL) || got == 0) return false;
        p += got;
        n -= got;
    }
    return true;
}

static inline bool Screen_PipeWriteAll(HANDLE h, const unsigned char* p, size_t n) {
    while (n > 0) {
        DWORD chunk = n > 0x10000 ? 0x10000 : (DWORD)n;
        DWORD put = 0;
        if (!WriteFile(h, p, chunk, &put, NULL) || put == 0) return false;
        p += put;
        n -= put;
    }
    return true;
}

/* Reads one length-prefixed frame from the helper's output pipe. Grows *buf as
 * needed (up to the payload cap). Returns false on EOF or an out-of-contract
 * header. */
static inline bool Screen_ReadFrame(HANDLE h, uint8_t* kind, unsigned char** buf, size_t* cap, uint32_t* len) {
    unsigned char hdr[SCREEN_FRAME_HEADER_LEN];
    if (!Screen_PipeReadAll(h, hdr, SCREEN_FRAME_HEADER_LEN)) return false;
    uint8_t k = 0;
    uint32_t n = 0;
    if (!ScreenFrame_DecodeHeader(hdr, &k, &n)) return false;
    if (n > *cap) {
        unsigned char* nb = (unsigned char*)realloc(*buf, n ? n : 1);
        if (!nb) return false;
        *buf = nb;
        *cap = n ? n : 1;
    }
    if (n > 0 && !Screen_PipeReadAll(h, *buf, n)) return false;
    *kind = k;
    *len = n;
    return true;
}

/* Writes one length-prefixed frame to the helper's input pipe. */
static inline bool Screen_WriteFrame(HANDLE h, uint8_t kind, const unsigned char* payload, uint32_t len) {
    if (len > SCREEN_FRAME_MAX_PAYLOAD) return false;
    unsigned char hdr[SCREEN_FRAME_HEADER_LEN];
    ScreenFrame_EncodeHeader(kind, len, hdr);
    if (!Screen_PipeWriteAll(h, hdr, SCREEN_FRAME_HEADER_LEN)) return false;
    return len == 0 || Screen_PipeWriteAll(h, payload, len);
}

/* ---------------------------------------------------------------------------
 * Offer payload parse (§6.5). Reads the fields the worker needs with the
 * bounded TermJson reader (never strstr). mode/unattended/ask_first here are
 * the same strict reads the grant digest was rebuilt from in VerifyResponseGrantKey
 * (ScreenCanonicalFromOffer), so what the worker launches with is what the
 * owner signed. operator is display-only, never digested.
 * ------------------------------------------------------------------------- */

/* Sanitize a display-only operator name into out: printable ASCII only, bounded
 * to 64 chars; '"' and '\\' are dropped so the name is safe on the helper's
 * command line (§7: bound it, printable only, treat as untrusted). */
static inline void Screen_SanitizeOperator(const char* raw, char* out, size_t out_cap) {
    size_t o = 0;
    for (const char* c = raw; *c && o + 1 < out_cap && o < 64; c++) {
        unsigned char ch = (unsigned char)*c;
        if (ch >= 0x20 && ch < 0x7F && ch != '"' && ch != '\\') out[o++] = (char)ch;
    }
    out[o] = '\0';
}

static inline bool Screen_ParsePayloadWindows(const char* json, ScreenSessionParamsWin* out) {
    if (!json || !out) return false;
    memset(out, 0, sizeof(*out));
    char operator_raw[256] = {0};
    TermJson j;
    if (!TermJson_Begin(&j, json, strlen(json))) return false;
    for (;;) {
        const char *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        char vt = 0;
        int r = TermJson_Next(&j, &k, &kl, &vt, &v, &vl);
        if (r == 0) break;
        if (r < 0) return false;
        if (TermJson_KeyIs(k, kl, "session_id")) {
            if (vt != 's' || !TermJson_CopyString(v, vl, out->session_id, sizeof(out->session_id))) return false;
        } else if (TermJson_KeyIs(k, kl, "mode")) {
            if (vt != 's' || !TermJson_CopyString(v, vl, out->mode, sizeof(out->mode))) return false;
        } else if (TermJson_KeyIs(k, kl, "connect_token")) {
            if (vt != 's' || !TermJson_CopyString(v, vl, out->connect_token, sizeof(out->connect_token))) return false;
        } else if (TermJson_KeyIs(k, kl, "operator")) {
            if (vt != 's' || !TermJson_CopyString(v, vl, operator_raw, sizeof(operator_raw))) return false;
        } else if (TermJson_KeyIs(k, kl, "unattended")) {
            if (vt != 'n' || vl != 4 || memcmp(v, "true", 4) != 0) return false; /* true or absent only */
            out->unattended = true;
        } else if (TermJson_KeyIs(k, kl, "ask_first")) {
            if (vt != 'n' || vl != 4 || memcmp(v, "true", 4) != 0) return false;
            out->ask_first = true;
        }
    }
    if (out->session_id[0] == '\0' || out->connect_token[0] == '\0') return false;
    if (out->mode[0] == '\0') strncpy(out->mode, "control", sizeof(out->mode) - 1);
    /* Only the two defined modes; anything else is rejected rather than coerced. */
    if (strcmp(out->mode, "control") != 0 && strcmp(out->mode, "view") != 0) return false;
    Screen_SanitizeOperator(operator_raw, out->operator_name, sizeof(out->operator_name));
    /* session_id reaches the hub query string / header (not the helper cmdline),
     * so keep it to a safe charset. */
    for (const char* c = out->session_id; *c; c++) {
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') ||
              *c == '-' || *c == '_')) {
            return false;
        }
    }
    return true;
}

/* ---------------------------------------------------------------------------
 * Helper launch into the active console session.
 * ------------------------------------------------------------------------- */

typedef BOOL (WINAPI *Screen_CreateEnvBlockFn)(LPVOID*, HANDLE, BOOL);
typedef BOOL (WINAPI *Screen_DestroyEnvBlockFn)(LPVOID);

/* Resolves <dir of the running agent exe>\ominull-screen-helper.exe. The helper
 * is signed and shipped beside the agent (§6.0); the release pins its digest. */
static inline bool Screen_HelperPathW(WCHAR* out, size_t out_count) {
    WCHAR modPath[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, modPath, (DWORD)(sizeof(modPath) / sizeof(modPath[0])));
    if (n == 0 || n >= sizeof(modPath) / sizeof(modPath[0])) return false;
    WCHAR* slash = NULL;
    for (WCHAR* p = modPath; *p; p++) {
        if (*p == L'\\' || *p == L'/') slash = p;
    }
    if (!slash) return false;
    *slash = L'\0';
    int wrote = _snwprintf(out, out_count, L"%s\\%S", modPath, SCREEN_HELPER_EXE_NAME);
    return wrote > 0 && (size_t)wrote < out_count;
}

typedef enum {
    SCREEN_LAUNCH_OK = 0,
    SCREEN_LAUNCH_RETRY = 1,       /* no active console session yet; caller retries */
    SCREEN_LAUNCH_DIGEST_FAIL = 2, /* helper binary does not match the pinned digest */
    SCREEN_LAUNCH_FAILED = 3       /* transient failure; caller may retry */
} ScreenLaunchResult;

/* Constant-time compare of two NUL-terminated 64-char lowercase hex digests. */
static inline bool Screen_HexEqConst(const char* a, const char* b) {
    unsigned char diff = 0;
    for (int i = 0; i < 64; i++) {
        if (a[i] == '\0' || b[i] == '\0') return false; /* length mismatch */
        diff |= (unsigned char)((unsigned char)a[i] ^ (unsigned char)b[i]);
    }
    return a[64] == '\0' && b[64] == '\0' && diff == 0;
}

#ifdef OMINULL_SCREEN_HELPER_SHA256
/* Hash the already-open helper file and compare to the release-pinned digest in
 * constant time. The handle is opened FILE_SHARE_READ only and stays open until
 * the process has started, so the file cannot be swapped between hash and launch. */
static inline bool Screen_HelperDigestOk(HANDLE hFile) {
    if (hFile == INVALID_HANDLE_VALUE) return false;
    if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) return false;
    ResponseSHA256Context ctx;
    Response_SHA256_Init(&ctx);
    unsigned char buf[65536];
    DWORD got = 0;
    for (;;) {
        if (!ReadFile(hFile, buf, (DWORD)sizeof(buf), &got, NULL)) return false;
        if (got == 0) break;
        Response_SHA256_Update(&ctx, buf, got);
    }
    uint8_t digest[32];
    Response_SHA256_Final(&ctx, digest);
    char hex[65];
    Response_BytesToHex(digest, 32, hex);
    return Screen_HexEqConst(hex, OMINULL_SCREEN_HELPER_SHA256);
}
#endif

typedef struct {
    HANDLE hJob;
    HANDLE hProcess;
    HANDLE hChildStdinWrite;  /* agent writes WS->helper frames here */
    HANDLE hChildStdoutRead;  /* agent reads helper->WS frames here */
} ScreenHelperProc;

/* Launches the helper as SYSTEM in the active console session. Returns
 * SCREEN_LAUNCH_OK and fills proc; the caller tears it down with
 * Screen_HelperTeardown. The connect token and session_id never reach the
 * helper; only --mode and the §7 flags (--unattended/--ask-first) and the
 * display-only --operator do. */
static inline ScreenLaunchResult Screen_LaunchHelperConsole(const ScreenSessionParamsWin* params, ScreenHelperProc* proc) {
    memset(proc, 0, sizeof(*proc));
    if (!params) return SCREEN_LAUNCH_FAILED;

    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) return SCREEN_LAUNCH_RETRY; /* no console session; caller retries */

    WCHAR helperPathW[MAX_PATH];
    if (!Screen_HelperPathW(helperPathW, sizeof(helperPathW) / sizeof(helperPathW[0]))) return SCREEN_LAUNCH_FAILED;

    /* Open (and pin) the helper that sits next to the running agent, resolved
     * from the agent's own module path (not the CWD). The handle stays open
     * across the launch so the file cannot be swapped under us. */
    HANDLE hHelperFile = CreateFileW(helperPathW, GENERIC_READ, FILE_SHARE_READ, NULL,
                                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hHelperFile == INVALID_HANDLE_VALUE) return SCREEN_LAUNCH_FAILED;
#ifdef OMINULL_SCREEN_HELPER_SHA256
    if (!Screen_HelperDigestOk(hHelperFile)) {
        CloseHandle(hHelperFile);
        return SCREEN_LAUNCH_DIGEST_FAIL;
    }
#else
    {
        static bool warned_unpinned = false;
        if (!warned_unpinned) {
            warned_unpinned = true;
            printf("[*] Screen helper launch is unpinned (dev build; no OMINULL_SCREEN_HELPER_SHA256).\n");
            fflush(stdout);
        }
    }
#endif

    /* "<helper>" --mode <control|view> [--unattended] [--ask-first] [--operator "<name>"].
     * mode is validated to control|view and operator is sanitized (printable,
     * no quote/backslash) by Screen_ParsePayloadWindows. */
    WCHAR operatorW[130] = {0};
    if (params->operator_name[0]) {
        MultiByteToWideChar(CP_UTF8, 0, params->operator_name, -1, operatorW,
                            (int)(sizeof(operatorW) / sizeof(operatorW[0])));
    }
    WCHAR cmdLine[640];
    int wrote;
    if (params->operator_name[0]) {
        wrote = _snwprintf(cmdLine, sizeof(cmdLine) / sizeof(cmdLine[0]),
                           L"\"%s\" --mode %S%ls%ls --operator \"%ls\"", helperPathW, params->mode,
                           params->unattended ? L" --unattended" : L"",
                           params->ask_first ? L" --ask-first" : L"", operatorW);
    } else {
        wrote = _snwprintf(cmdLine, sizeof(cmdLine) / sizeof(cmdLine[0]),
                           L"\"%s\" --mode %S%ls%ls", helperPathW, params->mode,
                           params->unattended ? L" --unattended" : L"",
                           params->ask_first ? L" --ask-first" : L"");
    }
    if (wrote < 0) {
        CloseHandle(hHelperFile);
        return SCREEN_LAUNCH_FAILED;
    }

    HANDLE hDup = NULL;
    LPVOID envBlock = NULL;
    HANDLE hChildStdinRead = NULL, hChildStdinWrite = NULL;
    HANDLE hChildStdoutRead = NULL, hChildStdoutWrite = NULL;
    HANDLE hNul = INVALID_HANDLE_VALUE;
    HMODULE hUserEnv = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = NULL;
    bool ok = false;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                          &hToken)) {
        CloseHandle(hHelperFile);
        return SCREEN_LAUNCH_FAILED;
    }
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hDup)) {
        CloseHandle(hToken);
        CloseHandle(hHelperFile);
        return SCREEN_LAUNCH_FAILED;
    }
    CloseHandle(hToken);

    if (!SetTokenInformation(hDup, TokenSessionId, &sessionId, sizeof(sessionId))) goto done;

    /* Per-session environment block (§6.1). Loaded dynamically so the agent's
     * link line is unchanged (no -luserenv). A NULL block is tolerable. */
    hUserEnv = LoadLibraryW(L"userenv.dll");
    if (hUserEnv) {
        Screen_CreateEnvBlockFn createEnv = (Screen_CreateEnvBlockFn)(void*)GetProcAddress(hUserEnv, "CreateEnvironmentBlock");
        if (createEnv) createEnv(&envBlock, hDup, FALSE);
    }

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&hChildStdinRead, &hChildStdinWrite, &sa, 0)) goto done;
    if (!CreatePipe(&hChildStdoutRead, &hChildStdoutWrite, &sa, 0)) goto done;
    /* Only the child's ends inherit; the agent's ends must not leak into it. */
    SetHandleInformation(hChildStdinWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hChildStdoutRead, HANDLE_FLAG_INHERIT, 0);

    /* stderr to NUL so helper diagnostics never corrupt the stdout frame stream. */
    hNul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, &sa,
                       OPEN_EXISTING, 0, NULL);

    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) goto done;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
    ZeroMemory(&jeli, sizeof(jeli));
    jeli.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));

    STARTUPINFOEXW six;
    ZeroMemory(&six, sizeof(six));
    six.StartupInfo.cb = sizeof(six);
    six.StartupInfo.lpDesktop = (LPWSTR)L"winsta0\\default";
    six.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    six.StartupInfo.hStdInput = hChildStdinRead;
    six.StartupInfo.hStdOutput = hChildStdoutWrite;
    six.StartupInfo.hStdError = (hNul != INVALID_HANDLE_VALUE) ? hNul : hChildStdoutWrite;

    /* Inherit ONLY the helper's own pipe/NUL ends. With bInheritHandles=TRUE and
     * no explicit list, every inheritable handle open in the agent at this moment
     * (e.g. a concurrent terminal worker's pipes) would leak into the SYSTEM
     * helper and could keep those pipes from ever seeing EOF (§6.1/§6.5/§6.7). */
    HANDLE inheritable[3];
    DWORD nInherit = 0;
    inheritable[nInherit++] = hChildStdinRead;
    inheritable[nInherit++] = hChildStdoutWrite;
    if (hNul != INVALID_HANDLE_VALUE) inheritable[nInherit++] = hNul;

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    if (!attrList) { CloseHandle(hJob); goto done; }
    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        HeapFree(GetProcessHeap(), 0, attrList);
        attrList = NULL;
        CloseHandle(hJob);
        goto done;
    }
    if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   inheritable, (SIZE_T)nInherit * sizeof(HANDLE), NULL, NULL)) {
        CloseHandle(hJob);
        goto done;
    }
    six.lpAttributeList = attrList;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL created = CreateProcessAsUserW(
        hDup, NULL, cmdLine, NULL, NULL, TRUE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB | EXTENDED_STARTUPINFO_PRESENT,
        envBlock, NULL, &six.StartupInfo, &pi);

    if (!created) {
        CloseHandle(hJob);
        goto done;
    }

    if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hJob);
        goto done;
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    proc->hJob = hJob;
    proc->hProcess = pi.hProcess;
    proc->hChildStdinWrite = hChildStdinWrite;
    proc->hChildStdoutRead = hChildStdoutRead;
    hChildStdinWrite = NULL; /* ownership moved to proc */
    hChildStdoutRead = NULL;
    ok = true;

done:
    if (attrList) {
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
    }
    /* The child holds its own duplicated handles now; close our copies of the
     * child-side ends and transient resources. */
    if (hChildStdinRead) CloseHandle(hChildStdinRead);
    if (hChildStdoutWrite) CloseHandle(hChildStdoutWrite);
    if (!ok) {
        if (hChildStdinWrite) CloseHandle(hChildStdinWrite);
        if (hChildStdoutRead) CloseHandle(hChildStdoutRead);
    }
    if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);
    if (envBlock && hUserEnv) {
        Screen_DestroyEnvBlockFn destroyEnv = (Screen_DestroyEnvBlockFn)(void*)GetProcAddress(hUserEnv, "DestroyEnvironmentBlock");
        if (destroyEnv) destroyEnv(envBlock);
    }
    if (hUserEnv) FreeLibrary(hUserEnv);
    if (hDup) CloseHandle(hDup);
    /* Held open across the launch so the binary could not be swapped between the
     * digest check and CreateProcessAsUserW; safe to release now. */
    CloseHandle(hHelperFile);
    return ok ? SCREEN_LAUNCH_OK : SCREEN_LAUNCH_FAILED;
}

static inline void Screen_HelperTeardown(ScreenHelperProc* proc) {
    if (!proc) return;
    if (proc->hChildStdinWrite) CloseHandle(proc->hChildStdinWrite); /* EOF -> helper exits */
    if (proc->hJob) TerminateJobObject(proc->hJob, 1);               /* fail-closed kill */
    if (proc->hChildStdoutRead) CloseHandle(proc->hChildStdoutRead);
    if (proc->hProcess) {
        WaitForSingleObject(proc->hProcess, 2000);
        CloseHandle(proc->hProcess);
    }
    if (proc->hJob) CloseHandle(proc->hJob);
    memset(proc, 0, sizeof(*proc));
}

/* ---------------------------------------------------------------------------
 * Service requests from the helper (§6.4). The agent service is the documented,
 * supported SendSAS caller; the helper may only ask via a kind=service frame.
 * ------------------------------------------------------------------------- */

/* HKLM\...\Policies\System : SoftwareSASGeneration. Services may send SAS when
 * it is 1 or 3 (bit0 set). Absent / "not configured" means disabled (the
 * default), and we never write it (§6.4). */
static inline bool Screen_SASPolicyAllows(void) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                      0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return false;
    DWORD val = 0, sz = (DWORD)sizeof(val), type = 0;
    LONG rc = RegQueryValueExW(hKey, L"SoftwareSASGeneration", NULL, &type, (LPBYTE)&val, &sz);
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return false;
    return val == 1 || val == 3;
}

/* Acts on a service request from the helper. SAS: call SendSAS(FALSE) from
 * sas.dll (loaded SYSTEM32-only; mingw lacks the import lib) when policy allows,
 * otherwise tell the operator with a sas_unavailable control frame (§4.1, §6.4).
 * Runs on the out-pump thread, which is the only WS sender, so sends don't race.
 * control is the session mode: SAS is refused outright in a view session, a
 * backstop to the helper (which only emits the opcode after a validated
 * control-mode ev:sas) in case the helper is compromised or buggy. */
static inline void Screen_HandleServiceRequest(HINTERNET hWS, bool control, const unsigned char* payload, uint32_t len) {
    if (len < 1 || payload[0] != SCREEN_SERVICE_OP_SAS) return; /* unknown opcode: ignore */
    bool sent = false;
    if (control && Screen_SASPolicyAllows()) {
        HMODULE hSas = LoadLibraryExW(L"sas.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (hSas) {
            typedef VOID (WINAPI *SendSASFn)(BOOL);
            SendSASFn pSendSAS = (SendSASFn)(void*)GetProcAddress(hSas, "SendSAS");
            if (pSendSAS) { pSendSAS(FALSE); sent = true; }
            FreeLibrary(hSas);
        }
    }
    if (!sent) {
        static const char unavail[] = "{\"type\":\"sas_unavailable\"}";
        WinHttpWebSocketSend(hWS, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, (PVOID)unavail,
                             (DWORD)(sizeof(unavail) - 1));
    }
}

/* ---------------------------------------------------------------------------
 * helper stdout -> hub WebSocket pump thread. A kind=service frame is acted on
 * here and never forwarded to the WS (§6.5).
 * ------------------------------------------------------------------------- */

/* One out-pump per helper generation. The thread OWNS hPipeOutRead and closes it
 * on exit, so no other thread can close the pipe out from under an in-flight
 * ReadFile (the SESSIONCHANGE respawn race): the supervisor tears the helper
 * down (EOF + job kill) to unblock the read, then joins this thread, which only
 * then releases the handle. The ctx itself is heap-owned by the supervisor and
 * freed after the join. */
typedef struct {
    HANDLE hPipeOutRead;  /* owned here; closed when the thread exits */
    HINTERNET hWS;
    bool control;         /* session mode, for the SAS backstop */
    volatile LONG running;
} ScreenOutPumpCtx;

static inline DWORD WINAPI Screen_OutPumpThreadProc(LPVOID lpParam) {
    ScreenOutPumpCtx* ctx = (ScreenOutPumpCtx*)lpParam;
    unsigned char* buf = NULL;
    size_t cap = 0;
    while (ctx->running) {
        uint8_t kind = 0;
        uint32_t len = 0;
        if (!Screen_ReadFrame(ctx->hPipeOutRead, &kind, &buf, &cap, &len)) break;
        if (kind == SCREEN_FRAME_KIND_SERVICE) {
            Screen_HandleServiceRequest(ctx->hWS, ctx->control, buf, len);
            continue; /* never relayed to the WS */
        }
        WINHTTP_WEB_SOCKET_BUFFER_TYPE wt = (kind == SCREEN_FRAME_KIND_BINARY)
            ? WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE
            : WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;
        DWORD err = WinHttpWebSocketSend(ctx->hWS, wt, len ? buf : (PVOID)"", len);
        if (err != ERROR_SUCCESS) break;
    }
    free(buf);
    if (ctx->hPipeOutRead) CloseHandle(ctx->hPipeOutRead);
    InterlockedExchange(&ctx->running, 0);
    return 0;
}

/* Start an out-pump generation: hands hPipeOutRead to a fresh thread with its own
 * heap context. On failure the pipe is closed and NULL returned. */
static inline ScreenOutPumpCtx* Screen_StartOutPump(HANDLE hPipeOutRead, HINTERNET hWS, bool control, HANDLE* thread) {
    ScreenOutPumpCtx* c = (ScreenOutPumpCtx*)calloc(1, sizeof(*c));
    if (!c) { CloseHandle(hPipeOutRead); *thread = NULL; return NULL; }
    c->hPipeOutRead = hPipeOutRead;
    c->hWS = hWS;
    c->control = control;
    c->running = 1;
    *thread = CreateThread(NULL, 0, Screen_OutPumpThreadProc, c, 0, NULL);
    if (!*thread) { CloseHandle(hPipeOutRead); free(c); return NULL; }
    return c;
}

/* Stop and join an out-pump generation and free its context. The caller must
 * have already torn the helper down (EOF + job kill) so the blocking ReadFile
 * returns; only then has the thread released hPipeOutRead. */
static inline void Screen_StopOutPump(ScreenOutPumpCtx* c, HANDLE* thread) {
    if (c) InterlockedExchange(&c->running, 0);
    if (thread && *thread) {
        WaitForSingleObject(*thread, 2000);
        CloseHandle(*thread);
        *thread = NULL;
    }
    free(c);
}

/* ---------------------------------------------------------------------------
 * hub WebSocket -> helper pump thread. Reassembles each WS message and writes it
 * as one frame to the *current* helper stdin, taken under a lock so the
 * supervisor can swap helpers underneath it on a session change (§6.1). A WS
 * text message becomes kind=0, binary kind=1 (§6.5); the bytes are never read.
 * ------------------------------------------------------------------------- */

typedef struct {
    CRITICAL_SECTION lock;
    HANDLE hStdinWrite;   /* current helper stdin, or NULL mid-swap */
    HINTERNET hWS;
    volatile LONG running;
} ScreenInPumpCtx;

static inline DWORD WINAPI Screen_InPumpThreadProc(LPVOID lpParam) {
    ScreenInPumpCtx* ctx = (ScreenInPumpCtx*)lpParam;
    unsigned char* msg = NULL;
    size_t msg_len = 0, msg_cap = 0;
    bool cur_is_binary = false;
    while (ctx->running) {
        if (msg_len >= SCREEN_FRAME_MAX_PAYLOAD) break;
        size_t need = msg_len + 16384;
        if (need > SCREEN_FRAME_MAX_PAYLOAD) need = SCREEN_FRAME_MAX_PAYLOAD;
        if (need > msg_cap) {
            unsigned char* nb = (unsigned char*)realloc(msg, need);
            if (!nb) break;
            msg = nb;
            msg_cap = need;
        }
        DWORD got = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE bt;
        DWORD room = (DWORD)(msg_cap - msg_len);
        DWORD err = WinHttpWebSocketReceive(ctx->hWS, msg + msg_len, room, &got, &bt);
        if (err != ERROR_SUCCESS) break;
        if (bt == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) break;
        if (msg_len == 0) {
            cur_is_binary = (bt == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE ||
                             bt == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE);
        }
        msg_len += got;
        if (bt == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE ||
            bt == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE) {
            continue; /* more fragments to come */
        }
        uint8_t kind = cur_is_binary ? SCREEN_FRAME_KIND_BINARY : SCREEN_FRAME_KIND_TEXT;
        /* Write under the lock so the supervisor cannot close this handle while
         * a write is in flight. A failed write during a helper swap is not
         * fatal: the frame is dropped (the next keyframe/input corrects it). */
        EnterCriticalSection(&ctx->lock);
        HANDLE h = ctx->hStdinWrite;
        bool wrote = (h != NULL) && Screen_WriteFrame(h, kind, msg, (uint32_t)msg_len);
        LeaveCriticalSection(&ctx->lock);
        (void)wrote;
        msg_len = 0;
    }
    free(msg);
    InterlockedExchange(&ctx->running, 0);
    return 0;
}

static inline void Screen_SendWSText(HINTERNET hWS, const char* json) {
    WinHttpWebSocketSend(hWS, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, (PVOID)json, (DWORD)strlen(json));
}

/* Launch the helper into the active console session, retrying ~500 ms while
 * there is no console session (WTSGetActiveConsoleSessionId == 0xFFFFFFFF) or on
 * a transient failure, for up to ~60 s or until the session ends (§6.1). A
 * digest mismatch is terminal and returned at once. */
static inline ScreenLaunchResult Screen_LaunchWithRetry(const ScreenSessionParamsWin* params, ScreenHelperProc* proc,
                                                        volatile LONG* running) {
    for (int attempt = 0; attempt < 120 && (!running || *running); attempt++) {
        ScreenLaunchResult lr = Screen_LaunchHelperConsole(params, proc);
        if (lr == SCREEN_LAUNCH_OK || lr == SCREEN_LAUNCH_DIGEST_FAIL) return lr;
        Sleep(500);
    }
    return SCREEN_LAUNCH_FAILED;
}

/* ---------------------------------------------------------------------------
 * The screen worker: dial the hub WS, launch the helper into the console
 * session, relay both directions, and respawn the helper on a session change.
 * Mirrors Terminal_RunWindowsWorker's WinHTTP lifecycle; the body is byte relay.
 * ------------------------------------------------------------------------- */

static inline int Screen_RunWindowsWorker(const AGENT_CONFIG* config, const ScreenSessionParamsWin* params) {
    if (!config || !params) return -1;
    const char* hub_url = config->hub_url;
    const char* endpoint_id = config->endpoint_id;
    const char* session_id = params->session_id;
    const char* token = params->connect_token;
    bool is_https = Hub_UsesTLS(config);

    /* 1. Dial the hub WebSocket first, so the operator can be told if the helper
     * will not start (e.g. a digest mismatch). Same path shape as terminal. */
    char hostA[128] = {0};
    int port = is_https ? 443 : 80;
    const char* p = hub_url;
    if (strncmp(p, "http://", 7) == 0) { p += 7; port = 80; }
    else if (strncmp(p, "https://", 8) == 0) { p += 8; port = 443; }
    const char* slash = strchr(p, '/');
    size_t host_len = slash ? (size_t)(slash - p) : strlen(p);
    if (host_len >= sizeof(hostA)) host_len = sizeof(hostA) - 1;
    strncpy(hostA, p, host_len);
    hostA[host_len] = '\0';
    char* colon = strchr(hostA, ':');
    if (colon) { *colon = '\0'; port = atoi(colon + 1); }

    WCHAR hostW[128];
    MultiByteToWideChar(CP_UTF8, 0, hostA, -1, hostW, sizeof(hostW) / sizeof(hostW[0]));

    HINTERNET hSession = WinHttpOpen(L"OminullAgent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET hConnect = NULL, hRequest = NULL, hWS = NULL;
    if (!hSession) goto fail;

    hConnect = WinHttpConnect(hSession, hostW, (INTERNET_PORT)port, 0);
    if (!hConnect) goto fail;

    /* The connect token goes in the X-Terminal-Token header only, never the URL
     * query (which lands in access logs / proxy history). The hub's screen agent
     * handler reads the token from that header when the query param is absent. */
    char pathA[512];
    snprintf(pathA, sizeof(pathA), "/api/v1/screen/ws/agent?session_id=%s&endpoint_id=%s",
             session_id, endpoint_id);
    WCHAR pathW[512];
    MultiByteToWideChar(CP_UTF8, 0, pathA, -1, pathW, sizeof(pathW) / sizeof(pathW[0]));

    DWORD flags = is_https ? WINHTTP_FLAG_SECURE : 0;
    hRequest = WinHttpOpenRequest(hConnect, L"GET", pathW, NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) goto fail;

    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) goto fail;

    char hdrsA[512];
    snprintf(hdrsA, sizeof(hdrsA), "X-Device-Endpoint-ID: %s\r\nX-Terminal-Token: %s\r\n", endpoint_id, token);
    WCHAR hdrsW[512];
    MultiByteToWideChar(CP_UTF8, 0, hdrsA, -1, hdrsW, sizeof(hdrsW) / sizeof(hdrsW[0]));

    Hub_AttachClientCert(hRequest, config);

    BOOL bSend = WinHttpSendRequest(hRequest, hdrsW, -1L, NULL, 0, 0, 0);
    if (!bSend && Hub_RetryWithoutClientCert(hRequest, GetLastError())) {
        bSend = WinHttpSendRequest(hRequest, hdrsW, -1L, NULL, 0, 0, 0);
    }
    if (!bSend || !WinHttpReceiveResponse(hRequest, NULL)) goto fail;
    if (!Hub_VerifyRequestPin(hRequest, config)) goto fail;

    hWS = WinHttpWebSocketCompleteUpgrade(hRequest, 0);
    WinHttpCloseHandle(hRequest);
    hRequest = NULL;
    if (!hWS) goto fail;

    /* 2. WS->helper pump with a swappable helper-stdin slot. */
    ScreenInPumpCtx inCtx;
    InitializeCriticalSection(&inCtx.lock);
    inCtx.hStdinWrite = NULL;
    inCtx.hWS = hWS;
    inCtx.running = 1;
    HANDLE hInThread = CreateThread(NULL, 0, Screen_InPumpThreadProc, &inCtx, 0, NULL);

    /* 3. Launch the helper (retrying across console-session transitions). */
    ScreenHelperProc proc;
    LONG epoch = g_ScreenSessionEpoch;
    ScreenLaunchResult lr = Screen_LaunchWithRetry(params, &proc, &inCtx.running);
    if (lr == SCREEN_LAUNCH_DIGEST_FAIL) {
        Screen_SendWSText(hWS, "{\"type\":\"bye\",\"reason\":\"helper_digest_mismatch\"}");
    }

    HANDLE hOutThread = NULL;
    ScreenOutPumpCtx* outCtx = NULL;
    bool control = (strcmp(params->mode, "control") == 0);
    if (lr == SCREEN_LAUNCH_OK) {
        EnterCriticalSection(&inCtx.lock);
        inCtx.hStdinWrite = proc.hChildStdinWrite;
        LeaveCriticalSection(&inCtx.lock);
        /* Hand the stdout read end to the out-pump, which now owns and will close
         * it; clear our copy so teardown never closes it mid-read. */
        outCtx = Screen_StartOutPump(proc.hChildStdoutRead, hWS, control, &hOutThread);
        proc.hChildStdoutRead = NULL;

        /* 4. Supervisor: keep the session alive; on a console session change
         * (§6.1) respawn the helper into the new session, reusing this WS. The
         * helper never migrates itself. */
        while (inCtx.running) {
            DWORD w = WaitForSingleObject(proc.hProcess, 300);
            bool helper_exited = (w == WAIT_OBJECT_0);
            LONG cur = g_ScreenSessionEpoch;
            if (!inCtx.running) break;
            bool out_dead = (outCtx == NULL) || (outCtx->running == 0);
            if (out_dead && !helper_exited && cur == epoch) break; /* WS send failed: socket gone */
            if (cur == epoch && !helper_exited) continue;          /* nothing changed */
            if (cur == epoch && helper_exited) break;              /* helper quit, no session change */

            /* Session changed: respawn into the new active console session. Stop
             * accepting WS input, tear the old helper down (EOF + job kill, which
             * unblocks the out-pump's read), then join and free the old out-pump
             * before starting a fresh generation. */
            epoch = cur;
            EnterCriticalSection(&inCtx.lock);
            inCtx.hStdinWrite = NULL;
            LeaveCriticalSection(&inCtx.lock);
            Screen_HelperTeardown(&proc);
            Screen_StopOutPump(outCtx, &hOutThread);
            outCtx = NULL;

            lr = Screen_LaunchWithRetry(params, &proc, &inCtx.running);
            if (lr != SCREEN_LAUNCH_OK) {
                if (lr == SCREEN_LAUNCH_DIGEST_FAIL)
                    Screen_SendWSText(hWS, "{\"type\":\"bye\",\"reason\":\"helper_digest_mismatch\"}");
                break;
            }
            EnterCriticalSection(&inCtx.lock);
            inCtx.hStdinWrite = proc.hChildStdinWrite;
            LeaveCriticalSection(&inCtx.lock);
            outCtx = Screen_StartOutPump(proc.hChildStdoutRead, hWS, control, &hOutThread);
            proc.hChildStdoutRead = NULL;
        }

        /* Tear down the current helper (closing stdin ends it; the job kill is
         * the fail-closed backstop), then join the out-pump that owns the read
         * end. */
        EnterCriticalSection(&inCtx.lock);
        inCtx.hStdinWrite = NULL;
        LeaveCriticalSection(&inCtx.lock);
        Screen_HelperTeardown(&proc);
        Screen_StopOutPump(outCtx, &hOutThread);
        outCtx = NULL;
    }

    /* 5. Stop the WS->helper pump (closing the WS aborts its blocking receive). */
    InterlockedExchange(&inCtx.running, 0);
    WinHttpWebSocketClose(hWS, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
    if (hInThread) { WaitForSingleObject(hInThread, 2000); CloseHandle(hInThread); }
    DeleteCriticalSection(&inCtx.lock);
    WinHttpCloseHandle(hWS);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return (lr == SCREEN_LAUNCH_OK || lr == SCREEN_LAUNCH_DIGEST_FAIL) ? 0 : -1;

fail:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return -1;
}

#endif /* _WIN32 */

#endif /* OMINULL_SCREEN_WINDOWS_H */
