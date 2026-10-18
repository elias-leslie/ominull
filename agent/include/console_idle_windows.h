/*
 * console_idle_windows.h - how long the person at the console has been away.
 *
 * Windows reports no last-input time for the local console session to a
 * SYSTEM service (WTSSessionInfo, WTSSessionInfoEx and WinStationQuery all
 * return 0 there), so maintenance packages could not tell an idle signed-in
 * console from someone typing. GetLastInputInfo answers it, but only inside
 * the session itself: the agent starts its own exe there with --console-idle
 * (as the signed-in user, no window), and that child exits with the idle
 * seconds. Scripts get OMINULL_CONSOLE_SESSION and OMINULL_CONSOLE_IDLE_SECONDS
 * when the measurement worked (script_exec_windows.h).
 */
#ifndef OMINULL_CONSOLE_IDLE_WINDOWS_H
#define OMINULL_CONSOLE_IDLE_WINDOWS_H

#include <windows.h>
#include <wtsapi32.h>
#include <stdbool.h>

#define CONSOLE_IDLE_ARG L"--console-idle"
#define CONSOLE_IDLE_FAILED 0xFFFFFFFFu
#define CONSOLE_IDLE_WAIT_MS 3000

/* The child side: run first thing in main() when argv[1] is --console-idle. */
static inline DWORD ConsoleIdle_ChildSeconds(void) {
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(lii);
    lii.dwTime = 0;
    if (!GetLastInputInfo(&lii)) return CONSOLE_IDLE_FAILED;
    DWORD ms = GetTickCount() - lii.dwTime; /* 32-bit: right across the 49-day wrap */
    return ms / 1000;
}

/* The agent side: the console session id and its idle seconds, or false when
 * there is no console session, nobody is signed in, or the child failed. */
static inline bool ConsoleIdle_Measure(DWORD* sessionId, DWORD* idleSeconds) {
    DWORD sid = WTSGetActiveConsoleSessionId();
    if (sid == 0xFFFFFFFFu || sid == 0) return false;
    HANDLE token = NULL;
    if (!WTSQueryUserToken(sid, &token)) return false;
    wchar_t exe[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, exe, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        CloseHandle(token);
        return false;
    }
    wchar_t cmd[MAX_PATH + 32];
    _snwprintf(cmd, sizeof(cmd) / sizeof(cmd[0]), L"\"%ls\" %ls", exe, CONSOLE_IDLE_ARG);
    cmd[sizeof(cmd) / sizeof(cmd[0]) - 1] = L'\0';
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"winsta0\\default";
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    BOOL ok = CreateProcessAsUserW(token, exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(token);
    if (!ok) return false;
    CloseHandle(pi.hThread);
    DWORD code = CONSOLE_IDLE_FAILED;
    if (WaitForSingleObject(pi.hProcess, CONSOLE_IDLE_WAIT_MS) == WAIT_OBJECT_0) {
        if (!GetExitCodeProcess(pi.hProcess, &code)) code = CONSOLE_IDLE_FAILED;
    } else {
        TerminateProcess(pi.hProcess, CONSOLE_IDLE_FAILED);
    }
    CloseHandle(pi.hProcess);
    if (code == CONSOLE_IDLE_FAILED) return false;
    *sessionId = sid;
    *idleSeconds = code;
    return true;
}

/* Tests replace the measurement; NULL measures for real. */
typedef bool (*ConsoleIdleProbe)(DWORD* sessionId, DWORD* idleSeconds);
static ConsoleIdleProbe g_ConsoleIdleProbe = NULL;

static inline bool ConsoleIdle_Probe(DWORD* sessionId, DWORD* idleSeconds) {
    return g_ConsoleIdleProbe ? g_ConsoleIdleProbe(sessionId, idleSeconds) : ConsoleIdle_Measure(sessionId, idleSeconds);
}

#endif
