#include <winsock2.h>
#include <windows.h>
#include <wincon.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "../include/terminal_windows.h"

static int failures = 0;

static void expect(const char* name, bool cond) {
    if (!cond) {
        printf("  [-] %s: FAIL\n", name);
        failures++;
    } else {
        printf("  [+] %s\n", name);
    }
}

static void test_allowlist_windows() {
    printf("[*] Testing Windows program allowlist...\n");

    char canonical[MAX_PATH];

    // Permitted executables
    expect("cmd.exe allowed", Terminal_IsAllowedProgramWindows("cmd.exe", canonical, sizeof(canonical)));
    expect("powershell.exe allowed", Terminal_IsAllowedProgramWindows("powershell.exe", canonical, sizeof(canonical)));

    // Disallowed executables, arguments, subshells
    expect("calc.exe rejected", !Terminal_IsAllowedProgramWindows("calc.exe", canonical, sizeof(canonical)));
    expect("notepad.exe rejected", !Terminal_IsAllowedProgramWindows("notepad.exe", canonical, sizeof(canonical)));
    expect("cmd with args rejected", !Terminal_IsAllowedProgramWindows("cmd.exe /c whoami", canonical, sizeof(canonical)));
    expect("powershell with args rejected", !Terminal_IsAllowedProgramWindows("powershell.exe -Command whoami", canonical, sizeof(canonical)));
    expect("relative path rejected", !Terminal_IsAllowedProgramWindows("..\\cmd.exe", canonical, sizeof(canonical)));
    expect("empty program rejected", !Terminal_IsAllowedProgramWindows("", canonical, sizeof(canonical)));
    expect("null program rejected", !Terminal_IsAllowedProgramWindows(NULL, canonical, sizeof(canonical)));
}

static void test_payload_parsing_windows() {
    printf("[*] Testing Windows payload parsing...\n");

    TerminalSessionParamsWin params;

    // Valid cmd.exe payload
    const char* valid_cmd = "{\"session_id\":\"sess-win-01\",\"program\":\"cmd.exe\",\"connect_token\":\"tok-win-01\"}";
    expect("parse valid cmd payload", Terminal_ParsePayloadWindows(valid_cmd, &params));
    expect("session_id parsed", strcmp(params.session_id, "sess-win-01") == 0);
    expect("program parsed", strcmp(params.program, "cmd.exe") == 0);
    expect("canonical path resolved", strstr(params.canonical_program, "cmd.exe") != NULL);

    // Valid powershell payload
    const char* valid_ps = "{\"session_id\":\"sess-win-02\",\"program\":\"powershell.exe\",\"connect_token\":\"tok-win-02\"}";
    expect("parse valid powershell payload", Terminal_ParsePayloadWindows(valid_ps, &params));
    expect("canonical powershell path resolved", strstr(params.canonical_program, "powershell.exe") != NULL);

    // Disallowed payload
    const char* evil = "{\"session_id\":\"sess-evil\",\"program\":\"calc.exe\",\"connect_token\":\"tok-1\"}";
    expect("reject disallowed program payload", !Terminal_ParsePayloadWindows(evil, &params));

    // Missing token
    const char* missing = "{\"session_id\":\"sess-win-03\",\"program\":\"cmd.exe\"}";
    expect("reject missing token payload", !Terminal_ParsePayloadWindows(missing, &params));
}

static void test_base64_windows() {
    printf("[*] Testing Windows Base64 encode/decode...\n");

    const unsigned char test_data[] = "Windows ConPTY Test Payload \x00\x01\x02\xFF\xFE";
    size_t in_len = sizeof(test_data);

    char encoded[128];
    size_t elen = Terminal_Base64EncodeWin(test_data, in_len, encoded, sizeof(encoded));
    expect("base64 encode length > 0", elen > 0);

    unsigned char decoded[128];
    size_t dlen = Terminal_Base64DecodeWin(encoded, elen, decoded, sizeof(decoded));
    expect("base64 decode roundtrip length", dlen == in_len);
    expect("base64 decode roundtrip content", memcmp(test_data, decoded, in_len) == 0);
}

static void test_conpty_lifecycle() {
    printf("[*] Testing ConPTY Pseudoconsole allocation and resize...\n");

    HANDLE hInR, hInW, hOutR, hOutW;
    CreatePipe(&hInR, &hInW, NULL, 0);
    CreatePipe(&hOutR, &hOutW, NULL, 0);

    COORD size = {80, 24};
    HPCON hPC = NULL;
    HRESULT hr = CreatePseudoConsole(size, hInR, hOutW, 0, &hPC);
    CloseHandle(hInR);
    CloseHandle(hOutW);

    if (FAILED(hr) || !hPC) {
        // ConPTY may not be emulated by Wine or requires native Win10 1809+ host
        printf("  [!] CreatePseudoConsole hr=0x%08lx (Note: requires Windows 10 Version 1809 / Build 17763+)\n", hr);
    } else {
        expect("CreatePseudoConsole succeeded", SUCCEEDED(hr));
        COORD newSize = {120, 40};
        hr = ResizePseudoConsole(hPC, newSize);
        expect("ResizePseudoConsole succeeded or E_NOTIMPL under Wine", SUCCEEDED(hr) || hr == (HRESULT)0x80004001L);
        ClosePseudoConsole(hPC);
        printf("  [+] ConPTY Pseudoconsole lifecycle verified.\n");
    }

    CloseHandle(hInW);
    CloseHandle(hOutR);
}

static void test_job_object_containment() {
    printf("[*] Testing Windows Job Object containment...\n");

    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    expect("CreateJobObjectW succeeded", hJob != NULL);

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
    ZeroMemory(&jeli, sizeof(jeli));
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    expect("SetInformationJobObject succeeded",
           SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli)));

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    char cmd[] = "C:\\Windows\\System32\\cmd.exe /c ping -n 10 127.0.0.1";
    BOOL created = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB,
                                  NULL, NULL, &si, &pi);
    expect("CreateProcessA suspended succeeded", created);

    if (created) {
        expect("AssignProcessToJobObject succeeded", AssignProcessToJobObject(hJob, pi.hProcess));
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);

        // Terminate Job Object -> kills process tree immediately
        expect("TerminateJobObject succeeded", TerminateJobObject(hJob, 0));
        WaitForSingleObject(pi.hProcess, 2000);

        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        expect("process terminated", exitCode != STILL_ACTIVE);
        CloseHandle(pi.hProcess);
    }

    CloseHandle(hJob);
}

int main() {
    printf("=== Starting Windows Terminal Worker Tests (Slice 3B.2) ===\n");
    test_allowlist_windows();
    test_payload_parsing_windows();
    test_base64_windows();
    test_conpty_lifecycle();
    test_job_object_containment();

    if (failures == 0) {
        printf("=== All Windows Terminal Worker Tests Passed Successfully! ===\n");
        return 0;
    }
    printf("=== Finished with %d failures! ===\n", failures);
    return 1;
}
