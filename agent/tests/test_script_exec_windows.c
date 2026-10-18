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
#include <assert.h>

#include "../include/script_exec_windows.h"

static int g_failures = 0;
static int g_tests_run = 0;

static void expect(const char* name, bool cond) {
    g_tests_run++;
    if (!cond) {
        printf("  [-] %s: FAIL\n", name);
        g_failures++;
    } else {
        printf("  [+] %s\n", name);
    }
}

static void test_interpreter_allowlist(void) {
    printf("[*] Testing Windows interpreter allowlist...\n");

    char canonical[MAX_PATH];

    // Permitted interpreters
    expect("cmd.exe allowed", ScriptExec_IsAllowedInterpreterWindows("cmd.exe", canonical, sizeof(canonical)));
    expect("cmd allowed", ScriptExec_IsAllowedInterpreterWindows("cmd", canonical, sizeof(canonical)));
    expect("powershell.exe allowed", ScriptExec_IsAllowedInterpreterWindows("powershell.exe", canonical, sizeof(canonical)));
    expect("powershell allowed", ScriptExec_IsAllowedInterpreterWindows("powershell", canonical, sizeof(canonical)));

    // Disallowed interpreters
    expect("/bin/sh rejected", !ScriptExec_IsAllowedInterpreterWindows("/bin/sh", canonical, sizeof(canonical)));
    expect("/bin/bash rejected", !ScriptExec_IsAllowedInterpreterWindows("/bin/bash", canonical, sizeof(canonical)));
    expect("calc.exe rejected", !ScriptExec_IsAllowedInterpreterWindows("calc.exe", canonical, sizeof(canonical)));
    expect("notepad.exe rejected", !ScriptExec_IsAllowedInterpreterWindows("notepad.exe", canonical, sizeof(canonical)));
    expect("cscript.exe rejected", !ScriptExec_IsAllowedInterpreterWindows("cscript.exe", canonical, sizeof(canonical)));
    expect("wscript.exe rejected", !ScriptExec_IsAllowedInterpreterWindows("wscript.exe", canonical, sizeof(canonical)));
    expect("python.exe rejected", !ScriptExec_IsAllowedInterpreterWindows("python.exe", canonical, sizeof(canonical)));
    expect("sh.exe rejected", !ScriptExec_IsAllowedInterpreterWindows("sh.exe", canonical, sizeof(canonical)));

    // Injection and flags rejected
    expect("cmd with args rejected", !ScriptExec_IsAllowedInterpreterWindows("cmd.exe /c whoami", canonical, sizeof(canonical)));
    expect("powershell with args rejected", !ScriptExec_IsAllowedInterpreterWindows("powershell.exe -ExecutionPolicy Bypass", canonical, sizeof(canonical)));
    expect("pipe character rejected", !ScriptExec_IsAllowedInterpreterWindows("cmd.exe|calc.exe", canonical, sizeof(canonical)));
    expect("semicolon rejected", !ScriptExec_IsAllowedInterpreterWindows("cmd.exe;whoami", canonical, sizeof(canonical)));
    expect("redirection rejected", !ScriptExec_IsAllowedInterpreterWindows("cmd.exe>foo", canonical, sizeof(canonical)));
    expect("empty string rejected", !ScriptExec_IsAllowedInterpreterWindows("", canonical, sizeof(canonical)));
    expect("null rejected", !ScriptExec_IsAllowedInterpreterWindows(NULL, canonical, sizeof(canonical)));
}

static void test_json_unescaping(void) {
    printf("[*] Testing Windows JSON unescaping...\n");

    char dst[1024];
    size_t out_len = 0;

    const char* raw1 = "hello\\nworld";
    expect("unescape newline", ScriptExec_UnescapeJSONStringWin(raw1, strlen(raw1), dst, sizeof(dst), &out_len));
    expect("newline converted", strcmp(dst, "hello\nworld") == 0);

    const char* raw2 = "quote:\\\" backslash:\\\\ tab:\\t";
    expect("unescape quote/backslash/tab", ScriptExec_UnescapeJSONStringWin(raw2, strlen(raw2), dst, sizeof(dst), &out_len));
    expect("special chars converted", strcmp(dst, "quote:\" backslash:\\ tab:\t") == 0);

    const char* raw3 = "code:\\u0041\\u0042";
    expect("unescape unicode", ScriptExec_UnescapeJSONStringWin(raw3, strlen(raw3), dst, sizeof(dst), &out_len));
    expect("unicode converted", strcmp(dst, "code:AB") == 0);
}

static void test_parameter_parsing(void) {
    printf("[*] Testing Windows parameter object parsing...\n");

    const char* json = "{\"target\":\"10.0.0.1\",\"port\":8080,\"verbose\":true}";
    ScriptParamEntryWin entries[8];
    size_t count = 0;

    ScriptExec_ParseParametersObjectWin(json, entries, 8, &count);
    expect("parsed 3 parameters", count == 3);
    expect("param 0 name is target", strcmp(entries[0].name, "target") == 0);
    expect("param 0 value is 10.0.0.1", strcmp(entries[0].value, "10.0.0.1") == 0);
    expect("param 1 name is port", strcmp(entries[1].name, "port") == 0);
    expect("param 1 value is 8080", strcmp(entries[1].value, "8080") == 0);
    expect("param 2 name is verbose", strcmp(entries[2].name, "verbose") == 0);
    expect("param 2 value is true", strcmp(entries[2].value, "true") == 0);
}

static void test_payload_parsing(void) {
    printf("[*] Testing Windows payload parsing...\n");

    const char* json =
        "{"
        "\"script_id\":\"scr-win-100\","
        "\"script_version\":3,"
        "\"script_digest\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\","
        "\"interpreter\":\"cmd.exe\","
        "\"source\":\"@echo off\\necho test\","
        "\"parameters\":{\"mode\":\"fast\",\"retries\":3},"
        "\"timeout_seconds\":45,"
        "\"max_output_bytes\":2097152"
        "}";

    ScriptExecParamsWin params;
    expect("parse valid payload", ScriptExec_ParsePayloadWin(json, &params));
    expect("script_id match", strcmp(params.script_id, "scr-win-100") == 0);
    expect("script_version match", params.script_version == 3);
    expect("script_digest match", strcmp(params.script_digest, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789") == 0);
    expect("interpreter match", strcmp(params.interpreter, "cmd.exe") == 0);
    expect("source unescaped", strcmp(params.source, "@echo off\necho test") == 0);
    expect("timeout_seconds match", params.timeout_seconds == 45);
    expect("max_output_bytes match", params.max_output_bytes == 2097152);
    expect("param_count match", params.param_count == 2);
    expect("param 0 name match", strcmp(params.params[0].name, "mode") == 0);
    expect("param 0 value match", strcmp(params.params[0].value, "fast") == 0);

    // Reject disallowed interpreter
    const char* evil_json =
        "{"
        "\"script_id\":\"scr-evil\","
        "\"interpreter\":\"calc.exe\","
        "\"source\":\"echo evil\""
        "}";
    expect("reject disallowed interpreter in payload", !ScriptExec_ParsePayloadWin(evil_json, &params));

    /* Maintenance packages run for up to an hour; past that the default applies. */
    expect("an hour-long timeout is accepted",
        ScriptExec_ParsePayloadWin("{\"script_id\":\"s\",\"interpreter\":\"cmd.exe\",\"source\":\"echo\",\"timeout_seconds\":3600}", &params) &&
        params.timeout_seconds == 3600);
    expect("a timeout over an hour falls back to the default",
        ScriptExec_ParsePayloadWin("{\"script_id\":\"s\",\"interpreter\":\"cmd.exe\",\"source\":\"echo\",\"timeout_seconds\":3601}", &params) &&
        params.timeout_seconds == SCRIPT_EXEC_DEFAULT_TIMEOUT);
}

static void test_cmd_simple_exec(void) {
    printf("[*] Testing Windows cmd.exe simple script execution...\n");

    const char* script_body = "@echo off\r\necho Hello from Ominull Windows Worker\r\n";
    size_t script_len = strlen(script_body);

    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)script_body, script_len, hash);
    char digest_hex[65];
    for (int i = 0; i < 32; i++) snprintf(digest_hex + (i * 2), 3, "%02x", hash[i]);

    ScriptExecParamsWin params;
    memset(&params, 0, sizeof(params));
    snprintf(params.script_id, sizeof(params.script_id), "scr-test-win-01");
    params.script_version = 1;
    snprintf(params.script_digest, sizeof(params.script_digest), "%s", digest_hex);
    snprintf(params.interpreter, sizeof(params.interpreter), "cmd.exe");
    snprintf(params.source, sizeof(params.source), "%s", script_body);
    params.source_len = script_len;
    params.timeout_seconds = 10;
    params.max_output_bytes = 65536;

    char output[4096] = {0};
    bool truncated = false;
    bool timed_out = false;
    int64_t duration_ms = 0;
    char error_code[64] = {0};

    int exit_code = ScriptExec_RunContainedWin(
        &params,
        "job-win-01",
        output,
        sizeof(output),
        &truncated,
        &timed_out,
        &duration_ms,
        error_code,
        sizeof(error_code)
    );

    expect("exit code is 0", exit_code == 0);
    expect("not timed out", !timed_out);
    expect("not truncated", !truncated);
    expect("no error code", error_code[0] == '\0');
    expect("output contains banner", strstr(output, "Hello from Ominull Windows Worker") != NULL);
}

static void test_parameter_delivery(void) {
    printf("[*] Testing Windows parameter delivery without template substitution...\n");

    const char* script_body = "@echo off\r\necho TARGET=%TARGET% PORT=%OMINULL_PARAM_PORT% JOB=%OMINULL_JOB_ID%\r\n";
    size_t script_len = strlen(script_body);

    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)script_body, script_len, hash);
    char digest_hex[65];
    for (int i = 0; i < 32; i++) snprintf(digest_hex + (i * 2), 3, "%02x", hash[i]);

    ScriptExecParamsWin params;
    memset(&params, 0, sizeof(params));
    snprintf(params.script_id, sizeof(params.script_id), "scr-param-win-02");
    params.script_version = 1;
    snprintf(params.script_digest, sizeof(params.script_digest), "%s", digest_hex);
    snprintf(params.interpreter, sizeof(params.interpreter), "cmd.exe");
    snprintf(params.source, sizeof(params.source), "%s", script_body);
    params.source_len = script_len;
    params.timeout_seconds = 10;
    params.max_output_bytes = 65536;

    const char* pjson = "{\"TARGET\":\"192.0.2.1\",\"port\":\"9090\"}";
    snprintf(params.parameters_json, sizeof(params.parameters_json), "%s", pjson);
    params.parameters_len = strlen(pjson);
    ScriptExec_ParseParametersObjectWin(pjson, params.params, SCRIPT_EXEC_MAX_PARAM_COUNT, &params.param_count);

    char output[4096] = {0};
    bool truncated = false;
    bool timed_out = false;
    int64_t duration_ms = 0;
    char error_code[64] = {0};

    int exit_code = ScriptExec_RunContainedWin(
        &params,
        "job-win-param-02",
        output,
        sizeof(output),
        &truncated,
        &timed_out,
        &duration_ms,
        error_code,
        sizeof(error_code)
    );

    expect("parameter exit code is 0", exit_code == 0);
    expect("output contains delivered TARGET", strstr(output, "TARGET=192.0.2.1") != NULL);
    expect("output contains delivered PORT", strstr(output, "PORT=9090") != NULL);
    expect("output contains delivered JOB", strstr(output, "JOB=job-win-param-02") != NULL);

    // Verify cleanup: script and param files removed
    char state_dir[MAX_PATH];
    ScriptExec_GetStateDirWin(state_dir, sizeof(state_dir));
    char script_path[MAX_PATH];
    snprintf(script_path, sizeof(script_path), "%s\\ominull_script_job-win-param-02.cmd", state_dir);
    char param_path[MAX_PATH];
    snprintf(param_path, sizeof(param_path), "%s\\ominull_params_job-win-param-02.json", state_dir);

    expect("script file cleaned up", GetFileAttributesA(script_path) == INVALID_FILE_ATTRIBUTES);
    expect("param file cleaned up", GetFileAttributesA(param_path) == INVALID_FILE_ATTRIBUTES);
}

static void test_digest_tamper_rejection(void) {
    printf("[*] Testing Windows digest tamper rejection...\n");

    const char* valid_script = "@echo off\r\necho valid\r\n";
    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)valid_script, strlen(valid_script), hash);
    char digest_hex[65];
    for (int i = 0; i < 32; i++) snprintf(digest_hex + (i * 2), 3, "%02x", hash[i]);

    // Tamper the script body!
    const char* tampered_script = "@echo off\r\necho TAMPERED\r\n";

    ScriptExecParamsWin params;
    memset(&params, 0, sizeof(params));
    snprintf(params.script_id, sizeof(params.script_id), "scr-tamper-03");
    snprintf(params.script_digest, sizeof(params.script_digest), "%s", digest_hex);
    snprintf(params.interpreter, sizeof(params.interpreter), "cmd.exe");
    snprintf(params.source, sizeof(params.source), "%s", tampered_script);
    params.source_len = strlen(tampered_script);
    params.timeout_seconds = 5;
    params.max_output_bytes = 1024;

    char output[4096] = {0};
    bool truncated = false;
    bool timed_out = false;
    int64_t duration_ms = 0;
    char error_code[64] = {0};

    int exit_code = ScriptExec_RunContainedWin(
        &params,
        "job-tamper-03",
        output,
        sizeof(output),
        &truncated,
        &timed_out,
        &duration_ms,
        error_code,
        sizeof(error_code)
    );

    expect("tampered script rejected with exit code 1", exit_code != 0);
    expect("error code is SCRIPT_DIGEST_MISMATCH", strcmp(error_code, "SCRIPT_DIGEST_MISMATCH") == 0);
    expect("no output produced", strlen(output) == 0);
    expect("duration is 0", duration_ms == 0);
}

static void test_output_truncation(void) {
    printf("[*] Testing Windows output truncation bounding...\n");

    const char* script_body =
        "@echo off\r\n"
        "for /L %%i in (1,1,30) do echo OutputLineNumber%%iRepeatedDataPaddingForCapTest\r\n";
    size_t script_len = strlen(script_body);

    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)script_body, script_len, hash);
    char digest_hex[65];
    for (int i = 0; i < 32; i++) snprintf(digest_hex + (i * 2), 3, "%02x", hash[i]);

    ScriptExecParamsWin params;
    memset(&params, 0, sizeof(params));
    snprintf(params.script_id, sizeof(params.script_id), "scr-trunc-04");
    snprintf(params.script_digest, sizeof(params.script_digest), "%s", digest_hex);
    snprintf(params.interpreter, sizeof(params.interpreter), "cmd.exe");
    snprintf(params.source, sizeof(params.source), "%s", script_body);
    params.source_len = script_len;
    params.timeout_seconds = 5;
    params.max_output_bytes = 250; // Cap at 250 bytes

    char output[4096] = {0};
    bool truncated = false;
    bool timed_out = false;
    int64_t duration_ms = 0;
    char error_code[64] = {0};

    int exit_code = ScriptExec_RunContainedWin(
        &params,
        "job-trunc-04",
        output,
        sizeof(output),
        &truncated,
        &timed_out,
        &duration_ms,
        error_code,
        sizeof(error_code)
    );

    expect("script executed successfully", exit_code == 0);
    expect("marked as truncated", truncated);
    expect("output contains truncation notice", strstr(output, "[...output truncated by ominull worker...]") != NULL);
}

static void test_timeout_containment(void) {
    printf("[*] Testing Windows Job Object timeout and containment...\n");

    // Script running loop with ping or sleep
    const char* script_body =
        "@echo off\r\n"
        "ping 127.0.0.1 -n 10 > nul\r\n";
    size_t script_len = strlen(script_body);

    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)script_body, script_len, hash);
    char digest_hex[65];
    for (int i = 0; i < 32; i++) snprintf(digest_hex + (i * 2), 3, "%02x", hash[i]);

    ScriptExecParamsWin params;
    memset(&params, 0, sizeof(params));
    snprintf(params.script_id, sizeof(params.script_id), "scr-timeout-05");
    snprintf(params.script_digest, sizeof(params.script_digest), "%s", digest_hex);
    snprintf(params.interpreter, sizeof(params.interpreter), "cmd.exe");
    snprintf(params.source, sizeof(params.source), "%s", script_body);
    params.source_len = script_len;
    params.timeout_seconds = 1; // 1 second timeout
    params.max_output_bytes = 1024;

    char output[4096] = {0};
    bool truncated = false;
    bool timed_out = false;
    int64_t duration_ms = 0;
    char error_code[64] = {0};

    int exit_code = ScriptExec_RunContainedWin(
        &params,
        "job-timeout-05",
        output,
        sizeof(output),
        &truncated,
        &timed_out,
        &duration_ms,
        error_code,
        sizeof(error_code)
    );

    expect("exit code indicates timeout (124)", exit_code == 124);
    expect("timed_out flag is true", timed_out);
    expect("duration reflects elapsed time >= 1000ms", duration_ms >= 900);
}

static void test_nonzero_exit_code(void) {
    printf("[*] Testing Windows non-zero exit code reporting...\n");

    const char* script_body = "@echo off\r\nexit /b 42\r\n";
    size_t script_len = strlen(script_body);

    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)script_body, script_len, hash);
    char digest_hex[65];
    for (int i = 0; i < 32; i++) snprintf(digest_hex + (i * 2), 3, "%02x", hash[i]);

    ScriptExecParamsWin params;
    memset(&params, 0, sizeof(params));
    snprintf(params.script_id, sizeof(params.script_id), "scr-exit-06");
    snprintf(params.script_digest, sizeof(params.script_digest), "%s", digest_hex);
    snprintf(params.interpreter, sizeof(params.interpreter), "cmd.exe");
    snprintf(params.source, sizeof(params.source), "%s", script_body);
    params.source_len = script_len;
    params.timeout_seconds = 5;
    params.max_output_bytes = 1024;

    char output[4096] = {0};
    bool truncated = false;
    bool timed_out = false;
    int64_t duration_ms = 0;
    char error_code[64] = {0};

    int exit_code = ScriptExec_RunContainedWin(
        &params,
        "job-exit-06",
        output,
        sizeof(output),
        &truncated,
        &timed_out,
        &duration_ms,
        error_code,
        sizeof(error_code)
    );

    expect("reported exit code is 42", exit_code == 42);
    expect("timed_out is false", !timed_out);
}

static void test_json_escaping_win(void) {
    printf("[*] Testing Windows JSON string escaping...\n");

    const char* in = "Line 1\r\nLine 2\t\"quoted\" \\backslash\\";
    char* escaped = ScriptExec_EscapeJSONWin(in);
    expect("escaping succeeded", escaped != NULL);
    expect("escaped contains backslash quote", strstr(escaped, "\\\"quoted\\\"") != NULL);
    expect("escaped contains backslash n", strstr(escaped, "\\n") != NULL);
    expect("escaped contains backslash r", strstr(escaped, "\\r") != NULL);
    expect("escaped contains backslash t", strstr(escaped, "\\t") != NULL);
    expect("escaped contains double backslash", strstr(escaped, "\\\\backslash\\\\") != NULL);
    if (escaped) free(escaped);
}

static void test_long_path_reaches_script(void) {
    printf("[*] Testing a PATH longer than MAX_PATH reaches the script whole...\n");

    char saved[32768] = {0};
    DWORD had = GetEnvironmentVariableA("PATH", saved, sizeof(saved));
    char longPath[32768];
    int n = snprintf(longPath, sizeof(longPath), "%s", had > 0 && had < sizeof(saved) ? saved : "C:\\Windows\\System32");
    for (int i = 0; i < 12 && n < 30000; i++) {
        n += snprintf(longPath + n, sizeof(longPath) - (size_t)n, ";C:\\Program Files\\OmniNull Long Path Padding %02d", i);
    }
    n += snprintf(longPath + n, sizeof(longPath) - (size_t)n, ";C:\\omninull-path-tail-marker");
    SetEnvironmentVariableA("PATH", longPath);

    const char* script_body = "@echo off\r\necho PATHIS=%PATH%\r\necho EXTIS=%PATHEXT%\r\n";
    size_t script_len = strlen(script_body);
    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)script_body, script_len, hash);
    char digest_hex[65];
    for (int i = 0; i < 32; i++) snprintf(digest_hex + (i * 2), 3, "%02x", hash[i]);

    ScriptExecParamsWin params;
    memset(&params, 0, sizeof(params));
    snprintf(params.script_id, sizeof(params.script_id), "scr-test-win-path");
    params.script_version = 1;
    snprintf(params.script_digest, sizeof(params.script_digest), "%s", digest_hex);
    snprintf(params.interpreter, sizeof(params.interpreter), "cmd.exe");
    snprintf(params.source, sizeof(params.source), "%s", script_body);
    params.source_len = script_len;
    params.timeout_seconds = 10;
    params.max_output_bytes = 65536;

    char output[8192] = {0};
    bool truncated = false, timed_out = false;
    int64_t duration_ms = 0;
    char error_code[64] = {0};
    int exit_code = ScriptExec_RunContainedWin(&params, "job-win-path", output, sizeof(output),
        &truncated, &timed_out, &duration_ms, error_code, sizeof(error_code));

    if (had > 0 && had < sizeof(saved)) SetEnvironmentVariableA("PATH", saved);

    expect("long PATH: exit code is 0", exit_code == 0);
    expect("long PATH: tail of PATH reaches the script", strstr(output, "omninull-path-tail-marker") != NULL);
    expect("PATHEXT reaches the script", strstr(output, "EXTIS=") != NULL && (strstr(output, ".EXE") != NULL || strstr(output, ".exe") != NULL));
    expect("long PATH: PATH is not the ComSpec value", strstr(output, "PATHIS=C:\\windows\\system32\\cmd.exe\r") == NULL &&
                                                        strstr(output, "PATHIS=C:\\Windows\\System32\\cmd.exe\r") == NULL);
}

/* Windows environment names ignore case: a parameter arrives once, as
 * OMINULL_PARAM_<UPPER>. Sending OMINULL_PARAM_mode as well made PowerShell's
 * Start-Process fail with "Item has already been added. Key in dictionary:
 * 'OMINULL_PARAM_MODE' Key being added: 'OMINULL_PARAM_mode'". */
static void test_parameter_once_per_name(void) {
    printf("[*] Testing each parameter reaches the script once...\n");
    const char* script_body = "@echo off\r\nset OMINULL_PARAM_\r\n";
    size_t script_len = strlen(script_body);
    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)script_body, script_len, hash);
    char digest_hex[65];
    for (int i = 0; i < 32; i++) snprintf(digest_hex + (i * 2), 3, "%02x", hash[i]);
    ScriptExecParamsWin params;
    memset(&params, 0, sizeof(params));
    snprintf(params.script_id, sizeof(params.script_id), "scr-param-once");
    params.script_version = 1;
    snprintf(params.script_digest, sizeof(params.script_digest), "%s", digest_hex);
    snprintf(params.interpreter, sizeof(params.interpreter), "cmd.exe");
    snprintf(params.source, sizeof(params.source), "%s", script_body);
    params.source_len = script_len;
    params.timeout_seconds = 10;
    params.max_output_bytes = 65536;
    const char* pjson = "{\"mode\":\"audit\"}";
    snprintf(params.parameters_json, sizeof(params.parameters_json), "%s", pjson);
    params.parameters_len = strlen(pjson);
    ScriptExec_ParseParametersObjectWin(pjson, params.params, SCRIPT_EXEC_MAX_PARAM_COUNT, &params.param_count);
    char output[4096] = {0};
    bool truncated = false, timed_out = false;
    int64_t duration_ms = 0;
    char error_code[64] = {0};
    int exit_code = ScriptExec_RunContainedWin(&params, "job-win-param-once", output, sizeof(output), &truncated, &timed_out,
                                               &duration_ms, error_code, sizeof(error_code));
    int lines = 0;
    for (const char* p = output; (p = strstr(p, "=audit")) != NULL; p++) lines++;
    expect("param once: exit code is 0", exit_code == 0);
    expect("param once: OMINULL_PARAM_MODE arrives", strstr(output, "OMINULL_PARAM_MODE=audit") != NULL);
    expect("param once: no lowercase duplicate", strstr(output, "OMINULL_PARAM_mode=") == NULL && lines == 1);
}

int main(void) {
    printf("=== Starting Windows Script Exec Worker C Tests (Slice 5C) ===\n");

    test_interpreter_allowlist();
    test_json_unescaping();
    test_parameter_parsing();
    test_payload_parsing();
    test_cmd_simple_exec();
    test_parameter_delivery();
    test_parameter_once_per_name();
    test_digest_tamper_rejection();
    test_output_truncation();
    test_timeout_containment();
    test_nonzero_exit_code();
    test_json_escaping_win();
    test_long_path_reaches_script();

    printf("\n=== Results: %d tests, %d failures ===\n", g_tests_run, g_failures);
    return g_failures == 0 ? 0 : 1;
}
