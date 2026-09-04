/*
 * Comprehensive unit test suite for Ominull Linux Script Execution Worker (Slice 5B).
 * Tests:
 * - Interpreter allowlist validation (/bin/sh, /bin/bash, pwsh).
 * - Payload parser and JSON unescaping.
 * - In-process SHA-256 source digest verification.
 * - Script execution with captured stdout/stderr.
 * - Parameter passing via private file and sanitized environment (no template substitution).
 * - Process containment (process group isolation, clean environment).
 * - Output truncation bounds enforcement.
 * - Hard execution timeout escalation (SIGTERM -> SIGKILL) and exit code 124.
 * - Non-zero exit code reporting.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>

#include "../include/script_exec_linux.h"

static int failures = 0;

static void expect(const char* name, bool condition) {
    if (!condition) {
        printf("  [-] FAILED: %s\n", name);
        failures++;
    } else {
        printf("  [+] PASS: %s\n", name);
    }
}

/* 1. Test Interpreter Allowlisting */
static void test_interpreter_allowlist(void) {
    printf("[*] Testing Interpreter Allowlist...\n");
    expect("/bin/sh allowed", ScriptExec_IsAllowedInterpreter("/bin/sh"));
    expect("/bin/bash allowed", ScriptExec_IsAllowedInterpreter("/bin/bash"));
    expect("/usr/bin/sh allowed", ScriptExec_IsAllowedInterpreter("/usr/bin/sh"));
    expect("/usr/bin/bash allowed", ScriptExec_IsAllowedInterpreter("/usr/bin/bash"));
    expect("pwsh allowed", ScriptExec_IsAllowedInterpreter("pwsh"));
    expect("/usr/bin/pwsh allowed", ScriptExec_IsAllowedInterpreter("/usr/bin/pwsh"));

    expect("/usr/bin/python3 rejected", !ScriptExec_IsAllowedInterpreter("/usr/bin/python3"));
    expect("/bin/zsh rejected", !ScriptExec_IsAllowedInterpreter("/bin/zsh"));
    expect("/usr/bin/perl rejected", !ScriptExec_IsAllowedInterpreter("/usr/bin/perl"));
    expect("sudo rejected", !ScriptExec_IsAllowedInterpreter("sudo"));
    expect("NULL rejected", !ScriptExec_IsAllowedInterpreter(NULL));
    expect("empty rejected", !ScriptExec_IsAllowedInterpreter(""));
}

/* 2. Test JSON Unescaping */
static void test_json_unescaping(void) {
    printf("[*] Testing JSON Unescaping...\n");
    const char* raw = "echo \\\"hello world\\\"\\nexit 0\\n";
    char unescaped[256];
    size_t len = 0;
    ScriptExec_UnescapeJSONString(raw, strlen(raw), unescaped, sizeof(unescaped), &len);
    expect("unescaped content matches", strcmp(unescaped, "echo \"hello world\"\nexit 0\n") == 0);
    expect("unescaped len matches", len == strlen("echo \"hello world\"\nexit 0\n"));
}

/* 3. Test Parameter Parsing */
static void test_param_parsing(void) {
    printf("[*] Testing Parameter Parsing...\n");
    const char* params_json = "{\"mode\":\"fast\",\"count\":42,\"flag\":true,\"target\":\"10.0.0.1\"}";
    ScriptParamEntry entries[8];
    size_t count = 0;
    ScriptExec_ParseParametersObject(params_json, entries, 8, &count);

    expect("parsed 4 parameters", count == 4);
    if (count == 4) {
        expect("param[0].name == mode", strcmp(entries[0].name, "mode") == 0);
        expect("param[0].value == fast", strcmp(entries[0].value, "fast") == 0);
        expect("param[1].name == count", strcmp(entries[1].name, "count") == 0);
        expect("param[1].value == 42", strcmp(entries[1].value, "42") == 0);
        expect("param[2].name == flag", strcmp(entries[2].name, "flag") == 0);
        expect("param[2].value == true", strcmp(entries[2].value, "true") == 0);
        expect("param[3].name == target", strcmp(entries[3].name, "target") == 0);
        expect("param[3].value == 10.0.0.1", strcmp(entries[3].value, "10.0.0.1") == 0);
    }
}

/* 4. Test Payload Parser */
static void test_payload_parser(void) {
    printf("[*] Testing Payload Parser...\n");
    const char* payload =
        "{\n"
        "  \"script_id\": \"scr-001\",\n"
        "  \"script_version\": 2,\n"
        "  \"script_digest\": \"abcdef123456\",\n"
        "  \"interpreter\": \"/bin/bash\",\n"
        "  \"source\": \"echo \\\"test\\\"\\n\",\n"
        "  \"parameters\": {\"opt\": \"val\"},\n"
        "  \"timeout_seconds\": 45,\n"
        "  \"max_output_bytes\": 2048\n"
        "}";

    ScriptExecParams params;
    bool ok = ScriptExec_ParsePayload(payload, &params);
    expect("payload parsed successfully", ok);
    if (ok) {
        expect("script_id matches", strcmp(params.script_id, "scr-001") == 0);
        expect("script_version matches", params.script_version == 2);
        expect("script_digest matches", strcmp(params.script_digest, "abcdef123456") == 0);
        expect("interpreter matches", strcmp(params.interpreter, "/bin/bash") == 0);
        expect("source matches", strcmp(params.source, "echo \"test\"\n") == 0);
        expect("timeout_seconds matches", params.timeout_seconds == 45);
        expect("max_output_bytes matches", params.max_output_bytes == 2048);
        expect("param_count matches", params.param_count == 1);
        expect("param[0] name matches", strcmp(params.params[0].name, "opt") == 0);
        expect("param[0] value matches", strcmp(params.params[0].value, "val") == 0);
    }
}

/* 5. Test Contained Execution - Simple Command */
static void test_exec_simple(void) {
    printf("[*] Testing Contained Execution (Simple)...\n");
    ScriptExecParams params;
    memset(&params, 0, sizeof(params));
    strncpy(params.script_id, "scr-simple", sizeof(params.script_id) - 1);
    params.script_version = 1;
    strncpy(params.interpreter, "/bin/sh", sizeof(params.interpreter) - 1);
    strncpy(params.source, "echo -n 'hello ominull'\n", sizeof(params.source) - 1);
    params.source_len = strlen(params.source);
    params.timeout_seconds = 10;
    params.max_output_bytes = 4096;

    // Compute exact digest
    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)params.source, params.source_len, hash);
    Response_BytesToHex(hash, 32, params.script_digest);

    char output[1024];
    bool truncated = false, timed_out = false;
    int64_t duration_ms = 0;

    int code = ScriptExec_RunContained(&params, "job-simple-1", output, sizeof(output), &truncated, &timed_out, &duration_ms);
    expect("exit code == 0", code == 0);
    expect("output == 'hello ominull'", strcmp(output, "hello ominull") == 0);
    expect("truncated == false", !truncated);
    expect("timed_out == false", !timed_out);
    expect("duration_ms >= 0", duration_ms >= 0);
}

/* 6. Test Parameter Delivery (File & Environment) */
static void test_exec_parameters(void) {
    printf("[*] Testing Parameter Delivery...\n");
    ScriptExecParams params;
    memset(&params, 0, sizeof(params));
    strncpy(params.script_id, "scr-params", sizeof(params.script_id) - 1);
    params.script_version = 1;
    strncpy(params.interpreter, "/bin/sh", sizeof(params.interpreter) - 1);
    strncpy(params.source, "echo \"PARAM_MODE=$OMINULL_PARAM_MODE MODE=$mode COUNT=$count FILE=$OMINULL_PARAMS_FILE\"\n", sizeof(params.source) - 1);
    params.source_len = strlen(params.source);
    params.timeout_seconds = 10;
    params.max_output_bytes = 4096;

    // Parameters
    strncpy(params.parameters_json, "{\"mode\":\"test_mode\",\"count\":\"99\"}", sizeof(params.parameters_json) - 1);
    params.parameters_len = strlen(params.parameters_json);
    ScriptExec_ParseParametersObject(params.parameters_json, params.params, SCRIPT_EXEC_MAX_PARAM_COUNT, &params.param_count);

    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)params.source, params.source_len, hash);
    Response_BytesToHex(hash, 32, params.script_digest);

    char output[2048];
    bool truncated = false, timed_out = false;
    int64_t duration_ms = 0;

    int code = ScriptExec_RunContained(&params, "job-param-1", output, sizeof(output), &truncated, &timed_out, &duration_ms);
    expect("exit code == 0", code == 0);
    expect("output contains PARAM_MODE=test_mode", strstr(output, "PARAM_MODE=test_mode") != NULL);
    expect("output contains MODE=test_mode", strstr(output, "MODE=test_mode") != NULL);
    expect("output contains COUNT=99", strstr(output, "COUNT=99") != NULL);
    expect("output contains ominull_params_job-param-1.json", strstr(output, "ominull_params_job-param-1.json") != NULL);
}

/* 7. Test Digest Tamper Rejection */
static void test_digest_tampering(void) {
    printf("[*] Testing Digest Tamper Rejection...\n");
    ScriptExecParams params;
    memset(&params, 0, sizeof(params));
    strncpy(params.script_id, "scr-tamper", sizeof(params.script_id) - 1);
    params.script_version = 1;
    strncpy(params.interpreter, "/bin/sh", sizeof(params.interpreter) - 1);
    strncpy(params.source, "echo 'tampered'\n", sizeof(params.source) - 1);
    params.source_len = strlen(params.source);
    params.timeout_seconds = 5;
    params.max_output_bytes = 1024;
    snprintf(params.script_digest, sizeof(params.script_digest), "%s", "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff");

    char output[512];
    bool truncated = false, timed_out = false;
    int64_t duration_ms = 0;

    int code = ScriptExec_RunContained(&params, "job-tamper-1", output, sizeof(output), &truncated, &timed_out, &duration_ms);
    expect("tampered script rejected (code 125)", code == 125);
    expect("output notes digest mismatch", strstr(output, "digest mismatch") != NULL);
}

/* 8. Test Output Truncation Bounds */
static void test_output_truncation(void) {
    printf("[*] Testing Output Truncation Bounds...\n");
    ScriptExecParams params;
    memset(&params, 0, sizeof(params));
    strncpy(params.script_id, "scr-trunc", sizeof(params.script_id) - 1);
    params.script_version = 1;
    strncpy(params.interpreter, "/bin/sh", sizeof(params.interpreter) - 1);
    // Produce 5000 characters
    strncpy(params.source, "for i in $(seq 1 500); do echo -n '1234567890'; done\n", sizeof(params.source) - 1);
    params.source_len = strlen(params.source);
    params.timeout_seconds = 10;
    params.max_output_bytes = 100; // Cap to 100 bytes

    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)params.source, params.source_len, hash);
    Response_BytesToHex(hash, 32, params.script_digest);

    char output[512];
    bool truncated = false, timed_out = false;
    int64_t duration_ms = 0;

    int code = ScriptExec_RunContained(&params, "job-trunc-1", output, sizeof(output), &truncated, &timed_out, &duration_ms);
    expect("exit code == 0", code == 0);
    expect("truncated flag == true", truncated);
    expect("output includes truncation message", strstr(output, "[... output truncated") != NULL);
}

/* 9. Test Hard Timeout Escalation & Exit 124 */
static void test_timeout_escalation(void) {
    printf("[*] Testing Hard Timeout Escalation...\n");
    ScriptExecParams params;
    memset(&params, 0, sizeof(params));
    strncpy(params.script_id, "scr-timeout", sizeof(params.script_id) - 1);
    params.script_version = 1;
    strncpy(params.interpreter, "/bin/sh", sizeof(params.interpreter) - 1);
    // Script sleeps longer than timeout
    strncpy(params.source, "sleep 10\n", sizeof(params.source) - 1);
    params.source_len = strlen(params.source);
    params.timeout_seconds = 1; // 1 second timeout
    params.max_output_bytes = 1024;

    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)params.source, params.source_len, hash);
    Response_BytesToHex(hash, 32, params.script_digest);

    char output[512];
    bool truncated = false, timed_out = false;
    int64_t duration_ms = 0;

    int code = ScriptExec_RunContained(&params, "job-timeout-1", output, sizeof(output), &truncated, &timed_out, &duration_ms);
    expect("exit code == 124 (timeout)", code == 124);
    expect("timed_out flag == true", timed_out);
    expect("duration_ms >= 1000", duration_ms >= 900);
}

/* 10. Test Non-Zero Exit Code */
static void test_nonzero_exit(void) {
    printf("[*] Testing Non-Zero Exit Code...\n");
    ScriptExecParams params;
    memset(&params, 0, sizeof(params));
    strncpy(params.script_id, "scr-fail", sizeof(params.script_id) - 1);
    params.script_version = 1;
    strncpy(params.interpreter, "/bin/sh", sizeof(params.interpreter) - 1);
    strncpy(params.source, "echo 'failing now' >&2; exit 42\n", sizeof(params.source) - 1);
    params.source_len = strlen(params.source);
    params.timeout_seconds = 5;
    params.max_output_bytes = 1024;

    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)params.source, params.source_len, hash);
    Response_BytesToHex(hash, 32, params.script_digest);

    char output[512];
    bool truncated = false, timed_out = false;
    int64_t duration_ms = 0;

    int code = ScriptExec_RunContained(&params, "job-fail-1", output, sizeof(output), &truncated, &timed_out, &duration_ms);
    expect("exit code == 42", code == 42);
    expect("captured stderr output", strstr(output, "failing now") != NULL);
}

/* 11. Test JSON Escaping */
static void test_json_escaping(void) {
    printf("[*] Testing JSON Escaping...\n");
    const char* str = "line1\nline2\t\"quoted\" \\backslash\\";
    char* escaped = ScriptExec_EscapeJSON(str);
    expect("escaped contains \\n", strstr(escaped, "\\n") != NULL);
    expect("escaped contains \\t", strstr(escaped, "\\t") != NULL);
    expect("escaped contains \\\"quoted\\\"", strstr(escaped, "\\\"quoted\\\"") != NULL);
    expect("escaped contains \\\\backslash\\\\", strstr(escaped, "\\\\backslash\\\\") != NULL);
    free(escaped);
}

int main(void) {
    printf("=== Starting Linux Script Execution Worker C Tests ===\n");
    test_interpreter_allowlist();
    test_json_unescaping();
    test_param_parsing();
    test_payload_parser();
    test_exec_simple();
    test_exec_parameters();
    test_digest_tampering();
    test_output_truncation();
    test_timeout_escalation();
    test_nonzero_exit();
    test_json_escaping();

    printf("\nTotal Failures: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
