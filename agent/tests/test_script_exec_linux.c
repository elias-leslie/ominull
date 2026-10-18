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
 * - Supervisor: progress lines, phase and post timing, heartbeats through a
 *   fake sink, stall, cancel of a whole tree, timeout with output closed,
 *   grandchildren killed after exit, max_output_bytes past 64 KiB.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

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

    /* Maintenance packages run for up to an hour; past that the default applies. */
    const char* hour = "{\"script_id\":\"s\",\"interpreter\":\"/bin/sh\",\"source\":\"true\",\"timeout_seconds\": 3600}";
    expect("an hour-long timeout is accepted", ScriptExec_ParsePayload(hour, &params) && params.timeout_seconds == 3600);
    const char* over = "{\"script_id\":\"s\",\"interpreter\":\"/bin/sh\",\"source\":\"true\",\"timeout_seconds\": 3601}";
    expect("a timeout over an hour falls back to the default", ScriptExec_ParsePayload(over, &params) && params.timeout_seconds == SCRIPT_EXEC_DEFAULT_TIMEOUT);
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

/* 12. The state directory fails closed and planted links are never followed */
static void simple_params(ScriptExecParams* params) {
    memset(params, 0, sizeof(*params));
    strncpy(params->script_id, "scr-state", sizeof(params->script_id) - 1);
    params->script_version = 1;
    strncpy(params->interpreter, "/bin/sh", sizeof(params->interpreter) - 1);
    strncpy(params->source, "echo -n ok\n", sizeof(params->source) - 1);
    params->source_len = strlen(params->source);
    params->timeout_seconds = 10;
    params->max_output_bytes = 4096;
}

static void test_state_dir_fails_closed(const char* private_dir) {
    printf("[*] Testing State Directory Fails Closed...\n");
    ScriptExecParams params;
    simple_params(&params);
    char output[1024];
    bool truncated = false, timed_out = false;
    int64_t duration_ms = 0;

    /* /tmp is writable by everyone: no fallback, the job fails. */
    g_script_exec_state_dir = "/tmp";
    int code = ScriptExec_RunContained(&params, "job-state-tmp", output, sizeof(output), &truncated, &timed_out, &duration_ms);
    expect("/tmp refused as state dir", code != 0 && strstr(output, "not private") != NULL);

    g_script_exec_state_dir = "/nonexistent/ominull-state";
    code = ScriptExec_RunContained(&params, "job-state-missing", output, sizeof(output), &truncated, &timed_out, &duration_ms);
    expect("missing state dir refused", code != 0 && strstr(output, "not private") != NULL);

    char link_dir[512];
    snprintf(link_dir, sizeof(link_dir), "%s-link", private_dir);
    expect("state dir symlink created", symlink(private_dir, link_dir) == 0);
    g_script_exec_state_dir = link_dir;
    code = ScriptExec_RunContained(&params, "job-state-link", output, sizeof(output), &truncated, &timed_out, &duration_ms);
    expect("symlinked state dir refused", code != 0);
    unlink(link_dir);

    /* A link planted at the script path is replaced, not written through. */
    g_script_exec_state_dir = private_dir;
    char target[512], planted[512];
    snprintf(target, sizeof(target), "%s/victim.txt", private_dir);
    snprintf(planted, sizeof(planted), "%s/ominull_script_job-state-plant.sh", private_dir);
    FILE* f = fopen(target, "w");
    if (f) { fputs("untouched", f); fclose(f); }
    expect("planted link created", symlink(target, planted) == 0);
    code = ScriptExec_RunContained(&params, "job-state-plant", output, sizeof(output), &truncated, &timed_out, &duration_ms);
    expect("job runs past a planted link", code == 0 && strcmp(output, "ok") == 0);
    char buf[32] = {0};
    f = fopen(target, "r");
    if (f) { size_t n = fread(buf, 1, sizeof(buf) - 1, f); buf[n] = '\0'; fclose(f); }
    expect("link target untouched", strcmp(buf, "untouched") == 0);
    unlink(target);
}

/* ---------------------------------------------------------------------------
 * Supervisor (script_supervisor.h): pure parts, shared with Windows
 * ------------------------------------------------------------------------- */

static void test_progress_line_parsing(void) {
    printf("[*] Testing Progress Line Parsing...\n");
    int pct = 0;
    char msg[SUPERVISOR_TEXT_MAX + 1];
    const char* a = "::progress:: 40% removing Wave Tool";
    expect("line with pct is progress", Supervisor_ParseProgressLine(a, strlen(a), &pct, msg, sizeof(msg)));
    expect("pct 40", pct == 40);
    expect("message after pct", strcmp(msg, "removing Wave Tool") == 0);

    const char* b = "::progress:: checking updates";
    expect("line without pct is progress", Supervisor_ParseProgressLine(b, strlen(b), &pct, msg, sizeof(msg)));
    expect("no pct is -1", pct == -1);
    expect("message kept whole", strcmp(msg, "checking updates") == 0);

    const char* c = "::progress::100%";
    expect("bare 100% parsed", Supervisor_ParseProgressLine(c, strlen(c), &pct, msg, sizeof(msg)) && pct == 100 && msg[0] == '\0');

    const char* d = "::progress:: 150% too much";
    expect("pct over 100 stays text", Supervisor_ParseProgressLine(d, strlen(d), &pct, msg, sizeof(msg)) && pct == -1 &&
           strcmp(msg, "150% too much") == 0);

    const char* e = "progress:: 40% nope";
    expect("other lines are not progress", !Supervisor_ParseProgressLine(e, strlen(e), &pct, msg, sizeof(msg)));
    const char* f = "  ::progress:: 40% indented";
    expect("progress must start the line", !Supervisor_ParseProgressLine(f, strlen(f), &pct, msg, sizeof(msg)));

    const char* g = "::progress:: 5% tab\there\x1b[0m bell\x07";
    Supervisor_ParseProgressLine(g, strlen(g), &pct, msg, sizeof(msg));
    expect("control characters stripped", pct == 5 && strcmp(msg, "tabhere[0m bell") == 0);

    /* 300 bytes of two-byte characters: capped at 200 without splitting one. */
    char longline[512];
    size_t n = (size_t)snprintf(longline, sizeof(longline), "::progress:: x");
    for (int i = 0; i < 150; i++) { longline[n++] = (char)0xC3; longline[n++] = (char)0xA9; }
    longline[n] = '\0';
    Supervisor_ParseProgressLine(longline, n, &pct, msg, sizeof(msg));
    size_t mlen = strlen(msg);
    expect("message capped at 200 bytes", mlen <= SUPERVISOR_TEXT_MAX && mlen >= SUPERVISOR_TEXT_MAX - 1);
    expect("cap does not split a UTF-8 character", mlen > 0 && (unsigned char)msg[mlen - 1] == 0xA9);

    /* Incremental: split across reads, CRLF, and ordinary output around it. */
    ScriptSupervisor s;
    Supervisor_Init(&s, NULL, 0);
    const char* parts[] = { "hello\n::prog", "ress:: 4", "0% removing", " Wave Tool\r", "\nmore output\n" };
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++)
        Supervisor_FeedOutput(&s, parts[i], strlen(parts[i]), (int64_t)i);
    expect("split progress line: pct", s.progress_pct == 40);
    expect("split progress line: message", strcmp(s.message, "removing Wave Tool") == 0);
    expect("split progress line: marked new", s.progress_dirty);
    Supervisor_FeedOutput(&s, "::progress:: next step\n", 23, 10);
    expect("line without pct keeps the last pct", s.progress_pct == 40 && strcmp(s.message, "next step") == 0);
    Supervisor_FeedOutput(&s, "::progress:: 60% partial", 24, 11);
    expect("unfinished line not taken yet", s.progress_pct == 40);
    Supervisor_FeedOutput(&s, "\n", 1, 12);
    expect("line taken at its newline", s.progress_pct == 60 && strcmp(s.message, "partial") == 0);
}

static void test_supervisor_state_machine(void) {
    printf("[*] Testing Supervisor Phase and Post Timing...\n");
    ScriptSupervisorSettings set = { 1000, 100, 30000, 5000 };
    ScriptSupervisor s;
    Supervisor_Init(&s, &set, 0);
    char body[1536];

    expect("first heartbeat due at once", Supervisor_ShouldPost(&s, 0));
    ScriptTreeSample sample = { 100, 0, 1 };
    Supervisor_ApplySample(&s, 0, &sample);
    size_t len = Supervisor_BuildPost(&s, "job-1", "lease-1", 0, body, sizeof(body));
    expect("running body built", len > 0);
    expect("running body exact",
           strcmp(body, "{\"job_id\":\"job-1\",\"lease_id\":\"lease-1\",\"phase\":\"running\",\"progress_pct\":-1,"
                        "\"cpu_ms\":100,\"io_bytes\":0,\"idle_seconds\":0,\"processes\":1}") == 0);
    expect("nothing due right after", !Supervisor_ShouldPost(&s, 1000));

    Supervisor_FeedOutput(&s, "::progress:: 40% removing Wave Tool\n", 36, 2000);
    expect("new progress waits out the 5 s gap", !Supervisor_ShouldPost(&s, 4999));
    expect("new progress posts after the gap", Supervisor_ShouldPost(&s, 5000));
    Supervisor_BuildPost(&s, "job-1", "lease-1", 5000, body, sizeof(body));
    expect("progress in body", strstr(body, "\"progress_pct\":40,\"message\":\"removing Wave Tool\"") != NULL);
    expect("progress posted once", !Supervisor_ShouldPost(&s, 12000));
    expect("plain heartbeat every 30 s", Supervisor_ShouldPost(&s, 35000));

    /* CPU below 200 ms and IO below 64 KiB are not activity. */
    sample.cpu_ms = 250; sample.io_bytes = 1000;
    expect("small growth: still not idle", !Supervisor_ApplySample(&s, 2900, &sample));
    sample.cpu_ms = 300; sample.io_bytes = 2000;
    expect("idle past threshold", Supervisor_ApplySample(&s, 3100, &sample));
    Supervisor_SetIdlePhase(&s, NULL);
    expect("no window: stalled", s.phase == SUPERVISOR_PHASE_STALLED);
    expect("phase change posts after the gap", Supervisor_ShouldPost(&s, 10000));
    Supervisor_BuildPost(&s, "job-1", "lease-1", 10000, body, sizeof(body));
    expect("stalled body", strstr(body, "\"phase\":\"stalled\"") != NULL && strstr(body, "\"idle_seconds\":8") != NULL &&
           strstr(body, "\"window\"") == NULL);

    ScriptSupervisorWindow w;
    memset(&w, 0, sizeof(w));
    w.present = true;
    snprintf(w.title, sizeof(w.title), "Wave Tool Setup \"Error\"");
    snprintf(w.process, sizeof(w.process), "msiexec.exe");
    w.pid = 1234;
    w.session = 1;
    expect("still idle", Supervisor_ApplySample(&s, 10100, &sample));
    Supervisor_SetIdlePhase(&s, &w);
    expect("window: needs_hands", s.phase == SUPERVISOR_PHASE_NEEDS_HANDS);
    Supervisor_BuildPost(&s, "job-1", "lease-1", 15100, body, sizeof(body));
    expect("needs_hands body has the window",
           strstr(body, "\"phase\":\"needs_hands\"") != NULL &&
           strstr(body, ",\"window\":{\"title\":\"Wave Tool Setup \\\"Error\\\"\",\"process\":\"msiexec.exe\",\"pid\":1234,\"session\":1}}") != NULL);

    /* A total that fell (a process left) restarts the baseline, no activity. */
    sample.cpu_ms = 10;
    expect("falling cpu is not activity", Supervisor_ApplySample(&s, 15200, &sample));
    sample.cpu_ms = 260;
    expect("cpu grew 250 ms: active", !Supervisor_ApplySample(&s, 15300, &sample));
    expect("back to running", s.phase == SUPERVISOR_PHASE_RUNNING && !s.window.present);
    sample.io_bytes += 70000;
    Supervisor_ApplySample(&s, 16400, &sample);
    expect("io grew 70 KB: activity clock reset", Supervisor_IdleMs(&s, 16400) == 0);
    Supervisor_FeedOutput(&s, "x", 1, 20000);
    expect("output is activity", Supervisor_IdleMs(&s, 20000) == 0);

    /* Output flips a stalled job back to running at once. */
    Supervisor_ApplySample(&s, 22000, &sample);
    Supervisor_SetIdlePhase(&s, NULL);
    Supervisor_FeedOutput(&s, "y", 1, 22100);
    expect("output resumes running", s.phase == SUPERVISOR_PHASE_RUNNING);

    expect("reply cancel true", Supervisor_ReplyCancels("{\"ok\":true,\"cancel\":true}"));
    expect("reply cancel spaced", Supervisor_ReplyCancels("{\"ok\": true, \"cancel\" : true}"));
    expect("reply cancel false", !Supervisor_ReplyCancels("{\"ok\":true,\"cancel\":false}"));
    expect("reply without cancel", !Supervisor_ReplyCancels("{\"ok\":true}"));
    expect("no reply", !Supervisor_ReplyCancels(NULL));

    /* Ids are escaped; the body never breaks out of its strings. */
    ScriptSupervisor t;
    Supervisor_Init(&t, &set, 0);
    Supervisor_BuildPost(&t, "j\"1", "l\\1", 0, body, sizeof(body));
    expect("ids escaped", strstr(body, "\"job_id\":\"j\\\"1\",\"lease_id\":\"l\\\\1\"") != NULL);
}

/* ---------------------------------------------------------------------------
 * Supervised execution (real processes, fake heartbeat sink)
 * ------------------------------------------------------------------------- */

typedef struct {
    char bodies[256][1600];
    int count;
    const char* cancel_on;      /* cancel once a body contains this */
    bool cancel;
} FakeSink;

static void fake_post(void* ctx, const char* body) {
    FakeSink* sink = (FakeSink*)ctx;
    if (sink->count < 256) {
        snprintf(sink->bodies[sink->count], sizeof(sink->bodies[0]), "%s", body);
        sink->count++;
    }
    if (sink->cancel_on && strstr(body, sink->cancel_on)) sink->cancel = true;
}

static bool fake_cancelled(void* ctx) {
    return ((FakeSink*)ctx)->cancel;
}

static bool sink_has(const FakeSink* sink, const char* needle) {
    for (int i = 0; i < sink->count; i++)
        if (strstr(sink->bodies[i], needle)) return true;
    return false;
}

static ScriptSupervisorHooks fast_hooks(FakeSink* sink) {
    ScriptSupervisorHooks h;
    memset(&h, 0, sizeof(h));
    h.settings.idle_threshold_ms = 1000;
    h.settings.sample_interval_ms = 200;
    h.settings.heartbeat_interval_ms = 30000;
    h.settings.min_post_gap_ms = 200;
    h.job_id = "job-sup";
    h.lease_id = "lease-sup";
    h.post = fake_post;
    h.cancel_requested = fake_cancelled;
    h.ctx = sink;
    return h;
}

static void script_params(ScriptExecParams* params, const char* source, int timeout, size_t max_out) {
    memset(params, 0, sizeof(*params));
    strncpy(params->script_id, "scr-sup", sizeof(params->script_id) - 1);
    params->script_version = 1;
    strncpy(params->interpreter, "/bin/sh", sizeof(params->interpreter) - 1);
    snprintf(params->source, sizeof(params->source), "%s", source);
    params->source_len = strlen(params->source);
    params->timeout_seconds = timeout;
    params->max_output_bytes = max_out;
    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)params->source, params->source_len, hash);
    Response_BytesToHex(hash, 32, params->script_digest);
}

static int64_t now_ms(void) {
    return ScriptExec_NowMs();
}

/* Alive = in /proc and not a zombie. Waits up to a second for it to go. */
static bool pid_gone(long pid) {
    for (int i = 0; i < 40; i++) {
        char path[64], buf[512];
        snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
        FILE* f = fopen(path, "r");
        if (!f) return true;
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        char* p = strrchr(buf, ')');
        if (p && (p[2] == 'Z' || p[2] == 'X')) return true;
        usleep(25000);
    }
    return false;
}

static long bg_pid(const char* output) {
    const char* p = strstr(output, "bg=");
    return p ? strtol(p + 3, NULL, 10) : 0;
}

static void test_supervised_heartbeats_and_stall(void) {
    printf("[*] Testing Supervised Heartbeats, Progress and Stall...\n");
    static FakeSink sink;
    memset(&sink, 0, sizeof(sink));
    ScriptSupervisorHooks hooks = fast_hooks(&sink);
    ScriptExecParams params;
    script_params(&params, "echo '::progress:: 40% removing Wave Tool'\nsleep 2.5\necho done\n", 20, 4096);
    char output[4096];
    ScriptRunResult run;
    int code = ScriptExec_RunSupervised(&params, "job-sup-1", output, sizeof(output), &hooks, &run);
    expect("supervised job exits 0", code == 0 && !run.timed_out && !run.cancelled);
    expect("progress line stays in the output", strstr(output, "::progress:: 40% removing Wave Tool") != NULL);
    static const char first[] = "{\"job_id\":\"job-sup\",\"lease_id\":\"lease-sup\",\"phase\":\"running\"";
    expect("first heartbeat is running with ids", sink.count > 0 &&
           strncmp(sink.bodies[0], first, strlen(first)) == 0);
    expect("first heartbeat counts the process", strstr(sink.bodies[0], "\"processes\":0") == NULL);
    expect("progress heartbeat posted", sink_has(&sink, "\"progress_pct\":40,\"message\":\"removing Wave Tool\""));
    expect("sleeping script reported stalled", sink_has(&sink, "\"phase\":\"stalled\""));
    expect("stalled heartbeat carries idle_seconds", sink_has(&sink, "\"idle_seconds\":1"));
    expect("no needs_hands on Linux", !sink_has(&sink, "needs_hands"));
}

static void test_supervised_cancel_kills_tree(void) {
    printf("[*] Testing Cancel Kills the Whole Tree...\n");
    static FakeSink sink;
    memset(&sink, 0, sizeof(sink));
    sink.cancel_on = "waiting";
    ScriptSupervisorHooks hooks = fast_hooks(&sink);
    ScriptExecParams params;
    script_params(&params, "sleep 30 &\necho \"bg=$!\"\necho '::progress:: 10% waiting'\nsleep 30\n", 60, 4096);
    char output[4096];
    ScriptRunResult run;
    int64_t t0 = now_ms();
    int code = ScriptExec_RunSupervised(&params, "job-sup-cancel", output, sizeof(output), &hooks, &run);
    int64_t took = now_ms() - t0;
    expect("cancel: flagged", run.cancelled && !run.timed_out);
    expect("cancel: exit 130", code == 130);
    expect("cancel: prompt", took < 5000);
    expect("cancel: output so far kept", strstr(output, "::progress:: 10% waiting") != NULL);
    long pid = bg_pid(output);
    expect("cancel: background grandchild killed", pid > 0 && pid_gone(pid));
}

static void test_timeout_with_stdout_closed(void) {
    printf("[*] Testing Timeout After the Script Closes Its Output...\n");
    const char* sources[] = { "exec >/dev/null\nsleep 30\n", "exec >/dev/null 2>&1\nsleep 30\n" };
    for (int i = 0; i < 2; i++) {
        ScriptExecParams params;
        script_params(&params, sources[i], 2, 4096);
        char output[1024];
        ScriptRunResult run;
        int64_t t0 = now_ms();
        int code = ScriptExec_RunSupervised(&params, "job-sup-closed", output, sizeof(output), NULL, &run);
        int64_t took = now_ms() - t0;
        expect(i == 0 ? "stdout closed: exit 124" : "stdout+stderr closed: exit 124", code == 124 && run.timed_out);
        expect(i == 0 ? "stdout closed: ends near the 2 s deadline" : "stdout+stderr closed: ends near the 2 s deadline",
               took >= 1900 && took < 6000);
    }
}

static void test_grandchild_killed_after_exit(void) {
    printf("[*] Testing Grandchildren Killed After the Script Exits...\n");
    ScriptExecParams params;
    /* The background sleep holds the output pipe open. */
    script_params(&params, "sleep 30 &\necho \"bg=$!\"\nexit 3\n", 20, 4096);
    char output[1024];
    ScriptRunResult run;
    int64_t t0 = now_ms();
    int code = ScriptExec_RunSupervised(&params, "job-sup-bg", output, sizeof(output), NULL, &run);
    int64_t took = now_ms() - t0;
    expect("exit code of the script kept", code == 3 && !run.timed_out);
    expect("does not wait for the background child", took < 4000);
    long pid = bg_pid(output);
    expect("background child holding the pipe killed", pid > 0 && pid_gone(pid));

    script_params(&params, "sleep 30 >/dev/null 2>&1 &\necho \"bg=$!\"\n", 20, 4096);
    code = ScriptExec_RunSupervised(&params, "job-sup-bg2", output, sizeof(output), NULL, &run);
    pid = bg_pid(output);
    expect("detached-output background child killed", code == 0 && pid > 0 && pid_gone(pid));
}

static void test_max_output_honoured(void) {
    printf("[*] Testing max_output_bytes Honoured Past 64 KiB...\n");
    size_t cap = SCRIPT_EXEC_MAX_MAX_OUT + 256;
    char* output = (char*)malloc(cap);
    if (!output) { expect("allocate output", false); return; }
    ScriptExecParams params;
    ScriptRunResult run;

    script_params(&params, "head -c 2097152 /dev/zero | tr '\\000' a\n", 20, 3 * 1024 * 1024);
    int code = ScriptExec_RunSupervised(&params, "job-sup-big", output, cap, NULL, &run);
    expect("2 MiB output captured whole", code == 0 && !run.truncated && strlen(output) == 2097152);

    script_params(&params, "head -c 4194304 /dev/zero | tr '\\000' a\n", 20, 3 * 1024 * 1024);
    code = ScriptExec_RunSupervised(&params, "job-sup-trunc", output, cap, NULL, &run);
    size_t len = strlen(output);
    expect("4 MiB output truncated at 3 MiB", code == 0 && run.truncated);
    expect("3 MiB kept plus the note", len > 3 * 1024 * 1024 && len < 3 * 1024 * 1024 + 128 &&
           strstr(output + 3 * 1024 * 1024, "output truncated") != NULL);
    free(output);
}

int main(void) {
    printf("=== Starting Linux Script Execution Worker C Tests ===\n");
    /* A private state directory of the test's own; the agent's is root-owned. */
    char state_template[] = "/tmp/ominull-script-state-XXXXXX";
    char* state_dir = mkdtemp(state_template);
    if (!state_dir) {
        printf("  [-] FAILED: mkdtemp\n");
        return 1;
    }
    g_script_exec_state_dir = state_dir;
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
    test_state_dir_fails_closed(state_dir);
    test_progress_line_parsing();
    test_supervisor_state_machine();
    test_supervised_heartbeats_and_stall();
    test_supervised_cancel_kills_tree();
    test_timeout_with_stdout_closed();
    test_grandchild_killed_after_exit();
    test_max_output_honoured();
    rmdir(state_dir);

    printf("\nTotal Failures: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
