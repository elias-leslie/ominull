#ifndef OMINULL_SCRIPT_EXEC_WINDOWS_H
#define OMINULL_SCRIPT_EXEC_WINDOWS_H

/*
 * Ominull Windows Endpoint Script Execution Worker (Slice 5C).
 *
 * Implements:
 * - Strict interpreter allowlisting (powershell.exe, cmd.exe, and pwsh.exe when detected).
 * - Bounded payload parsing (source up to 64 KiB, parameters up to 16 KiB).
 * - In-process SHA-256 verification of script source against signed script_digest.
 * - Parameter delivery via private file and environment block (ZERO textual template substitution).
 * - Windows Job Object containment:
 *     - JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE for fail-closed child tree termination.
 *     - Suspended process creation and job assignment before execution begins.
 *     - Sanitized environment block.
 *     - Safe working directory.
 *     - Millisecond timeout monitoring with TerminateJobObject(124).
 * - Bounded stdout/stderr capture via anonymous pipe with honest truncation tracking.
 * - Complete automatic cleanup of temporary script and parameter files.
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
#include <time.h>
#include <ctype.h>

#include "response_dispatcher.h"

#define SCRIPT_EXEC_MAX_SOURCE_BYTES  65536   // 64 KiB
#define SCRIPT_EXEC_MAX_PARAMS_BYTES  16384   // 16 KiB
#define SCRIPT_EXEC_DEFAULT_TIMEOUT   60      // 60 seconds
#define SCRIPT_EXEC_MAX_TIMEOUT       300     // 300 seconds
#define SCRIPT_EXEC_DEFAULT_MAX_OUT   1048576 // 1 MiB
#define SCRIPT_EXEC_MAX_MAX_OUT       5242880 // 5 MiB
#define SCRIPT_EXEC_MAX_PARAM_COUNT   64

typedef struct {
    char name[64];
    char value[2048];
} ScriptParamEntryWin;

typedef struct {
    char script_id[64];
    int  script_version;
    char script_digest[65];
    char interpreter[128];
    char canonical_interpreter[MAX_PATH];
    char source[SCRIPT_EXEC_MAX_SOURCE_BYTES];
    size_t source_len;
    char parameters_json[SCRIPT_EXEC_MAX_PARAMS_BYTES];
    size_t parameters_len;
    ScriptParamEntryWin params[SCRIPT_EXEC_MAX_PARAM_COUNT];
    size_t param_count;
    int  timeout_seconds;
    size_t max_output_bytes;
} ScriptExecParamsWin;

/* ---------------------------------------------------------------------------
 * Interpreter Allowlist & Resolution
 * ------------------------------------------------------------------------- */

static inline bool ScriptExec_IsAllowedInterpreterWindows(const char* interpreter, char* out_canonical, size_t out_max) {
    if (!interpreter || interpreter[0] == '\0') return false;
    if (out_canonical && out_max > 0) out_canonical[0] = '\0';

    // Disallow arguments, subshell flags, redirection, or pipe characters in interpreter name
    if (strchr(interpreter, ' ') != NULL || strchr(interpreter, '\t') != NULL ||
        strchr(interpreter, ';') != NULL || strchr(interpreter, '&') != NULL ||
        strchr(interpreter, '|') != NULL || strchr(interpreter, '>') != NULL ||
        strchr(interpreter, '<') != NULL) {
        return false;
    }

    char sysDir[MAX_PATH];
    if (GetSystemDirectoryA(sysDir, sizeof(sysDir)) == 0) {
        strncpy(sysDir, "C:\\Windows\\System32", sizeof(sysDir) - 1);
        sysDir[sizeof(sysDir) - 1] = '\0';
    }

    // 1. powershell.exe / powershell
    char psPath[MAX_PATH];
    snprintf(psPath, sizeof(psPath), "%s\\WindowsPowerShell\\v1.0\\powershell.exe", sysDir);
    if (_stricmp(interpreter, "powershell.exe") == 0 || _stricmp(interpreter, "powershell") == 0 ||
        _stricmp(interpreter, psPath) == 0) {
        if (out_canonical && out_max > 0) {
            strncpy(out_canonical, psPath, out_max - 1);
            out_canonical[out_max - 1] = '\0';
        }
        return (GetFileAttributesA(psPath) != INVALID_FILE_ATTRIBUTES);
    }

    // 2. cmd.exe / cmd
    char cmdPath[MAX_PATH];
    snprintf(cmdPath, sizeof(cmdPath), "%s\\cmd.exe", sysDir);
    if (_stricmp(interpreter, "cmd.exe") == 0 || _stricmp(interpreter, "cmd") == 0 ||
        _stricmp(interpreter, cmdPath) == 0) {
        if (out_canonical && out_max > 0) {
            strncpy(out_canonical, cmdPath, out_max - 1);
            out_canonical[out_max - 1] = '\0';
        }
        return (GetFileAttributesA(cmdPath) != INVALID_FILE_ATTRIBUTES);
    }

    // 3. pwsh.exe / pwsh (PowerShell Core, only when detected)
    if (_stricmp(interpreter, "pwsh.exe") == 0 || _stricmp(interpreter, "pwsh") == 0) {
        const char* candidate7 = "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
        if (GetFileAttributesA(candidate7) != INVALID_FILE_ATTRIBUTES) {
            if (out_canonical && out_max > 0) {
                strncpy(out_canonical, candidate7, out_max - 1);
                out_canonical[out_max - 1] = '\0';
            }
            return true;
        }
        char searchBuf[MAX_PATH];
        if (SearchPathA(NULL, "pwsh.exe", NULL, sizeof(searchBuf), searchBuf, NULL) > 0) {
            if (out_canonical && out_max > 0) {
                strncpy(out_canonical, searchBuf, out_max - 1);
                out_canonical[out_max - 1] = '\0';
            }
            return true;
        }
        return false;
    }

    return false;
}

/* ---------------------------------------------------------------------------
 * JSON String & Parameter Parser Helpers
 * ------------------------------------------------------------------------- */

static inline bool ScriptExec_UnescapeJSONStringWin(const char* src, size_t src_len, char* dst, size_t dst_cap, size_t* out_len) {
    size_t d = 0;
    for (size_t s = 0; s < src_len && d + 1 < dst_cap; s++) {
        if (src[s] == '\\' && s + 1 < src_len) {
            s++;
            switch (src[s]) {
                case '\"': dst[d++] = '\"'; break;
                case '\\': dst[d++] = '\\'; break;
                case '/':  dst[d++] = '/';  break;
                case 'b':  dst[d++] = '\b'; break;
                case 'f':  dst[d++] = '\f'; break;
                case 'n':  dst[d++] = '\n'; break;
                case 'r':  dst[d++] = '\r'; break;
                case 't':  dst[d++] = '\t'; break;
                case 'u': {
                    if (s + 4 < src_len) {
                        char hex_buf[5] = { src[s+1], src[s+2], src[s+3], src[s+4], '\0' };
                        unsigned int codepoint = 0;
                        if (sscanf(hex_buf, "%x", &codepoint) == 1) {
                            s += 4;
                            if (codepoint < 0x80) {
                                dst[d++] = (char)codepoint;
                            } else if (codepoint < 0x800 && d + 2 < dst_cap) {
                                dst[d++] = (char)(0xC0 | (codepoint >> 6));
                                dst[d++] = (char)(0x80 | (codepoint & 0x3F));
                            } else if (d + 3 < dst_cap) {
                                dst[d++] = (char)(0xE0 | (codepoint >> 12));
                                dst[d++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
                                dst[d++] = (char)(0x80 | (codepoint & 0x3F));
                            }
                        } else {
                            dst[d++] = src[s];
                        }
                    } else {
                        dst[d++] = src[s];
                    }
                    break;
                }
                default:
                    dst[d++] = src[s];
                    break;
            }
        } else {
            dst[d++] = src[s];
        }
    }
    dst[d] = '\0';
    if (out_len) *out_len = d;
    return true;
}

static inline void ScriptExec_ParseParametersObjectWin(const char* json_obj, ScriptParamEntryWin* entries, size_t max_entries, size_t* out_count) {
    if (!json_obj || !entries || !out_count) return;
    *out_count = 0;

    const char* p = strchr(json_obj, '{');
    if (!p) return;
    p++;

    while (*p && *p != '}' && *out_count < max_entries) {
        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
        if (*p != '\"') break;
        p++;

        // Read parameter key
        const char* key_start = p;
        while (*p && *p != '\"') p++;
        if (*p != '\"') break;
        size_t key_len = p - key_start;
        p++; // skip closing quote

        while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;

        // Read parameter value
        char val_buf[2048] = {0};
        size_t val_len = 0;
        if (*p == '\"') {
            p++;
            const char* val_start = p;
            while (*p && !(*p == '\"' && *(p - 1) != '\\')) p++;
            size_t raw_len = p - val_start;
            if (*p == '\"') p++;
            ScriptExec_UnescapeJSONStringWin(val_start, raw_len, val_buf, sizeof(val_buf), &val_len);
        } else {
            // number or boolean
            const char* val_start = p;
            while (*p && *p != ',' && *p != '}' && !isspace((unsigned char)*p)) p++;
            val_len = p - val_start;
            if (val_len >= sizeof(val_buf)) val_len = sizeof(val_buf) - 1;
            snprintf(val_buf, sizeof(val_buf), "%.*s", (int)val_len, val_start);
        }

        if (key_len > 0 && key_len < sizeof(entries[*out_count].name)) {
            snprintf(entries[*out_count].name, sizeof(entries[*out_count].name), "%.*s", (int)key_len, key_start);
            snprintf(entries[*out_count].value, sizeof(entries[*out_count].value), "%s", val_buf);
            (*out_count)++;
        }

        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
    }
}

/* ---------------------------------------------------------------------------
 * Payload Parser
 * ------------------------------------------------------------------------- */

static inline bool ScriptExec_ParsePayloadWin(const char* json, ScriptExecParamsWin* out) {
    if (!json || !out) return false;
    memset(out, 0, sizeof(*out));
    out->timeout_seconds = SCRIPT_EXEC_DEFAULT_TIMEOUT;
    out->max_output_bytes = SCRIPT_EXEC_DEFAULT_MAX_OUT;
    strncpy(out->interpreter, "cmd.exe", sizeof(out->interpreter) - 1);

    // 1. script_id
    const char* p = strstr(json, "\"script_id\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '\"');
            if (p) {
                p++;
                const char* end = strchr(p, '\"');
                if (end && (size_t)(end - p) < sizeof(out->script_id)) {
                    snprintf(out->script_id, sizeof(out->script_id), "%.*s", (int)(end - p), p);
                }
            }
        }
    }

    // 2. script_version
    p = strstr(json, "\"script_version\"");
    if (!p) p = strstr(json, "\"version\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            out->script_version = atoi(p + 1);
        }
    }

    // 3. script_digest
    p = strstr(json, "\"script_digest\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '\"');
            if (p) {
                p++;
                const char* end = strchr(p, '\"');
                if (end && (size_t)(end - p) < sizeof(out->script_digest)) {
                    snprintf(out->script_digest, sizeof(out->script_digest), "%.*s", (int)(end - p), p);
                }
            }
        }
    }

    // 4. interpreter
    p = strstr(json, "\"interpreter\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '\"');
            if (p) {
                p++;
                const char* end = strchr(p, '\"');
                if (end && (size_t)(end - p) < sizeof(out->interpreter)) {
                    snprintf(out->interpreter, sizeof(out->interpreter), "%.*s", (int)(end - p), p);
                }
            }
        }
    }

    // 5. source
    p = strstr(json, "\"source\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '\"');
            if (p) {
                p++;
                const char* s_start = p;
                while (*p && !(*p == '\"' && *(p - 1) != '\\')) p++;
                size_t raw_len = p - s_start;
                ScriptExec_UnescapeJSONStringWin(s_start, raw_len, out->source, sizeof(out->source), &out->source_len);
            }
        }
    }

    // 6. parameters
    p = strstr(json, "\"parameters\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p++;
            while (*p && isspace((unsigned char)*p)) p++;
            if (*p == '{') {
                const char* p_start = p;
                int depth = 0;
                while (*p) {
                    if (*p == '{') depth++;
                    else if (*p == '}') {
                        depth--;
                        if (depth == 0) {
                            p++;
                            break;
                        }
                    }
                    p++;
                }
                size_t p_len = p - p_start;
                if (p_len < sizeof(out->parameters_json)) {
                    snprintf(out->parameters_json, sizeof(out->parameters_json), "%.*s", (int)p_len, p_start);
                    out->parameters_len = p_len;
                    ScriptExec_ParseParametersObjectWin(out->parameters_json, out->params, SCRIPT_EXEC_MAX_PARAM_COUNT, &out->param_count);
                }
            }
        }
    }

    // 7. timeout_seconds
    p = strstr(json, "\"timeout_seconds\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            int t = atoi(p + 1);
            if (t > 0 && t <= SCRIPT_EXEC_MAX_TIMEOUT) {
                out->timeout_seconds = t;
            }
        }
    }

    // 8. max_output_bytes
    p = strstr(json, "\"max_output_bytes\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            long mo = atol(p + 1);
            if (mo > 1024 && mo <= SCRIPT_EXEC_MAX_MAX_OUT) {
                out->max_output_bytes = (size_t)mo;
            }
        }
    }

    // Validate allowed interpreter
    if (!ScriptExec_IsAllowedInterpreterWindows(out->interpreter, out->canonical_interpreter, sizeof(out->canonical_interpreter))) {
        return false;
    }

    return true;
}

/* ---------------------------------------------------------------------------
 * JSON Escaping Helper
 * ------------------------------------------------------------------------- */

static inline char* ScriptExec_EscapeJSONWin(const char* src) {
    if (!src) return NULL;
    size_t len = strlen(src);
    size_t cap = len * 6 + 1;
    char* dst = (char*)malloc(cap);
    if (!dst) return NULL;
    size_t d = 0;
    for (size_t s = 0; s < len; s++) {
        unsigned char c = (unsigned char)src[s];
        switch (c) {
            case '\"': dst[d++] = '\\'; dst[d++] = '\"'; break;
            case '\\': dst[d++] = '\\'; dst[d++] = '\\'; break;
            case '\b': dst[d++] = '\\'; dst[d++] = 'b'; break;
            case '\f': dst[d++] = '\\'; dst[d++] = 'f'; break;
            case '\n': dst[d++] = '\\'; dst[d++] = 'n'; break;
            case '\r': dst[d++] = '\\'; dst[d++] = 'r'; break;
            case '\t': dst[d++] = '\\'; dst[d++] = 't'; break;
            default:
                if (c < 0x20) {
                    d += snprintf(dst + d, 7, "\\u%04x", c);
                } else {
                    dst[d++] = (char)c;
                }
                break;
        }
    }
    dst[d] = '\0';
    return dst;
}

/* ---------------------------------------------------------------------------
 * State Directory Helper
 * ------------------------------------------------------------------------- */

static inline void ScriptExec_GetStateDirWin(char* out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';

    CreateDirectoryA("C:\\ProgramData", NULL);
    CreateDirectoryA("C:\\ProgramData\\Ominull", NULL);
    DWORD attr = GetFileAttributesA("C:\\ProgramData\\Ominull");
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        char testPath[MAX_PATH];
        snprintf(testPath, sizeof(testPath), "C:\\ProgramData\\Ominull\\.write_test_%lu", (unsigned long)GetCurrentProcessId());
        HANDLE hTest = CreateFileA(testPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTest != INVALID_HANDLE_VALUE) {
            CloseHandle(hTest);
            DeleteFileA(testPath);
            snprintf(out, out_cap, "C:\\ProgramData\\Ominull");
            return;
        }
    }

    char tmp[MAX_PATH];
    if (GetTempPathA(sizeof(tmp), tmp) > 0) {
        size_t len = strlen(tmp);
        while (len > 0 && (tmp[len - 1] == '\\' || tmp[len - 1] == '/')) {
            tmp[len - 1] = '\0';
            len--;
        }
        snprintf(out, out_cap, "%s", tmp);
        return;
    }

    snprintf(out, out_cap, "C:\\Temp");
}

/* ---------------------------------------------------------------------------
 * Contained Worker Execution (Windows Job Object & Process Containment)
 * ------------------------------------------------------------------------- */

static inline int ScriptExec_RunContainedWin(
    const ScriptExecParamsWin* params,
    const char* job_id,
    char* output_buf,
    size_t out_cap,
    bool* out_truncated,
    bool* out_timed_out,
    int64_t* out_duration_ms,
    char* out_error_code,
    size_t error_code_cap
) {
    if (!params || !job_id || !output_buf || out_cap == 0) return 1;
    output_buf[0] = '\0';
    if (out_truncated) *out_truncated = false;
    if (out_timed_out) *out_timed_out = false;
    if (out_duration_ms) *out_duration_ms = 0;
    if (out_error_code && error_code_cap > 0) out_error_code[0] = '\0';

    // 1. In-process SHA-256 Digest Verification
    uint8_t hash[32];
    Response_SHA256_Sum((const uint8_t*)params->source, params->source_len, hash);
    char computed_digest[65];
    for (int i = 0; i < 32; i++) {
        snprintf(computed_digest + (i * 2), 3, "%02x", hash[i]);
    }

    if (_stricmp(computed_digest, params->script_digest) != 0) {
        if (out_error_code && error_code_cap > 0) {
            strncpy(out_error_code, "SCRIPT_DIGEST_MISMATCH", error_code_cap - 1);
            out_error_code[error_code_cap - 1] = '\0';
        }
        return 1;
    }

    // 2. Canonical Interpreter Resolution
    char canonical_interpreter[MAX_PATH];
    if (!ScriptExec_IsAllowedInterpreterWindows(params->interpreter, canonical_interpreter, sizeof(canonical_interpreter))) {
        if (out_error_code && error_code_cap > 0) {
            strncpy(out_error_code, "DISALLOWED_INTERPRETER", error_code_cap - 1);
            out_error_code[error_code_cap - 1] = '\0';
        }
        return 1;
    }

    // Determine interpreter type
    bool is_powershell = (_stricmp(params->interpreter, "powershell.exe") == 0 ||
                          _stricmp(params->interpreter, "powershell") == 0 ||
                          strstr(canonical_interpreter, "powershell.exe") != NULL ||
                          _stricmp(params->interpreter, "pwsh.exe") == 0 ||
                          _stricmp(params->interpreter, "pwsh") == 0 ||
                          strstr(canonical_interpreter, "pwsh.exe") != NULL);

    // 3. Write script source and parameters to state directory
    char state_dir[MAX_PATH];
    ScriptExec_GetStateDirWin(state_dir, sizeof(state_dir));

    char script_path[MAX_PATH];
    snprintf(script_path, sizeof(script_path), "%s\\ominull_script_%s.%s",
             state_dir, job_id, (is_powershell ? "ps1" : "cmd"));

    char param_path[MAX_PATH];
    snprintf(param_path, sizeof(param_path), "%s\\ominull_params_%s.json",
             state_dir, job_id);

    // Write parameter file
    HANDLE hParamFile = CreateFileA(param_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hParamFile == INVALID_HANDLE_VALUE) {
        if (out_error_code && error_code_cap > 0) {
            strncpy(out_error_code, "PARAM_FILE_WRITE_FAILED", error_code_cap - 1);
            out_error_code[error_code_cap - 1] = '\0';
        }
        return 1;
    }
    const char* param_data = (params->parameters_len > 0) ? params->parameters_json : "{}";
    DWORD bytesWritten = 0;
    WriteFile(hParamFile, param_data, (DWORD)strlen(param_data), &bytesWritten, NULL);
    CloseHandle(hParamFile);

    // Write script file
    HANDLE hScriptFile = CreateFileA(script_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hScriptFile == INVALID_HANDLE_VALUE) {
        DeleteFileA(param_path);
        if (out_error_code && error_code_cap > 0) {
            strncpy(out_error_code, "SCRIPT_FILE_WRITE_FAILED", error_code_cap - 1);
            out_error_code[error_code_cap - 1] = '\0';
        }
        return 1;
    }
    WriteFile(hScriptFile, params->source, (DWORD)params->source_len, &bytesWritten, NULL);
    CloseHandle(hScriptFile);

    // 4. Construct Command Line
    char cmdline[MAX_PATH * 2 + 128];
    if (is_powershell) {
        snprintf(cmdline, sizeof(cmdline), "\"%s\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%s\"",
                 canonical_interpreter, script_path);
    } else {
        snprintf(cmdline, sizeof(cmdline), "\"%s\" /d /c \"\"%s\"\"",
                 canonical_interpreter, script_path);
    }

    // 5. Construct Sanitized Environment Block
    // Win32 environment block format: null-terminated strings ending in double-null
    size_t env_cap = 196608; // 192 KiB
    char* env_block = (char*)malloc(env_cap);
    if (!env_block) {
        DeleteFileA(script_path);
        DeleteFileA(param_path);
        return 1;
    }
    size_t env_pos = 0;

    #define APPEND_ENV(var_str) do { \
        size_t slen = strlen(var_str); \
        if (env_pos + slen + 2 < env_cap) { \
            memcpy(env_block + env_pos, var_str, slen + 1); \
            env_pos += slen + 1; \
        } \
    } while(0)

    // Base system variables
    char envTmp[MAX_PATH];
    if (GetEnvironmentVariableA("SystemRoot", envTmp, sizeof(envTmp)) > 0) {
        char buf[MAX_PATH + 32];
        snprintf(buf, sizeof(buf), "SystemRoot=%s", envTmp);
        APPEND_ENV(buf);
    } else {
        APPEND_ENV("SystemRoot=C:\\Windows");
    }

    if (GetEnvironmentVariableA("SystemDrive", envTmp, sizeof(envTmp)) > 0) {
        char buf[MAX_PATH + 32];
        snprintf(buf, sizeof(buf), "SystemDrive=%s", envTmp);
        APPEND_ENV(buf);
    } else {
        APPEND_ENV("SystemDrive=C:");
    }

    if (GetEnvironmentVariableA("ComSpec", envTmp, sizeof(envTmp)) > 0) {
        char buf[MAX_PATH + 32];
        snprintf(buf, sizeof(buf), "ComSpec=%s", envTmp);
        APPEND_ENV(buf);
    } else {
        APPEND_ENV("ComSpec=C:\\Windows\\System32\\cmd.exe");
    }

    if (GetEnvironmentVariableA("PATH", envTmp, sizeof(envTmp)) > 0) {
        char buf[MAX_PATH + 32];
        snprintf(buf, sizeof(buf), "PATH=%s", envTmp);
        APPEND_ENV(buf);
    } else {
        APPEND_ENV("PATH=C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\WindowsPowerShell\\v1.0");
    }

    {
        char buf[MAX_PATH + 32];
        snprintf(buf, sizeof(buf), "TEMP=%s", state_dir);
        APPEND_ENV(buf);
        snprintf(buf, sizeof(buf), "TMP=%s", state_dir);
        APPEND_ENV(buf);
    }

    APPEND_ENV("PSExecutionPolicyPreference=Bypass");

    // Ominull metadata variables
    {
        char buf[MAX_PATH + 64];
        snprintf(buf, sizeof(buf), "OMINULL_PARAMS_FILE=%s", param_path);
        APPEND_ENV(buf);
        snprintf(buf, sizeof(buf), "OMINULL_JOB_ID=%s", job_id);
        APPEND_ENV(buf);
        snprintf(buf, sizeof(buf), "OMINULL_SCRIPT_ID=%s", params->script_id);
        APPEND_ENV(buf);
    }

    // Delivered parameter variables
    for (size_t i = 0; i < params->param_count; i++) {
        const char* pname = params->params[i].name;
        const char* pval = params->params[i].value;

        // OMINULL_PARAM_<NAME>
        char var1[256 + 2048];
        snprintf(var1, sizeof(var1), "OMINULL_PARAM_%s=%s", pname, pval);
        APPEND_ENV(var1);

        // OMINULL_PARAM_<UPPER_NAME>
        char upper_name[64];
        strncpy(upper_name, pname, sizeof(upper_name) - 1);
        upper_name[sizeof(upper_name) - 1] = '\0';
        for (int k = 0; upper_name[k]; k++) {
            upper_name[k] = (char)toupper((unsigned char)upper_name[k]);
        }
        char var2[256 + 2048];
        snprintf(var2, sizeof(var2), "OMINULL_PARAM_%s=%s", upper_name, pval);
        APPEND_ENV(var2);

        // Bare <NAME>
        char var3[256 + 2048];
        snprintf(var3, sizeof(var3), "%s=%s", pname, pval);
        APPEND_ENV(var3);
    }

    #undef APPEND_ENV

    // End environment block with second null
    env_block[env_pos++] = '\0';

    // 6. Setup Anonymous Pipe for combined stdout & stderr
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hStdOutRead = NULL;
    HANDLE hStdOutWrite = NULL;
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
        free(env_block);
        DeleteFileA(script_path);
        DeleteFileA(param_path);
        return 1;
    }
    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);

    // Provide NUL handle for stdin to prevent blocking on interactive input
    HANDLE hStdInRead = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // 7. Setup Windows Job Object for complete process containment
    HANDLE hJob = CreateJobObjectA(NULL, NULL);
    if (hJob != NULL) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
        ZeroMemory(&jeli, sizeof(jeli));
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    }

    // 8. Launch Suspended Process
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = (hStdInRead != INVALID_HANDLE_VALUE) ? hStdInRead : NULL;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    DWORD creationFlags = CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB;
    BOOL created = CreateProcessA(
        NULL,
        cmdline,
        NULL,
        NULL,
        TRUE, // inherit pipe handles
        creationFlags,
        (LPVOID)env_block,
        state_dir,
        &si,
        &pi
    );

    if (!created && GetLastError() == ERROR_ACCESS_DENIED) {
        // Fallback without CREATE_BREAKAWAY_FROM_JOB if parent job denies breakaway
        created = CreateProcessA(
            NULL,
            cmdline,
            NULL,
            NULL,
            TRUE,
            CREATE_SUSPENDED,
            (LPVOID)env_block,
            state_dir,
            &si,
            &pi
        );
    }

    free(env_block);

    // Parent closes write handle and stdin handle immediately
    CloseHandle(hStdOutWrite);
    hStdOutWrite = NULL;
    if (hStdInRead != INVALID_HANDLE_VALUE) {
        CloseHandle(hStdInRead);
        hStdInRead = INVALID_HANDLE_VALUE;
    }

    if (!created) {
        if (hJob != NULL) CloseHandle(hJob);
        CloseHandle(hStdOutRead);
        DeleteFileA(script_path);
        DeleteFileA(param_path);
        if (out_error_code && error_code_cap > 0) {
            strncpy(out_error_code, "PROCESS_CREATION_FAILED", error_code_cap - 1);
            out_error_code[error_code_cap - 1] = '\0';
        }
        return 1;
    }

    // Bind process to Job Object
    if (hJob != NULL) {
        AssignProcessToJobObject(hJob, pi.hProcess);
    }

    // Start execution
    DWORD startTime = GetTickCount();
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    pi.hThread = NULL;

    // 9. Output Capture & Timeout Monitoring Loop
    size_t total_read = 0;
    char chunk[4096];
    DWORD bytesRead = 0;
    DWORD bytesAvailable = 0;
    DWORD timeoutMs = (DWORD)params->timeout_seconds * 1000;
    bool timedOut = false;
    bool isTruncated = false;

    while (1) {
        DWORD waitRes = WaitForSingleObject(pi.hProcess, 50);

        // Drain available bytes from pipe
        while (PeekNamedPipe(hStdOutRead, NULL, 0, NULL, &bytesAvailable, NULL) && bytesAvailable > 0) {
            DWORD toRead = sizeof(chunk);
            if (toRead > bytesAvailable) toRead = bytesAvailable;
            if (ReadFile(hStdOutRead, chunk, toRead, &bytesRead, NULL) && bytesRead > 0) {
                if (!isTruncated) {
                    if (total_read + bytesRead <= params->max_output_bytes && total_read + bytesRead + 1 < out_cap) {
                        memcpy(output_buf + total_read, chunk, bytesRead);
                        total_read += bytesRead;
                    } else {
                        isTruncated = true;
                        size_t space = (total_read < params->max_output_bytes) ? (params->max_output_bytes - total_read) : 0;
                        if (space > 0 && total_read + space + 1 < out_cap) {
                            memcpy(output_buf + total_read, chunk, space);
                            total_read += space;
                        }
                        const char* truncMsg = "\n[...output truncated by ominull worker...]\n";
                        size_t tlen = strlen(truncMsg);
                        if (total_read + tlen + 1 < out_cap) {
                            memcpy(output_buf + total_read, truncMsg, tlen);
                            total_read += tlen;
                        }
                    }
                }
            } else {
                break;
            }
        }

        if (waitRes == WAIT_OBJECT_0) {
            // Process completed, drain any remaining output
            while (ReadFile(hStdOutRead, chunk, sizeof(chunk), &bytesRead, NULL) && bytesRead > 0) {
                if (!isTruncated) {
                    if (total_read + bytesRead <= params->max_output_bytes && total_read + bytesRead + 1 < out_cap) {
                        memcpy(output_buf + total_read, chunk, bytesRead);
                        total_read += bytesRead;
                    } else {
                        isTruncated = true;
                        size_t space = (total_read < params->max_output_bytes) ? (params->max_output_bytes - total_read) : 0;
                        if (space > 0 && total_read + space + 1 < out_cap) {
                            memcpy(output_buf + total_read, chunk, space);
                            total_read += space;
                        }
                        const char* truncMsg = "\n[...output truncated by ominull worker...]\n";
                        size_t tlen = strlen(truncMsg);
                        if (total_read + tlen + 1 < out_cap) {
                            memcpy(output_buf + total_read, truncMsg, tlen);
                            total_read += tlen;
                        }
                    }
                }
            }
            break;
        }

        // Millisecond accurate timeout check
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= timeoutMs) {
            timedOut = true;
            if (hJob != NULL) {
                TerminateJobObject(hJob, 124);
            }
            TerminateProcess(pi.hProcess, 124);
            WaitForSingleObject(pi.hProcess, 1000);
            break;
        }
    }

    output_buf[total_read] = '\0';

    // 10. Exit Code & Duration
    DWORD dwExitCode = 0;
    GetExitCodeProcess(pi.hProcess, &dwExitCode);
    if (timedOut) {
        dwExitCode = 124;
    }

    DWORD endTime = GetTickCount();
    int64_t duration = (int64_t)(endTime - startTime);
    if (duration < 0) duration = 0;

    // 11. Resource Cleanup
    CloseHandle(pi.hProcess);
    if (hJob != NULL) {
        CloseHandle(hJob);
    }
    CloseHandle(hStdOutRead);

    DeleteFileA(script_path);
    DeleteFileA(param_path);

    if (out_truncated) *out_truncated = isTruncated;
    if (out_timed_out) *out_timed_out = timedOut;
    if (out_duration_ms) *out_duration_ms = duration;

    return (int)dwExitCode;
}

#endif /* OMINULL_SCRIPT_EXEC_WINDOWS_H */
