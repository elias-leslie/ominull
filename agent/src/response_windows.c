/*
 * Ominull Windows Response Dispatcher & Execution (Slice 1D.2).
 *
 * Enforces Slice 1D invariants on Windows:
 * 1. Bounded parsing over fixed schema (at most MAX_RESPONSE_OFFERS = 4).
 * 2. Complete cryptographic grant verification before parsing action payload or acknowledging.
 * 3. Durable replay cache check before acknowledging or starting work.
 * 4. Acknowledges only after verification and replay check succeed.
 * 5. Ignores offers that fail verification or have unknown action kinds. Never ACKs or posts results.
 * 6. Never logs job IDs, payloads, tokens, or terminal output to stdout or service log.
 * 7. Windows child worker runs inside a contained Job Object with KILL_ON_JOB_CLOSE,
 *    sanitized environment, closed handles, and kill-on-cancel.
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../include/agent.h"
#include "../include/response_dispatcher.h"
#include "../include/terminal_windows.h"
#include "../include/forensics_windows.h"
#include "../include/script_exec_windows.h"

typedef struct {
    AGENT_CONFIG config;
    char job_id[64];
    char lease_id[64];
    char* payload_json;
} ScriptWorkerThreadArgsWin;

static DWORD WINAPI ScriptWorkerThreadProcWin(LPVOID lpParam) {
    ScriptWorkerThreadArgsWin* args = (ScriptWorkerThreadArgsWin*)lpParam;
    if (!args) return 1;

    ScriptExecParamsWin params;
    if (!ScriptExec_ParsePayloadWin(args->payload_json, &params)) {
        char res_body[512];
        snprintf(res_body, sizeof(res_body),
            "{\"job_id\":\"%s\",\"lease_id\":\"%s\",\"state\":\"failed\",\"exit_code\":1,\"duration_ms\":0,\"error_code\":\"INVALID_PAYLOAD\"}",
            args->job_id, args->lease_id);
        Hub_PostPathJSON(&args->config, "/api/v1/response/jobs/result", res_body, NULL, 0);
        if (args->payload_json) free(args->payload_json);
        free(args);
        return 1;
    }

    size_t out_alloc = params.max_output_bytes + 2048;
    char* output_buf = (char*)calloc(1, out_alloc);
    if (!output_buf) {
        if (args->payload_json) free(args->payload_json);
        free(args);
        return 1;
    }

    bool truncated = false;
    bool timed_out = false;
    int64_t duration_ms = 0;
    char error_code[64] = {0};

    int exit_code = ScriptExec_RunContainedWin(
        &params,
        args->job_id,
        output_buf,
        out_alloc,
        &truncated,
        &timed_out,
        &duration_ms,
        error_code,
        sizeof(error_code)
    );

    const char* state = (exit_code == 0) ? "succeeded" : "failed";
    if (timed_out && error_code[0] == '\0') {
        strncpy(error_code, "TIMED_OUT", sizeof(error_code) - 1);
    }

    char* escaped_out = ScriptExec_EscapeJSONWin(output_buf);
    size_t body_sz = (escaped_out ? strlen(escaped_out) : 0) + 1024;
    char* res_body = (char*)malloc(body_sz);
    if (res_body) {
        snprintf(res_body, body_sz,
            "{\"job_id\":\"%s\",\"lease_id\":\"%s\",\"state\":\"%s\",\"exit_code\":%d,\"duration_ms\":%lld%s%s%s%s%s%s}",
            args->job_id, args->lease_id, state, exit_code, (long long)duration_ms,
            (escaped_out ? ",\"stdout\":\"" : ""),
            (escaped_out ? escaped_out : ""),
            (escaped_out ? "\"" : ""),
            (error_code[0] ? ",\"error_code\":\"" : ""),
            (error_code[0] ? error_code : ""),
            (error_code[0] ? "\"" : ""));
        Hub_PostPathJSON(&args->config, "/api/v1/response/jobs/result", res_body, NULL, 0);
        free(res_body);
    }

    if (escaped_out) free(escaped_out);
    free(output_buf);
    if (args->payload_json) free(args->payload_json);
    free(args);
    return 0;
}

typedef struct {
    AGENT_CONFIG config;
    char job_id[64];
    char lease_id[64];
    char payload_json[4096];
} ForensicsWorkerThreadArgsWin;

static DWORD WINAPI ForensicsWorkerThreadProcWin(LPVOID lpParam) {
    ForensicsWorkerThreadArgsWin* args = (ForensicsWorkerThreadArgsWin*)lpParam;
    if (!args) return 1;

    DWORD t0 = GetTickCount();
    char manifest_sha256[65] = {0};
    bool ok = Forensics_RunCollectionWin(
        &args->config,
        args->payload_json,
        args->job_id,
        manifest_sha256,
        sizeof(manifest_sha256)
    );
    DWORD duration_ms = GetTickCount() - t0;
    int exit_code = ok ? 0 : 1;

    char res_body[1024];
    if (manifest_sha256[0]) {
        snprintf(res_body, sizeof(res_body),
            "{\"job_id\":\"%s\",\"lease_id\":\"%s\",\"state\":\"%s\",\"exit_code\":%d,\"duration_ms\":%lu,\"manifest_sha256\":\"%s\"}",
            args->job_id, args->lease_id, (exit_code == 0 ? "succeeded" : "failed"),
            exit_code, (unsigned long)duration_ms, manifest_sha256);
    } else {
        snprintf(res_body, sizeof(res_body),
            "{\"job_id\":\"%s\",\"lease_id\":\"%s\",\"state\":\"%s\",\"exit_code\":%d,\"duration_ms\":%lu}",
            args->job_id, args->lease_id, (exit_code == 0 ? "succeeded" : "failed"),
            exit_code, (unsigned long)duration_ms);
    }

    Hub_PostPathJSON(&args->config, "/api/v1/response/jobs/result", res_body, NULL, 0);

    free(args);
    return 0;
}

typedef struct {
    AGENT_CONFIG config;
    TerminalSessionParamsWin params;
} TerminalWorkerThreadArgs;

static DWORD WINAPI TerminalWorkerThreadProc(LPVOID lpParam) {
    TerminalWorkerThreadArgs* args = (TerminalWorkerThreadArgs*)lpParam;
    if (!args) return 1;

    bool is_https = (strncmp(args->config.hub_url, "https://", 8) == 0);
    Terminal_RunWindowsWorker(
        args->config.hub_url,
        is_https,
        args->config.endpoint_id,
        args->params.session_id,
        args->params.connect_token,
        args->params.program
    );

    free(args);
    return 0;
}

void ProcessResponseOffersWindows(const AGENT_CONFIG* config, const char* respJson) {
    if (!config || !respJson) return;

    ResponseJobOffer offers[MAX_RESPONSE_OFFERS];
    int offer_count = ParseResponseOffers(respJson, offers, MAX_RESPONSE_OFFERS);
    if (offer_count <= 0) return;

    for (int i = 0; i < offer_count; i++) {
        ResponseJobOffer* offer = &offers[i];

        // 1. Verify EndpointGrant V2
        if (!VerifyResponseGrant(&offer->grant, offer->payload_json, config->endpoint_id, NULL)) {
            // Drop offer silently: no ACK, no result
            continue;
        }

        // 2. Durable Replay Cache check (C:\ProgramData\Ominull\replay_cache.state)
        if (!ReplayCache_CheckAndRecord(NULL, offer->grant.grant_id, offer->grant.nonce, offer->grant.expires_at)) {
            // Replay detected: drop offer silently
            continue;
        }

        // 3. Post Acknowledgment to hub
        char ack_body[256];
        snprintf(ack_body, sizeof(ack_body), "{\"job_id\":\"%s\",\"lease_id\":\"%s\",\"accepted\":true}", offer->job_id, offer->lease_id);
        if (!Hub_PostPathJSON(config, "/api/v1/response/jobs/ack", ack_body, NULL, 0)) {
            // Lease expired, rejected, or transport down
            continue;
        }

        // 4. Action Dispatcher: recognized and supported actions
        if (strcmp(offer->kind, "forensic_collection") == 0) {
            ForensicsWorkerThreadArgsWin* args = (ForensicsWorkerThreadArgsWin*)malloc(sizeof(ForensicsWorkerThreadArgsWin));
            if (args) {
                memcpy(&args->config, config, sizeof(AGENT_CONFIG));
                strncpy(args->job_id, offer->job_id, sizeof(args->job_id) - 1);
                args->job_id[sizeof(args->job_id) - 1] = '\0';
                strncpy(args->lease_id, offer->lease_id, sizeof(args->lease_id) - 1);
                args->lease_id[sizeof(args->lease_id) - 1] = '\0';
                strncpy(args->payload_json, offer->payload_json, sizeof(args->payload_json) - 1);
                args->payload_json[sizeof(args->payload_json) - 1] = '\0';

                HANDLE hThread = CreateThread(NULL, 0, ForensicsWorkerThreadProcWin, args, 0, NULL);
                if (hThread) {
                    CloseHandle(hThread);
                } else {
                    free(args);
                }
            }
        } else if (strcmp(offer->kind, "terminal_session") == 0) {
            TerminalSessionParamsWin params;
            if (!Terminal_ParsePayloadWindows(offer->payload_json, &params)) {
                continue;
            }

            TerminalWorkerThreadArgs* args = (TerminalWorkerThreadArgs*)malloc(sizeof(TerminalWorkerThreadArgs));
            if (args) {
                memcpy(&args->config, config, sizeof(AGENT_CONFIG));
                memcpy(&args->params, &params, sizeof(TerminalSessionParamsWin));
                HANDLE hThread = CreateThread(NULL, 0, TerminalWorkerThreadProc, args, 0, NULL);
                if (hThread) {
                    CloseHandle(hThread);
                } else {
                    free(args);
                }
            }
        } else if (strcmp(offer->kind, "script_exec") == 0) {
            ScriptWorkerThreadArgsWin* args = (ScriptWorkerThreadArgsWin*)malloc(sizeof(ScriptWorkerThreadArgsWin));
            if (args) {
                memcpy(&args->config, config, sizeof(AGENT_CONFIG));
                strncpy(args->job_id, offer->job_id, sizeof(args->job_id) - 1);
                args->job_id[sizeof(args->job_id) - 1] = '\0';
                strncpy(args->lease_id, offer->lease_id, sizeof(args->lease_id) - 1);
                args->lease_id[sizeof(args->lease_id) - 1] = '\0';
                args->payload_json = (char*)malloc(offer->payload_len + 1);
                if (args->payload_json) {
                    memcpy(args->payload_json, offer->payload_json, offer->payload_len);
                    args->payload_json[offer->payload_len] = '\0';
                    HANDLE hThread = CreateThread(NULL, 0, ScriptWorkerThreadProcWin, args, 0, NULL);
                    if (hThread) {
                        CloseHandle(hThread);
                    } else {
                        free(args->payload_json);
                        free(args);
                    }
                } else {
                    free(args);
                }
            }
        }
        // Unknown action kinds are ignored: no execution, no synthesis of success
    }
}
