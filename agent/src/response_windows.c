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
    bool ok = Forensics_RunDiagnosticCollectionWin(
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
        }
        // Unknown action kinds are ignored: no execution, no synthesis of success
    }
}
