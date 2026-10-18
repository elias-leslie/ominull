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
#include "../include/screen_windows.h"
#include "../include/forensics_windows.h"
#include "../include/script_exec_windows.h"

/* Bumped by the service (service.c) on SERVICE_CONTROL_SESSIONCHANGE; a live
 * screen worker watches it and respawns the helper into the new active console
 * session (REMOTE_SCREEN.md §6.1). Declared extern in screen_windows.h. */
volatile LONG g_ScreenSessionEpoch = 0;

typedef struct {
    AGENT_CONFIG config;
    char job_id[64];
    char lease_id[64];
    char* payload_json;
} ScriptWorkerThreadArgsWin;

/* Heartbeats of one script job (docs/RESPONSE_SUPERVISOR.md). The job thread
 * only drops the latest body here and moves on; a helper thread posts it, so
 * the hub's speed (and the shared WinHTTP connection's lock) never holds up
 * the output drain or the timeout. A newer body replaces one not yet sent.
 * A reply carrying "cancel":true sets the cancel flag. The poster is freed by
 * whichever of the two threads lets go of it last. */
typedef struct {
    AGENT_CONFIG config;
    CRITICAL_SECTION lock;
    HANDLE wake;
    char* pending;
    volatile LONG cancel;
    volatile LONG stop;
    volatile LONG refs;
} ScriptHeartbeatPosterWin;

static void ScriptHeartbeatReleaseWin(ScriptHeartbeatPosterWin* poster) {
    if (InterlockedDecrement(&poster->refs) != 0) return;
    free(poster->pending);
    CloseHandle(poster->wake);
    DeleteCriticalSection(&poster->lock);
    free(poster);
}

static DWORD WINAPI ScriptHeartbeatThreadProcWin(LPVOID lpParam) {
    ScriptHeartbeatPosterWin* poster = (ScriptHeartbeatPosterWin*)lpParam;
    for (;;) {
        WaitForSingleObject(poster->wake, INFINITE);
        EnterCriticalSection(&poster->lock);
        char* body = poster->pending;
        poster->pending = NULL;
        LeaveCriticalSection(&poster->lock);
        if (InterlockedCompareExchange(&poster->stop, 0, 0)) {
            free(body);
            break;
        }
        if (!body) continue;
        char reply[512] = {0};
        if (Hub_PostPathJSON(&poster->config, "/api/v1/response/jobs/progress", body, reply, sizeof(reply)) &&
            Supervisor_ReplyCancels(reply)) {
            InterlockedExchange(&poster->cancel, 1);
        }
        free(body);
    }
    ScriptHeartbeatReleaseWin(poster);
    return 0;
}

static void ScriptHeartbeatPostWin(void* ctx, const char* body) {
    ScriptHeartbeatPosterWin* poster = (ScriptHeartbeatPosterWin*)ctx;
    if (!poster || !body) return;
    char* copy = _strdup(body);
    if (!copy) return;
    EnterCriticalSection(&poster->lock);
    free(poster->pending);
    poster->pending = copy;
    LeaveCriticalSection(&poster->lock);
    SetEvent(poster->wake);
}

static bool ScriptHeartbeatCancelledWin(void* ctx) {
    ScriptHeartbeatPosterWin* poster = (ScriptHeartbeatPosterWin*)ctx;
    return poster && InterlockedCompareExchange(&poster->cancel, 0, 0) != 0;
}

/* NULL when the thread cannot start: the job then runs without heartbeats. */
static ScriptHeartbeatPosterWin* ScriptHeartbeatStartWin(const AGENT_CONFIG* config) {
    ScriptHeartbeatPosterWin* poster = (ScriptHeartbeatPosterWin*)calloc(1, sizeof(*poster));
    if (!poster) return NULL;
    memcpy(&poster->config, config, sizeof(AGENT_CONFIG));
    InitializeCriticalSection(&poster->lock);
    poster->wake = CreateEventA(NULL, FALSE, FALSE, NULL);
    poster->refs = 2;
    HANDLE thread = poster->wake ? CreateThread(NULL, 0, ScriptHeartbeatThreadProcWin, poster, 0, NULL) : NULL;
    if (!thread) {
        if (poster->wake) CloseHandle(poster->wake);
        DeleteCriticalSection(&poster->lock);
        free(poster);
        return NULL;
    }
    CloseHandle(thread);
    return poster;
}

/* Drops any unsent beat and lets the helper finish its post in flight on its
 * own; the result is posted without waiting for it. */
static void ScriptHeartbeatStopWin(ScriptHeartbeatPosterWin* poster) {
    if (!poster) return;
    InterlockedExchange(&poster->stop, 1);
    SetEvent(poster->wake);
    ScriptHeartbeatReleaseWin(poster);
}

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

    char error_code[64] = {0};
    ScriptRunResult run;
    ScriptHeartbeatPosterWin* poster = ScriptHeartbeatStartWin(&args->config);
    ScriptSupervisorHooks hooks = {
        .settings = Supervisor_DefaultSettings(),
        .job_id = args->job_id,
        .lease_id = args->lease_id,
        .post = poster ? ScriptHeartbeatPostWin : NULL,
        .cancel_requested = poster ? ScriptHeartbeatCancelledWin : NULL,
        .ctx = poster,
    };

    int exit_code = ScriptExec_RunSupervisedWin(
        &params,
        args->job_id,
        output_buf,
        out_alloc,
        &hooks,
        &run,
        error_code,
        sizeof(error_code)
    );
    ScriptHeartbeatStopWin(poster);

    const char* state = run.cancelled ? "cancelled" : (exit_code == 0) ? "succeeded" : "failed";
    if (run.cancelled) {
        snprintf(error_code, sizeof(error_code), "CANCELLED");
    } else if (run.timed_out && error_code[0] == '\0') {
        strncpy(error_code, "TIMED_OUT", sizeof(error_code) - 1);
    }
    int64_t duration_ms = run.duration_ms;

    char* escaped_out = ScriptExec_EscapeJSONWin(output_buf);
    size_t body_sz = (escaped_out ? strlen(escaped_out) : 0) + 1024;
    char* res_body = (char*)malloc(body_sz);
    if (res_body) {
        snprintf(res_body, body_sz,
            "{\"job_id\":\"%s\",\"lease_id\":\"%s\",\"state\":\"%s\",\"exit_code\":%d,\"duration_ms\":%lld%s%s%s%s%s%s%s}",
            args->job_id, args->lease_id, state, exit_code, (long long)duration_ms,
            (escaped_out ? ",\"stdout\":\"" : ""),
            (escaped_out ? escaped_out : ""),
            (escaped_out ? "\"" : ""),
            (error_code[0] ? ",\"error_code\":\"" : ""),
            (error_code[0] ? error_code : ""),
            (error_code[0] ? "\"" : ""),
            (run.truncated ? ",\"truncated\":true" : ""));
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

    Terminal_RunWindowsWorker(
        &args->config,
        args->params.session_id,
        args->params.connect_token,
        args->params.program
    );

    free(args);
    return 0;
}

typedef struct {
    AGENT_CONFIG config;
    ScreenSessionParamsWin params;
} ScreenWorkerThreadArgs;

static DWORD WINAPI ScreenWorkerThreadProc(LPVOID lpParam) {
    ScreenWorkerThreadArgs* args = (ScreenWorkerThreadArgs*)lpParam;
    if (!args) return 1;

    /* The helper is launched into the active console session and bytes are
     * relayed over its stdio; the connect token and session_id stay here and
     * never reach the helper. No message parsing happens in C beyond the pipe
     * framing and the 1-byte service opcode (REMOTE_SCREEN.md §6.5). */
    Screen_RunWindowsWorker(&args->config, &args->params);

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

        /* Screen offers get a small diagnostics trail (REMOTE_SCREEN.md §6/§9)
         * so a session that never reaches the viewer is not blind. Only safe
         * fields are logged: the session id (safe charset) and the mode, never
         * the connect token or any payload bytes. Other kinds are not logged
         * here, keeping the "never log job ids/payloads" invariant for them. */
        bool is_screen = (strcmp(offer->kind, "screen_session") == 0);
        char log_sid[64] = "?";
        char log_mode[16] = "?";
        if (is_screen) {
            ScreenSessionParamsWin lp;
            if (Screen_ParsePayloadWindows(offer->payload_json, &lp)) {
                strncpy(log_sid, lp.session_id, sizeof(log_sid) - 1);
                log_sid[sizeof(log_sid) - 1] = '\0';
                strncpy(log_mode, lp.mode, sizeof(log_mode) - 1);
                log_mode[sizeof(log_mode) - 1] = '\0';
            }
            Screen_LogSession(log_sid, "offer received", log_mode);
        }

        // 1. Verify EndpointGrant V2, against the pinned key, for this kind,
        //    inside this endpoint's capability manifest
        const char* refuse1 = Agent_TrustOfferRefusal(offer->kind, &offer->grant);
        if (refuse1) {
            if (is_screen) Screen_LogSession(log_sid, "offer refused", refuse1);
            continue;
        }
        /* Against the pinned key in memory (trust.pin), never a file copy; a
         * script on a host-authority host against its host key. V3 grants
         * must name this job. No ACK, no result on a refusal. */
        const char* refuse2 = Agent_TrustOfferGrantRefusal(offer->job_id, &offer->grant, offer->payload_json, config->endpoint_id);
        if (refuse2) {
            if (is_screen) Screen_LogSession(log_sid, "offer refused", refuse2);
            continue;
        }

        // 2. Durable Replay Cache check (C:\ProgramData\Ominull\replay_cache.state)
        if (!ReplayCache_CheckAndRecord(NULL, offer->grant.grant_id, offer->grant.nonce, offer->grant.expires_at)) {
            // Replay detected: drop offer silently
            if (is_screen) Screen_LogSession(log_sid, "offer refused", "replay");
            continue;
        }

        // 3. Post Acknowledgment to hub
        char ack_body[256];
        snprintf(ack_body, sizeof(ack_body), "{\"job_id\":\"%s\",\"lease_id\":\"%s\",\"accepted\":true}", offer->job_id, offer->lease_id);
        if (!Hub_PostPathJSON(config, "/api/v1/response/jobs/ack", ack_body, NULL, 0)) {
            // Lease expired, rejected, or transport down
            if (is_screen) Screen_LogSession(log_sid, "ack failed", "lease expired, rejected, or transport down");
            continue;
        }
        if (is_screen) Screen_LogSession(log_sid, "ack ok", NULL);

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
        } else if (strcmp(offer->kind, "screen_session") == 0) {
            ScreenSessionParamsWin params;
            if (!Screen_ParsePayloadWindows(offer->payload_json, &params)) {
                continue;
            }

            ScreenWorkerThreadArgs* args = (ScreenWorkerThreadArgs*)malloc(sizeof(ScreenWorkerThreadArgs));
            if (args) {
                memcpy(&args->config, config, sizeof(AGENT_CONFIG));
                memcpy(&args->params, &params, sizeof(ScreenSessionParamsWin));
                HANDLE hThread = CreateThread(NULL, 0, ScreenWorkerThreadProc, args, 0, NULL);
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
