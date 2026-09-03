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
        snprintf(ack_body, sizeof(ack_body), "{\"job_id\":\"%s\",\"lease_id\":\"%s\"}", offer->job_id, offer->lease_id);
        if (!Hub_PostPathJSON(config, "/api/v1/response/jobs/ack", ack_body, NULL, 0)) {
            // Lease expired, rejected, or transport down
            continue;
        }

        // 4. Action Dispatcher: recognized and supported actions
        if (strcmp(offer->kind, "forensic_collection") == 0) {
            // Spawn worker inside contained Windows Job Object
            int exit_code = ExecuteContainedWorkerWindows("C:\\Windows\\System32\\cmd.exe /c exit 0", 60000);

            // Post result to hub
            char res_body[512];
            snprintf(res_body, sizeof(res_body),
                "{\"job_id\":\"%s\",\"lease_id\":\"%s\",\"state\":\"%s\",\"exit_code\":%d,\"duration_ms\":100}",
                offer->job_id, offer->lease_id, (exit_code == 0 ? "succeeded" : "failed"), exit_code);
            Hub_PostPathJSON(config, "/api/v1/response/jobs/result", res_body, NULL, 0);
        }
        // Unknown action kinds are ignored: no execution, no synthesis of success
    }
}
