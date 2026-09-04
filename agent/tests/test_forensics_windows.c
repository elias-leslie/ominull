/*
 * Unit test suite for Windows Forensics Engine (Slice 4A.2: Diagnostic Profile).
 * Verifies:
 * - Payload parser & bounds validation
 * - Windows key management (BCrypt RNG + TweetNaCl Ed25519)
 * - Allowlisted Windows diagnostic collectors (Win32 APIs)
 * - Canonical length-prefixed binary manifest encoding (OMINULL-MANIFEST-V2)
 * - Detached Ed25519 signature generation and verification
 */

#define _WIN32_WINNT 0x0A00
#define NTDDI_VERSION 0x0A000006

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "../include/agent.h"
#include "../include/forensics_windows.h"

static int failures = 0;

static void expect(const char* name, bool cond) {
    if (!cond) {
        printf("  [-] FAIL: %s\n", name);
        failures++;
    } else {
        printf("  [+] PASS: %s\n", name);
    }
}

static void test_payload_parsing(void) {
    printf("[*] Testing Windows Forensics_ParsePayloadWin...\n");

    const char* sample = "{\"profile\":\"diagnostic\",\"bundle_id\":\"bundle-win-01\",\"max_bytes\":1048576,\"timeout_seconds\":45}";
    ForensicCollectionParamsWin params;
    expect("parse valid payload", Forensics_ParsePayloadWin(sample, &params));
    expect("bundle_id matches", strcmp(params.bundle_id, "bundle-win-01") == 0);
    expect("profile matches", strcmp(params.profile, "diagnostic") == 0);
    expect("max_bytes matches", params.max_bytes == 1048576);
    expect("timeout matches", params.timeout_seconds == 45);

    const char* empty_json = "{}";
    ForensicCollectionParamsWin defaults;
    expect("parse empty json", Forensics_ParsePayloadWin(empty_json, &defaults));
    expect("default profile", strcmp(defaults.profile, "diagnostic") == 0);
    expect("default max_bytes", defaults.max_bytes == FORENSICS_DEFAULT_MAX_BUNDLE_BYTES);
    expect("default timeout", defaults.timeout_seconds == 60);
}

static void test_key_management(void) {
    printf("[*] Testing Windows Key Management...\n");

    const char* test_key_path = "test_win_evidence_signer.key";
    remove(test_key_path);
    remove(FORENSICS_DEFAULT_PUB_PATH_WIN);

    uint8_t pub[32], priv[64];
    char pub_hex[65];
    expect("create new keypair", Forensics_GetOrCreateEndpointKeyWin(test_key_path, pub, priv, pub_hex, sizeof(pub_hex)));
    expect("pub hex len 64", strlen(pub_hex) == 64);

    uint8_t pub2[32], priv2[64];
    char pub_hex2[65];
    expect("reload existing keypair", Forensics_GetOrCreateEndpointKeyWin(test_key_path, pub2, priv2, pub_hex2, sizeof(pub_hex2)));
    expect("pub keys match", memcmp(pub, pub2, 32) == 0);
    expect("priv keys match", memcmp(priv, priv2, 64) == 0);
    expect("pub hex match", strcmp(pub_hex, pub_hex2) == 0);

    // Sign and verify test message
    const char* test_msg = "Ominull Windows Forensics Evidence Manifest";
    uint8_t sig[64];
    expect("sign message", Ed25519_Sign(sig, (const uint8_t*)test_msg, strlen(test_msg), priv));
    expect("verify signature", Ed25519_Verify(sig, (const uint8_t*)test_msg, strlen(test_msg), pub));

    remove(test_key_path);
    remove(FORENSICS_DEFAULT_PUB_PATH_WIN);
}

static void test_collectors(void) {
    printf("[*] Testing Windows Diagnostic Profile Collectors...\n");

    AGENT_CONFIG config;
    ZeroMemory(&config, sizeof(config));
    strcpy(config.endpoint_id, "win11-test-endpoint");
    strcpy(config.hub_url, "https://10.0.0.58:9443");

    // 1. OS Version
    ForensicCollectedItemWin it_os;
    expect("collect os_version", Forensics_CollectOSVersionWin(&it_os));
    expect("os_version status collected", it_os.status == COLLECTOR_STATUS_COLLECTED);
    expect("os_version has data", it_os.size_bytes > 0 && it_os.data != NULL);
    expect("os_version has platform windows", strstr((char*)it_os.data, "\"platform\": \"windows\"") != NULL);
    free(it_os.data);

    // 2. Network Interfaces
    ForensicCollectedItemWin it_if;
    expect("collect interfaces", Forensics_CollectInterfacesWin(&it_if));
    expect("interfaces status collected or empty", it_if.status == COLLECTOR_STATUS_COLLECTED || it_if.status == COLLECTOR_STATUS_EMPTY);
    expect("interfaces has json", it_if.data && it_if.data[0] == '[');
    free(it_if.data);

    // 3. Routes
    ForensicCollectedItemWin it_rt;
    expect("collect routes", Forensics_CollectRoutesWin(&it_rt));
    expect("routes collected", it_rt.status == COLLECTOR_STATUS_COLLECTED);
    expect("routes has header", it_rt.data && strstr((char*)it_rt.data, "Destination") != NULL);
    free(it_rt.data);

    // 4. DNS
    ForensicCollectedItemWin it_dns;
    expect("collect dns", Forensics_CollectDNSWin(&it_dns));
    expect("dns collected", it_dns.status == COLLECTOR_STATUS_COLLECTED);
    expect("dns has header", it_dns.data && strstr((char*)it_dns.data, "DNS") != NULL);
    free(it_dns.data);

    // 5. Resources
    ForensicCollectedItemWin it_res;
    expect("collect resources", Forensics_CollectResourcesWin(&it_res));
    expect("resources status collected", it_res.status == COLLECTOR_STATUS_COLLECTED);
    expect("resources has memory", it_res.data && strstr((char*)it_res.data, "memory_load_percent") != NULL);
    expect("resources has drive", it_res.data && strstr((char*)it_res.data, "system_drive") != NULL);
    free(it_res.data);

    // 6. Services
    ForensicCollectedItemWin it_svc;
    expect("collect services", Forensics_CollectServicesWin(&it_svc));
    expect("services status valid", it_svc.status == COLLECTOR_STATUS_COLLECTED || it_svc.status == COLLECTOR_STATUS_EMPTY || it_svc.status == COLLECTOR_STATUS_PERMISSION_DENIED);
    expect("services has json", it_svc.data && it_svc.data[0] == '[');
    free(it_svc.data);

    // 7. System Logs
    ForensicCollectedItemWin it_log;
    expect("collect system logs", Forensics_CollectSystemLogsWin(&it_log));
    expect("logs bounded <= 131072", it_log.size_bytes <= 131072);
    expect("logs status valid", it_log.status == COLLECTOR_STATUS_COLLECTED || it_log.status == COLLECTOR_STATUS_EMPTY);
    free(it_log.data);

    // 8. Agent Diagnostics
    ForensicCollectedItemWin it_diag;
    expect("collect agent diag", Forensics_CollectAgentDiagWin(&config, &it_diag));
    expect("agent diag status collected", it_diag.status == COLLECTOR_STATUS_COLLECTED);
    expect("agent diag has pid", it_diag.data && strstr((char*)it_diag.data, "agent_pid") != NULL);
    expect("agent diag has endpoint_id", it_diag.data && strstr((char*)it_diag.data, "win11-test-endpoint") != NULL);
    free(it_diag.data);
}

static void test_manifest_encoding(void) {
    printf("[*] Testing Windows Manifest Canonical Encoding...\n");

    uint8_t pub[32], priv[64];
    uint8_t seed[32] = {42};
    Ed25519_CreateKeypairFromSeed(pub, priv, seed);

    ForensicCollectedItemWin items[2];
    memset(items, 0, sizeof(items));

    strncpy(items[0].name, "os_version.json", sizeof(items[0].name) - 1);
    items[0].size_bytes = 100;
    memcpy(items[0].sha256, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", 64);
    items[0].sha256[64] = '\0';
    items[0].status = COLLECTOR_STATUS_COLLECTED;

    strncpy(items[1].name, "routes.txt", sizeof(items[1].name) - 1);
    items[1].size_bytes = 200;
    memcpy(items[1].sha256, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 64);
    items[1].sha256[64] = '\0';
    items[1].status = COLLECTOR_STATUS_COLLECTED;

    uint8_t canonical_buf[2048];
    size_t len = Forensics_EncodeManifestCanonicalWin(
        canonical_buf, sizeof(canonical_buf),
        "b-win-100", "ep-win-01", "default", "job-win-01", "diagnostic",
        1725450000, items, 2
    );

    expect("manifest encoded len > 0", len > 0);
    expect("starts with OMINULL-MANIFEST-V2", memcmp(canonical_buf, "OMINULL-MANIFEST-V2\0", 20) == 0);

    // Sign manifest
    uint8_t sig[64];
    expect("sign canonical manifest", Ed25519_Sign(sig, canonical_buf, len, priv));
    expect("verify canonical manifest", Ed25519_Verify(sig, canonical_buf, len, pub));
}

static int s_mock_upload_count = 0;
static bool s_mock_finalize_called = false;

bool Hub_PostPathData(const AGENT_CONFIG* config, const char* apiPath, const char* contentType,
                      const void* data, size_t dataLen, char* respOut, size_t respCap) {
    (void)config; (void)contentType; (void)data; (void)dataLen;
    if (strstr(apiPath, "/api/v1/evidence/items")) {
        s_mock_upload_count++;
        if (respOut && respCap > 0) snprintf(respOut, respCap, "{\"status\":\"ok\"}");
        return true;
    }
    if (strstr(apiPath, "/api/v1/evidence/finalize")) {
        s_mock_finalize_called = true;
        if (respOut && respCap > 0) snprintf(respOut, respCap, "{\"status\":\"completed\",\"receipt_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}");
        return true;
    }
    return false;
}

bool Hub_PostPathJSON(const AGENT_CONFIG* config, const char* apiPath, const char* jsonBody, char* respOut, size_t respCap) {
    if (!jsonBody) return false;
    return Hub_PostPathData(config, apiPath, "application/json", jsonBody, strlen(jsonBody), respOut, respCap);
}

static void test_run_diagnostic_collection_e2e(void) {
    printf("[*] Testing Windows Forensics_RunDiagnosticCollectionWin E2E...\n");

    AGENT_CONFIG config;
    ZeroMemory(&config, sizeof(config));
    strcpy(config.endpoint_id, "win11-e2e-test");
    strcpy(config.hub_url, "https://10.0.0.58:9443");
    strcpy(config.api_key, "omd_test_credential");

    s_mock_upload_count = 0;
    s_mock_finalize_called = false;

    const char* payload = "{\"profile\":\"diagnostic\",\"max_bytes\":5242880,\"timeout_seconds\":60}";
    char manifest_sha256[65] = {0};

    bool ok = Forensics_RunDiagnosticCollectionWin(&config, payload, "win-job-e2e-01", manifest_sha256, sizeof(manifest_sha256));
    expect("run diagnostic collection e2e succeeds", ok);
    expect("uploaded 8 items", s_mock_upload_count == 8);
    expect("finalize called", s_mock_finalize_called);
    expect("manifest sha256 computed (len 64)", strlen(manifest_sha256) == 64);
}

static void test_live_volatile_collectors_win(void) {
    printf("[*] Testing Windows Live Volatile Profile Collectors...\n");
    ForensicCollectedItemWin item;

    // 1. Process Snapshot
    expect("collect win process snapshot", Forensics_CollectProcessSnapshotWin(&item, 512 * 1024));
    expect("win process snapshot status valid", item.status == COLLECTOR_STATUS_COLLECTED || item.status == COLLECTOR_STATUS_TRUNCATED);
    expect("win process snapshot has json", item.data != NULL && strstr((char*)item.data, "\"processes\"") != NULL);
    free(item.data);

    // 2. Socket to Process
    expect("collect win sockets", Forensics_CollectSocketToProcessWin(&item, 512 * 1024));
    expect("win sockets status valid", item.status == COLLECTOR_STATUS_COLLECTED || item.status == COLLECTOR_STATUS_EMPTY);
    expect("win sockets has json", item.data != NULL && strstr((char*)item.data, "\"sockets\"") != NULL);
    free(item.data);

    // 3. Logged-in Sessions
    expect("collect win sessions", Forensics_CollectLoggedInSessionsWin(&item, 512 * 1024));
    expect("win sessions status valid", item.status == COLLECTOR_STATUS_COLLECTED || item.status == COLLECTOR_STATUS_EMPTY);
    expect("win sessions has json", item.data != NULL && strstr((char*)item.data, "\"sessions\"") != NULL);
    free(item.data);

    // 4. Network Neighbors
    expect("collect win neighbors", Forensics_CollectNetworkNeighborsWin(&item, 512 * 1024));
    expect("win neighbors status valid", item.status == COLLECTOR_STATUS_COLLECTED || item.status == COLLECTOR_STATUS_EMPTY);
    expect("win neighbors has json", item.data != NULL && strstr((char*)item.data, "\"neighbors\"") != NULL);
    free(item.data);

    // 5. Firewall State
    expect("collect win firewall", Forensics_CollectFirewallStateWin(&item, 512 * 1024));
    expect("win firewall status collected", item.status == COLLECTOR_STATUS_COLLECTED);
    expect("win firewall has json", item.data != NULL && strstr((char*)item.data, "\"firewall_framework\"") != NULL);
    free(item.data);

    // 6. Loaded Modules
    expect("collect win modules", Forensics_CollectLoadedModulesWin(&item, 512 * 1024));
    expect("win modules status valid", item.status == COLLECTOR_STATUS_COLLECTED || item.status == COLLECTOR_STATUS_EMPTY);
    expect("win modules has json", item.data != NULL && strstr((char*)item.data, "\"modules\"") != NULL);
    free(item.data);
}

static void test_ir_standard_collectors_win(void) {
    printf("[*] Testing Windows IR Standard Profile Collectors...\n");
    ForensicCollectedItemWin item;

    // 1. Persistence
    expect("collect win persistence", Forensics_CollectPersistenceWin(&item, 512 * 1024));
    expect("win persistence status valid", item.status == COLLECTOR_STATUS_COLLECTED);
    expect("win persistence has json", item.data != NULL && strstr((char*)item.data, "\"registry_run\"") != NULL);
    free(item.data);

    // 2. Scheduled Tasks
    expect("collect win scheduled tasks", Forensics_CollectScheduledTasksWin(&item, 512 * 1024));
    expect("win scheduled tasks status valid", item.status == COLLECTOR_STATUS_COLLECTED || item.status == COLLECTOR_STATUS_EMPTY);
    expect("win scheduled tasks has json", item.data != NULL && strstr((char*)item.data, "\"tasks\"") != NULL);
    free(item.data);

    // 3. Security Events
    expect("collect win security events", Forensics_CollectSecurityEventsWin(&item, 128 * 1024));
    expect("win security events status valid", item.status == COLLECTOR_STATUS_COLLECTED || item.status == COLLECTOR_STATUS_EMPTY);
    expect("win security events has data", item.data != NULL && item.size_bytes > 0);
    free(item.data);

    // 4. Shell History
    expect("collect win shell history", Forensics_CollectShellHistoryWin(&item, 256 * 1024));
    expect("win shell history status valid", item.status == COLLECTOR_STATUS_COLLECTED || item.status == COLLECTOR_STATUS_EMPTY);
    expect("win shell history has data", item.data != NULL && item.size_bytes > 0);
    free(item.data);
}

static void test_run_live_volatile_collection_e2e(void) {
    printf("[*] Testing Windows Forensics_RunCollectionWin (live_volatile) E2E...\n");

    AGENT_CONFIG config;
    ZeroMemory(&config, sizeof(config));
    strcpy(config.endpoint_id, "win11-volatile-test");
    strcpy(config.hub_url, "https://10.0.0.58:9443");
    strcpy(config.api_key, "omd_test_credential");

    s_mock_upload_count = 0;
    s_mock_finalize_called = false;

    const char* payload = "{\"profile\":\"live_volatile\",\"max_bytes\":5242880,\"timeout_seconds\":60}";
    char manifest_sha256[65] = {0};

    bool ok = Forensics_RunCollectionWin(&config, payload, "win-job-volatile-01", manifest_sha256, sizeof(manifest_sha256));
    expect("run live_volatile collection e2e succeeds", ok);
    expect("uploaded 6 items", s_mock_upload_count == 6);
    expect("finalize called", s_mock_finalize_called);
    expect("manifest sha256 computed (len 64)", strlen(manifest_sha256) == 64);
}

static void test_run_ir_standard_collection_e2e(void) {
    printf("[*] Testing Windows Forensics_RunCollectionWin (ir_standard) E2E...\n");

    AGENT_CONFIG config;
    ZeroMemory(&config, sizeof(config));
    strcpy(config.endpoint_id, "win11-ir-test");
    strcpy(config.hub_url, "https://10.0.0.58:9443");
    strcpy(config.api_key, "omd_test_credential");

    s_mock_upload_count = 0;
    s_mock_finalize_called = false;

    const char* payload = "{\"profile\":\"ir_standard\",\"max_bytes\":10485760,\"timeout_seconds\":120}";
    char manifest_sha256[65] = {0};

    bool ok = Forensics_RunCollectionWin(&config, payload, "win-job-ir-01", manifest_sha256, sizeof(manifest_sha256));
    expect("run ir_standard collection e2e succeeds", ok);
    expect("uploaded 18 items", s_mock_upload_count == 18);
    expect("finalize called", s_mock_finalize_called);
    expect("manifest sha256 computed (len 64)", strlen(manifest_sha256) == 64);
}

int main(void) {
    printf("=== Starting Windows Forensics C Tests ===\n");
    test_payload_parsing();
    test_key_management();
    test_collectors();
    test_live_volatile_collectors_win();
    test_ir_standard_collectors_win();
    test_manifest_encoding();
    test_run_diagnostic_collection_e2e();
    test_run_live_volatile_collection_e2e();
    test_run_ir_standard_collection_e2e();

    printf("\n=== Results: %d failures ===\n", failures);
    return (failures == 0) ? 0 : 1;
}
