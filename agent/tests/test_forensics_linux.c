/*
 * Unit tests for Ominull Linux Forensic Collection Engine (Slice 4A.1).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "../include/forensics_linux.h"

static int failures = 0;

static void expect(const char* name, bool cond) {
    if (!cond) {
        printf("  [-] FAIL: %s\n", name);
        failures++;
    } else {
        printf("  [+] PASS: %s\n", name);
    }
}

static void test_payload_parsing() {
    printf("[*] Testing Forensics_ParsePayload...\n");
    const char* json = "{\"bundle_id\":\"b-12345\",\"profile\":\"diagnostic\",\"max_bytes\":5242880,\"timeout_seconds\":30}";
    ForensicCollectionParams p;
    expect("parse valid payload", Forensics_ParsePayload(json, &p));
    expect("bundle_id matches", strcmp(p.bundle_id, "b-12345") == 0);
    expect("profile matches", strcmp(p.profile, "diagnostic") == 0);
    expect("max_bytes matches", p.max_bytes == 5242880);
    expect("timeout matches", p.timeout_seconds == 30);

    const char* json2 = "{}";
    expect("parse empty json", Forensics_ParsePayload(json2, &p));
    expect("default profile", strcmp(p.profile, "diagnostic") == 0);
    expect("default max_bytes", p.max_bytes == FORENSICS_DEFAULT_MAX_BUNDLE_BYTES);
    expect("default timeout", p.timeout_seconds == 60);
}

static void test_key_management() {
    printf("[*] Testing Key Management...\n");
    char temp_key[128];
    snprintf(temp_key, sizeof(temp_key), "/tmp/test_ev_key_%d.key", (int)getpid());
    unlink(temp_key);

    uint8_t pub1[32], priv1[64];
    char pub_hex1[65] = {0};
    expect("create new keypair", Forensics_GetOrCreateEndpointKey(temp_key, pub1, priv1, pub_hex1, sizeof(pub_hex1)));
    expect("pub hex len 64", strlen(pub_hex1) == 64);

    uint8_t pub2[32], priv2[64];
    char pub_hex2[65] = {0};
    expect("reload existing keypair", Forensics_GetOrCreateEndpointKey(temp_key, pub2, priv2, pub_hex2, sizeof(pub_hex2)));
    expect("pub keys match", memcmp(pub1, pub2, 32) == 0);
    expect("priv keys match", memcmp(priv1, priv2, 64) == 0);
    expect("pub hex match", strcmp(pub_hex1, pub_hex2) == 0);

    // Test signature
    const char* msg = "evidence manifest test payload";
    uint8_t sig[64];
    expect("sign message", Ed25519_Sign(sig, (const uint8_t*)msg, strlen(msg), priv2));
    expect("verify signature", Ed25519_Verify(sig, (const uint8_t*)msg, strlen(msg), pub2));

    unlink(temp_key);
}

static void test_collectors() {
    printf("[*] Testing Diagnostic Profile Collectors...\n");

    // 1. OS Version
    char* data = NULL;
    size_t sz = 0;
    ForensicCollectorStatus status;
    expect("collect os_version", Forensics_CollectOSVersion(&data, &sz, &status));
    expect("os_version status collected", status == COLLECTOR_STATUS_COLLECTED);
    expect("os_version has data", data != NULL && sz > 0);
    expect("os_version has os_release", strstr(data, "\"os_release\"") != NULL);
    expect("os_version has kernel", strstr(data, "\"kernel\"") != NULL);
    free(data);

    // 2. Network Interfaces
    data = NULL; sz = 0;
    expect("collect interfaces", Forensics_CollectNetworkInterfaces(&data, &sz, &status));
    expect("interfaces status collected", status == COLLECTOR_STATUS_COLLECTED);
    expect("interfaces has json", data != NULL && strstr(data, "\"interfaces\"") != NULL);
    free(data);

    // 3. Routes
    data = NULL; sz = 0;
    expect("collect routes", Forensics_CollectRoutes(&data, &sz, &status));
    expect("routes collected or empty", status == COLLECTOR_STATUS_COLLECTED || status == COLLECTOR_STATUS_EMPTY);
    free(data);

    // 4. DNS Config
    data = NULL; sz = 0;
    expect("collect dns", Forensics_CollectDNSConfig(&data, &sz, &status));
    expect("dns collected or empty", status == COLLECTOR_STATUS_COLLECTED || status == COLLECTOR_STATUS_EMPTY);
    free(data);

    // 5. Resource Summary
    data = NULL; sz = 0;
    expect("collect resources", Forensics_CollectResourceSummary(&data, &sz, &status));
    expect("resources status collected", status == COLLECTOR_STATUS_COLLECTED);
    expect("resources has memory", data != NULL && strstr(data, "\"memory_bytes\"") != NULL);
    expect("resources has load", strstr(data, "\"load_average\"") != NULL);
    free(data);

    // 6. Service State
    data = NULL; sz = 0;
    expect("collect service state", Forensics_CollectServiceState(&data, &sz, &status));
    expect("services status collected", status == COLLECTOR_STATUS_COLLECTED);
    expect("services has json", data != NULL && strstr(data, "\"services\"") != NULL);
    free(data);

    // 7. System Logs (bounded)
    data = NULL; sz = 0;
    expect("collect system logs", Forensics_CollectSystemLogs(&data, &sz, &status, 1024));
    expect("logs bounded <= 1024", sz <= 1024);
    free(data);

    // 8. Agent Diagnostics
    data = NULL; sz = 0;
    expect("collect agent diag", Forensics_CollectAgentDiagnostics("test-ep-1", "http://127.0.0.1:9999", &data, &sz, &status));
    expect("agent diag status collected", status == COLLECTOR_STATUS_COLLECTED);
    expect("agent diag has pid", data != NULL && strstr(data, "\"agent_pid\"") != NULL);
    free(data);
}

static void test_manifest_encoding() {
    printf("[*] Testing Manifest Canonical Encoding...\n");

    ForensicCollectedItem items[2];
    memset(items, 0, sizeof(items));
    strncpy(items[0].name, "os_version.json", sizeof(items[0].name) - 1);
    items[0].size_bytes = 512;
    snprintf(items[0].sha256, sizeof(items[0].sha256), "%s", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    items[0].status = COLLECTOR_STATUS_COLLECTED;

    strncpy(items[1].name, "routes.txt", sizeof(items[1].name) - 1);
    items[1].size_bytes = 100;
    snprintf(items[1].sha256, sizeof(items[1].sha256), "%s", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
    items[1].status = COLLECTOR_STATUS_EMPTY;

    uint8_t buf[2048];
    size_t len = Forensics_EncodeManifestCanonical(
        buf,
        sizeof(buf),
        "bundle-001",
        "ep-001",
        "tenant-default",
        "job-001",
        "diagnostic",
        1700000000,
        items,
        2
    );

    expect("manifest encoded len > 0", len > 0);
    expect("starts with OMINULL-MANIFEST-V2", memcmp(buf, "OMINULL-MANIFEST-V2\0", 20) == 0);

    // Detached signature
    uint8_t seed[32] = "seed1234567890123456789012345678";
    uint8_t pk[32], sk[64], sig[64];
    Ed25519_CreateKeypairFromSeed(pk, sk, seed);
    expect("sign canonical manifest", Ed25519_Sign(sig, buf, len, sk));
    expect("verify canonical manifest", Ed25519_Verify(sig, buf, len, pk));
}

int main() {
    printf("=== Starting Linux Forensics C Tests ===\n");
    test_payload_parsing();
    test_key_management();
    test_collectors();
    test_manifest_encoding();

    printf("\n=== Results: %d failures ===\n", failures);
    return failures > 0 ? 1 : 0;
}
