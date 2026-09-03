/*
 * Comprehensive unit test suite for Ominull Response Dispatcher (Slice 1D.1).
 * Tests SHA-256, bounded offer parsing, durable replay cache, and
 * cryptographic grant verification with Ed25519 and canonical encoding.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../include/response_dispatcher.h"

static int failures = 0;

static void expect(const char* name, bool got, bool want) {
    if (got != want) {
        printf("  [-] %s: got %s, want %s\n", name, got ? "true" : "false", want ? "true" : "false");
        failures++;
    } else {
        printf("  [+] %s\n", name);
    }
}

/* 1. Test In-Process SHA-256 */
static void test_sha256(void) {
    uint8_t hash[32];
    char hex[65];

    // Empty string
    Response_SHA256_Sum((const uint8_t*)"", 0, hash);
    Response_BytesToHex(hash, 32, hex);
    expect("sha256('') == e3b0c442...",
           strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0, true);

    // "abc"
    Response_SHA256_Sum((const uint8_t*)"abc", 3, hash);
    Response_BytesToHex(hash, 32, hex);
    expect("sha256('abc') == ba7816bf...",
           strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0, true);
}

/* 2. Test Bounded Offer Parser */
static void test_offer_parser(void) {
    const char* sample_heartbeat =
        "{\n"
        "  \"status\": \"ok\",\n"
        "  \"response_offers\": [\n"
        "    {\n"
        "      \"job_id\": \"job-001\",\n"
        "      \"lease_id\": \"lease-001\",\n"
        "      \"kind\": \"forensic_collection\",\n"
        "      \"grant\": {\n"
        "        \"version\": 2,\n"
        "        \"grant_id\": \"grant-001\",\n"
        "        \"tenant_id\": \"default\",\n"
        "        \"endpoint_id\": \"ep-linux-1\",\n"
        "        \"action_kind\": \"forensic_collection\",\n"
        "        \"action_digest\": \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\",\n"
        "        \"operator_id\": \"admin\",\n"
        "        \"response_session_id\": \"sess-001\",\n"
        "        \"issued_at\": 1788350400,\n"
        "        \"expires_at\": 1788354000,\n"
        "        \"nonce\": \"nonce-001\",\n"
        "        \"signer_key_id\": \"key-001\",\n"
        "        \"signature\": \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n"
        "      },\n"
        "      \"payload_json\": \"{\\\"profile\\\":\\\"diagnostic\\\"}\"\n"
        "    }\n"
        "  ]\n"
        "}";

    ResponseJobOffer offers[MAX_RESPONSE_OFFERS];
    int parsed = ParseResponseOffers(sample_heartbeat, offers, MAX_RESPONSE_OFFERS);
    expect("parsed exactly 1 valid offer", parsed == 1, true);
    if (parsed == 1) {
        expect("job_id matches", strcmp(offers[0].job_id, "job-001") == 0, true);
        expect("lease_id matches", strcmp(offers[0].lease_id, "lease-001") == 0, true);
        expect("kind matches", strcmp(offers[0].kind, "forensic_collection") == 0, true);
        expect("grant.version == 2", offers[0].grant.version == 2, true);
        expect("grant.endpoint_id matches", strcmp(offers[0].grant.endpoint_id, "ep-linux-1") == 0, true);
        expect("payload_json matches", strcmp(offers[0].payload_json, "{\"profile\":\"diagnostic\"}") == 0, true);
    }

    // Malformed offer (missing grant signature)
    const char* malformed_json =
        "{\"response_offers\": [{\"job_id\": \"j1\", \"lease_id\": \"l1\", \"kind\": \"k1\", \"grant\": {\"version\": 2}}]}";
    parsed = ParseResponseOffers(malformed_json, offers, MAX_RESPONSE_OFFERS);
    expect("malformed offer rejected", parsed == 0, true);
}

/* 3. Test Durable Replay Cache */
static void test_replay_cache(void) {
    char tmp_cache[64] = "/tmp/ominull_test_replay_XXXXXX";
    int fd = mkstemp(tmp_cache);
    if (fd >= 0) close(fd);

    int64_t now = (int64_t)time(NULL);
    bool r1 = ReplayCache_CheckAndRecord(tmp_cache, "grant-100", "nonce-100", now + 300);
    expect("first recording of grant-100 succeeds", r1, true);

    bool r2 = ReplayCache_CheckAndRecord(tmp_cache, "grant-100", "nonce-999", now + 300);
    expect("replay of grant-100 is rejected", r2 == false, true);

    bool r3 = ReplayCache_CheckAndRecord(tmp_cache, "grant-101", "nonce-100", now + 300);
    expect("replay of nonce-100 is rejected", r3 == false, true);

    bool r4 = ReplayCache_CheckAndRecord(tmp_cache, "grant-102", "nonce-102", now + 300);
    expect("distinct grant-102 succeeds", r4, true);

    unlink(tmp_cache);
}

/* 4. Test End-to-End Cryptographic Grant Verification */
static void test_grant_verification(void) {
    // Generate an Ed25519 keypair using openssl
    char tmp_dir[64] = "/tmp/ominull_test_keys_XXXXXX";
    if (!mkdtemp(tmp_dir)) return;

    char key_path[128], pub_path[128];
    snprintf(key_path, sizeof(key_path), "%s/ed25519.key", tmp_dir);
    snprintf(pub_path, sizeof(pub_path), "%s/ed25519.pub", tmp_dir);

    char gen_cmd[512];
    snprintf(gen_cmd, sizeof(gen_cmd),
             "openssl genpkey -algorithm Ed25519 -out %s >/dev/null 2>&1 && "
             "openssl pkey -in %s -pubout -out %s >/dev/null 2>&1",
             key_path, key_path, pub_path);
    int ret = system(gen_cmd);
    expect("generated test Ed25519 keypair", ret == 0, true);

    int64_t now = (int64_t)time(NULL);
    const char* payload = "{\"action\":\"quarantine\",\"target\":\"10.0.0.5\"}";
    uint8_t payload_hash[32];
    Response_SHA256_Sum((const uint8_t*)payload, strlen(payload), payload_hash);
    char payload_digest[65];
    Response_BytesToHex(payload_hash, 32, payload_digest);

    ResponseGrant grant;
    memset(&grant, 0, sizeof(grant));
    grant.version = 2;
    strcpy(grant.grant_id, "test-grant-uuid-1");
    strcpy(grant.tenant_id, "default");
    strcpy(grant.endpoint_id, "ep-linux-target");
    strcpy(grant.action_kind, "quarantine");
    strcpy(grant.action_digest, payload_digest);
    strcpy(grant.operator_id, "admin");
    strcpy(grant.response_session_id, "sess-test");
    grant.issued_at = now - 10;
    grant.expires_at = now + 300;
    strcpy(grant.nonce, "test-nonce-123");
    strcpy(grant.signer_key_id, "signer-key-id-1");

    // Canonical bytes
    uint8_t canonical_bytes[1024];
    size_t c_len = EncodeGrantV2Canonical(
        grant.version, grant.grant_id, grant.tenant_id, grant.endpoint_id,
        grant.action_kind, grant.action_digest, grant.operator_id,
        grant.response_session_id, grant.issued_at, grant.expires_at,
        grant.nonce, grant.signer_key_id, canonical_bytes, sizeof(canonical_bytes)
    );
    expect("canonical encoding generated", c_len > 0, true);

    // Sign canonical bytes with private key
    char tmp_data[128], tmp_sig[128];
    snprintf(tmp_data, sizeof(tmp_data), "%s/data.bin", tmp_dir);
    snprintf(tmp_sig, sizeof(tmp_sig), "%s/sig.bin", tmp_dir);
    FILE* f_data = fopen(tmp_data, "wb");
    if (f_data) {
        fwrite(canonical_bytes, 1, c_len, f_data);
        fclose(f_data);
    }

    char sign_cmd[512];
    snprintf(sign_cmd, sizeof(sign_cmd),
             "openssl pkeyutl -sign -rawin -inkey %s -in %s -out %s >/dev/null 2>&1",
             key_path, tmp_data, tmp_sig);
    ret = system(sign_cmd);
    expect("signed canonical grant with openssl pkeyutl", ret == 0, true);

    // Read signature bytes and hex encode into grant.signature
    FILE* f_sig = fopen(tmp_sig, "rb");
    uint8_t sig_raw[64];
    if (f_sig) {
        if (fread(sig_raw, 1, 64, f_sig) == 64) {
            Response_BytesToHex(sig_raw, 64, grant.signature);
        }
        fclose(f_sig);
    }

    // 1. Valid grant verification
    bool ok = VerifyResponseGrant(&grant, payload, "ep-linux-target", pub_path);
    expect("valid grant verifies successfully", ok, true);

    // 2. Tampered payload verification
    bool ok_tamper = VerifyResponseGrant(&grant, "{\"tampered\": true}", "ep-linux-target", pub_path);
    expect("tampered payload fails verification", ok_tamper == false, true);

    // 3. Endpoint ID mismatch (stolen grant)
    bool ok_mismatch = VerifyResponseGrant(&grant, payload, "ep-victim-machine", pub_path);
    expect("mismatched endpoint ID fails verification", ok_mismatch == false, true);

    // 4. Expired grant
    grant.expires_at = now - 100;
    bool ok_expired = VerifyResponseGrant(&grant, payload, "ep-linux-target", pub_path);
    expect("expired grant fails verification", ok_expired == false, true);

    // Cleanup
    unlink(key_path);
    unlink(pub_path);
    unlink(tmp_data);
    unlink(tmp_sig);
    rmdir(tmp_dir);
}

int main(void) {
    printf("[*] Running Ominull Response Dispatcher test suite (Slice 1D.1)...\n");
    test_sha256();
    test_offer_parser();
    test_replay_cache();
    test_grant_verification();

    if (failures == 0) {
        printf("[+] All response dispatcher tests passed cleanly.\n");
        return 0;
    }
    printf("[-] %d test failures.\n", failures);
    return 1;
}
