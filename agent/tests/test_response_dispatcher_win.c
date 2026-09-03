/*
 * Unit test suite for Windows Response Dispatcher & Job Object Containment (Slice 1D.2).
 * Verifies bounded offer parsing, SHA-256, Ed25519 verification, Win32 locked replay cache,
 * and Windows Job Object worker containment.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

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

    Response_SHA256_Sum((const uint8_t*)"", 0, hash);
    Response_BytesToHex(hash, 32, hex);
    expect("sha256('') == e3b0c442...",
           strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0, true);

    Response_SHA256_Sum((const uint8_t*)"abc", 3, hash);
    Response_BytesToHex(hash, 32, hex);
    expect("sha256('abc') == ba7816bf...",
           strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0, true);
}

/* 2. Test Bounded Offer Parser */
static void test_offer_parser(void) {
    const char* sample =
        "{\"status\":\"ok\",\"response_offers\":[{"
        "\"job_id\":\"win-job-1\","
        "\"lease_id\":\"win-lease-1\","
        "\"kind\":\"forensic_collection\","
        "\"grant\":{"
        "\"version\":2,\"grant_id\":\"g-win-1\",\"tenant_id\":\"default\","
        "\"endpoint_id\":\"windows-desktop-t6bg81p\",\"action_kind\":\"forensic_collection\","
        "\"action_digest\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
        "\"operator_id\":\"secops\",\"response_session_id\":\"sess-win-1\","
        "\"issued_at\":1788350400,\"expires_at\":1788354000,"
        "\"nonce\":\"nonce-win-1\",\"signer_key_id\":\"key-win-1\","
        "\"signature\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\""
        "},"
        "\"payload_json\":\"{\\\"profile\\\":\\\"triage\\\"}\""
        "}]}";

    ResponseJobOffer offers[MAX_RESPONSE_OFFERS];
    int count = ParseResponseOffers(sample, offers, MAX_RESPONSE_OFFERS);
    expect("parsed 1 valid windows offer", count == 1, true);
    if (count == 1) {
        expect("job_id matches", strcmp(offers[0].job_id, "win-job-1") == 0, true);
        expect("grant.endpoint_id matches", strcmp(offers[0].grant.endpoint_id, "windows-desktop-t6bg81p") == 0, true);
    }
}

/* 3. Test Win32 Durable Locked Replay Cache */
static void test_win32_replay_cache(void) {
    char tempPath[MAX_PATH];
    char tempFile[MAX_PATH];
    GetTempPathA(sizeof(tempPath), tempPath);
    GetTempFileNameA(tempPath, "omrep", 0, tempFile);

    int64_t now = (int64_t)time(NULL);
    bool r1 = ReplayCache_CheckAndRecord(tempFile, "win-grant-1", "win-nonce-1", now + 300);
    expect("first recording of win-grant-1 succeeds", r1, true);

    bool r2 = ReplayCache_CheckAndRecord(tempFile, "win-grant-1", "win-nonce-2", now + 300);
    expect("replay of win-grant-1 rejected", r2 == false, true);

    bool r3 = ReplayCache_CheckAndRecord(tempFile, "win-grant-2", "win-nonce-1", now + 300);
    expect("replay of win-nonce-1 rejected", r3 == false, true);

    bool r4 = ReplayCache_CheckAndRecord(tempFile, "win-grant-2", "win-nonce-2", now + 300);
    expect("distinct win-grant-2 succeeds", r4, true);

    DeleteFileA(tempFile);
}

/* 4. Test Ed25519 Signature Verification on Windows */
static void test_ed25519_verify_win(void) {
    // Go-generated test vector
    const char* pub_hex = "342421b1298bcf57bc3b74694604892816d309dd59392faad357a89357891227";
    const char* msg_hex = "68656c6c6f2066726f6d206f6d696e756c6c20726573706f6e73652074657374";
    const char* sig_hex = "ddabab09cbdeeb8b2c24a8403fff8854dc710172b6e3dc954e3b5319806d69b4c9f16cc51061ca7e6250756754a8c80a634dda047319e5871a81c03fda52770e";

    uint8_t pub[32], msg[32], sig[64];
    Response_HexToBytes(pub_hex, pub, 32);
    Response_HexToBytes(msg_hex, msg, 32);
    Response_HexToBytes(sig_hex, sig, 64);

    bool ok = Ed25519_Verify(sig, msg, 32, pub);
    expect("pure-C Ed25519 verification succeeds on Windows", ok, true);

    msg[0] ^= 0xFF;
    bool ok_tamper = Ed25519_Verify(sig, msg, 32, pub);
    expect("tampered message rejected on Windows", ok_tamper == false, true);
}

/* 5. Test Windows Job Object Worker Containment */
static void test_job_object_containment(void) {
    // Execute a simple harmless command in a Job Object with timeout
    int code = ExecuteContainedWorkerWindows("cmd.exe /c exit 0", 10000);
    expect("contained worker exits 0 cleanly in Job Object", code == 0, true);

    int fail_code = ExecuteContainedWorkerWindows("cmd.exe /c exit 42", 10000);
    expect("contained worker propagates non-zero exit code 42", fail_code == 42, true);
}

int main(void) {
    printf("[*] Running Windows Response Dispatcher & Job Object test suite (Slice 1D.2)...\n");
    test_sha256();
    test_offer_parser();
    test_win32_replay_cache();
    test_ed25519_verify_win();
    test_job_object_containment();

    if (failures == 0) {
        printf("[+] All Windows response dispatcher tests passed cleanly.\n");
        return 0;
    }
    printf("[-] %d test failures.\n", failures);
    return 1;
}
