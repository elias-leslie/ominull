/* The heartbeat reply as agent_trust.h reads it: pinned keys,
 * the capability manifest, first-run enforcement adoption and enforcement
 * grants, plus the agent-update grant. Keys are pinned once from the signed
 * fixtures (trust_fixtures.h), so grants are parsed past the key lookup; each
 * input then starts from that same pinned, not yet bootstrapped context. */
#include "fuzz_common.h"
#include "../../include/agent_trust.h"
#include "../trust_fixtures.h"
#include "../../include/release_verify_posix.h"

static TrustContext pristine, T;
static char dir[64] = "/tmp/ominull-fuzz-trust-XXXXXX";

static bool no_verify(const char* msg, size_t len, const uint8_t* der, size_t derlen) {
    (void)msg; (void)len; (void)der; (void)derlen;
    return false;
}

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc; (void)argv;
    Fuzz_QuietStdout();
    if (!mkdtemp(dir)) abort();
    Trust_Init(&T, FX_ENDPOINT, dir, dir, false);
    g_ReleaseVerifyPem = FX_TB_PUB_PEM;
    snprintf(g_ReleaseVerifyDir, sizeof(g_ReleaseVerifyDir), "%s", dir);
    T.verify_release = ReleaseVerifyPosix;
    static char resp[8192];
    size_t n = strlen(FX_KEYS_JSON);
    snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"trust\":%.*s,\"bundle_sig\":\"%s\"},\"capability_manifest\":%s}",
             (int)(n - 1), FX_KEYS_JSON, FX_TB_SIG, FX_M_ENGAGEMENT_1);
    Trust_ProcessHeartbeat(&T, resp, strlen(resp), FX_T0);
    if (!T.have_key[TRUST_KEY_RESPONSE]) {
        fprintf(stderr, "fuzz_trust_reply: fixture keys did not pin\n");
        abort();
    }
    /* No openssl child per input: later pins simply fail to verify. */
    T.verify_release = no_verify;
    T.state.exists = false;
    pristine = T;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* text = Fuzz_Text(data, size);
    T = pristine;
    (void)Trust_ProcessHeartbeat(&T, text, size, FX_T0 + 100);
    T = pristine;
    (void)Trust_UpdateAuthorized(&T, text, size, "9.9.9", FX_T0 + 100);
    free(text);
    return 0;
}
