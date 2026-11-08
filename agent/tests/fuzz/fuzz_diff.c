/* The Rust hub-input library against the C readers: every input through both,
 * any difference or Rust panic is a crash. Built by scripts/fuzz-agent.sh. */
#include "fuzz_common.h"
#include "hub_input_diff.h"

/* Without LTO the prebuilt core still names this; panics abort, so it never runs. */
void rust_eh_personality(void) {}

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc; (void)argv;
    Fuzz_QuietStdout();
    Diff_Abi();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Diff_One(data, size);
    /* The P-256 path, for panics and bad reads; the verdicts are compared with
     * openssl and CNG in test_hub_input_diff. */
    if (size >= 96) {
        uint8_t hash[32];
        memcpy(hash, data + 64, 32);
        (void)hi_p256_verify_hash(data, hash, data + 96, size - 96);
        (void)hi_p256_verify_xy(data, (const char*)data + 64, 32, data + 96, size - 96);
    }
    char* text = Fuzz_Text(data, size);
    (void)hi_p256_verify_pem(text, "m", 1, data, size);
    free(text);
    return 0;
}
