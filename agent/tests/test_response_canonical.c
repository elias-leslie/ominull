/*
 * Byte-exact cross-language test for Ominull Response Canonical Encoder.
 * Tests that C-generated canonical bytes match Go-generated canonical fixtures
 * bit-for-bit and byte-for-byte.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../include/response_canonical.h"

static int failures = 0;

static void expect(const char* name, bool got, bool want) {
    if (got != want) {
        printf("  [-] %s: got %s, want %s\n", name, got ? "true" : "false", want ? "true" : "false");
        failures++;
    } else {
        printf("  [+] %s\n", name);
    }
}

static uint8_t* readFile(const char* path, size_t* outLen) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        printf("  [-] cannot open binary fixture: %s\n", path);
        failures++;
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    uint8_t* buf = (uint8_t*)malloc(sz);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, sz, f);
    fclose(f);
    if (outLen) *outLen = n;
    return buf;
}

int main(int argc, char** argv) {
    const char* binFixturePath = "hub/tests/fixtures/response/grant_v2_canonical.bin";
    if (argc > 1) {
        binFixturePath = argv[1];
    }

    size_t wantLen = 0;
    uint8_t* wantBytes = readFile(binFixturePath, &wantLen);
    if (!wantBytes) {
        return 1;
    }

    uint8_t gotBytes[1024];
    size_t gotLen = EncodeGrantV2Canonical(
        2,
        "00000000-0000-0000-0000-000000000001",
        "tenant-production",
        "linux-ominull-target-linux",
        "forensic_collection",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "operator-secops",
        "sess-0000-0000-0001",
        1788350400,
        1788354000,
        "0123456789abcdef0123456789abcdef",
        "65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8",
        gotBytes,
        sizeof(gotBytes)
    );

    expect("canonical grant encoding succeeded", gotLen > 0, true);
    expect("canonical grant length matches fixture exactly", gotLen == wantLen, true);
    if (gotLen == wantLen) {
        bool match = (memcmp(gotBytes, wantBytes, gotLen) == 0);
        expect("canonical grant bytes match Go-generated fixture byte-for-byte", match, true);
    }

    /* Test proof encoding */
    const char* targets[] = {"ep-1", "ep-2"};
    uint8_t proofBytes[512];
    size_t proofLen = EncodeProofV2Canonical(
        2,
        "sess-test",
        "tenant-prod",
        "forensic_collection",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        targets,
        2,
        1788350400,
        "abcdef123456",
        proofBytes,
        sizeof(proofBytes)
    );
    expect("canonical proof encoding succeeded", proofLen > 0, true);

    free(wantBytes);

    if (failures == 0) {
        printf("[+] All response canonical encoder tests passed byte-exact verification.\n");
        return 0;
    } else {
        printf("[-] %d response canonical encoder tests failed.\n", failures);
        return 1;
    }
}
