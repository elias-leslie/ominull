/*
 * DerToRawSignature sits in the agent's update trust path: every release
 * signature passes through it before CNG ever sees one. It is the only
 * hand-written parsing in that path, so it is tested against signatures
 * openssl actually produced, and against structures that must be refused.
 */
#include <stdio.h>
#include <stdlib.h>
#include "../include/der_sig.h"

static int failures = 0;

static void expect(const char* name, bool got, bool want) {
    if (got != want) {
        printf("  [-] %s: got %s, want %s\n", name, got ? "accept" : "reject", want ? "accept" : "reject");
        failures++;
    } else {
        printf("  [+] %s\n", name);
    }
}

static size_t readHex(const char* path, unsigned char* out, size_t cap) {
    FILE* f = fopen(path, "rb");
    if (!f) { printf("  [-] cannot open %s\n", path); failures++; return 0; }
    size_t n = fread(out, 1, cap, f);
    fclose(f);
    return n;
}

int main(int argc, char** argv) {
    unsigned char raw[64];

    /* 1. A real signature from openssl, with the expected r||s alongside it. */
    if (argc >= 3) {
        unsigned char der[256];
        size_t derLen = readHex(argv[1], der, sizeof(der));
        unsigned char want[64];
        size_t wantLen = readHex(argv[2], want, sizeof(want));
        bool ok = DerToRawSignature(der, derLen, raw);
        expect("openssl-produced DER is accepted", ok, true);
        if (ok && wantLen == 64) {
            if (memcmp(raw, want, 64) != 0) {
                printf("  [-] converted r||s does not match openssl's own values\n");
                failures++;
            } else {
                printf("  [+] converted r||s matches openssl's own values\n");
            }
        }
    }

    /* 2. Structures that must be refused. A signature that fails to parse must
     *    never fall through as a zeroed - and therefore attacker-chosen -
     *    r||s pair. */
    unsigned char empty[1] = {0};
    expect("empty input rejected", DerToRawSignature(empty, 0, raw), false);

    unsigned char notSeq[] = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    expect("non-SEQUENCE tag rejected", DerToRawSignature(notSeq, sizeof(notSeq), raw), false);

    unsigned char shortSeq[] = {0x30, 0x40, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    expect("declared length past the buffer rejected", DerToRawSignature(shortSeq, sizeof(shortSeq), raw), false);

    unsigned char trailing[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0xAA};
    expect("trailing bytes after the SEQUENCE rejected", DerToRawSignature(trailing, sizeof(trailing), raw), false);

    unsigned char badInner[] = {0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x01};
    expect("non-INTEGER component rejected", DerToRawSignature(badInner, sizeof(badInner), raw), false);

    unsigned char zeroLen[] = {0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01};
    expect("zero-length INTEGER rejected", DerToRawSignature(zeroLen, sizeof(zeroLen), raw), false);

    /* An oversized r cannot be a P-256 scalar and must not be truncated into one. */
    unsigned char oversize[7 + 33 + 3];
    size_t i = 0;
    oversize[i++] = 0x30; oversize[i++] = 0x24;
    oversize[i++] = 0x02; oversize[i++] = 0x21;
    for (int k = 0; k < 33; k++) oversize[i++] = 0xAA;
    oversize[i++] = 0x02; oversize[i++] = 0x01; oversize[i++] = 0x01;
    expect("33-byte INTEGER with no sign padding rejected", DerToRawSignature(oversize, i, raw), false);

    /* 3. Short values must be left-padded, not left-aligned: an r of 0x01 is
     *    31 zero bytes then 0x01, never 0x01 then 31 zeros. */
    unsigned char tiny[] = {0x30, 0x06, 0x02, 0x01, 0x07, 0x02, 0x01, 0x09};
    if (DerToRawSignature(tiny, sizeof(tiny), raw)) {
        if (raw[31] == 0x07 && raw[63] == 0x09 && raw[0] == 0 && raw[32] == 0) {
            printf("  [+] short integers are left-padded to 32 bytes\n");
        } else {
            printf("  [-] short integers were not left-padded correctly\n");
            failures++;
        }
    } else {
        printf("  [-] a valid short-integer signature was rejected\n");
        failures++;
    }

    if (failures) {
        printf("[-] %d DER signature test(s) failed\n", failures);
        return 1;
    }
    printf("[+] All DER signature parsing tests passed\n");
    return 0;
}
