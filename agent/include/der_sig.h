#ifndef OMINULL_DER_SIG_H
#define OMINULL_DER_SIG_H

/*
 * ECDSA DER signature -> fixed-width r||s.
 *
 * Kept separate from the Windows updater because it is plain structure
 * parsing with no platform dependency, which means it can be tested on the
 * build host rather than only on a live endpoint. It sits in the trust path,
 * so it gets a test of its own: see agent/tests/test_der_sig.c.
 */

#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* DerToRawSignature converts an ECDSA signature from the DER encoding openssl
 * produces - SEQUENCE { INTEGER r, INTEGER s } - into the fixed 64-byte r||s
 * pair BCryptVerifySignature expects. DER integers are signed, so r and s carry
 * a leading zero byte whenever their top bit is set and may be shorter than 32
 * bytes when they have leading zeros; both cases are normalised here. This is
 * plain structure parsing, not cryptography: anything malformed is rejected and
 * the real verification is still done by CNG. */
static bool DerToRawSignature(const unsigned char* der, size_t derLen, unsigned char out[64]) {
    size_t i = 0;
    if (derLen < 8 || der[i++] != 0x30) return false;

    size_t seqLen;
    if (der[i] & 0x80) {
        size_t lenBytes = der[i] & 0x7F;
        i++;
        if (lenBytes == 0 || lenBytes > 2 || i + lenBytes > derLen) return false;
        seqLen = 0;
        for (size_t k = 0; k < lenBytes; k++) seqLen = (seqLen << 8) | der[i++];
    } else {
        seqLen = der[i++];
    }
    if (i + seqLen != derLen) return false;

    memset(out, 0, 64);
    for (int half = 0; half < 2; half++) {
        if (i >= derLen || der[i++] != 0x02) return false;
        if (i >= derLen) return false;
        size_t intLen = der[i++];
        if (intLen & 0x80) return false;            /* r and s are never that long */
        if (i + intLen > derLen || intLen == 0) return false;

        const unsigned char* val = der + i;
        i += intLen;
        while (intLen > 0 && *val == 0x00) { val++; intLen--; }   /* strip sign padding */
        if (intLen == 0 || intLen > 32) return false;

        memcpy(out + (half * 32) + (32 - intLen), val, intLen);
    }
    return true;
}


#endif /* OMINULL_DER_SIG_H */
