/*
 * Release signature check for the Windows agent through CNG: a DER ECDSA
 * P-256 signature over a SHA-256 digest, against a raw public point (X then
 * Y, 32 bytes each). The compiled-in release key verifies trust bundles,
 * routine-keys statements and agent updates; a pinned routine key verifies
 * agent updates only (Trust_UpdateSigner).
 */
#ifndef OMINULL_RELEASE_VERIFY_WIN_H
#define OMINULL_RELEASE_VERIFY_WIN_H

#include <windows.h>
#include <bcrypt.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "der_sig.h"

static inline bool ReleaseVerifyWinHash(const uint8_t xy[64], const uint8_t hash[32], const uint8_t* der, size_t derlen) {
    unsigned char raw[64];
    if (!xy || !hash || !der || !DerToRawSignature(der, derlen, raw)) return false;
    unsigned char blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    BCRYPT_ECCKEY_BLOB* hdr = (BCRYPT_ECCKEY_BLOB*)blob;
    hdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    hdr->cbKey = 32;
    memcpy(blob + sizeof(BCRYPT_ECCKEY_BLOB), xy, 64);
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) != 0) return false;
    if (BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey, blob, sizeof(blob), 0) == 0)
        ok = BCryptVerifySignature(hKey, NULL, (PUCHAR)hash, 32, raw, 64, 0) == 0;
    if (hKey) BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static inline bool ReleaseVerifyWinSha256(const void* data, size_t len, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return false;
    bool ok = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0 && BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0) == 0 &&
              BCryptFinishHash(hHash, out, 32, 0) == 0;
    if (hHash) BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static inline bool ReleaseVerifyWinMsg(const uint8_t xy[64], const char* msg, size_t len, const uint8_t* der, size_t derlen) {
    uint8_t hash[32];
    return msg && ReleaseVerifyWinSha256(msg, len, hash) && ReleaseVerifyWinHash(xy, hash, der, derlen);
}

#endif
