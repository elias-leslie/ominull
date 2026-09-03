#ifndef OMINULL_RESPONSE_CANONICAL_H
#define OMINULL_RESPONSE_CANONICAL_H

/*
 * Deterministic length-prefixed canonical binary encoder for Ominull Endpoint Grants
 * and Action Proofs.
 *
 * Implements the shared wire format defined in Phase 0.2:
 * 1. Fixed domain-separation label with 4-byte big-endian length prefix.
 * 2. Every variable-length string / byte slice carries a 4-byte big-endian length prefix.
 * 3. Integers are encoded as fixed-width big-endian (4 bytes for uint32, 8 bytes for int64).
 * 4. Hex identifiers (action_digest, nonce, signer_key_id) are lowercased for stability.
 * 5. Ambiguity between adjacent fields and delimiter injection are impossible.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

typedef struct {
    uint8_t* buf;
    size_t cap;
    size_t len;
    bool overflow;
} ResponseCanonicalBuffer;

static inline void CanonicalBuf_Init(ResponseCanonicalBuffer* b, uint8_t* storage, size_t cap) {
    b->buf = storage;
    b->cap = cap;
    b->len = 0;
    b->overflow = false;
}

static inline bool CanonicalBuf_WriteUint32(ResponseCanonicalBuffer* b, uint32_t val) {
    if (b->len + 4 > b->cap) {
        b->overflow = true;
        return false;
    }
    b->buf[b->len + 0] = (uint8_t)((val >> 24) & 0xFF);
    b->buf[b->len + 1] = (uint8_t)((val >> 16) & 0xFF);
    b->buf[b->len + 2] = (uint8_t)((val >> 8) & 0xFF);
    b->buf[b->len + 3] = (uint8_t)(val & 0xFF);
    b->len += 4;
    return true;
}

static inline bool CanonicalBuf_WriteInt64(ResponseCanonicalBuffer* b, int64_t val) {
    if (b->len + 8 > b->cap) {
        b->overflow = true;
        return false;
    }
    uint64_t u = (uint64_t)val;
    for (int i = 7; i >= 0; i--) {
        b->buf[b->len + (7 - i)] = (uint8_t)((u >> (i * 8)) & 0xFF);
    }
    b->len += 8;
    return true;
}

static inline bool CanonicalBuf_WriteBytes(ResponseCanonicalBuffer* b, const uint8_t* data, size_t len) {
    if (!CanonicalBuf_WriteUint32(b, (uint32_t)len)) return false;
    if (b->len + len > b->cap) {
        b->overflow = true;
        return false;
    }
    if (len > 0 && data) {
        memcpy(b->buf + b->len, data, len);
    }
    b->len += len;
    return true;
}

static inline bool CanonicalBuf_WriteString(ResponseCanonicalBuffer* b, const char* str) {
    size_t len = str ? strlen(str) : 0;
    return CanonicalBuf_WriteBytes(b, (const uint8_t*)str, len);
}

static inline bool CanonicalBuf_WriteHexNormalized(ResponseCanonicalBuffer* b, const char* hexStr) {
    size_t len = hexStr ? strlen(hexStr) : 0;
    if (!CanonicalBuf_WriteUint32(b, (uint32_t)len)) return false;
    if (b->len + len > b->cap) {
        b->overflow = true;
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        b->buf[b->len + i] = (uint8_t)tolower((unsigned char)hexStr[i]);
    }
    b->len += len;
    return true;
}

static inline bool CanonicalBuf_WriteStringSlice(ResponseCanonicalBuffer* b, const char* const* items, size_t count) {
    if (!CanonicalBuf_WriteUint32(b, (uint32_t)count)) return false;
    for (size_t i = 0; i < count; i++) {
        if (!CanonicalBuf_WriteString(b, items[i])) return false;
    }
    return true;
}

/*
 * EncodeGrantV2Canonical encodes an EndpointGrant V2 into deterministic canonical bytes.
 * Returns the number of bytes written, or 0 on overflow or failure.
 */
static inline size_t EncodeGrantV2Canonical(
    uint32_t version,
    const char* grant_id,
    const char* tenant_id,
    const char* endpoint_id,
    const char* action_kind,
    const char* action_digest,
    const char* operator_id,
    const char* response_session_id,
    int64_t issued_at,
    int64_t expires_at,
    const char* nonce,
    const char* signer_key_id,
    uint8_t* out,
    size_t out_cap
) {
    ResponseCanonicalBuffer b;
    CanonicalBuf_Init(&b, out, out_cap);
    if (!CanonicalBuf_WriteString(&b, "OMINULL-ENDPOINT-GRANT-V2")) return 0;
    if (!CanonicalBuf_WriteUint32(&b, version)) return 0;
    if (!CanonicalBuf_WriteString(&b, grant_id)) return 0;
    if (!CanonicalBuf_WriteString(&b, tenant_id)) return 0;
    if (!CanonicalBuf_WriteString(&b, endpoint_id)) return 0;
    if (!CanonicalBuf_WriteString(&b, action_kind)) return 0;
    if (!CanonicalBuf_WriteHexNormalized(&b, action_digest)) return 0;
    if (!CanonicalBuf_WriteString(&b, operator_id)) return 0;
    if (!CanonicalBuf_WriteString(&b, response_session_id)) return 0;
    if (!CanonicalBuf_WriteInt64(&b, issued_at)) return 0;
    if (!CanonicalBuf_WriteInt64(&b, expires_at)) return 0;
    if (!CanonicalBuf_WriteHexNormalized(&b, nonce)) return 0;
    if (!CanonicalBuf_WriteHexNormalized(&b, signer_key_id)) return 0;
    if (b.overflow) return 0;
    return b.len;
}

/*
 * EncodeProofV2Canonical encodes an ActionProof V2 into deterministic canonical bytes.
 * Returns the number of bytes written, or 0 on overflow or failure.
 */
static inline size_t EncodeProofV2Canonical(
    uint32_t version,
    const char* session_id,
    const char* tenant_id,
    const char* action_kind,
    const char* action_digest,
    const char* const* target_endpoints,
    size_t target_count,
    int64_t timestamp,
    const char* nonce,
    uint8_t* out,
    size_t out_cap
) {
    ResponseCanonicalBuffer b;
    CanonicalBuf_Init(&b, out, out_cap);
    if (!CanonicalBuf_WriteString(&b, "OMINULL-ACTION-PROOF-V2")) return 0;
    if (!CanonicalBuf_WriteUint32(&b, version)) return 0;
    if (!CanonicalBuf_WriteString(&b, session_id)) return 0;
    if (!CanonicalBuf_WriteString(&b, tenant_id)) return 0;
    if (!CanonicalBuf_WriteString(&b, action_kind)) return 0;
    if (!CanonicalBuf_WriteHexNormalized(&b, action_digest)) return 0;
    if (!CanonicalBuf_WriteStringSlice(&b, target_endpoints, target_count)) return 0;
    if (!CanonicalBuf_WriteInt64(&b, timestamp)) return 0;
    if (!CanonicalBuf_WriteHexNormalized(&b, nonce)) return 0;
    if (b.overflow) return 0;
    return b.len;
}

#endif /* OMINULL_RESPONSE_CANONICAL_H */
