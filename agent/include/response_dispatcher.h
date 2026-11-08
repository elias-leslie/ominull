#ifndef OMINULL_RESPONSE_DISPATCHER_H
#define OMINULL_RESPONSE_DISPATCHER_H

/*
 * Ominull Response Dispatcher: Bounded Offer Parser, In-Process Grant Verifier,
 * Durable Replay Cache, and Contained Worker Execution (Slice 1D.1 & Slice 1D.2).
 *
 * Implements:
 * - Bounded parsing of heartbeat response_offers over a fixed schema (no loose substrings).
 * - Cryptographic verification of EndpointGrant V2 using canonical binary encoding
 *   (response_canonical.h) and tenant Ed25519 public key (ed25519_verify.h).
 * - Independent SHA-256 digest recomputation over action payload.
 * - Clock window checks with +/- 60s tolerance.
 * - Endpoint ID binding check against local endpoint identity.
 * - Durable replay cache with atomic file locking and expiration pruning.
 * - Linux worker containment: fork(), setpgid(), clearenv(), safe cwd, closed descriptors, RLIMIT_CPU.
 * - Windows worker containment: CreateJobObjectW, KILL_ON_JOB_CLOSE, suspended CreateProcessA,
 *   bInheritHandles=FALSE, sanitized envBlock, safe cwd, kill-on-cancel.
 * - Confidentiality: Zero logging of job IDs, tokens, payloads, or terminal bytes.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define OMINULL_DEFAULT_RESPONSE_PUBKEY_PATH "C:\\ProgramData\\Ominull\\response.pub"
#define OMINULL_DEFAULT_REPLAY_CACHE_PATH    "C:\\ProgramData\\Ominull\\replay_cache.state"
#ifndef strcasecmp
#define strcasecmp _stricmp
#endif
#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/resource.h>
#define OMINULL_DEFAULT_RESPONSE_PUBKEY_PATH "/etc/ominull/response.pub"
#define OMINULL_DEFAULT_REPLAY_CACHE_PATH    "/var/lib/ominull/replay_cache.state"
#endif

#include "response_canonical.h"
#include "ed25519_verify.h"
#include "terminal_frame.h"   /* TermJson: bounded JSON reader for the screen offer payload */

#define MAX_RESPONSE_OFFERS 4
#define MAX_PAYLOAD_JSON_LEN 65536

/* ---------------------------------------------------------------------------
 * In-Process SHA-256 Implementation (FIPS 180-4)
 * ------------------------------------------------------------------------- */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
} ResponseSHA256Context;

static inline uint32_t Response_ROTR32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static inline void Response_SHA256_Transform(ResponseSHA256Context* ctx, const uint8_t data[64]) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = Response_ROTR32(w[i - 15], 7) ^ Response_ROTR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = Response_ROTR32(w[i - 2], 17) ^ Response_ROTR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = Response_ROTR32(e, 6) ^ Response_ROTR32(e, 11) ^ Response_ROTR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = Response_ROTR32(a, 2) ^ Response_ROTR32(a, 13) ^ Response_ROTR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static inline void Response_SHA256_Init(ResponseSHA256Context* ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static inline void Response_SHA256_Update(ResponseSHA256Context* ctx, const uint8_t* data, size_t len) {
    size_t buffer_idx = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    if (buffer_idx > 0 && buffer_idx + len >= 64) {
        size_t fill = 64 - buffer_idx;
        memcpy(ctx->buffer + buffer_idx, data, fill);
        Response_SHA256_Transform(ctx, ctx->buffer);
        data += fill;
        len -= fill;
        buffer_idx = 0;
    }

    while (len >= 64) {
        Response_SHA256_Transform(ctx, data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer + buffer_idx, data, len);
    }
}

static inline void Response_SHA256_Final(ResponseSHA256Context* ctx, uint8_t hash[32]) {
    uint64_t total_bits = ctx->count * 8;
    size_t buffer_idx = (size_t)(ctx->count & 0x3F);

    ctx->buffer[buffer_idx++] = 0x80;
    if (buffer_idx > 56) {
        memset(ctx->buffer + buffer_idx, 0, 64 - buffer_idx);
        Response_SHA256_Transform(ctx, ctx->buffer);
        buffer_idx = 0;
    }
    memset(ctx->buffer + buffer_idx, 0, 56 - buffer_idx);

    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)(total_bits >> ((7 - i) * 8));
    }
    Response_SHA256_Transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        hash[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static inline void Response_SHA256_Sum(const uint8_t* data, size_t len, uint8_t hash[32]) {
    ResponseSHA256Context ctx;
    Response_SHA256_Init(&ctx);
    Response_SHA256_Update(&ctx, data, len);
    Response_SHA256_Final(&ctx, hash);
}

static inline void Response_BytesToHex(const uint8_t* bytes, size_t len, char* hexOut) {
    static const char hexChars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hexOut[i * 2]     = hexChars[(bytes[i] >> 4) & 0x0F];
        hexOut[i * 2 + 1] = hexChars[bytes[i] & 0x0F];
    }
    hexOut[len * 2] = '\0';
}

static inline bool Response_HexToBytes(const char* hex, uint8_t* out, size_t outLen) {
    if (!hex || strlen(hex) < outLen * 2) return false;
    for (size_t i = 0; i < outLen; i++) {
        unsigned int val;
        if (sscanf(hex + (i * 2), "%02x", &val) != 1) return false;
        out[i] = (uint8_t)val;
    }
    return true;
}

/* ---------------------------------------------------------------------------
 * Public Key Loader (PEM, Hex, and Raw Binary)
 * ------------------------------------------------------------------------- */

static inline int Response_B64Val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Response_Base64Decode decodes standard base64. Whitespace is skipped (PEM
 * bodies); any other character outside the alphabet, data after padding, more
 * than two pad characters or output past out_cap makes it return 0, so a
 * value is never silently truncated or read two ways. */
static inline size_t Response_Base64Decode(const char* in, size_t in_len, uint8_t* out, size_t out_cap) {
    size_t out_len = 0, chars = 0, pad = 0;
    uint32_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        chars++;
        if (c == '=') {
            if (++pad > 2) return 0;
            continue;
        }
        if (pad) return 0;
        int v = Response_B64Val(c);
        if (v < 0) return 0;
        buf = ((buf << 6) | (uint32_t)v) & 0xFFFFFFu;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out_len >= out_cap) return 0;
            out[out_len++] = (uint8_t)((buf >> bits) & 0xFFu);
        }
    }
    if (pad && chars % 4 != 0) return 0;
    return out_len;
}

static inline bool Response_LoadPublicKey(const char* key_path, uint8_t pub_bytes[32]) {
    if (!key_path || !pub_bytes) return false;
    FILE* f = fopen(key_path, "rb");
    if (!f) return false;
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return false;
    buf[n] = '\0';

    // 1. Check if PEM format
    char* begin = strstr(buf, "-----BEGIN");
    if (begin) {
        char* end_header = strstr(begin, "\n");
        if (!end_header) return false;
        char* footer = strstr(end_header, "-----END");
        if (!footer) return false;
        uint8_t der[256];
        size_t der_len = Response_Base64Decode(end_header, (size_t)(footer - end_header), der, sizeof(der));
        if (der_len == 44) {
            memcpy(pub_bytes, der + 12, 32);
            return true;
        }
        if (der_len == 32) {
            memcpy(pub_bytes, der, 32);
            return true;
        }
        return false;
    }

    // 2. Check if 64-character hex string
    if (n >= 64) {
        bool is_hex = true;
        for (int i = 0; i < 64; i++) {
            char c = buf[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                is_hex = false; break;
            }
        }
        if (is_hex) {
            return Response_HexToBytes(buf, pub_bytes, 32);
        }
    }

    // 3. Raw 32 bytes
    if (n >= 32) {
        memcpy(pub_bytes, buf, 32);
        return true;
    }
    return false;
}

/* ---------------------------------------------------------------------------
 * Bounded Fixed-Schema JSON Parser for Response Offers
 * ------------------------------------------------------------------------- */

typedef struct {
    uint32_t version;
    char     grant_id[64];
    char     tenant_id[64];
    char     endpoint_id[64];
    char     action_kind[64];
    char     action_digest[65];
    char     operator_id[64];
    char     response_session_id[64];
    int64_t  issued_at;
    int64_t  expires_at;
    char     nonce[65];
    char     job_id[64];        /* V3: the hub job this grant is for */
    char     signer_key_id[65];
    char     signature[130];
} ResponseGrant;

typedef struct {
    char          job_id[64];
    char          lease_id[64];
    char          kind[64];
    ResponseGrant grant;
    char          payload_json[MAX_PAYLOAD_JSON_LEN];
    size_t        payload_len;
} ResponseJobOffer;

static inline void SkipWhitespace(const char** p) {
    while (**p && (**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r')) {
        (*p)++;
    }
}

/* ParseBoundedString reads one JSON string at *p (after whitespace), fully
 * decoded (escapes, \u, surrogate pairs) into out, and moves *p past it. False
 * on a raw control byte, a bad escape, \u0000, or a value that does not fit:
 * never a truncated or half-decoded copy. */
static inline bool ParseBoundedString(const char** p, char* out, size_t outCap) {
    SkipWhitespace(p);
    if (**p != '"') return false;
    const char* start = *p + 1;
    const char* q = start;
    while (*q && *q != '"') {
        if ((unsigned char)*q < 0x20) return false;
        if (*q == '\\') {
            if (!q[1]) return false;
            q++;
        }
        q++;
    }
    if (*q != '"') return false;
    if (!TermJson_DecodeString(start, (size_t)(q - start), out, outCap, NULL)) return false;
    *p = q + 1;
    return true;
}

/* How deep the heartbeat reply may nest (baseline rules, trust control,
 * capability manifest); a bound on the reader's recursion, not a format rule. */
#define RESPONSE_REPLY_MAX_DEPTH 32

/* Response_JsonSpan: the extent of the JSON value at s (a NUL-terminated
 * reply), read with the strict reader, so braces and quotes inside strings
 * never move the end. */
static inline bool Response_JsonSpan(const char* s, size_t* len) {
    TermJson j = {.s = s, .n = strlen(s), .i = 0, .first = true, .max_depth = RESPONSE_REPLY_MAX_DEPTH};
    if (!TermJson_SkipValue(&j, 0)) return false;
    *len = j.i;
    return true;
}

/* Response_DecodeMember decodes a string member value; vt must be 's'. */
static inline bool Response_DecodeMember(char vt, const char* v, size_t vl, char* out, size_t cap) {
    return vt == 's' && TermJson_DecodeString(v, vl, out, cap, NULL) && out[0] != '\0';
}

static inline bool ParseInt64Field(const char** p, int64_t* out) {
    SkipWhitespace(p);
    bool negative = false;
    if (**p == '-') {
        negative = true;
        (*p)++;
    }
    if (!isdigit((unsigned char)**p)) return false;
    uint64_t val = 0;
    while (isdigit((unsigned char)**p)) {
        unsigned d = (unsigned)(**p - '0');
        if (val > (UINT64_C(9223372036854775807) - d) / 10) return false;   /* beyond INT64_MAX */
        val = val * 10 + d;
        (*p)++;
    }
    *out = negative ? -(int64_t)val : (int64_t)val;
    return true;
}

static inline bool ParseUint32Field(const char** p, uint32_t* out) {
    int64_t v = 0;
    if (!ParseInt64Field(p, &v) || v < 0 || v > 0xFFFFFFFFLL) return false;
    *out = (uint32_t)v;
    return true;
}

/* Response_Int64 reads a JSON integer span (digits, optional minus). */
static inline bool Response_Int64(char vt, const char* v, size_t vl, int64_t* out) {
    if (vt != 'n' || vl == 0 || vl >= 24) return false;
    char buf[24];
    memcpy(buf, v, vl);
    buf[vl] = '\0';
    const char* q = buf;
    return ParseInt64Field(&q, out) && *q == '\0';
}

/* ExtractGrantObject reads the grant object at *p and moves *p past it. Top
 * level members only, each known member at most once, strings fully decoded;
 * unknown members (any JSON value) are skipped by the strict reader. */
static inline bool ExtractGrantObject(const char** p, ResponseGrant* grant) {
    SkipWhitespace(p);
    memset(grant, 0, sizeof(*grant));
    size_t span = 0;
    if (**p != '{' || !Response_JsonSpan(*p, &span)) return false;
    TermJson j;
    if (!TermJson_Begin(&j, *p, span)) return false;
    enum { G_VERSION, G_GRANT_ID, G_TENANT, G_ENDPOINT, G_KIND, G_DIGEST, G_OPERATOR, G_SESSION, G_ISSUED, G_EXPIRES,
           G_NONCE, G_JOB, G_SIGNER, G_SIGNATURE, G_N };
    static const char* const names[G_N] = {"version", "grant_id", "tenant_id", "endpoint_id", "action_kind",
                                           "action_digest", "operator_id", "response_session_id", "issued_at",
                                           "expires_at", "nonce", "job_id", "signer_key_id", "signature"};
    bool seen[G_N] = {false};
    for (;;) {
        const char *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        char vt = 0;
        int r = TermJson_Next(&j, &k, &kl, &vt, &v, &vl);
        if (r == 0) break;
        if (r < 0) return false;
        int m = -1;
        for (int i = 0; i < G_N; i++)
            if (TermJson_KeyIs(k, kl, names[i])) m = i;
        if (m < 0) continue;   /* forward compatible */
        if (seen[m]) return false;
        seen[m] = true;
        int64_t x = 0;
        bool ok = true;
        switch (m) {
        case G_VERSION:
            ok = Response_Int64(vt, v, vl, &x) && x >= 0 && x <= 0xFFFFFFFFLL;
            grant->version = (uint32_t)x;
            break;
        case G_GRANT_ID:  ok = Response_DecodeMember(vt, v, vl, grant->grant_id, sizeof(grant->grant_id)); break;
        case G_TENANT:    ok = vt == 's' && TermJson_DecodeString(v, vl, grant->tenant_id, sizeof(grant->tenant_id), NULL); break;
        case G_ENDPOINT:  ok = Response_DecodeMember(vt, v, vl, grant->endpoint_id, sizeof(grant->endpoint_id)); break;
        case G_KIND:      ok = Response_DecodeMember(vt, v, vl, grant->action_kind, sizeof(grant->action_kind)); break;
        case G_DIGEST:    ok = Response_DecodeMember(vt, v, vl, grant->action_digest, sizeof(grant->action_digest)); break;
        case G_OPERATOR:  ok = vt == 's' && TermJson_DecodeString(v, vl, grant->operator_id, sizeof(grant->operator_id), NULL); break;
        case G_SESSION:   ok = vt == 's' && TermJson_DecodeString(v, vl, grant->response_session_id, sizeof(grant->response_session_id), NULL); break;
        case G_ISSUED:    ok = Response_Int64(vt, v, vl, &grant->issued_at); break;
        case G_EXPIRES:   ok = Response_Int64(vt, v, vl, &grant->expires_at); break;
        case G_NONCE:     ok = vt == 's' && TermJson_DecodeString(v, vl, grant->nonce, sizeof(grant->nonce), NULL); break;
        case G_JOB:       ok = vt == 's' && TermJson_DecodeString(v, vl, grant->job_id, sizeof(grant->job_id), NULL); break;
        case G_SIGNER:    ok = vt == 's' && TermJson_DecodeString(v, vl, grant->signer_key_id, sizeof(grant->signer_key_id), NULL); break;
        case G_SIGNATURE: ok = Response_DecodeMember(vt, v, vl, grant->signature, sizeof(grant->signature)); break;
        }
        if (!ok) return false;
    }
    *p += span;

    /* V2, or V3 which binds the hub job id (an empty one is no V3 grant). */
    if ((grant->version != 2 && grant->version != 3) || (grant->version == 3 && grant->job_id[0] == '\0') ||
        grant->grant_id[0] == '\0' ||
        grant->endpoint_id[0] == '\0' || grant->action_kind[0] == '\0' ||
        grant->action_digest[0] == '\0' || grant->signature[0] == '\0') {
        return false;
    }
    return true;
}

/* Response_ForensicsPayload reads a forensic_collection payload
 * {"profile","max_bytes","timeout_seconds"[,"bundle_id"][,"options"]} with the
 * strict reader: top-level members once each, strings decoded, numbers plain
 * integers. bundle_id goes into evidence URLs and the manifest, so it is
 * [A-Za-z0-9._-] only. Values out of range keep the caller's defaults. */
static inline bool Response_ForensicsPayload(const char* json, char* bundle_id, size_t bundle_cap, char* profile,
                                             size_t profile_cap, int64_t* max_bytes, int* timeout_seconds) {
    if (!json) return false;
    TermJson j;
    if (!TermJson_Begin(&j, json, strlen(json))) return false;
    bool seen_bundle = false, seen_profile = false, seen_max = false, seen_timeout = false;
    for (;;) {
        const char *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        char vt = 0;
        int r = TermJson_Next(&j, &k, &kl, &vt, &v, &vl);
        if (r == 0) break;
        if (r < 0) return false;
        int64_t x = 0;
        if (TermJson_KeyIs(k, kl, "bundle_id")) {
            if (seen_bundle || !Response_DecodeMember(vt, v, vl, bundle_id, bundle_cap)) return false;
            seen_bundle = true;
            for (const char* c = bundle_id; *c; c++)
                if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') || *c == '.' || *c == '_' || *c == '-'))
                    return false;
        } else if (TermJson_KeyIs(k, kl, "profile")) {
            if (seen_profile || !Response_DecodeMember(vt, v, vl, profile, profile_cap)) return false;
            seen_profile = true;
        } else if (TermJson_KeyIs(k, kl, "max_bytes")) {
            if (seen_max || !Response_Int64(vt, v, vl, &x)) return false;
            seen_max = true;
            if (x > 0) *max_bytes = x;
        } else if (TermJson_KeyIs(k, kl, "timeout_seconds")) {
            if (seen_timeout || !Response_Int64(vt, v, vl, &x)) return false;
            seen_timeout = true;
            if (x > 0 && x <= 86400) *timeout_seconds = (int)x;
        }
    }
    return true;
}

/* Response_ReadOffer reads one offer object (len bytes at s) into offer.
 * False when a member is malformed or repeated, or a required one is missing. */
static inline bool Response_ReadOffer(const char* s, size_t len, ResponseJobOffer* offer) {
    memset(offer, 0, sizeof(*offer));
    TermJson j;
    if (!TermJson_Begin(&j, s, len)) return false;
    bool has_job_id = false, has_lease_id = false, has_kind = false, has_grant = false, has_payload = false;
    for (;;) {
        const char *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        char vt = 0;
        int r = TermJson_Next(&j, &k, &kl, &vt, &v, &vl);
        if (r == 0) break;
        if (r < 0) return false;
        if (TermJson_KeyIs(k, kl, "job_id")) {
            if (has_job_id || !Response_DecodeMember(vt, v, vl, offer->job_id, sizeof(offer->job_id))) return false;
            has_job_id = true;
        } else if (TermJson_KeyIs(k, kl, "lease_id")) {
            if (has_lease_id || !Response_DecodeMember(vt, v, vl, offer->lease_id, sizeof(offer->lease_id))) return false;
            has_lease_id = true;
        } else if (TermJson_KeyIs(k, kl, "kind")) {
            if (has_kind || !Response_DecodeMember(vt, v, vl, offer->kind, sizeof(offer->kind))) return false;
            has_kind = true;
        } else if (TermJson_KeyIs(k, kl, "grant")) {
            const char* g = v;
            if (has_grant || vt != 'x' || !ExtractGrantObject(&g, &offer->grant) || g != v + vl) return false;
            has_grant = true;
        } else if (TermJson_KeyIs(k, kl, "payload_json")) {
            if (has_payload) return false;
            has_payload = true;
            if (vt == 's') {   /* the hub's form: the payload as a JSON string */
                if (!TermJson_DecodeString(v, vl, offer->payload_json, sizeof(offer->payload_json), &offer->payload_len))
                    return false;
            } else if (vt == 'x' && v[0] == '{') {   /* an object, kept as written */
                if (vl >= sizeof(offer->payload_json)) return false;
                memcpy(offer->payload_json, v, vl);
                offer->payload_json[vl] = '\0';
                offer->payload_len = vl;
            } else {
                return false;
            }
        }
    }
    return has_job_id && has_lease_id && has_kind && has_grant;
}

/* ParseResponseOffers reads the heartbeat reply's top-level response_offers
 * array (never a "response_offers" that sits inside another value). A malformed
 * offer is dropped and the rest still read; a malformed reply yields none. */
static inline int ParseResponseOffers(const char* json, ResponseJobOffer* outOffers, size_t maxOffers) {
    if (!json || !outOffers || maxOffers == 0) return 0;
    TermJson top;
    if (!TermJson_Begin(&top, json, strlen(json))) return 0;
    top.max_depth = RESPONSE_REPLY_MAX_DEPTH;
    const char* arr = NULL;
    size_t arr_len = 0;
    for (;;) {
        const char *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        char vt = 0;
        int r = TermJson_Next(&top, &k, &kl, &vt, &v, &vl);
        if (r == 0) break;
        if (r < 0) return 0;
        if (!TermJson_KeyIs(k, kl, "response_offers")) continue;
        if (arr || vt != 'x' || v[0] != '[') return 0;
        arr = v;
        arr_len = vl;
    }
    if (!arr) return 0;

    TermJson a = {.s = arr, .n = arr_len, .i = 1, .first = true, .max_depth = RESPONSE_REPLY_MAX_DEPTH};
    int count = 0;
    TermJson_SkipWs(&a);
    if (a.i < a.n && a.s[a.i] == ']') return 0;
    while (a.i < a.n && (size_t)count < maxOffers) {
        TermJson_SkipWs(&a);
        size_t start = a.i;
        if (!TermJson_SkipValue(&a, 1)) break;
        ResponseJobOffer* offer = &outOffers[count];
        if (arr[start] == '{' && Response_ReadOffer(arr + start, a.i - start, offer)) count++;
        TermJson_SkipWs(&a);
        if (a.i >= a.n || a.s[a.i] != ',') break;
        a.i++;
    }
    return count;
}

/* ---------------------------------------------------------------------------
 * Grant Verification & Digest Verification
 * ------------------------------------------------------------------------- */

/* ScreenCanonicalFromOffer rebuilds the exact bytes the hub digested for a
 * screen_session grant (REMOTE_SCREEN.md §3/§6): {"mode":"control|view"} with
 * ,"unattended":true and/or ,"ask_first":true appended in that fixed order, no
 * spaces, false members omitted. The offer payload
 * ({"session_id","mode","connect_token","operator"[,"unattended":true][,"ask_first":true]})
 * is read with the bounded TermJson reader, never strstr. mode must be exactly
 * control or view; unattended and ask_first must be the JSON literal true or be
 * absent (a literal false, which the hub never sends, is refused). operator,
 * session_id and connect_token are not digested and are ignored here. */
static inline bool ScreenCanonicalFromOffer(const char* payload_json, char* out, size_t out_cap) {
    if (!payload_json || !out) return false;
    char mode[16] = {0};
    bool have_mode = false, unattended = false, ask_first = false;
    TermJson j;
    if (!TermJson_Begin(&j, payload_json, strlen(payload_json))) return false;
    for (;;) {
        const char *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        char vt = 0;
        int r = TermJson_Next(&j, &k, &kl, &vt, &v, &vl);
        if (r == 0) break;
        if (r < 0) return false;
        /* A repeated member is refused, so the digest and the worker read one value. */
        if (TermJson_KeyIs(k, kl, "mode")) {
            if (have_mode || vt != 's' || !TermJson_CopyString(v, vl, mode, sizeof(mode))) return false;
            have_mode = true;
        } else if (TermJson_KeyIs(k, kl, "unattended")) {
            if (unattended || vt != 'n' || vl != 4 || memcmp(v, "true", 4) != 0) return false; /* true or absent only */
            unattended = true;
        } else if (TermJson_KeyIs(k, kl, "ask_first")) {
            if (ask_first || vt != 'n' || vl != 4 || memcmp(v, "true", 4) != 0) return false;
            ask_first = true;
        }
    }
    if (!have_mode || (strcmp(mode, "control") != 0 && strcmp(mode, "view") != 0)) return false;
    int n = snprintf(out, out_cap, "{\"mode\":\"%s\"%s%s}", mode,
                     unattended ? ",\"unattended\":true" : "",
                     ask_first ? ",\"ask_first\":true" : "");
    return n > 0 && (size_t)n < out_cap;
}

/* TerminalCanonicalFromOffer rebuilds the bytes the hub digested for a
 * terminal_session grant: {"program":"<value>"} with the program member's raw
 * JSON string content copied unchanged (the hub's json.Marshal escaping is
 * what it signed). The offer must parse whole with TermPayload_Parse, the
 * worker's reader, which refuses a repeated session_id, program or
 * connect_token; program must be a top-level string. A nested or repeated
 * "program" can therefore never sign one program while another starts. */
#define TERMINAL_CANON_MAX 192
static inline bool TerminalCanonicalFromOffer(const char* payload_json, char* out, size_t out_cap) {
    if (!payload_json || !out || out_cap == 0) return false;
    out[0] = '\0';
    char sid[64], prog[64], tok[128];
    if (!TermPayload_Parse(payload_json, sid, sizeof(sid), prog, sizeof(prog), tok, sizeof(tok))) return false;
    TermJson j;
    if (!TermJson_Begin(&j, payload_json, strlen(payload_json))) return false;
    const char* raw = NULL;
    size_t raw_len = 0;
    for (;;) {
        const char *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        char vt = 0;
        int r = TermJson_Next(&j, &k, &kl, &vt, &v, &vl);
        if (r == 0) break;
        if (r < 0) return false;
        if (TermJson_KeyIs(k, kl, "program")) {
            if (vt != 's' || raw) return false;
            raw = v;
            raw_len = vl;
        }
    }
    if (!raw) return false;
    int n = snprintf(out, out_cap, "{\"program\":\"%.*s\"}", (int)raw_len, raw);
    return n > 0 && (size_t)n < out_cap;
}

/* VerifyResponseGrantKey checks a response job grant against a public key
 * held in memory (the agent's pinned response key). */
static inline bool VerifyResponseGrantKey(
    const ResponseGrant* grant,
    const char* payload_json,
    const char* expected_endpoint_id,
    const uint8_t pub_bytes[32]
) {
    if (!grant || !expected_endpoint_id || !pub_bytes) return false;

    // 1. Version 2, or 3 (V2 plus the hub job id; the caller compares it with the offer's)
    if (grant->version != 2 && grant->version != 3) return false;
    if (grant->version == 3 && !grant->job_id[0]) return false;

    // 2. Strict endpoint binding
    if (strcmp(grant->endpoint_id, expected_endpoint_id) != 0) return false;

    // 3. Expiration window check with +/- 60s tolerance
    int64_t now = (int64_t)time(NULL);
    if (now < grant->issued_at - 60) return false; // Clock skew in future
    if (now > grant->expires_at + 60) return false; // Expired

    // 4. Server/Client SHA-256 Digest Recomputation over payload
    uint8_t computed_hash[32];
    size_t payload_len = payload_json ? strlen(payload_json) : 0;
    Response_SHA256_Sum((const uint8_t*)(payload_json ? payload_json : ""), payload_len, computed_hash);
    char computed_hex[65];
    Response_BytesToHex(computed_hash, 32, computed_hex);

    if (grant->action_kind[0] && strcmp(grant->action_kind, "terminal_session") == 0) {
        /* The terminal grant digests {"program":...} alone. Rebuilt with the
         * worker's own reader (one top-level program member, a string), so the
         * program the signature names is the program the worker starts. */
        char canon[TERMINAL_CANON_MAX];
        if (!payload_json || !TerminalCanonicalFromOffer(payload_json, canon, sizeof(canon))) return false;
        Response_SHA256_Sum((const uint8_t*)canon, strlen(canon), computed_hash);
        Response_BytesToHex(computed_hash, 32, computed_hex);
    } else if (grant->action_kind[0] && strcmp(grant->action_kind, "screen_session") == 0) {
        /* The screen grant binds the canonical {"mode"[,"unattended"][,"ask_first"]}
         * subset, not the whole offer (REMOTE_SCREEN.md §6). Rebuild it from the
         * offer and recompute; mode/unattended/ask_first thus reach the worker only
         * through this verified digest. */
        char canon[64];
        if (!payload_json || !ScreenCanonicalFromOffer(payload_json, canon, sizeof(canon))) return false;
        Response_SHA256_Sum((const uint8_t*)canon, strlen(canon), computed_hash);
        Response_BytesToHex(computed_hash, 32, computed_hex);
    }
    if (strcasecmp(grant->action_digest, computed_hex) != 0) {
        return false; // Action digest tampered or mismatched
    }

    // 5. Binary canonical encoding (OMINULL-ENDPOINT-GRANT-V2 or -V3)
    uint8_t canonical_bytes[1024];
    size_t canonical_len = EncodeGrantCanonical(
        grant->version,
        grant->grant_id,
        grant->tenant_id,
        grant->endpoint_id,
        grant->action_kind,
        grant->action_digest,
        grant->operator_id,
        grant->response_session_id,
        grant->issued_at,
        grant->expires_at,
        grant->nonce,
        grant->job_id,
        grant->signer_key_id,
        canonical_bytes,
        sizeof(canonical_bytes)
    );
    if (canonical_len == 0) return false;

    // 6. Decode Ed25519 signature (128 hex chars -> 64 raw bytes)
    uint8_t sig_bytes[64];
    if (!Response_HexToBytes(grant->signature, sig_bytes, 64)) return false;

    // 7. Verify in-process against the trusted tenant public key
    return Ed25519_Verify(sig_bytes, canonical_bytes, canonical_len, pub_bytes);
}

static inline bool VerifyResponseGrant(
    const ResponseGrant* grant,
    const char* payload_json,
    const char* expected_endpoint_id,
    const char* pubkey_path
) {
    const char* key_path = pubkey_path ? pubkey_path : OMINULL_DEFAULT_RESPONSE_PUBKEY_PATH;
    uint8_t pub_bytes[32];
    if (!Response_LoadPublicKey(key_path, pub_bytes)) return false;   // Public key missing or unreadable
    return VerifyResponseGrantKey(grant, payload_json, expected_endpoint_id, pub_bytes);
}

/* ---------------------------------------------------------------------------
 * Durable Replay Cache
 *
 * One line per accepted grant: "grant_id nonce expires_at". A grant is
 * accepted at most once: its grant id and its nonce are each refused while
 * the entry is kept. Entries are kept until expires_at plus the verifier's
 * clock grace (REPLAY_CACHE_GRACE_SECONDS), so a grant that still verifies
 * can never find its entry gone. The cache fails closed: when it holds
 * REPLAY_CACHE_MAX live entries, cannot allocate, or cannot be written, the
 * new grant is refused rather than an old entry dropped.
 * ------------------------------------------------------------------------- */

#define REPLAY_CACHE_MAX 4096
#define REPLAY_CACHE_GRACE_SECONDS 60

/* ReplayCache_Keep: whether an entry expiring at exp still guards at now. */
static inline bool ReplayCache_Keep(int64_t exp, int64_t now) {
    return exp > now - REPLAY_CACHE_GRACE_SECONDS;
}

#ifdef _WIN32
static inline bool ReplayCache_CheckAndRecord(
    const char* cache_path,
    const char* grant_id,
    const char* nonce,
    int64_t expires_at
) {
    if (!grant_id || grant_id[0] == '\0') return false;
    const char* path = cache_path ? cache_path : OMINULL_DEFAULT_REPLAY_CACHE_PATH;

    HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof(ov));
    if (!LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &ov)) {
        CloseHandle(hFile);
        return false;
    }

    bool accepted = false;
    DWORD fileSize = GetFileSize(hFile, NULL);
    char* buf = fileSize == INVALID_FILE_SIZE ? NULL : (char*)malloc((size_t)fileSize + 1);
    char** retained = (char**)malloc(REPLAY_CACHE_MAX * sizeof(char*));
    size_t retained_count = 0;
    DWORD bytesRead = 0;
    if (!buf || !retained || !ReadFile(hFile, buf, fileSize, &bytesRead, NULL)) goto done;
    buf[bytesRead] = '\0';

    int64_t now = (int64_t)time(NULL);
    bool ok = true;
    char* line = strtok(buf, "\r\n");
    while (line && ok) {
        char g_id[64] = {0}, n_id[65] = {0};
        long long exp = 0;
        if (sscanf(line, "%63s %64s %lld", g_id, n_id, &exp) >= 1) {
            if (!ReplayCache_Keep((int64_t)exp, now)) {
                /* past expiry plus grace: its grant no longer verifies; dropped */
            } else if (strcmp(g_id, grant_id) == 0 || (nonce && nonce[0] && strcmp(n_id, nonce) == 0)) {
                ok = false; /* replay */
            } else {
                if (retained_count >= REPLAY_CACHE_MAX - 1) ok = false;   /* full: refuse, never drop */
                else if (!(retained[retained_count] = _strdup(line))) ok = false;
                else retained_count++;
            }
        }
        line = strtok(NULL, "\r\n");
    }
    if (!ok) goto done;

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    if (!SetEndOfFile(hFile)) goto done;
    DWORD written = 0;
    ok = true;
    for (size_t i = 0; i < retained_count && ok; i++) {
        ok = WriteFile(hFile, retained[i], (DWORD)strlen(retained[i]), &written, NULL) &&
             WriteFile(hFile, "\r\n", 2, &written, NULL);
    }
    char new_entry[256];
    int nlen = snprintf(new_entry, sizeof(new_entry), "%s %s %lld\r\n", grant_id, nonce && nonce[0] ? nonce : "-", (long long)expires_at);
    ok = ok && nlen > 0 && (size_t)nlen < sizeof(new_entry) && WriteFile(hFile, new_entry, (DWORD)nlen, &written, NULL) &&
         written == (DWORD)nlen && FlushFileBuffers(hFile);
    accepted = ok;

done:
    if (retained) {
        for (size_t i = 0; i < retained_count; i++) free(retained[i]);
        free(retained);
    }
    free(buf);
    UnlockFileEx(hFile, 0, MAXDWORD, MAXDWORD, &ov);
    CloseHandle(hFile);
    return accepted;
}
#else
static inline bool ReplayCache_CheckAndRecord(
    const char* cache_path,
    const char* grant_id,
    const char* nonce,
    int64_t expires_at
) {
    if (!grant_id || grant_id[0] == '\0') return false;
    const char* path = cache_path ? cache_path : OMINULL_DEFAULT_REPLAY_CACHE_PATH;

    int fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) return false;

    if (flock(fd, LOCK_EX) < 0) {
        close(fd);
        return false;
    }

    FILE* fp = fdopen(fd, "r+");
    if (!fp) {
        flock(fd, LOCK_UN);
        close(fd);
        return false;
    }

    int64_t now = (int64_t)time(NULL);
    char line[256];
    bool ok = true, accepted = false;
    char** retained = (char**)malloc(REPLAY_CACHE_MAX * sizeof(char*));
    size_t retained_count = 0;
    if (!retained) ok = false;

    while (ok && fgets(line, sizeof(line), fp)) {
        char g_id[64] = {0}, n_id[65] = {0};
        long long exp = 0;
        if (sscanf(line, "%63s %64s %lld", g_id, n_id, &exp) >= 1) {
            if (!ReplayCache_Keep((int64_t)exp, now)) {
                /* past expiry plus grace: its grant no longer verifies; dropped */
            } else if (strcmp(g_id, grant_id) == 0 || (nonce && nonce[0] && strcmp(n_id, nonce) == 0)) {
                ok = false; /* replay */
            } else {
                if (retained_count >= REPLAY_CACHE_MAX - 1) ok = false;   /* full: refuse, never drop */
                else if (!(retained[retained_count] = strdup(line))) ok = false;
                else retained_count++;
            }
        }
    }
    if (ok && ferror(fp)) ok = false;

    if (ok) {
        fseek(fp, 0, SEEK_SET);
        if (ftruncate(fd, 0) == 0) {
            for (size_t i = 0; i < retained_count && ok; i++) {
                size_t l = strlen(retained[i]);
                if (fputs(retained[i], fp) < 0) ok = false;
                else if (l && retained[i][l - 1] != '\n' && fputc('\n', fp) == EOF) ok = false;
            }
            if (ok && fprintf(fp, "%s %s %lld\n", grant_id, nonce && nonce[0] ? nonce : "-", (long long)expires_at) < 0) ok = false;
            if (ok && fflush(fp) != 0) ok = false;
            if (ok && fsync(fd) != 0) ok = false;
            accepted = ok;
        }
    }

    if (retained) {
        for (size_t i = 0; i < retained_count; i++) free(retained[i]);
        free(retained);
    }

    flock(fd, LOCK_UN);
    fclose(fp);
    return accepted;
}
#endif

/* ---------------------------------------------------------------------------
 * Windows Worker Containment (Job Objects & Suspended Process Execution)
 * ------------------------------------------------------------------------- */

#ifdef _WIN32
static inline int ExecuteContainedWorkerWindows(const char* cmdLine, DWORD timeoutMs) {
    if (!cmdLine || cmdLine[0] == '\0') return -1;

    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) return -1;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
    ZeroMemory(&jeli, sizeof(jeli));
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
        CloseHandle(hJob);
        return -1;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    const char envBlock[] = "PATH=C:\\Windows\\System32;C:\\Windows\0SYSTEMROOT=C:\\Windows\0\0";

    char cmdBuf[2048];
    strncpy(cmdBuf, cmdLine, sizeof(cmdBuf) - 1);
    cmdBuf[sizeof(cmdBuf) - 1] = '\0';

    CreateDirectoryA("C:\\ProgramData", NULL);
    CreateDirectoryA("C:\\ProgramData\\Ominull", NULL);

    const char* workDir = "C:\\ProgramData\\Ominull";
    DWORD attr = GetFileAttributesA(workDir);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        workDir = NULL;
    }

    BOOL created = CreateProcessA(
        NULL,
        cmdBuf,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB,
        (LPVOID)envBlock,
        workDir,
        &si,
        &pi
    );

    if (!created) {
        CloseHandle(hJob);
        return -1;
    }

    if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hJob);
        return -1;
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    DWORD waitRes = WaitForSingleObject(pi.hProcess, timeoutMs);
    int exitCode = -1;
    if (waitRes == WAIT_OBJECT_0) {
        DWORD dwCode = 0;
        if (GetExitCodeProcess(pi.hProcess, &dwCode)) {
            exitCode = (int)dwCode;
        }
    } else {
        TerminateJobObject(hJob, 1);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(hJob);
    return exitCode;
}
#endif

#endif /* OMINULL_RESPONSE_DISPATCHER_H */
