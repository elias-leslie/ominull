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

static inline size_t Response_Base64Decode(const char* in, size_t in_len, uint8_t* out, size_t out_cap) {
    size_t out_len = 0;
    int buf = 0, bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '=') break;
        int v = Response_B64Val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out_len < out_cap) {
                out[out_len++] = (uint8_t)((buf >> bits) & 0xFF);
            }
        }
    }
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

static inline bool ParseBoundedString(const char** p, char* out, size_t outCap) {
    SkipWhitespace(p);
    if (**p != '"') return false;
    (*p)++;
    size_t i = 0;
    while (**p && **p != '"') {
        if (**p == '\\' && *(*p + 1)) {
            (*p)++;
        }
        if (i + 1 < outCap) {
            out[i++] = **p;
        } else {
            return false;
        }
        (*p)++;
    }
    if (**p != '"') return false;
    (*p)++;
    out[i] = '\0';
    return true;
}

static inline bool ParseInt64Field(const char** p, int64_t* out) {
    SkipWhitespace(p);
    bool negative = false;
    if (**p == '-') {
        negative = true;
        (*p)++;
    }
    if (!isdigit((unsigned char)**p)) return false;
    int64_t val = 0;
    while (isdigit((unsigned char)**p)) {
        val = (val * 10) + (**p - '0');
        (*p)++;
    }
    *out = negative ? -val : val;
    return true;
}

static inline bool ParseUint32Field(const char** p, uint32_t* out) {
    int64_t v = 0;
    if (!ParseInt64Field(p, &v) || v < 0 || v > 0xFFFFFFFFLL) return false;
    *out = (uint32_t)v;
    return true;
}

static inline bool ExtractGrantObject(const char** p, ResponseGrant* grant) {
    SkipWhitespace(p);
    if (**p != '{') return false;
    (*p)++;
    memset(grant, 0, sizeof(*grant));

    int brace_depth = 1;
    while (**p && brace_depth > 0) {
        SkipWhitespace(p);
        if (**p == '}') {
            brace_depth--;
            (*p)++;
            break;
        }
        if (**p == ',') {
            (*p)++;
            continue;
        }
        char key[64] = {0};
        if (!ParseBoundedString(p, key, sizeof(key))) return false;
        SkipWhitespace(p);
        if (**p != ':') return false;
        (*p)++;
        SkipWhitespace(p);

        if (strcmp(key, "version") == 0) {
            if (!ParseUint32Field(p, &grant->version)) return false;
        } else if (strcmp(key, "grant_id") == 0) {
            if (!ParseBoundedString(p, grant->grant_id, sizeof(grant->grant_id))) return false;
        } else if (strcmp(key, "tenant_id") == 0) {
            if (!ParseBoundedString(p, grant->tenant_id, sizeof(grant->tenant_id))) return false;
        } else if (strcmp(key, "endpoint_id") == 0) {
            if (!ParseBoundedString(p, grant->endpoint_id, sizeof(grant->endpoint_id))) return false;
        } else if (strcmp(key, "action_kind") == 0) {
            if (!ParseBoundedString(p, grant->action_kind, sizeof(grant->action_kind))) return false;
        } else if (strcmp(key, "action_digest") == 0) {
            if (!ParseBoundedString(p, grant->action_digest, sizeof(grant->action_digest))) return false;
        } else if (strcmp(key, "operator_id") == 0) {
            if (!ParseBoundedString(p, grant->operator_id, sizeof(grant->operator_id))) return false;
        } else if (strcmp(key, "response_session_id") == 0) {
            if (!ParseBoundedString(p, grant->response_session_id, sizeof(grant->response_session_id))) return false;
        } else if (strcmp(key, "issued_at") == 0) {
            if (!ParseInt64Field(p, &grant->issued_at)) return false;
        } else if (strcmp(key, "expires_at") == 0) {
            if (!ParseInt64Field(p, &grant->expires_at)) return false;
        } else if (strcmp(key, "nonce") == 0) {
            if (!ParseBoundedString(p, grant->nonce, sizeof(grant->nonce))) return false;
        } else if (strcmp(key, "signer_key_id") == 0) {
            if (!ParseBoundedString(p, grant->signer_key_id, sizeof(grant->signer_key_id))) return false;
        } else if (strcmp(key, "signature") == 0) {
            if (!ParseBoundedString(p, grant->signature, sizeof(grant->signature))) return false;
        } else {
            // Forward-compatible: skip unknown scalar or nested value
            if (**p == '"') {
                char dummy[256];
                ParseBoundedString(p, dummy, sizeof(dummy));
            } else if (**p == '{' || **p == '[') {
                int depth = 1;
                char open = **p;
                char close = (open == '{') ? '}' : ']';
                (*p)++;
                while (**p && depth > 0) {
                    if (**p == open) depth++;
                    else if (**p == close) depth--;
                    (*p)++;
                }
            } else {
                while (**p && **p != ',' && **p != '}') (*p)++;
            }
        }
    }

    if (grant->version != 2 || grant->grant_id[0] == '\0' ||
        grant->endpoint_id[0] == '\0' || grant->action_kind[0] == '\0' ||
        grant->action_digest[0] == '\0' || grant->signature[0] == '\0') {
        return false;
    }
    return true;
}

static inline int ParseResponseOffers(const char* json, ResponseJobOffer* outOffers, size_t maxOffers) {
    if (!json || !outOffers || maxOffers == 0) return 0;

    const char* p = json;
    const char* offers_needle = "\"response_offers\"";
    const char* found = strstr(p, offers_needle);
    if (!found) return 0;

    p = found + strlen(offers_needle);
    SkipWhitespace(&p);
    if (*p != ':') return 0;
    p++;
    SkipWhitespace(&p);
    if (*p != '[') return 0;
    p++;

    int count = 0;
    while (*p && *p != ']' && (size_t)count < maxOffers) {
        SkipWhitespace(&p);
        if (*p == ']') break;
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p != '{') return count;
        p++;

        ResponseJobOffer offer;
        memset(&offer, 0, sizeof(offer));
        bool has_job_id = false, has_lease_id = false, has_kind = false, has_grant = false;

        while (*p && *p != '}') {
            SkipWhitespace(&p);
            if (*p == '}') break;
            if (*p == ',') { p++; continue; }

            char key[64] = {0};
            if (!ParseBoundedString(&p, key, sizeof(key))) break;
            SkipWhitespace(&p);
            if (*p != ':') break;
            p++;
            SkipWhitespace(&p);

            if (strcmp(key, "job_id") == 0) {
                if (ParseBoundedString(&p, offer.job_id, sizeof(offer.job_id))) has_job_id = true;
            } else if (strcmp(key, "lease_id") == 0) {
                if (ParseBoundedString(&p, offer.lease_id, sizeof(offer.lease_id))) has_lease_id = true;
            } else if (strcmp(key, "kind") == 0) {
                if (ParseBoundedString(&p, offer.kind, sizeof(offer.kind))) has_kind = true;
            } else if (strcmp(key, "grant") == 0) {
                if (ExtractGrantObject(&p, &offer.grant)) has_grant = true;
            } else if (strcmp(key, "payload_json") == 0) {
                if (*p == '"') {
                    if (ParseBoundedString(&p, offer.payload_json, sizeof(offer.payload_json))) {
                        offer.payload_len = strlen(offer.payload_json);
                    }
                } else if (*p == '{') {
                    const char* start = p;
                    int depth = 1;
                    p++;
                    while (*p && depth > 0) {
                        if (*p == '{') depth++;
                        else if (*p == '}') depth--;
                        p++;
                    }
                    size_t raw_len = (size_t)(p - start);
                    if (raw_len < sizeof(offer.payload_json)) {
                        memcpy(offer.payload_json, start, raw_len);
                        offer.payload_json[raw_len] = '\0';
                        offer.payload_len = raw_len;
                    }
                }
            } else {
                if (*p == '"') {
                    char dummy[256];
                    ParseBoundedString(&p, dummy, sizeof(dummy));
                } else {
                    while (*p && *p != ',' && *p != '}') p++;
                }
            }
        }
        if (*p == '}') p++;

        if (has_job_id && has_lease_id && has_kind && has_grant) {
            outOffers[count++] = offer;
        }
    }
    return count;
}

/* ---------------------------------------------------------------------------
 * Grant Verification & Digest Verification
 * ------------------------------------------------------------------------- */

static inline bool VerifyResponseGrant(
    const ResponseGrant* grant,
    const char* payload_json,
    const char* expected_endpoint_id,
    const char* pubkey_path
) {
    if (!grant || !expected_endpoint_id) return false;

    // 1. Version must be strictly 2
    if (grant->version != 2) return false;

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

    if (strcasecmp(grant->action_digest, computed_hex) != 0) {
        return false; // Action digest tampered or mismatched
    }

    // 5. Binary canonical encoding (OMINULL-ENDPOINT-GRANT-V2)
    uint8_t canonical_bytes[1024];
    size_t canonical_len = EncodeGrantV2Canonical(
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
        grant->signer_key_id,
        canonical_bytes,
        sizeof(canonical_bytes)
    );
    if (canonical_len == 0) return false;

    // 6. Decode Ed25519 signature (128 hex chars -> 64 raw bytes)
    uint8_t sig_bytes[64];
    if (!Response_HexToBytes(grant->signature, sig_bytes, 64)) return false;

    // 7. Load trusted tenant public key and verify in-process
    const char* key_path = pubkey_path ? pubkey_path : OMINULL_DEFAULT_RESPONSE_PUBKEY_PATH;
    uint8_t pub_bytes[32];
    if (!Response_LoadPublicKey(key_path, pub_bytes)) {
        return false; // Public key missing or unreadable
    }

    return Ed25519_Verify(sig_bytes, canonical_bytes, canonical_len, pub_bytes);
}

/* ---------------------------------------------------------------------------
 * Durable Replay Cache
 * ------------------------------------------------------------------------- */

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

    DWORD fileSize = GetFileSize(hFile, NULL);
    char* buf = (char*)malloc(fileSize + 1);
    if (!buf) {
        UnlockFileEx(hFile, 0, MAXDWORD, MAXDWORD, &ov);
        CloseHandle(hFile);
        return false;
    }

    DWORD bytesRead = 0;
    ReadFile(hFile, buf, fileSize, &bytesRead, NULL);
    buf[bytesRead] = '\0';

    int64_t now = (int64_t)time(NULL);
    bool replay_detected = false;

    char** retained = (char**)malloc(1024 * sizeof(char*));
    size_t retained_count = 0;

    char* line = strtok(buf, "\r\n");
    while (line) {
        char g_id[64] = {0}, n_id[65] = {0};
        int64_t exp = 0;
        if (sscanf(line, "%63s %64s %lld", g_id, n_id, (long long*)&exp) >= 1) {
            if (strcmp(g_id, grant_id) == 0 || (nonce && nonce[0] && strcmp(n_id, nonce) == 0)) {
                replay_detected = true;
            }
            if (exp > now && retained && retained_count < 1024) {
                retained[retained_count++] = strdup(line);
            }
        }
        line = strtok(NULL, "\r\n");
    }
    free(buf);

    if (!replay_detected) {
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        SetEndOfFile(hFile);
        DWORD written = 0;
        for (size_t i = 0; i < retained_count; i++) {
            WriteFile(hFile, retained[i], (DWORD)strlen(retained[i]), &written, NULL);
            WriteFile(hFile, "\r\n", 2, &written, NULL);
        }
        char new_entry[256];
        int nlen = snprintf(new_entry, sizeof(new_entry), "%s %s %lld\r\n", grant_id, nonce ? nonce : "-", (long long)expires_at);
        if (nlen > 0) {
            WriteFile(hFile, new_entry, (DWORD)nlen, &written, NULL);
        }
        FlushFileBuffers(hFile);
    }

    if (retained) {
        for (size_t i = 0; i < retained_count; i++) free(retained[i]);
        free(retained);
    }

    UnlockFileEx(hFile, 0, MAXDWORD, MAXDWORD, &ov);
    CloseHandle(hFile);
    return !replay_detected;
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
    bool replay_detected = false;

    char** retained = (char**)malloc(1024 * sizeof(char*));
    size_t retained_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        char g_id[64] = {0}, n_id[65] = {0};
        int64_t exp = 0;
        if (sscanf(line, "%63s %64s %ld", g_id, n_id, &exp) >= 1) {
            if (strcmp(g_id, grant_id) == 0 || (nonce && nonce[0] && strcmp(n_id, nonce) == 0)) {
                replay_detected = true;
            }
            if (exp > now && retained && retained_count < 1024) {
                retained[retained_count++] = strdup(line);
            }
        }
    }

    if (!replay_detected) {
        fseek(fp, 0, SEEK_SET);
        if (ftruncate(fd, 0) == 0) {
            for (size_t i = 0; i < retained_count; i++) {
                fputs(retained[i], fp);
            }
            fprintf(fp, "%s %s %ld\n", grant_id, nonce ? nonce : "-", expires_at);
            fflush(fp);
            fsync(fd);
        }
    }

    if (retained) {
        for (size_t i = 0; i < retained_count; i++) free(retained[i]);
        free(retained);
    }

    flock(fd, LOCK_UN);
    fclose(fp);
    return !replay_detected;
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
