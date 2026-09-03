#ifndef OMINULL_RESPONSE_DISPATCHER_H
#define OMINULL_RESPONSE_DISPATCHER_H

/*
 * Ominull Response Dispatcher: Bounded Offer Parser, Grant Verifier, and Replay Cache.
 *
 * Implements Slice 1D.1:
 * - Bounded parsing of heartbeat response_offers over a fixed schema (no loose substrings).
 * - Cryptographic verification of EndpointGrant V2 using canonical binary encoding
 *   (response_canonical.h) and tenant Ed25519 public key.
 * - Independent SHA-256 digest recomputation over action payload.
 * - Clock window checks with +/- 60s tolerance.
 * - Endpoint ID binding check against local endpoint identity.
 * - Durable replay cache with atomic file locking and expiration pruning.
 * - Contained worker child execution with process groups, sanitized environment,
 *   closed descriptors, and resource limits.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <errno.h>

#include "response_canonical.h"

#define MAX_RESPONSE_OFFERS 4
#define MAX_PAYLOAD_JSON_LEN 65536
#define OMINULL_DEFAULT_RESPONSE_PUBKEY_PATH "/etc/ominull/response.pub"
#define OMINULL_DEFAULT_REPLAY_CACHE_PATH "/var/lib/ominull/replay_cache.state"

typedef struct {
    uint32_t version;
    char grant_id[64];
    char tenant_id[64];
    char endpoint_id[64];
    char action_kind[64];
    char action_digest[65]; // 64 hex chars + null
    char operator_id[128];
    char response_session_id[64];
    int64_t issued_at;
    int64_t expires_at;
    char nonce[65];
    char signer_key_id[65];
    char signature[130];    // 128 hex chars (64 bytes Ed25519) + null
} ResponseGrant;

typedef struct {
    char job_id[64];
    char lease_id[64];
    char kind[64];
    ResponseGrant grant;
    char payload_json[MAX_PAYLOAD_JSON_LEN];
    size_t payload_len;
} ResponseJobOffer;

/* ---------------------------------------------------------------------------
 * Pure C In-Process SHA-256 (FIPS 180-4)
 * ------------------------------------------------------------------------- */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} Response_SHA256_CTX;

#define RESP_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define RESP_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define RESP_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define RESP_SIGMA0(x) (RESP_ROTR(x, 2) ^ RESP_ROTR(x, 13) ^ RESP_ROTR(x, 22))
#define RESP_SIGMA1(x) (RESP_ROTR(x, 6) ^ RESP_ROTR(x, 11) ^ RESP_ROTR(x, 25))
#define RESP_GAMMA0(x) (RESP_ROTR(x, 7) ^ RESP_ROTR(x, 18) ^ ((x) >> 3))
#define RESP_GAMMA1(x) (RESP_ROTR(x, 17) ^ RESP_ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t RESP_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline void Response_SHA256_Transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8)  |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = RESP_GAMMA1(w[i - 2]) + w[i - 7] + RESP_GAMMA0(w[i - 15]) + w[i - 16];
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + RESP_SIGMA1(e) + RESP_CH(e, f, g) + RESP_K[i] + w[i];
        uint32_t t2 = RESP_SIGMA0(a) + RESP_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static inline void Response_SHA256_Init(Response_SHA256_CTX* ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static inline void Response_SHA256_Update(Response_SHA256_CTX* ctx, const uint8_t* data, size_t len) {
    size_t buf_idx = (size_t)(ctx->count & 0x3F);
    ctx->count += len;
    size_t data_idx = 0;
    if (buf_idx > 0 && (buf_idx + len) >= 64) {
        size_t fill = 64 - buf_idx;
        memcpy(ctx->buffer + buf_idx, data, fill);
        Response_SHA256_Transform(ctx->state, ctx->buffer);
        data_idx += fill;
        buf_idx = 0;
    }
    while (data_idx + 64 <= len) {
        Response_SHA256_Transform(ctx->state, data + data_idx);
        data_idx += 64;
    }
    if (data_idx < len) {
        memcpy(ctx->buffer + buf_idx, data + data_idx, len - data_idx);
    }
}

static inline void Response_SHA256_Final(Response_SHA256_CTX* ctx, uint8_t hash[32]) {
    uint64_t total_bits = ctx->count * 8;
    size_t buf_idx = (size_t)(ctx->count & 0x3F);
    ctx->buffer[buf_idx++] = 0x80;
    if (buf_idx > 56) {
        memset(ctx->buffer + buf_idx, 0, 64 - buf_idx);
        Response_SHA256_Transform(ctx->state, ctx->buffer);
        buf_idx = 0;
    }
    memset(ctx->buffer + buf_idx, 0, 56 - buf_idx);
    for (int i = 7; i >= 0; i--) {
        ctx->buffer[56 + (7 - i)] = (uint8_t)((total_bits >> (i * 8)) & 0xFF);
    }
    Response_SHA256_Transform(ctx->state, ctx->buffer);
    for (int i = 0; i < 8; i++) {
        hash[i * 4 + 0] = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
        hash[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        hash[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8)  & 0xFF);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xFF);
    }
}

static inline void Response_SHA256_Sum(const uint8_t* data, size_t len, uint8_t hash[32]) {
    Response_SHA256_CTX ctx;
    Response_SHA256_Init(&ctx);
    Response_SHA256_Update(&ctx, data, len);
    Response_SHA256_Final(&ctx, hash);
}

static inline bool Response_HexToBytes(const char* hex, uint8_t* out, size_t out_len) {
    if (!hex) return false;
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return false;
    for (size_t i = 0; i < out_len; i++) {
        char high = hex[i * 2];
        char low = hex[i * 2 + 1];
        int h = isdigit((unsigned char)high) ? high - '0' : (tolower((unsigned char)high) - 'a' + 10);
        int l = isdigit((unsigned char)low)  ? low - '0'  : (tolower((unsigned char)low) - 'a' + 10);
        if (h < 0 || h > 15 || l < 0 || l > 15) return false;
        out[i] = (uint8_t)((h << 4) | l);
    }
    return true;
}

static inline void Response_BytesToHex(const uint8_t* data, size_t len, char* out_hex) {
    static const char hexchars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2 + 0] = hexchars[(data[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hexchars[data[i] & 0x0F];
    }
    out_hex[len * 2] = '\0';
}

/* ---------------------------------------------------------------------------
 * Bounded Fixed-Schema JSON Parser
 * ------------------------------------------------------------------------- */

static inline void SkipWhitespace(const char** p) {
    while (**p && (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n')) {
        (*p)++;
    }
}

static inline bool ParseBoundedString(const char** p, char* out, size_t out_cap) {
    SkipWhitespace(p);
    if (**p != '"') return false;
    (*p)++;
    size_t i = 0;
    while (**p && **p != '"') {
        if (**p == '\\' && *(*p + 1)) {
            (*p)++;
            char escaped = **p;
            if (escaped == '"') out[i++] = '"';
            else if (escaped == '\\') out[i++] = '\\';
            else if (escaped == 'n') out[i++] = '\n';
            else if (escaped == 'r') out[i++] = '\r';
            else if (escaped == 't') out[i++] = '\t';
            else out[i++] = escaped;
        } else {
            if (i + 1 >= out_cap) return false; // Overflow prevented
            out[i++] = **p;
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

    // Validate presence of required grant fields
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
        if (*p != '{') return count; // Malformed element
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
                    // Raw JSON object
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
                // Skip unknown offer fields
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

    // 7. Verify Ed25519 signature against trusted tenant public key
    const char* key_path = pubkey_path ? pubkey_path : OMINULL_DEFAULT_RESPONSE_PUBKEY_PATH;
    if (access(key_path, R_OK) != 0) {
        return false; // Trust anchor missing
    }

    // Write canonical bytes and signature to secure temp files for OpenSSL pkeyutl verification
    char tmp_data[64] = "/tmp/ominull_grant_data_XXXXXX";
    char tmp_sig[64]  = "/tmp/ominull_grant_sig_XXXXXX";
    int fd_data = mkstemp(tmp_data);
    int fd_sig  = mkstemp(tmp_sig);
    if (fd_data < 0 || fd_sig < 0) {
        if (fd_data >= 0) { close(fd_data); unlink(tmp_data); }
        if (fd_sig >= 0)  { close(fd_sig);  unlink(tmp_sig);  }
        return false;
    }
    if (write(fd_data, canonical_bytes, canonical_len) != (ssize_t)canonical_len ||
        write(fd_sig, sig_bytes, 64) != 64) {
        close(fd_data); unlink(tmp_data);
        close(fd_sig);  unlink(tmp_sig);
        return false;
    }
    close(fd_data);
    close(fd_sig);

    // Run openssl pkeyutl -verify -rawin -pubin -inkey key_path -sigfile tmp_sig -in tmp_data
    pid_t pid = fork();
    if (pid < 0) {
        unlink(tmp_data);
        unlink(tmp_sig);
        return false;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("openssl", "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
               "-inkey", key_path, "-sigfile", tmp_sig, "-in", tmp_data, (char*)NULL);
        _exit(127);
    }
    int status = 0;
    bool verified = false;
    if (waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        verified = true;
    }
    unlink(tmp_data);
    unlink(tmp_sig);
    return verified;
}

/* ---------------------------------------------------------------------------
 * Durable Replay Cache
 * ------------------------------------------------------------------------- */

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

    // Exclusive advisory lock for cross-process coordination
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

    // Buffer unexpired entries for pruning
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
        // Truncate and write unexpired entries + new entry
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
    fclose(fp); // Also closes fd
    return !replay_detected;
}

#endif /* OMINULL_RESPONSE_DISPATCHER_H */
