#ifndef OMINULL_TERMINAL_FRAME_H
#define OMINULL_TERMINAL_FRAME_H

/*
 * Terminal wire helpers shared by the Linux and Windows terminal workers.
 *
 * The hub sends one JSON text message per frame:
 *   {"type":"stdin|resize|close","timestamp":"...","data":"<base64>","rows":N,"cols":N}
 * and the offer payload {"session_id":..,"program":..,"connect_token":..}.
 * Field order, whitespace and unknown fields (including nested values) are
 * tolerated; the parser is bounded by the message length and never reads past it.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TERMINAL_JSON_MAX_DEPTH 8

typedef struct {
    const char* s;
    size_t n;
    size_t i;
    bool first;
} TermJson;

static inline void TermJson_SkipWs(TermJson* j) {
    while (j->i < j->n && (j->s[j->i] == ' ' || j->s[j->i] == '\t' || j->s[j->i] == '\r' || j->s[j->i] == '\n')) j->i++;
}

/* Reads a JSON string at the cursor; out and out_len span the raw content between
 * the quotes (escapes left in place). */
static inline bool TermJson_String(TermJson* j, const char** out, size_t* out_len) {
    if (j->i >= j->n || j->s[j->i] != '"') return false;
    size_t start = ++j->i;
    while (j->i < j->n) {
        char c = j->s[j->i];
        if (c == '\\') {
            j->i += 2;
            continue;
        }
        if (c == '"') {
            if (out) *out = j->s + start;
            if (out_len) *out_len = j->i - start;
            j->i++;
            return true;
        }
        if ((unsigned char)c < 0x20) return false;
        j->i++;
    }
    return false;
}

static inline bool TermJson_SkipValue(TermJson* j, int depth) {
    if (depth > TERMINAL_JSON_MAX_DEPTH) return false;
    TermJson_SkipWs(j);
    if (j->i >= j->n) return false;
    char c = j->s[j->i];
    if (c == '"') return TermJson_String(j, NULL, NULL);
    if (c == '{' || c == '[') {
        char close = (c == '{') ? '}' : ']';
        j->i++;
        TermJson_SkipWs(j);
        if (j->i < j->n && j->s[j->i] == close) {
            j->i++;
            return true;
        }
        while (j->i < j->n) {
            if (c == '{') {
                TermJson_SkipWs(j);
                if (!TermJson_String(j, NULL, NULL)) return false;
                TermJson_SkipWs(j);
                if (j->i >= j->n || j->s[j->i] != ':') return false;
                j->i++;
            }
            if (!TermJson_SkipValue(j, depth + 1)) return false;
            TermJson_SkipWs(j);
            if (j->i >= j->n) return false;
            if (j->s[j->i] == ',') {
                j->i++;
                continue;
            }
            if (j->s[j->i] == close) {
                j->i++;
                return true;
            }
            return false;
        }
        return false;
    }
    /* number, true, false, null */
    size_t start = j->i;
    while (j->i < j->n) {
        char d = j->s[j->i];
        if ((d >= '0' && d <= '9') || (d >= 'a' && d <= 'z') || d == '-' || d == '+' || d == '.' || d == 'E') {
            j->i++;
        } else {
            break;
        }
    }
    return j->i > start;
}

static inline bool TermJson_Begin(TermJson* j, const char* s, size_t n) {
    j->s = s;
    j->n = n;
    j->i = 0;
    j->first = true;
    TermJson_SkipWs(j);
    if (j->i >= j->n || j->s[j->i] != '{') return false;
    j->i++;
    return true;
}

/* Next top-level member. Returns 1 with key/value spans, 0 at the closing brace
 * (only whitespace may follow), -1 on malformed input. vtype: 's' string (raw
 * content), 'n' scalar (raw text), 'x' object or array (raw text). */
static inline int TermJson_Next(TermJson* j, const char** key, size_t* key_len, char* vtype, const char** val, size_t* val_len) {
    TermJson_SkipWs(j);
    if (j->i >= j->n) return -1;
    if (j->s[j->i] == '}') {
        j->i++;
        TermJson_SkipWs(j);
        return (j->i == j->n || j->s[j->i] == '\0') ? 0 : -1;
    }
    if (!j->first) {
        if (j->s[j->i] != ',') return -1;
        j->i++;
        TermJson_SkipWs(j);
    }
    j->first = false;
    if (!TermJson_String(j, key, key_len)) return -1;
    TermJson_SkipWs(j);
    if (j->i >= j->n || j->s[j->i] != ':') return -1;
    j->i++;
    TermJson_SkipWs(j);
    if (j->i >= j->n) return -1;
    if (j->s[j->i] == '"') {
        *vtype = 's';
        return TermJson_String(j, val, val_len) ? 1 : -1;
    }
    size_t start = j->i;
    *vtype = (j->s[j->i] == '{' || j->s[j->i] == '[') ? 'x' : 'n';
    if (!TermJson_SkipValue(j, 1)) return -1;
    *val = j->s + start;
    *val_len = j->i - start;
    TermJson_SkipWs(j);
    if (j->i < j->n && j->s[j->i] != ',' && j->s[j->i] != '}') return -1;
    return 1;
}

static inline bool TermJson_KeyIs(const char* key, size_t key_len, const char* want) {
    size_t w = strlen(want);
    return key_len == w && memcmp(key, want, w) == 0;
}

/* Copies a raw JSON string span into out, resolving simple escapes. Fails rather
 * than truncates. \u escapes are accepted only for ASCII. */
static inline bool TermJson_CopyString(const char* raw, size_t raw_len, char* out, size_t out_max) {
    size_t o = 0;
    for (size_t i = 0; i < raw_len; i++) {
        char c = raw[i];
        if (c == '\\') {
            if (++i >= raw_len) return false;
            switch (raw[i]) {
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u': {
                if (i + 4 >= raw_len) return false;
                char hex[5];
                memcpy(hex, raw + i + 1, 4);
                hex[4] = '\0';
                char* end = NULL;
                long v = strtol(hex, &end, 16);
                if (!end || *end != '\0' || v <= 0 || v > 0x7f) return false;
                c = (char)v;
                i += 4;
                break;
            }
            default: return false;
            }
        }
        if (o + 1 >= out_max) return false;
        out[o++] = c;
    }
    if (out_max == 0) return false;
    out[o] = '\0';
    return true;
}

static inline bool TermJson_Int(const char* raw, size_t raw_len, long* out) {
    char buf[24];
    if (raw_len == 0 || raw_len >= sizeof(buf)) return false;
    memcpy(buf, raw, raw_len);
    buf[raw_len] = '\0';
    char* end = NULL;
    long v = strtol(buf, &end, 10);
    if (!end || *end != '\0') return false;
    *out = v;
    return true;
}

/* ---------------------------------------------------------------------------
 * Incoming terminal frame
 * ------------------------------------------------------------------------- */

typedef struct {
    char type[16];
    const char* data; /* raw base64 span inside the message, not terminated */
    size_t data_len;
    long rows;
    long cols;
} TermInFrame;

static inline bool TermFrame_Parse(const char* json, size_t len, TermInFrame* f) {
    memset(f, 0, sizeof(*f));
    TermJson j;
    if (!TermJson_Begin(&j, json, len)) return false;
    for (;;) {
        const char *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        char vt = 0;
        int r = TermJson_Next(&j, &k, &kl, &vt, &v, &vl);
        if (r == 0) break;
        if (r < 0) return false;
        if (TermJson_KeyIs(k, kl, "type")) {
            if (vt != 's' || !TermJson_CopyString(v, vl, f->type, sizeof(f->type))) return false;
        } else if (TermJson_KeyIs(k, kl, "data")) {
            if (vt == 's') {
                f->data = v;
                f->data_len = vl;
            } else if (!(vt == 'n' && vl == 4 && memcmp(v, "null", 4) == 0)) {
                return false;
            }
        } else if (TermJson_KeyIs(k, kl, "rows")) {
            if (vt != 'n' || !TermJson_Int(v, vl, &f->rows)) f->rows = 0;
        } else if (TermJson_KeyIs(k, kl, "cols")) {
            if (vt != 'n' || !TermJson_Int(v, vl, &f->cols)) f->cols = 0;
        }
    }
    return f->type[0] != '\0';
}

/* Offer payload: copies the three fields exactly; a field that does not fit fails. */
static inline bool TermPayload_Parse(const char* json, char* session_id, size_t sid_max, char* program, size_t prog_max,
                                     char* token, size_t tok_max) {
    if (!json) return false;
    session_id[0] = program[0] = token[0] = '\0';
    TermJson j;
    if (!TermJson_Begin(&j, json, strlen(json))) return false;
    for (;;) {
        const char *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        char vt = 0;
        int r = TermJson_Next(&j, &k, &kl, &vt, &v, &vl);
        if (r == 0) break;
        if (r < 0) return false;
        char* dst = NULL;
        size_t max = 0;
        if (TermJson_KeyIs(k, kl, "session_id")) {
            dst = session_id;
            max = sid_max;
        } else if (TermJson_KeyIs(k, kl, "program")) {
            dst = program;
            max = prog_max;
        } else if (TermJson_KeyIs(k, kl, "connect_token")) {
            dst = token;
            max = tok_max;
        }
        if (dst) {
            if (vt != 's' || !TermJson_CopyString(v, vl, dst, max)) return false;
        }
    }
    return true;
}

/* ---------------------------------------------------------------------------
 * Base64
 * ------------------------------------------------------------------------- */

static const char term_b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline size_t TermB64_EncodedLen(size_t in_len) { return 4 * ((in_len + 2) / 3); }

static inline size_t TermB64_Encode(const unsigned char* in, size_t in_len, char* out, size_t out_max) {
    size_t out_len = TermB64_EncodedLen(in_len);
    if (out_len + 1 > out_max) return 0;
    size_t i = 0, j = 0;
    while (i < in_len) {
        size_t rem = in_len - i;
        uint32_t a = in[i++];
        uint32_t b = (rem > 1) ? in[i++] : 0;
        uint32_t c = (rem > 2) ? in[i++] : 0;
        uint32_t t = (a << 16) | (b << 8) | c;
        out[j++] = term_b64_table[(t >> 18) & 0x3F];
        out[j++] = term_b64_table[(t >> 12) & 0x3F];
        out[j++] = (rem > 1) ? term_b64_table[(t >> 6) & 0x3F] : '=';
        out[j++] = (rem > 2) ? term_b64_table[t & 0x3F] : '=';
    }
    out[j] = '\0';
    return j;
}

static inline int TermB64_Val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decodes base64, skipping whitespace and JSON escape backslashes ("\/").
 * Stops at padding or the first invalid character. */
static inline size_t TermB64_Decode(const char* in, size_t in_len, unsigned char* out, size_t out_max) {
    size_t j = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t' || c == '\\') continue;
        if (c == '=') break;
        int v = TermB64_Val(c);
        if (v < 0) break;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (j >= out_max) return j;
            out[j++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    return j;
}

#endif /* OMINULL_TERMINAL_FRAME_H */
