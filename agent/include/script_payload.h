#ifndef OMINULL_SCRIPT_PAYLOAD_H
#define OMINULL_SCRIPT_PAYLOAD_H

/*
 * The script_exec offer payload, read the same way on Linux and Windows:
 *   {"script_id","script_version","script_digest","interpreter","source",
 *    "parameters":{name:value},"timeout_seconds","max_output_bytes"}
 * (hub response.ScriptExecPayload, json.Marshal). The grant signs the whole
 * payload; this reader makes sure the bytes it signs mean one thing to the
 * agent: top-level members only, each known member at most once, strings fully
 * decoded (escapes, \u, surrogate pairs) and never truncated, the parameters
 * object read member by member (a value may hold a quote, a backslash or a
 * brace). Anything else refuses the whole payload.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#ifndef _WIN32
#include <strings.h>
#endif

#include "terminal_frame.h"

#define SCRIPT_PARAM_NAME_MAX 64
#define SCRIPT_PARAM_VALUE_MAX 2048

typedef struct {
    char name[SCRIPT_PARAM_NAME_MAX];
    char value[SCRIPT_PARAM_VALUE_MAX];
} ScriptParam;

/* Where ScriptPayload_Parse writes; the platform structs own the storage. */
typedef struct {
    char* script_id;        size_t script_id_cap;
    int* script_version;
    char* script_digest;    size_t script_digest_cap;
    char* interpreter;      size_t interpreter_cap;   /* keeps its default when absent */
    char* source;           size_t source_cap;        size_t* source_len;
    char* parameters_json;  size_t parameters_cap;    size_t* parameters_len;
    ScriptParam* params;    size_t params_cap;        size_t* param_count;
    int* timeout_seconds;   int timeout_max;          /* out of range keeps the default */
    size_t* max_output_bytes; size_t max_output_min; size_t max_output_max;   /* min exclusive */
} ScriptPayloadFields;

/* ScriptParam_NameOK: 1-63 of [A-Za-z0-9_-] (hub scripts.paramNameRe). The name
 * becomes part of an environment variable name. */
static inline bool ScriptParam_NameOK(const char* n) {
    size_t i = 0;
    for (; n[i]; i++) {
        char c = n[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
    }
    return i > 0 && i < SCRIPT_PARAM_NAME_MAX;
}

/* ScriptParam_Identifier: [A-Za-z_][A-Za-z0-9_]*, a name a shell can read. */
static inline bool ScriptParam_Identifier(const char* n, bool lower_only) {
    if (!n[0] || (n[0] >= '0' && n[0] <= '9')) return false;
    for (size_t i = 0; n[i]; i++) {
        char c = n[i];
        if (!((c >= 'a' && c <= 'z') || (!lower_only && c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) return false;
    }
    return true;
}

/* ScriptParam_BareExport: whether the value may also be set under the bare
 * name on Linux. Only a lower-case identifier, so a parameter can never set
 * PATH, LD_PRELOAD, BASH_ENV, BASH_FUNC_x%% or any other upper-case variable
 * the interpreter or loader reads. Windows names ignore case, so there the
 * executor takes any identifier the environment block does not hold yet. */
static inline bool ScriptParam_BareExport(const char* n) { return ScriptParam_Identifier(n, true); }

/* Integer member: decimal digits with an optional minus, nothing else. */
static inline bool ScriptPayload_Int(const char* v, size_t vl, long long* out) {
    size_t i = 0;
    bool neg = false;
    if (vl && v[0] == '-') { neg = true; i = 1; }
    if (i >= vl || vl - i > 18) return false;
    long long x = 0;
    for (; i < vl; i++) {
        if (v[i] < '0' || v[i] > '9') return false;
        x = x * 10 + (v[i] - '0');
    }
    *out = neg ? -x : x;
    return true;
}

/* ScriptPayload_Params reads the parameters object v (vl bytes): names per
 * ScriptParam_NameOK, each once, values strings (decoded) or plain literals
 * (as written), at most cap of them. */
static inline bool ScriptPayload_Params(const char* v, size_t vl, ScriptParam* params, size_t cap, size_t* count) {
    *count = 0;
    TermJson j;
    if (!TermJson_Begin(&j, v, vl)) return false;
    size_t n = 0;
    for (;;) {
        const char *k = NULL, *pv = NULL;
        size_t kl = 0, pl = 0;
        char vt = 0;
        int r = TermJson_Next(&j, &k, &kl, &vt, &pv, &pl);
        if (r == 0) break;
        if (r < 0 || n >= cap) return false;
        ScriptParam* e = &params[n];
        if (!TermJson_DecodeString(k, kl, e->name, sizeof(e->name), NULL) || !ScriptParam_NameOK(e->name)) return false;
        for (size_t i = 0; i < n; i++)
            if (strcasecmp(params[i].name, e->name) == 0) return false;   /* OMINULL_PARAM_<UPPER> must stay unique */
        if (vt == 's') {
            if (!TermJson_DecodeString(pv, pl, e->value, sizeof(e->value), NULL)) return false;
        } else if (vt == 'n') {   /* a number or literal, as written */
            if (pl >= sizeof(e->value)) return false;
            memcpy(e->value, pv, pl);
            e->value[pl] = '\0';
        } else {
            return false;
        }
        n++;
    }
    *count = n;
    return true;
}

/* ScriptPayload_Parse fills f from json. The caller has set the defaults
 * (interpreter, timeout, output cap). False on any malformed, repeated or
 * oversized member, or when there is no source. */
static inline bool ScriptPayload_Parse(const char* json, const ScriptPayloadFields* f) {
    if (!json || !f) return false;
    f->script_id[0] = f->script_digest[0] = f->source[0] = f->parameters_json[0] = '\0';
    *f->script_version = 0;
    *f->source_len = *f->parameters_len = *f->param_count = 0;
    enum { S_ID, S_VER, S_LEGACY_VER, S_DIGEST, S_INTERP, S_SOURCE, S_PARAMS, S_TIMEOUT, S_MAXOUT, S_N };
    static const char* const names[S_N] = {"script_id", "script_version", "version", "script_digest", "interpreter",
                                           "source", "parameters", "timeout_seconds", "max_output_bytes"};
    bool seen[S_N] = {false};
    long long legacy_version = 0;
    TermJson j;
    if (!TermJson_Begin(&j, json, strlen(json))) return false;
    for (;;) {
        const char *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        char vt = 0;
        int r = TermJson_Next(&j, &k, &kl, &vt, &v, &vl);
        if (r == 0) break;
        if (r < 0) return false;
        int m = -1;
        for (int i = 0; i < S_N; i++)
            if (TermJson_KeyIs(k, kl, names[i])) m = i;
        if (m < 0) continue;   /* unknown members are the hub's to add */
        if (seen[m]) return false;
        seen[m] = true;
        long long x = 0;
        switch (m) {
        case S_ID:
            if (vt != 's' || !TermJson_DecodeString(v, vl, f->script_id, f->script_id_cap, NULL)) return false;
            break;
        case S_VER:
        case S_LEGACY_VER:
            if (vt != 'n' || !ScriptPayload_Int(v, vl, &x) || x < 0 || x > 2147483647LL) return false;
            if (m == S_VER) *f->script_version = (int)x;
            else legacy_version = x;
            break;
        case S_DIGEST:
            if (vt != 's' || !TermJson_DecodeString(v, vl, f->script_digest, f->script_digest_cap, NULL)) return false;
            break;
        case S_INTERP:
            if (vt != 's' || !TermJson_DecodeString(v, vl, f->interpreter, f->interpreter_cap, NULL)) return false;
            break;
        case S_SOURCE:
            if (vt != 's' || !TermJson_DecodeString(v, vl, f->source, f->source_cap, f->source_len)) return false;
            break;
        case S_PARAMS:
            if (vt != 'x' || v[0] != '{' || vl >= f->parameters_cap) return false;
            memcpy(f->parameters_json, v, vl);   /* written whole to the params file */
            f->parameters_json[vl] = '\0';
            *f->parameters_len = vl;
            if (!ScriptPayload_Params(v, vl, f->params, f->params_cap, f->param_count)) return false;
            break;
        case S_TIMEOUT:
            if (vt != 'n' || !ScriptPayload_Int(v, vl, &x)) return false;
            if (x > 0 && x <= f->timeout_max) *f->timeout_seconds = (int)x;
            break;
        case S_MAXOUT:
            if (vt != 'n' || !ScriptPayload_Int(v, vl, &x)) return false;
            if (x > 0 && (unsigned long long)x > f->max_output_min && (unsigned long long)x <= f->max_output_max) *f->max_output_bytes = (size_t)x;
            break;
        }
    }
    if (!seen[S_VER] && seen[S_LEGACY_VER]) *f->script_version = (int)legacy_version;
    return *f->source_len > 0;
}

#endif
