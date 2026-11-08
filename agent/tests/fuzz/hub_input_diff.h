/*
 * Differential check of the Rust hub-input library against the agent's C
 * readers on one input. Built without OMINULL_HUB_INPUT, so the headers below
 * are the reference; any difference aborts. Used by fuzz_diff.c (libFuzzer) and
 * test_hub_input_diff.c (seeds, saved corpus and mutations, on Linux and under
 * wine, where long is 32 bits). Compares the verdict always, and the outputs
 * when the input was accepted (a refused parse's buffers are never read).
 */
#ifndef OMINULL_HUB_INPUT_DIFF_H
#define OMINULL_HUB_INPUT_DIFF_H
#ifdef OMINULL_HUB_INPUT
#error "the differential test compares against the C readers; build it without OMINULL_HUB_INPUT"
#endif

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/cert_renewal.h"
#include "../../include/response_dispatcher.h"
#include "../../include/script_payload.h"
#include "../../include/hub_scrape.h"
#include "../../include/agent_trust.h"
#include "../../include/hub_input.h"

#define DIFF(cond, what) do { if (!(cond)) { fprintf(stderr, "hub-input difference: %s\n", (what)); fflush(stderr); abort(); } } while (0)

static inline void Diff_Abi(void) {
    DIFF(hi_abi_size(HI_ABI_TERM_IN_FRAME) == sizeof(TermInFrame), "TermInFrame size");
    DIFF(hi_abi_size(HI_ABI_RESPONSE_GRANT) == sizeof(ResponseGrant), "ResponseGrant size");
    DIFF(hi_abi_size(HI_ABI_RESPONSE_JOB_OFFER) == sizeof(ResponseJobOffer), "ResponseJobOffer size");
    DIFF(hi_abi_size(HI_ABI_SCRIPT_PARAM) == sizeof(ScriptParam), "ScriptParam size");
    DIFF(hi_abi_size(HI_ABI_SCRIPT_PAYLOAD_FIELDS) == sizeof(ScriptPayloadFields), "ScriptPayloadFields size");
    DIFF(hi_abi_size(HI_ABI_TRUST_RULE) == sizeof(TrustRule), "TrustRule size");
    DIFF(hi_abi_size(HI_ABI_TRUST_MANIFEST) == sizeof(TrustManifest), "TrustManifest size");
    DIFF(hi_abi_size(HI_ABI_TRUST_ROUTINE_KEY) == sizeof(TrustRoutineKey), "TrustRoutineKey size");
    DIFF(hi_abi_size(HI_ABI_TRUST_ACTION) == sizeof(TrustAction), "TrustAction size");
    DIFF(hi_abi_size(HI_ABI_SHA256_CTX) == sizeof(ResponseSHA256Context), "ResponseSHA256Context size");
}

static inline void Diff_TermFrame(const char* raw, size_t n) {
    TermInFrame a, b;
    bool ra = TermFrame_Parse(raw, n, &a), rb = hi_term_frame_parse(raw, n, &b);
    DIFF(ra == rb, "TermFrame_Parse verdict");
    if (ra) {
        DIFF(strcmp(a.type, b.type) == 0, "frame type");
        DIFF(a.data == b.data && a.data_len == b.data_len, "frame data span");
        DIFF(a.rows == b.rows && a.cols == b.cols, "frame size");
    }
}

static inline void Diff_TermB64(const char* raw, size_t n) {
    static unsigned char a[4096], b[4096];
    static const size_t caps[] = {0, 1, 3, 64, sizeof(a)};
    for (size_t c = 0; c < sizeof(caps) / sizeof(caps[0]); c++) {
        size_t ra = TermB64_Decode(raw, n, a, caps[c]), rb = hi_term_b64_decode(raw, n, b, caps[c]);
        DIFF(ra == rb, "TermB64_Decode length");
        DIFF(memcmp(a, b, ra) == 0, "TermB64_Decode bytes");
        ra = Response_Base64Decode(raw, n, a, caps[c]);
        rb = hi_base64_decode(raw, n, b, caps[c]);
        DIFF(ra == rb, "Response_Base64Decode length");
        DIFF(memcmp(a, b, ra) == 0, "Response_Base64Decode bytes");
    }
}

static inline void Diff_TermPayload(const char* text) {
    char sa[64], pa[64], ta[128], sb[64], pb[64], tb[128];
    bool ra = TermPayload_Parse(text, sa, sizeof(sa), pa, sizeof(pa), ta, sizeof(ta));
    bool rb = hi_term_payload_parse(text, sb, sizeof(sb), pb, sizeof(pb), tb, sizeof(tb));
    DIFF(ra == rb, "TermPayload_Parse verdict");
    if (ra) DIFF(strcmp(sa, sb) == 0 && strcmp(pa, pb) == 0 && strcmp(ta, tb) == 0, "terminal payload fields");
    char ca[TERMINAL_CANON_MAX], cb[TERMINAL_CANON_MAX];
    ra = TerminalCanonicalFromOffer(text, ca, sizeof(ca));
    rb = hi_terminal_canonical(text, cb, sizeof(cb));
    DIFF(ra == rb, "TerminalCanonicalFromOffer verdict");
    if (ra) DIFF(strcmp(ca, cb) == 0, "terminal canonical bytes");
    char da[64], db[64];
    ra = ScreenCanonicalFromOffer(text, da, sizeof(da));
    rb = hi_screen_canonical(text, db, sizeof(db));
    DIFF(ra == rb, "ScreenCanonicalFromOffer verdict");
    if (ra) DIFF(strcmp(da, db) == 0, "screen canonical bytes");
    char ma[16] = {0}, mb[16] = {0}, oa[256] = {0}, ob[256] = {0};
    sa[0] = sb[0] = ta[0] = tb[0] = 0;
    bool ua = false, ub = false, fa = false, fb = false;
    ra = Screen_ReadPayload(text, sa, sizeof(sa), ma, sizeof(ma), ta, sizeof(ta), oa, sizeof(oa), &ua, &fa);
    rb = hi_screen_payload(text, sb, sizeof(sb), mb, sizeof(mb), tb, sizeof(tb), ob, sizeof(ob), &ub, &fb);
    DIFF(ra == rb, "Screen_ReadPayload verdict");
    if (ra) DIFF(strcmp(sa, sb) == 0 && strcmp(ma, mb) == 0 && strcmp(ta, tb) == 0 && strcmp(oa, ob) == 0 && ua == ub && fa == fb, "screen payload fields");
}

static inline void Diff_Forensics(const char* text) {
    char ba[64] = "def-bundle", bb[64] = "def-bundle", pa[32] = "def-profile", pb[32] = "def-profile";
    int64_t ma = 5, mb = 5;
    int ta = 7, tb = 7;
    bool ra = Response_ForensicsPayload(text, ba, sizeof(ba), pa, sizeof(pa), &ma, &ta);
    bool rb = hi_forensics_payload(text, bb, sizeof(bb), pb, sizeof(pb), &mb, &tb);
    DIFF(ra == rb, "Response_ForensicsPayload verdict");
    if (ra) DIFF(strcmp(ba, bb) == 0 && strcmp(pa, pb) == 0 && ma == mb && ta == tb, "forensic payload fields");
}

static inline void Diff_Cert(const char* text) {
    static char a[12288], b[12288];
    static const size_t caps[] = {2, 16, sizeof(a)};
    static const char* const keys[] = {"cert_pem_b64", "key_pem_b64", "pfx_b64", "not_after"};
    for (size_t k = 0; k < 4; k++) {
        for (size_t c = 0; c < 3; c++) {
            bool ra = CertRenewal_Field(text, keys[k], a, caps[c]), rb = hi_cert_field(text, keys[k], b, caps[c]);
            DIFF(ra == rb, "CertRenewal_Field verdict");
            if (ra) {
                DIFF(strcmp(a, b) == 0, "certificate field");
                static char pa[8192], pb[8192];
                size_t la = CertRenewal_DecodePEM(a, "-----BEGIN CERTIFICATE-----", pa, sizeof(pa));
                size_t lb = hi_cert_decode_pem(b, "-----BEGIN CERTIFICATE-----", pb, sizeof(pb));
                DIFF(la == lb, "CertRenewal_DecodePEM length");
                if (la) DIFF(strcmp(pa, pb) == 0, "certificate PEM");
            }
        }
    }
    static char pa[8192], pb[8192];
    size_t la = CertRenewal_DecodePEM(text, "-----BEGIN", pa, sizeof(pa)), lb = hi_cert_decode_pem(text, "-----BEGIN", pb, sizeof(pb));
    DIFF(la == lb, "CertRenewal_DecodePEM length on raw input");
    if (la) DIFF(strcmp(pa, pb) == 0, "PEM on raw input");
}

static inline void Diff_Grant(const char* text, const char* raw, size_t n) {
    static ResponseGrant a, b;
    const char* pa = text;
    const char* pb = text;
    memset(&a, 0xA5, sizeof(a));
    memset(&b, 0xA5, sizeof(b));
    bool ra = ExtractGrantObject(&pa, &a), rb = hi_extract_grant(&pb, &b);
    DIFF(ra == rb, "ExtractGrantObject verdict");
    DIFF(pa == pb, "ExtractGrantObject cursor");
    if (ra) DIFF(memcmp(&a, &b, sizeof(a)) == 0, "grant fields");
    pa = pb = raw;
    /* An empty input has no first byte to look at, in either reader. */
    if (n) {
        memset(&a, 0xA5, sizeof(a));
        memset(&b, 0xA5, sizeof(b));
        ra = ExtractGrantObjectN(&pa, n, &a);
        rb = hi_extract_grant_n(&pb, n, &b);
        DIFF(ra == rb, "ExtractGrantObjectN verdict");
        DIFF(pa == pb, "ExtractGrantObjectN cursor");
        if (ra) DIFF(memcmp(&a, &b, sizeof(a)) == 0, "grant fields (bounded)");
    }
}

static inline void Diff_Offers(const char* text, const char* raw, size_t n) {
    static ResponseJobOffer a[MAX_RESPONSE_OFFERS], b[MAX_RESPONSE_OFFERS];
    memset(a, 0xA5, sizeof(a));
    memset(b, 0xA5, sizeof(b));
    bool ra = Response_ReadOffer(raw, n, &a[0]), rb = hi_read_offer(raw, n, &b[0]);
    DIFF(ra == rb, "Response_ReadOffer verdict");
    if (ra) DIFF(memcmp(&a[0], &b[0], sizeof(a[0])) == 0, "offer fields");
    memset(a, 0xA5, sizeof(a));
    memset(b, 0xA5, sizeof(b));
    int ca = ParseResponseOffers(text, a, MAX_RESPONSE_OFFERS), cb = hi_parse_offers(text, b, MAX_RESPONSE_OFFERS);
    DIFF(ca == cb, "ParseResponseOffers count");
    for (int i = 0; i < ca; i++) {
        DIFF(memcmp(&a[i], &b[i], sizeof(a[i])) == 0, "parsed offer");
        Diff_TermPayload(a[i].payload_json);
        Diff_Forensics(a[i].payload_json);
    }
}

typedef struct {
    char script_id[64], script_digest[65], interpreter[128], source[32768], parameters_json[8192];
    ScriptParam params[16];
    int version, timeout;
    size_t source_len, parameters_len, param_count, max_out;
} DiffScript;

static inline ScriptPayloadFields Diff_ScriptFields(DiffScript* s) {
    memset(s, 0, sizeof(*s));
    s->timeout = 300;
    s->max_out = 1024;
    strcpy(s->interpreter, "/bin/sh");
    ScriptPayloadFields f = {
        s->script_id, sizeof(s->script_id), &s->version, s->script_digest, sizeof(s->script_digest),
        s->interpreter, sizeof(s->interpreter), s->source, sizeof(s->source), &s->source_len,
        s->parameters_json, sizeof(s->parameters_json), &s->parameters_len,
        s->params, 16, &s->param_count,
        &s->timeout, 3600, &s->max_out, 16, 1048576,
    };
    return f;
}

static inline void Diff_Script(const char* text) {
    static DiffScript a, b;
    ScriptPayloadFields fa = Diff_ScriptFields(&a), fb = Diff_ScriptFields(&b);
    bool ra = ScriptPayload_Parse(text, &fa), rb = hi_script_payload_parse(text, &fb);
    DIFF(ra == rb, "ScriptPayload_Parse verdict");
    if (ra) {
        DIFF(strcmp(a.script_id, b.script_id) == 0 && strcmp(a.script_digest, b.script_digest) == 0 && strcmp(a.interpreter, b.interpreter) == 0, "script ids");
        DIFF(a.source_len == b.source_len && memcmp(a.source, b.source, a.source_len + 1) == 0, "script source");
        DIFF(a.parameters_len == b.parameters_len && memcmp(a.parameters_json, b.parameters_json, a.parameters_len + 1) == 0, "script parameters text");
        DIFF(a.version == b.version && a.timeout == b.timeout && a.max_out == b.max_out, "script numbers");
        DIFF(a.param_count == b.param_count, "script parameter count");
        for (size_t i = 0; i < a.param_count; i++)
            DIFF(strcmp(a.params[i].name, b.params[i].name) == 0 && strcmp(a.params[i].value, b.params[i].value) == 0 && a.params[i].env_skip == b.params[i].env_skip, "script parameter");
    }
}

static inline void Diff_Scrape(const char* text) {
    static const char* const keys[] = {"version", "url", "package", "signature", "sha256", "release_sig"};
    static char a[512], b[512];
    static const size_t caps[] = {1, 2, 32, sizeof(a)};
    for (size_t k = 0; k < 6; k++) {
        for (size_t c = 0; c < 4; c++) {
            a[0] = b[0] = 0;
            bool ra = Scrape_StringFlat(text, keys[k], a, caps[c]), rb = hi_scrape_string_flat(text, keys[k], b, caps[c]);
            DIFF(ra == rb, "Scrape_StringFlat verdict");
            DIFF(strcmp(a, b) == 0, "Scrape_StringFlat value");
            a[0] = b[0] = 0;
            ra = Scrape_StringSpaced(text, keys[k], a, caps[c]);
            rb = hi_scrape_string_spaced(text, keys[k], b, caps[c]);
            DIFF(ra == rb, "Scrape_StringSpaced verdict");
            DIFF(strcmp(a, b) == 0, "Scrape_StringSpaced value");
        }
    }
    static char ca[128], cb[128];
    ca[0] = cb[0] = 0;
    bool ra = Scrape_DeviceCredential(text, ca, sizeof(ca)), rb = hi_scrape_device_credential(text, cb, sizeof(cb));
    DIFF(ra == rb, "Scrape_DeviceCredential verdict");
    if (ra) DIFF(strcmp(ca, cb) == 0, "device credential");
}

typedef struct {
    char tokens[256][64];
    int n;
} DiffTokens;

static inline void Diff_TakeToken(const char* ip, void* ctx) {
    DiffTokens* t = (DiffTokens*)ctx;
    if (t->n < 256) snprintf(t->tokens[t->n], 64, "%s", ip);
    t->n++;
}

static inline void Diff_AddressList(const char* text) {
    static DiffTokens a, b;
    a.n = b.n = 0;
    Scrape_AddressList(text, "threat_indicators", Diff_TakeToken, &a);
    hi_scrape_address_list(text, "threat_indicators", Diff_TakeToken, &b);
    DIFF(a.n == b.n, "address list count");
    for (int i = 0; i < a.n && i < 256; i++) DIFF(strcmp(a.tokens[i], b.tokens[i]) == 0, "address list token");
}

static inline void Diff_RoutineList(const char* s) {
    static TrustRoutineKey a[TRUST_MAX_ROUTINE_KEYS], b[TRUST_MAX_ROUTINE_KEYS];
    int ca = -1, cb = -1;
    memset(a, 0xA5, sizeof(a));
    memset(b, 0xA5, sizeof(b));
    bool ra = Trust_ParseRoutineList(s, a, &ca), rb = hi_trust_parse_routine_list(s, b, &cb);
    DIFF(ra == rb, "Trust_ParseRoutineList verdict");
    if (ra) DIFF(ca == cb && memcmp(a, b, sizeof(a)) == 0, "routine keys");
}

static inline void Diff_Address(const char* s) {
    DIFF(Trust_IsIPLiteral(s) == hi_trust_is_ip_literal(s), "Trust_IsIPLiteral");
    DIFF(Trust_IsAllowEntry(s) == hi_trust_is_allow_entry(s), "Trust_IsAllowEntry");
    DIFF(Trust_PublicAddress(s) == hi_trust_public_address(s), "Trust_PublicAddress");
}

static inline void Diff_TjValue(const char* v, const char* ve);

/* Every reader the trust path has, over one object or value span. */
static inline void Diff_TjMember(const char* obj, const char* end, const char* key, int walk) {
    const char *va = NULL, *vea = NULL, *vb = NULL, *veb = NULL;
    int ra = TJ_Member(obj, end, key, &va, &vea), rb = hi_tj_member(obj, end, key, &vb, &veb);
    DIFF(ra == rb, "TJ_Member verdict");
    if (ra != 1) return;
    DIFF(va == vb && vea == veb, "TJ_Member span");
    if (walk) Diff_TjValue(va, vea);
}

static inline void Diff_TjValue(const char* v, const char* ve) {
    static char a[256], b[256];
    static const size_t caps[] = {1, 8, 64, sizeof(a)};
    for (size_t c = 0; c < 4; c++) {
        bool ra = TJ_Plain(v, ve, a, caps[c]), rb = hi_tj_plain(v, ve, b, caps[c]);
        DIFF(ra == rb, "TJ_Plain verdict");
        if (ra) {
            DIFF(strcmp(a, b) == 0, "TJ_Plain value");
            Diff_Address(a);
            Diff_RoutineList(a);
        }
    }
    int64_t ia = -1, ib = -1;
    bool ra = TJ_Int(v, ve, &ia), rb = hi_tj_int(v, ve, &ib);
    DIFF(ra == rb && (!ra || ia == ib), "TJ_Int");
    ia = ib = -1;
    ra = Trust_PositiveInt(v, ve, &ia);
    rb = hi_trust_positive_int(v, ve, &ib);
    DIFF(ra == rb && (!ra || ia == ib), "Trust_PositiveInt");
    DIFF((TJ_SkipValue(v, ve, 1) == hi_tj_skip_value(v, ve, 1)), "TJ_SkipValue");
    DIFF((TJ_SkipString(v, ve) == hi_tj_skip_string(v, ve)), "TJ_SkipString");
    static char la[64][64], lb[64][64];
    static const int lcaps[] = {1, 4, 32, 64};
    for (size_t c = 0; c < 4; c++) {
        memset(la, 0, sizeof(la));
        memset(lb, 0, sizeof(lb));
        int na = TJ_PlainArray(v, ve, la, lcaps[c]), nb = hi_tj_plain_array(v, ve, lb, lcaps[c]);
        DIFF(na == nb, "TJ_PlainArray count");
        if (na > 0) DIFF(memcmp(la, lb, (size_t)na * 64) == 0, "TJ_PlainArray values");
    }
    static TrustRule ra2[TRUST_MAX_RULES], rb2[TRUST_MAX_RULES];
    static const int rcaps[] = {1, 4, TRUST_MAX_RULES};
    for (size_t c = 0; c < 3; c++) {
        memset(ra2, 0, sizeof(ra2));
        memset(rb2, 0, sizeof(rb2));
        int na = Trust_ParseRules(v, ve, ra2, rcaps[c]), nb = hi_trust_parse_rules(v, ve, rb2, rcaps[c]);
        DIFF(na == nb, "Trust_ParseRules count");
        if (na > 0) DIFF(memcmp(ra2, rb2, (size_t)na * sizeof(TrustRule)) == 0, "Trust_ParseRules values");
        for (int i = 0; i < na; i++) DIFF(Trust_RuleValid(&ra2[i]) == hi_trust_rule_valid(&rb2[i]), "Trust_RuleValid");
    }
    static TrustManifest ma, mb;
    memset(&ma, 0xA5, sizeof(ma));
    memset(&mb, 0xA5, sizeof(mb));
    ra = Trust_ParseManifest(v, ve, &ma);
    rb = hi_trust_parse_manifest(v, ve, &mb);
    DIFF(ra == rb, "Trust_ParseManifest verdict");
    if (ra) DIFF(memcmp(&ma, &mb, sizeof(ma)) == 0, "manifest fields");
    static ResponseGrant ga, gb;
    static uint8_t pa[TRUST_MAX_PAYLOAD], pb[TRUST_MAX_PAYLOAD];
    size_t la2 = 0, lb2 = 0;
    memset(&ga, 0xA5, sizeof(ga));
    memset(&gb, 0xA5, sizeof(gb));
    ra = Trust_ReadGrantObject(v, ve, &ga, pa, &la2);
    rb = hi_trust_read_grant_object(v, ve, &gb, pb, &lb2);
    DIFF(ra == rb, "Trust_ReadGrantObject verdict");
    if (ra) {
        DIFF(memcmp(&ga, &gb, sizeof(ga)) == 0, "grant object grant");
        DIFF(la2 == lb2 && memcmp(pa, pb, la2) == 0, "grant object payload");
    }
}

static inline void Diff_Action(const char* raw, size_t n) {
    static TrustAction a, b;
    static const char* const kinds[] = {"mesh_quarantine", "auto_isolate", "agent_update", "isolation_change", "script_exec"};
    static const char* const endpoints[] = {"ep-1", "mesh:10.0.0.1"};
    for (size_t k = 0; k < 5; k++) {
        for (size_t e = 0; e < 2; e++) {
            memset(&a, 0xA5, sizeof(a));
            memset(&b, 0xA5, sizeof(b));
            const char* ra = Trust_ParseAction(raw, n, kinds[k], endpoints[e], "ep-1", &a);
            const char* rb = hi_trust_parse_action(raw, n, kinds[k], endpoints[e], "ep-1", &b);
            DIFF((ra == NULL) == (rb == NULL), "Trust_ParseAction verdict");
            if (ra) DIFF(strcmp(ra, rb) == 0, "Trust_ParseAction reason");
            else DIFF(memcmp(&a, &b, sizeof(a)) == 0, "action fields");
        }
    }
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    const char* ra = Trust_ParseBaselines(raw, raw + n, "ep-1", &a);
    const char* rb = hi_trust_parse_baselines(raw, raw + n, "ep-1", &b);
    DIFF((ra == NULL) == (rb == NULL), "Trust_ParseBaselines verdict");
    if (ra) DIFF(strcmp(ra, rb) == 0, "Trust_ParseBaselines reason");
    else DIFF(a.ruleCount == b.ruleCount && memcmp(a.rules, b.rules, sizeof(a.rules)) == 0, "baseline rules");
}

static inline void Diff_Trust(const char* raw, size_t n) {
    const char* end = raw + n;
    static const char* const keys[] = {
        "route", "body", "targets", "baselines", "endpoints", "rules", "service", "destination", "protocol", "port", "target_ip", "endpoint_id",
        "version", "allow_ips", "grant", "payload_b64", "v", "tenant_id", "profile", "signer_key_id", "signature", "seq", "issued_at", "caps",
        "trust", "routine_keys", "capability_manifest", "is_isolated", "isolation_allow_ips", "quarantined_peers", "isolation_baseline",
        "enforcement_grants", "agent_update_grant", "agent_update", "epoch", "keys", "sig", "response_key", "auto_isolate_key", "policy_key", "bundle_sig",
    };
    Diff_TjValue(raw, end);
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) Diff_TjMember(raw, end, keys[k], 1);
    /* Array elements, the way the heartbeat walks enforcement_grants. */
    const char *v, *ve;
    if (TJ_Member(raw, end, "enforcement_grants", &v, &ve) == 1) {
        const char* p = TJ_Ws(v, ve);
        if (p < ve && *p == '[') {
            p = TJ_Ws(p + 1, ve);
            for (int i = 0; i < TRUST_MAX_GRANTS && p < ve && *p != ']'; i++) {
                const char* e = TJ_SkipValue(p, ve, 1);
                DIFF(e == hi_tj_skip_value(p, ve, 1), "TJ_SkipValue over a grant");
                if (!e) break;
                Diff_TjValue(p, e);
                static ResponseGrant g;
                static uint8_t pl[TRUST_MAX_PAYLOAD];
                size_t pn = 0;
                if (Trust_ReadGrantObject(p, e, &g, pl, &pn)) {   /* the payload the signature covers */
                    char* one = (char*)malloc(pn ? pn : 1);
                    if (!one) abort();
                    if (pn) memcpy(one, pl, pn);
                    Diff_TjValue(one, one + pn);
                    Diff_Action(one, pn);
                    free(one);
                }
                p = TJ_Ws(e, ve);
                if (p < ve && *p == ',') p = TJ_Ws(p + 1, ve);
            }
        }
    }
    Diff_Action(raw, n);
}

/* Only hex digits read as hex in the library; sscanf's %02x also took a sign, a
 * space and 0x. Where the text is all hex digits the two agree. */
static inline void Diff_Hex(const char* text, size_t n) {
    uint8_t a[32], b[32];
    size_t want = n / 2 > 32 ? 32 : n / 2;
    bool all_hex = true;
    for (size_t i = 0; i < want * 2; i++)
        if (!isxdigit((unsigned char)text[i])) all_hex = false;
    if (strlen(text) < want * 2) all_hex = false;
    bool rb = hi_hex_to_bytes(text, b, want);
    if (all_hex) {
        bool ra = Response_HexToBytes(text, a, want);
        DIFF(ra == rb, "Response_HexToBytes verdict");
        if (ra) DIFF(memcmp(a, b, want) == 0, "Response_HexToBytes bytes");
    } else if (want) {
        DIFF(!rb, "hex with a non-digit accepted");
    }
}

static inline void Diff_Sha256(const uint8_t* data, size_t n) {
    uint8_t a[32], b[32];
    Response_SHA256_Sum(data, n, a);
    hi_sha256_sum(data, n, b);
    DIFF(memcmp(a, b, 32) == 0, "SHA-256 sum");
    ResponseSHA256Context ca, cb;
    Response_SHA256_Init(&ca);
    hi_sha256_init(&cb);
    size_t off = 0, step = 1;
    while (off < n) {
        size_t take = n - off < step ? n - off : step;
        Response_SHA256_Update(&ca, data + off, take);
        hi_sha256_update(&cb, data + off, take);
        off += take;
        step = (step * 3 + data[off - 1]) % 131 + 1;
    }
    Response_SHA256_Final(&ca, a);
    hi_sha256_final(&cb, b);
    DIFF(memcmp(a, b, 32) == 0, "SHA-256 streaming");
}

/* A real signature over the input, then the same one with a flipped bit, a wrong
 * key and a key made of input bytes. The two verifiers must agree on each. */
static inline void Diff_Ed25519(const uint8_t* data, size_t n) {
    static uint8_t pub[32], priv[64];
    static bool have = false;
    if (!have) {
        uint8_t seed[32];
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7 + 1);
        DIFF(Ed25519_CreateKeypairFromSeed(pub, priv, seed), "test key");
        have = true;
    }
    uint8_t sig[64];
    DIFF(Ed25519_Sign(sig, data, n, priv), "test signature");
    DIFF(Ed25519_Verify(sig, data, n, pub) && hi_ed25519_verify(sig, data, n, pub), "genuine Ed25519 signature");
    uint8_t bad[64], k2[32];
    memcpy(bad, sig, 64);
    size_t bit = n ? (size_t)data[n / 2] * 257 + n : 3;
    bad[(bit / 8) % 64] ^= (uint8_t)(1u << (bit % 8));
    DIFF(Ed25519_Verify(bad, data, n, pub) == hi_ed25519_verify(bad, data, n, pub), "Ed25519 flipped signature");
    memcpy(k2, pub, 32);
    k2[(bit / 8) % 32] ^= (uint8_t)(1u << (bit % 8));
    DIFF(Ed25519_Verify(sig, data, n, k2) == hi_ed25519_verify(sig, data, n, k2), "Ed25519 flipped key");
    if (n >= 96) {
        DIFF(Ed25519_Verify(data, data + 96, n - 96, data + 64) == hi_ed25519_verify(data, data + 96, n - 96, data + 64), "Ed25519 input bytes");
    }
}

/* One input through every reader. raw has exactly n readable bytes; text is the
 * same bytes with a terminator (an embedded NUL ends the text early, as on the wire). */
static inline void Diff_One(const uint8_t* data, size_t n) {
    char* raw = (char*)malloc(n ? n : 1);
    char* text = (char*)malloc(n + 1);
    if (!raw || !text) abort();
    if (n) memcpy(raw, data, n);
    if (n) memcpy(text, data, n);
    text[n] = '\0';
    size_t tn = strlen(text);
    Diff_TermFrame(raw, n);
    Diff_TermB64(raw, n);
    Diff_TermPayload(text);
    Diff_Forensics(text);
    Diff_Cert(text);
    Diff_Grant(text, raw, n);
    Diff_Offers(text, raw, n);
    Diff_Script(text);
    Diff_Scrape(text);
    Diff_AddressList(text);
    if (tn < 80) Diff_Address(text);
    Diff_Trust(raw, n);
    Diff_Hex(text, tn);
    Diff_Sha256(data, n);
    if (tn < TRUST_ROUTINE_LIST_MAX + 1) Diff_RoutineList(text);
    /* Signing is slow; a fixed slice of inputs, so a saved crash replays. */
    if (n == 0 || (data[n - 1] & 0x0F) == 0) Diff_Ed25519(data, n);
    free(raw);
    free(text);
}

#endif
