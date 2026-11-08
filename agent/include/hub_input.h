#ifndef OMINULL_HUB_INPUT_H
#define OMINULL_HUB_INPUT_H

/*
 * The Rust library that reads what the hub sends and checks signatures
 * (agent/hubinput, libominull_hubinput.a, scripts/build-hub-input.sh).
 *
 * Building with -DOMINULL_HUB_INPUT moves each parser family below to the
 * library. Without it the headers' own C readers run: those remain the
 * reference the differential tests (agent/tests/fuzz/hub_input_diff.h) compare
 * the library against. Struct parameters are void* so this header stands alone;
 * the wrappers in each owning header assert the sizes match.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef OMINULL_HUB_INPUT
/* One switch per family, flipped as each one passes its differential test. */
#define HI_TERM_FRAME
#define HI_BASE64_CERT
#define HI_OFFERS
#define HI_PAYLOADS
#define HI_SCRIPT
#define HI_TRUST
#define HI_SCRAPE
#define HI_CRYPTO
#endif

enum {
    HI_ABI_TERM_IN_FRAME = 0,
    HI_ABI_RESPONSE_GRANT,
    HI_ABI_RESPONSE_JOB_OFFER,
    HI_ABI_SCRIPT_PARAM,
    HI_ABI_SCRIPT_PAYLOAD_FIELDS,
    HI_ABI_TRUST_RULE,
    HI_ABI_TRUST_MANIFEST,
    HI_ABI_TRUST_ROUTINE_KEY,
    HI_ABI_TRUST_ACTION,
    HI_ABI_SHA256_CTX,
};
size_t hi_abi_size(int which);

/* Terminal frames and payloads. */
bool hi_term_frame_parse(const char* json, size_t len, void* frame);
bool hi_term_payload_parse(const char* json, char* sid, size_t sid_max, char* prog, size_t prog_max, char* tok, size_t tok_max);
size_t hi_term_b64_decode(const char* in, size_t len, unsigned char* out, size_t max);
bool hi_screen_payload(const char* json, char* sid, size_t sid_max, char* mode, size_t mode_max, char* tok, size_t tok_max,
                       char* op, size_t op_max, bool* unattended, bool* ask_first);

/* Base64 and the client certificate object. */
size_t hi_base64_decode(const char* in, size_t len, uint8_t* out, size_t cap);
bool hi_cert_field(const char* json, const char* key, char* out, size_t cap);
size_t hi_cert_decode_pem(const char* b64, const char* begin, char* out, size_t cap);

/* Offers and grants. */
bool hi_extract_grant_n(const char** p, size_t n, void* grant);
bool hi_extract_grant(const char** p, void* grant);
bool hi_read_offer(const char* s, size_t len, void* offer);
int hi_parse_offers(const char* json, void* offers, size_t max);
bool hi_forensics_payload(const char* json, char* bundle, size_t bundle_cap, char* profile, size_t profile_cap, int64_t* max_bytes, int* timeout);
bool hi_screen_canonical(const char* json, char* out, size_t cap);
bool hi_terminal_canonical(const char* json, char* out, size_t cap);

/* script_exec. */
bool hi_script_payload_parse(const char* json, const void* fields);

/* The trust reader and what it reads. */
const char* hi_tj_skip_string(const char* p, const char* end);
const char* hi_tj_skip_value(const char* p, const char* end, int depth);
int hi_tj_member(const char* obj, const char* end, const char* key, const char** v, const char** vend);
bool hi_tj_plain(const char* v, const char* vend, char* out, size_t cap);
int hi_tj_plain_array(const char* v, const char* vend, void* out, int cap);
bool hi_tj_int(const char* v, const char* vend, int64_t* out);
bool hi_trust_parse_manifest(const char* v, const char* ve, void* manifest);
int hi_trust_parse_rules(const char* v, const char* ve, void* rules, int cap);
bool hi_trust_rule_valid(const void* rule);
const char* hi_trust_parse_baselines(const char* payload, const char* end, const char* self, void* action);
const char* hi_trust_parse_action(const char* payload, size_t len, const char* kind, const char* grant_endpoint, const char* self, void* action);
bool hi_trust_read_grant_object(const char* v, const char* ve, void* grant, uint8_t* payload, size_t* plen);
bool hi_trust_parse_routine_list(const char* s, void* keys, int* count);
bool hi_trust_positive_int(const char* v, const char* ve, int64_t* out);
bool hi_trust_is_ip_literal(const char* s);
bool hi_trust_is_allow_entry(const char* s);
bool hi_trust_public_address(const char* s);

/* Plain-search field readers. */
bool hi_scrape_string_flat(const char* json, const char* key, char* out, size_t cap);
bool hi_scrape_string_spaced(const char* json, const char* key, char* out, size_t cap);
bool hi_scrape_device_credential(const char* json, char* out, size_t cap);
void hi_scrape_address_list(const char* json, const char* key, void (*take)(const char* ip, void* ctx), void* ctx);

/* Digests and signatures. */
void hi_sha256_init(void* ctx);
void hi_sha256_update(void* ctx, const uint8_t* data, size_t len);
void hi_sha256_final(void* ctx, uint8_t hash[32]);
void hi_sha256_sum(const uint8_t* data, size_t len, uint8_t hash[32]);
bool hi_hex_to_bytes(const char* hex, uint8_t* out, size_t len);
bool hi_ed25519_verify(const uint8_t sig[64], const uint8_t* msg, size_t len, const uint8_t pub[32]);
bool hi_p256_verify_xy(const uint8_t xy[64], const char* msg, size_t len, const uint8_t* der, size_t der_len);
bool hi_p256_verify_hash(const uint8_t xy[64], const uint8_t hash[32], const uint8_t* der, size_t der_len);
bool hi_p256_verify_pem(const char* pem, const char* msg, size_t len, const uint8_t* der, size_t der_len);

#endif
