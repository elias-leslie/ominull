#ifndef OMINULL_CERT_RENEWAL_H
#define OMINULL_CERT_RENEWAL_H

/* Client certificate renewal, the parsing half (both platforms).
 *
 * The hub hands a renewal-capable agent a new client certificate inside its
 * heartbeat reply, well before the old one expires:
 *
 *   "client_certificate":{"cert_pem_b64":"...","key_pem_b64":"...",
 *                         "pfx_b64":"...","not_after":"..."}
 *
 * Every value is base64 so no JSON escaping is involved. The reply arrived on
 * the pinned, authenticated session, but it is still parsed strictly: a value
 * cut short, or one that does not decode to what it claims to be, is refused,
 * and the agent keeps the certificate it has (the hub offers again later).
 * Installing is platform code (linux/main.c, src/hub_tls.c). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "response_dispatcher.h"

#define CERT_RENEWAL_B64_MAX 12288
#define CERT_RENEWAL_PEM_MAX 8192

/* CertRenewal_Field copies the base64 value of key from the reply's
 * client_certificate object. False when the object or key is absent, the value
 * does not end within cap, or it holds anything but base64. */
static inline bool CertRenewal_Field(const char* json, const char* key, char* out, size_t cap) {
#ifdef HI_BASE64_CERT
    return hi_cert_field(json, key, out, cap);
#else
    if (!json || !key || !out || cap < 2) return false;
    out[0] = '\0';
    const char* obj = strstr(json, "\"client_certificate\":{");
    if (!obj) return false;
    const char* end = strchr(obj + strlen("\"client_certificate\":{"), '}');
    if (!end) return false;
    char needle[64];
    int n = snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    if (n <= 0 || (size_t)n >= sizeof(needle)) return false;
    const char* p = strstr(obj, needle);
    if (!p || p > end) return false;
    p += n;
    size_t i = 0;
    for (; p[i] && p[i] != '"'; i++) {
        char c = p[i];
        bool b64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                   c == '+' || c == '/' || c == '=';
        if (!b64 || i + 1 >= cap) {
            out[0] = '\0';
            return false;
        }
        out[i] = c;
    }
    if (p[i] != '"' || i == 0) {
        out[0] = '\0';
        return false;
    }
    out[i] = '\0';
    return true;
#endif
}

/* CertRenewal_DecodePEM decodes b64 into out as a NUL-terminated PEM document
 * that must open with the expected BEGIN line and close with an END line.
 * Returns the length, or 0 when it does not. */
static inline size_t CertRenewal_DecodePEM(const char* b64, const char* begin, char* out, size_t cap) {
#ifdef HI_BASE64_CERT
    return hi_cert_decode_pem(b64, begin, out, cap);
#else
    if (!b64 || !begin || !out || cap < 2) return 0;
    size_t n = Response_Base64Decode(b64, strlen(b64), (uint8_t*)out, cap - 1);
    if (n == 0) return 0;
    out[n] = '\0';
    if (strlen(out) != n || strncmp(out, begin, strlen(begin)) != 0 || !strstr(out, "\n-----END ")) {
        memset(out, 0, cap);
        return 0;
    }
    return n;
#endif
}

/* A swap is: write <key>.new and <cert>.new, prove them, hard-link the live
 * key to <key>.old, rename <key>.new over the key, rename <cert>.new over the
 * certificate, remove <key>.old. Cleanup removes <cert>.new before <key>.new,
 * so <cert>.new without <key>.new only happens between the two renames.
 * CertRenewal_Recovery says what a restart finds and what to do about it. */
typedef enum {
    CERT_RECOVERY_NONE = 0,   /* nothing staged */
    CERT_RECOVERY_FINISH,     /* new key is live, new certificate staged: rename it in */
    CERT_RECOVERY_DISCARD,    /* a pair was staged but not installed: remove it */
    CERT_RECOVERY_CLEAN_OLD,  /* the swap finished; remove the old key */
} CertRecovery;

static inline CertRecovery CertRenewal_Recovery(bool certNew, bool keyNew, bool keyOld) {
    if (certNew && !keyNew && keyOld) return CERT_RECOVERY_FINISH;
    if (certNew || keyNew) return CERT_RECOVERY_DISCARD;
    if (keyOld) return CERT_RECOVERY_CLEAN_OLD;
    return CERT_RECOVERY_NONE;
}

#endif
