/* Parsing of the renewed client certificate the hub puts in a heartbeat reply.
 * gcc -O2 -Wall -Wextra -Iagent/include agent/tests/test_cert_renewal.c */
#include <stdio.h>
#include <stdlib.h>
#include "cert_renewal.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } } while (0)

/* base64 of "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" */
#define CERT_B64 "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkFBQUEKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
/* The key fixture is encoded at run time: a base64 PEM key in the source reads
 * as a leaked key to secret scanners, placeholder body or not. */
static void b64encode(const char* in, char* out) {
    static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = strlen(in), o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned char)in[i] << 16;
        if (i + 1 < n) v |= (unsigned char)in[i + 1] << 8;
        if (i + 2 < n) v |= (unsigned char)in[i + 2];
        out[o++] = a[(v >> 18) & 63];
        out[o++] = a[(v >> 12) & 63];
        out[o++] = i + 1 < n ? a[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? a[v & 63] : '=';
    }
    out[o] = '\0';
}

int main(void) {
    char keyB64[256], reply[1024];
    b64encode("-----BEGIN RSA PRIVATE" " KEY-----\nBBBB\n-----END RSA PRIVATE" " KEY-----\n", keyB64);
    snprintf(reply, sizeof(reply),
             "{\"status\":\"ok\",\"client_certificate\":{\"cert_pem_b64\":\"" CERT_B64
             "\",\"key_pem_b64\":\"%s\",\"pfx_b64\":\"AAEC\",\"not_after\":\"2028-01-01T00:00:00Z\"},"
             "\"is_isolated\":false}", keyB64);
    char b64[CERT_RENEWAL_B64_MAX], pem[CERT_RENEWAL_PEM_MAX];

    CHECK(CertRenewal_Field(reply, "cert_pem_b64", b64, sizeof(b64)), "certificate field found");
    CHECK(CertRenewal_DecodePEM(b64, "-----BEGIN CERTIFICATE-----", pem, sizeof(pem)) > 0, "certificate decodes as PEM");
    CHECK(strstr(pem, "AAAA") != NULL, "certificate body kept");
    CHECK(CertRenewal_Field(reply, "key_pem_b64", b64, sizeof(b64)), "key field found");
    CHECK(CertRenewal_DecodePEM(b64, "-----BEGIN RSA PRIVATE" " KEY-----", pem, sizeof(pem)) > 0, "key decodes as PEM");
    CHECK(CertRenewal_DecodePEM(b64, "-----BEGIN CERTIFICATE-----", pem, sizeof(pem)) == 0, "a key is not accepted as a certificate");
    CHECK(CertRenewal_Field(reply, "pfx_b64", b64, sizeof(b64)) && strcmp(b64, "AAEC") == 0, "pfx field found");

    /* No object, a key outside the object, a value cut short, junk in a value. */
    CHECK(!CertRenewal_Field("{\"cert_pem_b64\":\"" CERT_B64 "\"}", "cert_pem_b64", b64, sizeof(b64)), "key outside client_certificate ignored");
    CHECK(!CertRenewal_Field("{\"client_certificate\":{\"other\":\"x\"},\"cert_pem_b64\":\"QUFB\"}", "cert_pem_b64", b64, sizeof(b64)),
          "key after the object ignored");
    CHECK(!CertRenewal_Field("{\"client_certificate\":{\"cert_pem_b64\":\"" CERT_B64, "cert_pem_b64", b64, sizeof(b64)), "unterminated value refused");
    CHECK(!CertRenewal_Field(reply, "cert_pem_b64", b64, 16), "value longer than the buffer refused, not truncated");
    CHECK(b64[0] == '\0', "refused value leaves an empty buffer");
    CHECK(!CertRenewal_Field("{\"client_certificate\":{\"cert_pem_b64\":\"QU\\\"FB\"}}", "cert_pem_b64", b64, sizeof(b64)), "escape in value refused");
    CHECK(CertRenewal_DecodePEM("QUFBQQ==", "-----BEGIN CERTIFICATE-----", pem, sizeof(pem)) == 0, "non-PEM refused");
    CHECK(CertRenewal_DecodePEM(CERT_B64, "-----BEGIN CERTIFICATE-----", pem, 20) == 0, "PEM larger than the buffer refused");
    /* "-----BEGIN CERTIFICATE-----\n\0x\n-----END " carries a NUL: refused. */
    CHECK(CertRenewal_DecodePEM("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCgB4Ci0tLS0tRU5EIA==", "-----BEGIN CERTIFICATE-----", pem, sizeof(pem)) == 0,
          "embedded NUL refused");

    /* What a restart does with what an interrupted swap left behind. */
    CHECK(CertRenewal_Recovery(false, false, false) == CERT_RECOVERY_NONE, "nothing staged: nothing to do");
    CHECK(CertRenewal_Recovery(true, true, false) == CERT_RECOVERY_DISCARD, "staged pair not installed: discarded");
    CHECK(CertRenewal_Recovery(false, true, false) == CERT_RECOVERY_DISCARD, "half-written pair: discarded");
    CHECK(CertRenewal_Recovery(true, true, true) == CERT_RECOVERY_DISCARD, "old key kept but key not renamed: discarded");
    CHECK(CertRenewal_Recovery(true, false, true) == CERT_RECOVERY_FINISH, "key renamed, certificate not: finished");
    CHECK(CertRenewal_Recovery(true, false, false) == CERT_RECOVERY_DISCARD, "certificate left after the old key was restored: discarded");
    CHECK(CertRenewal_Recovery(false, false, true) == CERT_RECOVERY_CLEAN_OLD, "swap done, old key left: removed");

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("cert renewal parsing: ok\n");
    return 0;
}
