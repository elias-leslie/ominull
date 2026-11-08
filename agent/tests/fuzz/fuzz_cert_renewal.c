/* client_certificate in the heartbeat reply: base64 fields and PEM decoding. */
#include "fuzz_common.h"
#include "../../include/cert_renewal.h"

static char b64[CERT_RENEWAL_B64_MAX];
static char pem[CERT_RENEWAL_PEM_MAX];

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* text = Fuzz_Text(data, size);
    if (CertRenewal_Field(text, "cert_pem_b64", b64, sizeof(b64)))
        (void)CertRenewal_DecodePEM(b64, "-----BEGIN CERTIFICATE-----", pem, sizeof(pem));
    if (CertRenewal_Field(text, "key_pem_b64", b64, sizeof(b64)))
        (void)CertRenewal_DecodePEM(b64, "-----BEGIN ", pem, sizeof(pem));
    free(text);
    return 0;
}
