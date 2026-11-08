/* Hub_RetryWithoutClientCert under the two kinds of failed handshake: a certificate
 * this endpoint can't use is put down, so it can't lock itself out of its own updates;
 * a server whose certificate fails costs it nothing, whoever sent it there. */
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
static WINHTTP_STATUS_CALLBACK captured;
static WINHTTP_STATUS_CALLBACK FixtureSetCallback(HINTERNET h, WINHTTP_STATUS_CALLBACK callback, DWORD flags, DWORD_PTR reserved) {
    (void)h; (void)reserved;
    if (flags & WINHTTP_CALLBACK_FLAG_SECURE_FAILURE) captured = callback;
    return NULL;
}
static int freed;
static BOOL FixtureFree(const void *cert) {
    (void)cert;
    freed++;
    return TRUE;
}
#define WinHttpSetStatusCallback FixtureSetCallback
#define CertFreeCertificateContext FixtureFree
#include "../src/hub_tls.c"
#undef CertFreeCertificateContext

static void Handshake(DWORD flags) {
    captured((HINTERNET)(uintptr_t)1, 0, WINHTTP_CALLBACK_STATUS_SECURE_FAILURE, &flags, sizeof(flags));
}
int main(void) {
    int failures = 0;
    static AGENT_CONFIG config;
    Hub_AttachClientCert((HINTERNET)(uintptr_t)1, &config);
    if (!captured) {
        puts("The handshake callback was never set");
        return 1;
    }
    static const DWORD serverFaults[] = {
        WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA, WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID,
        WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID, WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT,
        WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA | WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR,
    };
    g_cached = (PCCERT_CONTEXT)(uintptr_t)1;
    for (size_t i = 0; i < sizeof(serverFaults) / sizeof(serverFaults[0]); i++) {
        Handshake(serverFaults[i]);
        if (Hub_RetryWithoutClientCert((HINTERNET)(uintptr_t)1, ERROR_WINHTTP_SECURE_FAILURE) || !g_cached || freed) {
            printf("A server's bad certificate (flags 0x%lx) cost this endpoint its own\n", (unsigned long)serverFaults[i]);
            failures++;
        }
    }
    /* A server fault followed by a failure that isn't one: the second must decide. */
    Handshake(WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA);
    Handshake(WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR);
    if (!Hub_RetryWithoutClientCert((HINTERNET)(uintptr_t)1, ERROR_WINHTTP_SECURE_FAILURE) || g_cached || !g_certUnusable || freed != 1) {
        puts("A certificate this endpoint can't use wasn't put down, so it could lock itself out");
        failures++;
    }
    /* WinHTTP reporting no detail keeps the old answer: the lockout is the worse outcome. */
    g_cached = (PCCERT_CONTEXT)(uintptr_t)1;
    freed = 0;
    if (!Hub_RetryWithoutClientCert((HINTERNET)(uintptr_t)1, ERROR_WINHTTP_SECURE_FAILURE) || g_cached || freed != 1) {
        puts("A failure with no detail didn't put the certificate down");
        failures++;
    }
    printf("Client certificate fallback failures: %d\n", failures);
    return failures ? 1 : 0;
}
