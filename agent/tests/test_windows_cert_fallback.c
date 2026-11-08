/* Hub_RetryWithoutClientCert under the kinds of failed handshake: a certificate this
 * endpoint can't use is put down, so it can't lock itself out of its own updates; a
 * server whose own certificate fails costs it nothing, whoever sent it there. */
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#define FIXTURE_FAILED ((HINTERNET)(uintptr_t)1)
#define FIXTURE_OTHER ((HINTERNET)(uintptr_t)2)
static BOOL canOpen, sendWithCert, receiveWithCert, answersWithout, offered;
static int asks, opened, closed;
static HINTERNET FixtureOpen(LPCWSTR a, DWORD b, LPCWSTR c, LPCWSTR d, DWORD e) {
    (void)a; (void)b; (void)c; (void)d; (void)e;
    if (!canOpen) return NULL;
    opened++;
    return FIXTURE_OTHER;
}
static BOOL FixtureTimeouts(HINTERNET h, int a, int b, int c, int d) {
    (void)h; (void)a; (void)b; (void)c; (void)d;
    return TRUE;
}
static HINTERNET FixtureConnect(HINTERNET h, LPCWSTR host, INTERNET_PORT port, DWORD c) {
    (void)h; (void)c;
    if (wcscmp(host, L"2001:db8::9") || port != 9443) puts("Asked the wrong address");
    opened++;
    return FIXTURE_OTHER;
}
static HINTERNET FixtureOpenRequest(HINTERNET h, LPCWSTR a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR *e, DWORD f) {
    (void)h; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    opened++;
    offered = FALSE;
    return FIXTURE_OTHER;
}
static BOOL FixtureSetOption(HINTERNET h, DWORD option, LPVOID value, DWORD len) {
    (void)h; (void)len;
    if (option == WINHTTP_OPTION_CLIENT_CERT_CONTEXT && value) offered = TRUE;
    return TRUE;
}
static DWORD sendError = ERROR_WINHTTP_SECURE_FAILURE;
static BOOL FixtureSend(HINTERNET h, LPCWSTR a, DWORD b, LPVOID c, DWORD d, DWORD e, DWORD_PTR f) {
    (void)h; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    asks++;
    BOOL sent = offered ? sendWithCert : answersWithout;
    if (!sent) SetLastError(sendError);
    return sent;
}
static DWORD receiveError = SEC_E_UNTRUSTED_ROOT;
static BOOL FixtureReceive(HINTERNET h, LPVOID a) {
    (void)h; (void)a;
    if (offered && !receiveWithCert) {
        SetLastError(receiveError);
        return FALSE;
    }
    return TRUE;
}
static BOOL FixtureClose(HINTERNET h) {
    (void)h;
    closed++;
    return TRUE;
}
#define WinHttpOpen FixtureOpen
#define WinHttpSetTimeouts FixtureTimeouts
#define WinHttpConnect FixtureConnect
#define WinHttpOpenRequest FixtureOpenRequest
#define WinHttpSetOption FixtureSetOption
#define WinHttpSendRequest FixtureSend
#define WinHttpReceiveResponse FixtureReceive
#define WinHttpCloseHandle FixtureClose
#include "../src/hub_tls.c"

static AGENT_CONFIG config;
static int failures;
typedef struct {
    const char *name;
    unsigned long err;
    BOOL canOpen, sendWithCert, receiveWithCert, answersWithout;
    bool wantRetry, wantKept;
    int wantAsks;
} CASE;
static void Check(const CASE *c) {
    g_cached = (PCCERT_CONTEXT)(uintptr_t)1;
    g_certUnusable = false;
    g_clientCertLoaded = true;
    canOpen = c->canOpen;
    sendWithCert = c->sendWithCert;
    receiveWithCert = c->receiveWithCert;
    answersWithout = c->answersWithout;
    asks = opened = closed = 0;
    bool retry = Hub_RetryWithoutClientCert(FIXTURE_FAILED, c->err, &config);
    if (retry != c->wantRetry || (g_cached != NULL) != c->wantKept || g_certUnusable == c->wantKept ||
        asks != c->wantAsks || opened != closed || GetLastError() != c->err) {
        printf("%s: retry %d, certificate kept %d, asked %d, opened %d, closed %d, last error %lu\n", c->name, retry,
               g_cached != NULL, asks, opened, closed, GetLastError());
        failures++;
    }
}
int main(void) {
    snprintf(config.hub_url, sizeof(config.hub_url), "https://[2001:db8::9]:9443");
    const unsigned long tls = ERROR_WINHTTP_SECURE_FAILURE;
    static const CASE cases[] = {
        {"a server whose own certificate fails", tls, TRUE, FALSE, FALSE, FALSE, false, true, 2},
        {"a certificate only this endpoint can't use", tls, TRUE, FALSE, FALSE, TRUE, true, false, 2},
        {"a certificate the hub refuses after the handshake", tls, TRUE, TRUE, FALSE, TRUE, true, false, 2},
        {"a wrong address this time, the right one on a fresh lookup", tls, TRUE, TRUE, TRUE, TRUE, false, true, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) Check(&cases[i]);
    /* These don't reach the hub, so the last error is whatever they were given. */
    static const CASE unasked[] = {
        {"a failure that can't be asked about", tls, FALSE, FALSE, FALSE, FALSE, false, true, 0},
    };
    Check(&unasked[0]);
    /* The hub answering a moment later says nothing about a certificate that never got
     * as far as a TLS failure. */
    static const CASE notTLS = {"a hub restarting between the two questions", tls, TRUE, FALSE, FALSE, TRUE, false, true, 1};
    sendError = ERROR_WINHTTP_CANNOT_CONNECT;
    Check(&notTLS);
    sendError = ERROR_WINHTTP_SECURE_FAILURE;
    static const CASE timedOut = {"an answer that timed out", tls, TRUE, TRUE, FALSE, TRUE, false, true, 1};
    receiveError = ERROR_WINHTTP_TIMEOUT;
    Check(&timedOut);
    receiveError = SEC_E_UNTRUSTED_ROOT;
    g_cached = (PCCERT_CONTEXT)(uintptr_t)1;
    g_certUnusable = false;
    asks = 0;
    if (!Hub_RetryWithoutClientCert(FIXTURE_FAILED, ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED, &config) || !g_cached || asks) {
        puts("The hub asking who this is shouldn't cost the certificate or a question");
        failures++;
    }
    if (Hub_RetryWithoutClientCert(FIXTURE_FAILED, ERROR_WINHTTP_CANNOT_CONNECT, &config) || !g_cached || asks) {
        puts("Any other failure shouldn't cost the certificate or a question");
        failures++;
    }
    /* Under TLS 1.3 the hub's refusal lands on the preflight's receive, as seen on real
     * Windows. It puts the certificate down, and the next preflight goes without it. */
    snprintf(config.client_pfx_path, sizeof(config.client_pfx_path), "unused");
    canOpen = sendWithCert = answersWithout = TRUE;
    receiveWithCert = FALSE;
    g_cached = (PCCERT_CONTEXT)(uintptr_t)1;
    g_certUnusable = false;
    receiveError = ERROR_WINHTTP_TIMEOUT;
    asks = 0;
    if (Hub_TransportReady(&config) || !g_cached || asks != 1) {
        printf("A timeout isn't a refusal: certificate kept %d, asked %d\n", g_cached != NULL, asks);
        failures++;
    }
    receiveError = SEC_E_UNTRUSTED_ROOT;
    if (Hub_TransportReady(&config) || g_cached || !g_certUnusable) {
        printf("A refusal after the handshake kept the certificate: unusable %d\n", g_certUnusable);
        failures++;
    }
    if (!Hub_TransportReady(&config)) {
        puts("The preflight after a refusal didn't go through without the certificate");
        failures++;
    }
    /* A dropped certificate gets another try on the hour, in case the drop was wrong. */
    g_droppedAt = GetTickCount() - (CLIENT_CERT_RECHECK_MS - 60000);
    if (Hub_AttachClientCert(FIXTURE_OTHER, &config) || g_cached) {
        puts("A dropped certificate came back early");
        failures++;
    }
    g_droppedAt = GetTickCount() - CLIENT_CERT_RECHECK_MS;
    if (!Hub_AttachClientCert(FIXTURE_OTHER, &config) || !g_cached || g_certUnusable || !Hub_HasClientCert()) {
        printf("A dropped certificate didn't come back on the hour: unusable %d\n", g_certUnusable);
        failures++;
    }
    if (!Hub_RetryWithoutClientCert(FIXTURE_FAILED, tls, &config) || g_cached || !g_certUnusable) {
        puts("A certificate still refused on the hour wasn't dropped again");
        failures++;
    }
    printf("Client certificate fallback failures: %d\n", failures);
    return failures ? 1 : 0;
}
