/* Hub_RetryWithoutClientCert under the two kinds of failed handshake: a certificate
 * this endpoint can't use is put down, so it can't lock itself out of its own updates;
 * a server whose own certificate fails costs it nothing, whoever sent it there. */
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#define FIXTURE_FAILED ((HINTERNET)(uintptr_t)1)
#define FIXTURE_OTHER ((HINTERNET)(uintptr_t)2)
static BOOL urlKnown = TRUE, serverOk;
static int sends, opened, closed;
static BOOL FixtureQueryOption(HINTERNET h, DWORD option, LPVOID out, LPDWORD size) {
    (void)h;
    if (!urlKnown || option != WINHTTP_OPTION_URL) return FALSE;
    static const WCHAR url[] = L"https://hub.example:9443/api/v1/events";
    memcpy(out, url, sizeof(url));
    *size = sizeof(url);
    return TRUE;
}
static HINTERNET FixtureOpen(LPCWSTR a, DWORD b, LPCWSTR c, LPCWSTR d, DWORD e) {
    (void)a; (void)b; (void)c; (void)d; (void)e;
    opened++;
    return FIXTURE_OTHER;
}
static BOOL FixtureTimeouts(HINTERNET h, int a, int b, int c, int d) {
    (void)h; (void)a; (void)b; (void)c; (void)d;
    return TRUE;
}
static HINTERNET FixtureConnect(HINTERNET h, LPCWSTR host, INTERNET_PORT port, DWORD c) {
    (void)h; (void)c;
    if (wcscmp(host, L"hub.example") || port != 9443) puts("Asked the wrong address");
    opened++;
    return FIXTURE_OTHER;
}
static HINTERNET FixtureOpenRequest(HINTERNET h, LPCWSTR a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR *e, DWORD f) {
    (void)h; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    opened++;
    return FIXTURE_OTHER;
}
static BOOL FixtureSend(HINTERNET h, LPCWSTR a, DWORD b, LPVOID c, DWORD d, DWORD e, DWORD_PTR f) {
    (void)h; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    sends++;
    return serverOk;
}
static BOOL FixtureSetOption(HINTERNET h, DWORD a, LPVOID b, DWORD c) {
    (void)h; (void)a; (void)b; (void)c;
    return TRUE;
}
static BOOL FixtureClose(HINTERNET h) {
    (void)h;
    closed++;
    return TRUE;
}
#define WinHttpQueryOption FixtureQueryOption
#define WinHttpOpen FixtureOpen
#define WinHttpSetTimeouts FixtureTimeouts
#define WinHttpConnect FixtureConnect
#define WinHttpOpenRequest FixtureOpenRequest
#define WinHttpSendRequest FixtureSend
#define WinHttpSetOption FixtureSetOption
#define WinHttpCloseHandle FixtureClose
#include "../src/hub_tls.c"

static int failures;
static void Check(const char *name, unsigned long err, BOOL known, BOOL server, bool wantRetry, bool wantKept, int wantSends) {
    g_cached = (PCCERT_CONTEXT)(uintptr_t)1;
    g_certUnusable = false;
    g_clientCertLoaded = true;
    urlKnown = known;
    serverOk = server;
    sends = opened = closed = 0;
    bool retry = Hub_RetryWithoutClientCert(FIXTURE_FAILED, err);
    if (retry != wantRetry || (g_cached != NULL) != wantKept || g_certUnusable == wantKept || sends != wantSends || opened != closed) {
        printf("%s: retry %d, certificate kept %d, handshakes %d, opened %d, closed %d\n", name, retry, g_cached != NULL, sends, opened, closed);
        failures++;
    }
}
int main(void) {
    Check("a server whose own certificate fails", ERROR_WINHTTP_SECURE_FAILURE, TRUE, FALSE, false, true, 1);
    Check("a certificate only this endpoint can't use", ERROR_WINHTTP_SECURE_FAILURE, TRUE, TRUE, true, false, 1);
    Check("a failure that can't be asked about", ERROR_WINHTTP_SECURE_FAILURE, FALSE, FALSE, true, false, 0);
    Check("the hub asking who this is", ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED, TRUE, FALSE, true, true, 0);
    Check("any other failure", ERROR_WINHTTP_CANNOT_CONNECT, TRUE, TRUE, false, true, 0);
    printf("Client certificate fallback failures: %d\n", failures);
    return failures ? 1 : 0;
}
