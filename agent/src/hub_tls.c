/* ---------------------------------------------------------------------------
 * Hub transport security (Windows)
 *
 * Everything this agent sends to the hub carries the tenant API key, and
 * everything it reads back can move the host: an isolation command, a mesh
 * quarantine list, a release descriptor. On plain HTTP all of that is readable
 * and forgeable by anyone on the path.
 *
 * WinHTTP used to be told to ignore an unknown CA, a wrong usage, a mismatched
 * name and an expired certificate. Those four flags existed because there was
 * no trusted anchor to check against; enrolment now installs the hub's CA, so
 * they are gone and every hub request is validated normally.
 *
 * Validation alone is not the whole guarantee. Windows would accept any
 * certificate from any anchor in the machine store, so this file adds the pin:
 * the chain the hub presents has to end at the CA enrolment planted on disk,
 * and no other.
 *
 * The pin runs as a preflight rather than as a check on the request that
 * carries the key. WinHTTP hands out the negotiated certificate only after the
 * request has been sent, so checking there would detect an impostor only once
 * the API key had already been given to it. The preflight fetches the hub's
 * public CA endpoint - which carries no secret - proves the peer is the hub,
 * and only then is the real request allowed to go. Every later response is
 * checked too, so a hub that changes identity mid-session is refused before
 * anything it said is acted on.
 * ------------------------------------------------------------------------- */

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/agent.h"

#ifndef WINHTTP_OPTION_SERVER_CERT_CONTEXT
#define WINHTTP_OPTION_SERVER_CERT_CONTEXT 78
#endif

/* The agent runs as LocalSystem, so chains are built against the machine store
 * that enrolment imported the CA into. */
#ifndef HCCE_LOCAL_MACHINE
#define HCCE_LOCAL_MACHINE ((HCERTCHAINENGINE)0x1)
#endif

/* How long a successful preflight is trusted for. Long enough that the
 * telemetry loop is not re-handshaking every few seconds, short enough that a
 * revoked or replaced hub identity is noticed within one coffee break. */
#define PIN_REVALIDATE_MS (15 * 60 * 1000)

void Hub_SplitURL(const char* hubUrl, char* host, size_t hostLen, WORD* port, BOOL* isHttps) {
    const char* p = hubUrl;
    *isHttps = FALSE;
    *port = 80;
    if (strncmp(p, "https://", 8) == 0) {
        *isHttps = TRUE;
        *port = 443;
        p += 8;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    }
    const char* colon = strchr(p, ':');
    const char* slash = strchr(p, '/');
    if (colon) {
        snprintf(host, hostLen, "%.*s", (int)(colon - p), p);
        *port = (WORD)atoi(colon + 1);
    } else if (slash) {
        snprintf(host, hostLen, "%.*s", (int)(slash - p), p);
    } else {
        snprintf(host, hostLen, "%s", p);
    }
}

bool Hub_UsesTLS(const AGENT_CONFIG* config) {
    return config && strncmp(config->hub_url, "https://", 8) == 0;
}

/* Complains at most once a minute. The failure persists until an operator fixes
 * it, and the telemetry loop would otherwise fill the log with one line every
 * few seconds. */
static void ReportRefusal(const char* reason) {
    static ULONGLONG lastReport = 0;
    ULONGLONG now = GetTickCount64();
    if (lastReport != 0 && now - lastReport < 60000) return;
    lastReport = now;
    fprintf(stderr, "[!] Refusing to talk to the hub: %s\n", reason);
    fflush(stderr);
}

/* LoadPinnedCA reads the PEM enrolment left on disk and turns it into a
 * certificate context. A file that is not a certificate fails here rather than
 * becoming a trust anchor. */
static PCCERT_CONTEXT LoadPinnedCA(const char* caPath) {
    HANDLE hFile = CreateFileA(caPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0 || size > 64 * 1024) {
        CloseHandle(hFile);
        return NULL;
    }

    char* pem = (char*)malloc(size + 1);
    if (!pem) {
        CloseHandle(hFile);
        return NULL;
    }
    DWORD got = 0;
    BOOL read = ReadFile(hFile, pem, size, &got, NULL);
    CloseHandle(hFile);
    if (!read || got == 0) {
        free(pem);
        return NULL;
    }
    pem[got] = '\0';

    DWORD derLen = 0;
    if (!CryptStringToBinaryA(pem, got, CRYPT_STRING_BASE64HEADER, NULL, &derLen, NULL, NULL) || derLen == 0) {
        free(pem);
        return NULL;
    }
    BYTE* der = (BYTE*)malloc(derLen);
    if (!der) {
        free(pem);
        return NULL;
    }
    if (!CryptStringToBinaryA(pem, got, CRYPT_STRING_BASE64HEADER, der, &derLen, NULL, NULL)) {
        free(der);
        free(pem);
        return NULL;
    }
    free(pem);

    PCCERT_CONTEXT ca = CertCreateCertificateContext(X509_ASN_ENCODING, der, derLen);
    free(der);
    return ca;
}

/* ChainEndsAtPinnedCA builds the chain for the certificate the hub presented
 * and compares its root, byte for byte, with the pinned CA. Comparing the
 * encoded certificate rather than a name or a serial is deliberate: those are
 * chosen by whoever issued the certificate, and an impostor picks its own. */
static bool ChainEndsAtPinnedCA(PCCERT_CONTEXT serverCert, PCCERT_CONTEXT pinnedCA) {
    CERT_CHAIN_PARA para;
    ZeroMemory(&para, sizeof(para));
    para.cbSize = sizeof(para);

    PCCERT_CHAIN_CONTEXT chain = NULL;
    if (!CertGetCertificateChain(HCCE_LOCAL_MACHINE, serverCert, NULL, NULL, &para, 0, NULL, &chain)) {
        return false;
    }

    bool ok = false;
    if (chain->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR &&
        chain->cChain > 0 && chain->rgpChain[0]->cElement > 0) {
        DWORD last = chain->rgpChain[0]->cElement - 1;
        PCCERT_CONTEXT root = chain->rgpChain[0]->rgpElement[last]->pCertContext;
        ok = root->cbCertEncoded == pinnedCA->cbCertEncoded &&
             memcmp(root->pbCertEncoded, pinnedCA->pbCertEncoded, pinnedCA->cbCertEncoded) == 0;
    }

    CertFreeCertificateChain(chain);
    return ok;
}

bool Hub_VerifyRequestPin(void* hRequest, const AGENT_CONFIG* config) {
    if (!Hub_UsesTLS(config)) return true;

    PCCERT_CONTEXT serverCert = NULL;
    DWORD certLen = sizeof(serverCert);
    if (!WinHttpQueryOption((HINTERNET)hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                            &serverCert, &certLen) || !serverCert) {
        ReportRefusal("WinHTTP did not report the certificate the hub presented, so it cannot be pinned.");
        return false;
    }

    PCCERT_CONTEXT pinnedCA = LoadPinnedCA(config->ca_path);
    if (!pinnedCA) {
        char reason[512];
        snprintf(reason, sizeof(reason),
                 "the CA certificate %s could not be read or is not a certificate. Enrolment "
                 "installs it; without it the hub's identity cannot be checked.", config->ca_path);
        ReportRefusal(reason);
        CertFreeCertificateContext(serverCert);
        return false;
    }

    bool ok = ChainEndsAtPinnedCA(serverCert, pinnedCA);
    if (!ok) {
        ReportRefusal("the certificate presented does not chain to the CA this endpoint was enrolled with. "
                      "Something other than the hub answered, and nothing it said will be acted on.");
    }

    CertFreeCertificateContext(pinnedCA);
    CertFreeCertificateContext(serverCert);
    return ok;
}

/* Preflight dials the hub's public CA endpoint and pins the answer. Nothing
 * secret is sent, so an impostor learns only that an Ominull agent exists -
 * and it never gets the API key, because the telemetry request is not made
 * until this has passed. */
static bool Preflight(const AGENT_CONFIG* config) {
    char host[128] = {0};
    WORD port = 443;
    BOOL isHttps = FALSE;
    Hub_SplitURL(config->hub_url, host, sizeof(host), &port, &isHttps);

    WCHAR wHost[128] = {0};
    MultiByteToWideChar(CP_UTF8, 0, host, -1, wHost, 128);

    bool ok = false;
    HINTERNET hRequest = NULL, hConnect = NULL;
    HINTERNET hSession = WinHttpOpen(L"OminullAgent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    WinHttpSetTimeouts(hSession, 5000, 5000, 10000, 10000);

    hConnect = WinHttpConnect(hSession, wHost, port, 0);
    if (!hConnect) goto done;

    /* No SECURITY_FLAG overrides. An unknown CA, a wrong name or an expired
     * certificate must fail the handshake here, before the pin is even
     * reached. */
    hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/v1/pki/ca.crt", NULL,
                                  WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hRequest) goto done;

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
        char reason[256];
        snprintf(reason, sizeof(reason),
                 "the TLS handshake with %s was rejected (WinHTTP error %lu). The hub's CA has to be "
                 "installed in the machine trust store for the connection to be made at all.",
                 host, GetLastError());
        ReportRefusal(reason);
        goto done;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) goto done;

    ok = Hub_VerifyRequestPin(hRequest, config);

done:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

bool Hub_TransportReady(const AGENT_CONFIG* config) {
    if (!config) return false;

    if (!Hub_UsesTLS(config)) {
        if (config->allow_plaintext) return true;
        ReportRefusal("the configured hub URL is not https://. Re-enrol this endpoint against the hub's "
                      "TLS address, or pass --allow-plaintext to accept a cleartext transport deliberately.");
        return false;
    }

    if (config->ca_path[0] == '\0') {
        ReportRefusal("no CA certificate is configured; pass --ca <path>.");
        return false;
    }

    static ULONGLONG lastOk = 0;
    ULONGLONG now = GetTickCount64();
    if (lastOk != 0 && now - lastOk < PIN_REVALIDATE_MS) {
        return true;
    }
    if (!Preflight(config)) {
        return false;
    }
    lastOk = now;
    return true;
}
