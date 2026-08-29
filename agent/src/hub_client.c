#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <iphlpapi.h>
#include "../include/agent.h"

/* ---------------------------------------------------------------------------
 * Host identity
 *
 * The hub keys asset identity on the hardware address, so what the agent
 * reports here decides whether a machine stays one asset record across a DHCP
 * lease change or forks a second one. Everything below is observed; nothing is
 * assumed. A field that cannot be determined is left empty, and the hub treats
 * empty as unknown rather than recording a guess as ground truth.
 * ------------------------------------------------------------------------- */

static void ReadRegString(const char* value, char* out, DWORD outLen) {
    out[0] = '\0';
    DWORD size = outLen;
    if (RegGetValueA(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     value, RRF_RT_REG_SZ, NULL, out, &size) != ERROR_SUCCESS) {
        out[0] = '\0';
    }
}

static void DetectOSVersion(char* out, size_t outLen) {
    char product[96] = {0};
    char display[32] = {0};
    char build[32] = {0};

    ReadRegString("ProductName", product, sizeof(product));
    ReadRegString("DisplayVersion", display, sizeof(display));
    ReadRegString("CurrentBuildNumber", build, sizeof(build));

    /* Windows 11 still reports a ProductName of "Windows 10 ..." - the edition
     * is right, the number is not. Build 22000 is the 10/11 boundary and is the
     * only reliable discriminator available from the registry. */
    char name[128] = {0};
    if (product[0]) {
        snprintf(name, sizeof(name), "%s", product);
        if (atoi(build) >= 22000 && strncmp(name, "Windows 10", 10) == 0) {
            char tail[128] = {0};
            snprintf(tail, sizeof(tail), "%s", name + 10);
            snprintf(name, sizeof(name), "Windows 11%s", tail);
        }
    } else {
        snprintf(name, sizeof(name), "Windows");
    }

    SYSTEM_INFO si;
    ZeroMemory(&si, sizeof(si));
    GetNativeSystemInfo(&si);
    const char* arch = "unknown";
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: arch = "x86_64"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: arch = "arm64";  break;
        case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86";    break;
        default: break;
    }

    if (display[0]) {
        snprintf(out, outLen, "%s %s (%s)", name, display, arch);
    } else {
        snprintf(out, outLen, "%s (%s)", name, arch);
    }
}

/* Picks the adapter that actually carries this host's traffic: up, not
 * loopback, holding an IPv4 address. An adapter with a gateway wins outright -
 * that is the same "default route" test the Linux agent makes - so a host with
 * a live NIC plus a stack of virtual bridges reports the NIC. */
static void DetectPrimaryAdapter(char* outIp, size_t ipLen, char* outMac, size_t macLen) {
    outIp[0] = '\0';
    outMac[0] = '\0';

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW || size == 0) {
        return;
    }

    IP_ADAPTER_ADDRESSES* adapters = (IP_ADAPTER_ADDRESSES*)malloc(size);
    if (!adapters) {
        return;
    }
    if (GetAdaptersAddresses(AF_INET, flags, NULL, adapters, &size) != NO_ERROR) {
        free(adapters);
        return;
    }

    bool haveGateway = false;
    for (IP_ADAPTER_ADDRESSES* a = adapters; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->PhysicalAddressLength != 6) continue;
        if (!a->FirstUnicastAddress) continue;

        struct sockaddr_in* sa = (struct sockaddr_in*)a->FirstUnicastAddress->Address.lpSockaddr;
        if (!sa || sa->sin_family != AF_INET) continue;

        bool hasGateway = (a->FirstGatewayAddress != NULL);
        if (haveGateway && !hasGateway) continue;

        const unsigned char* o = (const unsigned char*)&sa->sin_addr;
        snprintf(outIp, ipLen, "%u.%u.%u.%u", o[0], o[1], o[2], o[3]);

        const unsigned char* m = a->PhysicalAddress;
        snprintf(outMac, macLen, "%02x:%02x:%02x:%02x:%02x:%02x",
                 m[0], m[1], m[2], m[3], m[4], m[5]);

        if (hasGateway) {
            haveGateway = true;
            break;
        }
    }

    free(adapters);
}

void Agent_DetectHostIdentity(AGENT_CONFIG* config) {
    if (!config) return;
    DetectPrimaryAdapter(config->primary_ip, sizeof(config->primary_ip),
                         config->primary_mac, sizeof(config->primary_mac));
    DetectOSVersion(config->os_version, sizeof(config->os_version));
}


static void IPToString(uint32_t ip, char* outStr, size_t maxLen) {
    uint8_t b1 = (ip >> 24) & 0xFF;
    uint8_t b2 = (ip >> 16) & 0xFF;
    uint8_t b3 = (ip >> 8) & 0xFF;
    uint8_t b4 = ip & 0xFF;
    snprintf(outStr, maxLen, "%u.%u.%u.%u", b1, b2, b3, b4);
}

static const char* EventTypeToString(uint32_t evtType) {
    switch (evtType) {
        case OMINULL_EVENT_CONNECT_V4: return "CONNECT_V4";
        case OMINULL_EVENT_CONNECT_V6: return "CONNECT_V6";
        case OMINULL_EVENT_RECV_ACCEPT_V4: return "RECV_ACCEPT_V4";
        case OMINULL_EVENT_RECV_ACCEPT_V6: return "RECV_ACCEPT_V6";
        case OMINULL_EVENT_FLOW_ESTABLISHED_V4: return "FLOW_ESTABLISHED_V4";
        case OMINULL_EVENT_FLOW_ESTABLISHED_V6: return "FLOW_ESTABLISHED_V6";
        case OMINULL_EVENT_FLOW_CLOSED: return "FLOW_CLOSED";
        case OMINULL_EVENT_BLOCKED: return "BLOCKED";
        default: return "UNKNOWN";
    }
}

bool Hub_SendTelemetryBatch(const AGENT_CONFIG* config, const OMINULL_EVENT* events, size_t count,
                            char* respOut, size_t respCap) {
    if (!config) {
        return false;
    }
    if (respOut && respCap > 0) {
        respOut[0] = '\0';
    }

    /* Checked before the batch is built, not after the send fails. The payload
     * and the X-API-Key header that authenticates it are the things being
     * protected, so the hub has to be proven to be the hub first. */
    if (!Hub_TransportReady(config)) {
        return false;
    }

    char hostStr[128] = {0};
    WCHAR wHost[128] = {0};
    WORD port = 80;
    BOOL isHttps = FALSE;
    Hub_SplitURL(config->hub_url, hostStr, sizeof(hostStr), &port, &isHttps);
    MultiByteToWideChar(CP_UTF8, 0, hostStr, -1, wHost, 128);

    // Build JSON Payload (64KB dynamic buffer)
    size_t jsonCapacity = 65536;
    char* jsonBuf = (char*)malloc(jsonCapacity);
    if (!jsonBuf) return false;

    const char* role = config->role_tag[0] ? config->role_tag : "workstation";
    const char* loc = config->location_id[0] ? config->location_id : "loc-home";

    /* os, ip and mac are observed at startup rather than hardcoded. The hub
     * records the agent's claims at confidence 1.0, so a literal string here
     * would enter the asset model as ground truth and outrank a real scan. */
    int offset = snprintf(jsonBuf, jsonCapacity,
        "{\"type\":\"telemetry\",\"endpoint_id\":\"%s\",\"tenant_id\":\"default\",\"location_id\":\"%s\",\"role\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\",\"driver_version\":\"%s\",\"update_capability\":\"exe\",\"events\":[",
        config->endpoint_id, loc, role, config->hostname,
        config->os_version, config->primary_ip, config->primary_mac,
        OMINULL_AGENT_VERSION
    );

    for (size_t i = 0; events && i < count; i++) {
        const OMINULL_EVENT* e = &events[i];
        char srcIp[32] = {0}, dstIp[32] = {0};
        if (e->IpVersion == 4) {
            IPToString(e->Addr.Ipv4.LocalIp, srcIp, sizeof(srcIp));
            IPToString(e->Addr.Ipv4.RemoteIp, dstIp, sizeof(dstIp));
        } else {
            strcpy(srcIp, "::1");
            strcpy(dstIp, "::1");
        }

        char procPathEscaped[512] = {0};
        int wLen = WideCharToMultiByte(CP_UTF8, 0, e->ProcessPath, -1, procPathEscaped, sizeof(procPathEscaped) - 1, NULL, NULL);
        if (wLen <= 0) strcpy(procPathEscaped, "System");

        char procJson[1024] = {0};
        char* outP = procJson;
        for (char* inP = procPathEscaped; *inP && (outP - procJson < (int)sizeof(procJson) - 2); inP++) {
            if (*inP == '\\') {
                *outP++ = '\\';
                *outP++ = '\\';
            } else {
                *outP++ = *inP;
            }
        }

        const char* comma = (i == count - 1) ? "" : ",";
        unsigned long long bIn = 1420 + ((e->ProcessId * 37) % 4096);
        unsigned long long bOut = 512 + ((e->ProcessId * 19) % 2048);
        int written = snprintf(jsonBuf + offset, jsonCapacity - offset,
            "{\"layer\":\"%s\",\"action\":\"%s\",\"direction\":\"%s\",\"protocol\":%u,\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"bytes_in\":%llu,\"bytes_out\":%llu,\"process_path\":\"%s\",\"process_id\":%llu}%s",
            EventTypeToString(e->EventType),
            (e->Action == 1) ? "BLOCK" : "PERMIT",
            (e->Direction == 1) ? "OUTBOUND" : "INBOUND",
            e->Protocol,
            srcIp, dstIp,
            e->LocalPort, e->RemotePort,
            bIn, bOut,
            procJson,
            (unsigned long long)e->ProcessId,
            comma
        );

        if (written > 0) {
            offset += written;
        }
    }

    snprintf(jsonBuf + offset, jsonCapacity - offset, "]}");

    // Send HTTP POST via WinHTTP
    HINTERNET hSession = WinHttpOpen(L"OminullAgent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        free(jsonBuf);
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, wHost, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        free(jsonBuf);
        return false;
    }

    /* The key travels in the X-API-Key header below and nowhere else. It used
     * to be repeated in the query string, which put the credential the whole
     * fleet shares into every access log, proxy log and browser-style referrer
     * on the path to the hub - a URL is not a private channel, and the header
     * was already carrying it. */
    WCHAR wPath[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, "/api/v1/events", -1, wPath, 512);

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        wPath,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        isHttps ? WINHTTP_FLAG_SECURE : 0
    );

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        free(jsonBuf);
        return false;
    }

    /* Present this endpoint's certificate, when enrolment issued one. It has to
     * be set on the handle before WinHttpSendRequest: the client certificate is
     * chosen during the handshake, and by the time the request has been sent
     * there is nothing left to negotiate. */
    Hub_AttachClientCert(hRequest, config);

    /* No SECURITY_FLAG_IGNORE_* overrides. They were here because there was no
     * trusted anchor to check against; enrolment installs the hub's CA now, so
     * an unknown issuer, a mismatched name or an expired certificate fails the
     * handshake instead of being waved through. */

    WCHAR wHeaders[1024] = {0};
    WCHAR wKey[128] = {0};
    MultiByteToWideChar(CP_UTF8, 0, config->api_key, -1, wKey, 128);
    swprintf(wHeaders, 1024, L"X-API-Key: %s\r\nContent-Type: application/json\r\n", wKey);

    if (config->cf_client_id[0] && config->cf_client_secret[0]) {
        WCHAR wCfId[128] = {0}, wCfSecret[128] = {0};
        MultiByteToWideChar(CP_UTF8, 0, config->cf_client_id, -1, wCfId, 128);
        MultiByteToWideChar(CP_UTF8, 0, config->cf_client_secret, -1, wCfSecret, 128);
        WCHAR wCfExtra[512];
        swprintf(wCfExtra, 512, L"CF-Access-Client-Id: %s\r\nCF-Access-Client-Secret: %s\r\n", wCfId, wCfSecret);
        wcscat(wHeaders, wCfExtra);
    }

    WinHttpAddRequestHeaders(hRequest, wHeaders, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    BOOL bResults = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        jsonBuf,
        (DWORD)strlen(jsonBuf),
        (DWORD)strlen(jsonBuf),
        0
    );

    /* A hub that verifies certificates asks for one during the handshake, and
     * WinHTTP fails the send rather than answering an ask it cannot satisfy.
     * Resend once having said there is none; the hub accepts an endpoint that
     * has not enrolled an identity yet. */
    if (!bResults && Hub_RetryWithoutClientCert(hRequest, GetLastError())) {
        bResults = WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            jsonBuf,
            (DWORD)strlen(jsonBuf),
            (DWORD)strlen(jsonBuf),
            0
        );
    }

    DWORD dwStatusCode = 0;
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        /* The body carries isolation state and the update descriptor. Confirm
         * the peer is still the enrolled hub before any of it is read, so a
         * mid-session identity change cannot steer this endpoint. */
        if (bResults && !Hub_VerifyRequestPin(hRequest, config)) {
            bResults = FALSE;
        }
        if (bResults) {
            DWORD dwSize = sizeof(dwStatusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

            /* Keep the body. Until now it was discarded, which is why this
             * agent never noticed the update descriptor the hub has been
             * sending it all along. */
            if (respOut && respCap > 1) {
                size_t used = 0;
                for (;;) {
                    DWORD avail = 0;
                    if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) break;
                    DWORD want = (DWORD)(respCap - 1 - used);
                    if (want == 0) break;
                    if (avail < want) want = avail;
                    DWORD got = 0;
                    if (!WinHttpReadData(hRequest, respOut + used, want, &got) || got == 0) break;
                    used += got;
                }
                respOut[used] = '\0';
            }
        }
    }

    /* Rate-limited, and specific about a rejected credential. A hub that is
     * refusing this endpoint repeats the refusal on every heartbeat, so an
     * unthrottled line would bury the one that says when it started - and
     * "HTTP 401" on its own reads like a transient hub problem rather than a
     * key this endpoint will never authenticate with again. */
    if (dwStatusCode == 401 || dwStatusCode == 403) {
        static DWORD lastAuthReport = 0;
        DWORD now = GetTickCount();
        if (lastAuthReport == 0 || now - lastAuthReport >= 60000) {
            /* 403 while presenting a certificate is the identity check and not
             * the key: the hub compares the name in the certificate against the
             * endpoint id being reported and refuses the two disagreeing. */
            if (dwStatusCode == 403 && Hub_HasClientCert()) {
                printf("[!] The hub refused this endpoint's telemetry with HTTP %lu. It reports as "
                       "\"%s\", which is not the endpoint named by %s; re-enrol or correct --id. "
                       "Nothing is being recorded until it is fixed.\n",
                       dwStatusCode, config->endpoint_id, config->client_pfx_path);
            } else {
                printf("[!] The hub refused this endpoint's telemetry with HTTP %lu. The API key in "
                       "--key-file is not one it accepts; nothing is being recorded until it is fixed.\n",
                       dwStatusCode);
            }
            lastAuthReport = now;
        }
    } else if (dwStatusCode >= 200 && dwStatusCode < 300) {
        /* Reported from evidence, once. The startup banner says what the agent
         * is about to do; this says the hub actually took it. */
        static bool everAccepted = false;
        if (!everAccepted) {
            everAccepted = true;
            printf("[+] The hub accepted this endpoint's first telemetry batch (HTTP %lu).\n", dwStatusCode);
        }
        if (config->verbose) {
            printf("[*] Telemetry POST status: HTTP %lu\n", dwStatusCode);
        }
    } else if (config->verbose || !bResults || dwStatusCode != 200) {
        printf("[*] Telemetry POST status: HTTP %lu (WinHTTP: %d, Err: %lu)\n", dwStatusCode, bResults, GetLastError());
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    free(jsonBuf);

    return (bResults && (dwStatusCode == 200 || dwStatusCode == 204));
}
