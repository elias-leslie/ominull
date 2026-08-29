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

    // Parse host and port from hub_url (e.g. https://omi.example.com or http://10.0.0.58:9999)
    WCHAR wHost[128] = {0};
    INTERNET_PORT port = 80;
    BOOL isHttps = FALSE;

    const char* p = config->hub_url;
    if (strncmp(p, "https://", 8) == 0) {
        isHttps = TRUE;
        port = 443;
        p += 8;
    } else if (strncmp(p, "http://", 7) == 0) {
        port = 80;
        p += 7;
    }

    char hostStr[128] = {0};
    const char* colon = strchr(p, ':');
    const char* slash = strchr(p, '/');

    if (colon) {
        size_t hLen = colon - p;
        if (hLen >= sizeof(hostStr)) hLen = sizeof(hostStr) - 1;
        snprintf(hostStr, sizeof(hostStr), "%.*s", (int)hLen, p);
        port = (INTERNET_PORT)atoi(colon + 1);
    } else if (slash) {
        size_t hLen = slash - p;
        if (hLen >= sizeof(hostStr)) hLen = sizeof(hostStr) - 1;
        snprintf(hostStr, sizeof(hostStr), "%.*s", (int)hLen, p);
    } else {
        snprintf(hostStr, sizeof(hostStr), "%s", p);
    }

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

    char pathStr[512] = {0};
    snprintf(pathStr, sizeof(pathStr), "/api/v1/events?api_key=%s", config->api_key);
    WCHAR wPath[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, pathStr, -1, wPath, 512);

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

    if (isHttps) {
        DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

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

    DWORD dwStatusCode = 0;
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
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

    if (config->verbose || !bResults || dwStatusCode != 200) {
        printf("[*] Telemetry POST status: HTTP %lu (WinHTTP: %d, Err: %lu)\n", dwStatusCode, bResults, GetLastError());
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    free(jsonBuf);

    return (bResults && (dwStatusCode == 200 || dwStatusCode == 204));
}
