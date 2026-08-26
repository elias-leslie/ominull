#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "../include/agent.h"

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

bool Hub_SendTelemetryBatch(const AGENT_CONFIG* config, const OMINULL_EVENT* events, size_t count) {
    if (!config || !events || count == 0) {
        return false;
    }

    // Parse host and port from hub_url (e.g. http://10.0.0.57:9999)
    WCHAR wHost[128] = {0};
    INTERNET_PORT port = 9999;
    BOOL isHttps = FALSE;

    const char* p = config->hub_url;
    if (strncmp(p, "https://", 8) == 0) {
        isHttps = TRUE;
        p += 8;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    }

    char hostStr[128] = {0};
    const char* colon = strchr(p, ':');
    const char* slash = strchr(p, '/');

    if (colon) {
        size_t hLen = colon - p;
        if (hLen >= sizeof(hostStr)) hLen = sizeof(hostStr) - 1;
        strncpy(hostStr, p, hLen);
        port = (INTERNET_PORT)atoi(colon + 1);
    } else if (slash) {
        size_t hLen = slash - p;
        if (hLen >= sizeof(hostStr)) hLen = sizeof(hostStr) - 1;
        strncpy(hostStr, p, hLen);
    } else {
        strncpy(hostStr, p, sizeof(hostStr) - 1);
    }

    MultiByteToWideChar(CP_UTF8, 0, hostStr, -1, wHost, 128);

    // Build JSON Payload (64KB dynamic buffer)
    size_t jsonCapacity = 65536;
    char* jsonBuf = (char*)malloc(jsonCapacity);
    if (!jsonBuf) return false;

    int offset = snprintf(jsonBuf, jsonCapacity,
        "{\"type\":\"telemetry\",\"endpoint_id\":\"%s\",\"hostname\":\"%s\",\"os\":\"Windows\",\"driver_version\":\"%s\",\"events\":[",
        config->endpoint_id, config->hostname, OMINULL_AGENT_VERSION
    );

    for (size_t i = 0; i < count; i++) {
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
        int written = snprintf(jsonBuf + offset, jsonCapacity - offset,
            "{\"layer\":\"%s\",\"action\":\"%s\",\"direction\":\"%s\",\"protocol\":%u,\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"process_path\":\"%s\",\"process_id\":%llu}%s",
            EventTypeToString(e->EventType),
            (e->Action == 1) ? "BLOCK" : "PERMIT",
            (e->Direction == 1) ? "OUTBOUND" : "INBOUND",
            e->Protocol,
            srcIp, dstIp,
            e->LocalPort, e->RemotePort,
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

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        L"/api/v1/events",
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

    WCHAR wKeyHeader[256];
    WCHAR wKey[128];
    MultiByteToWideChar(CP_UTF8, 0, config->api_key, -1, wKey, 128);
    swprintf(wKeyHeader, 256, L"X-API-Key: %s\r\nContent-Type: application/json\r\n", wKey);

    WinHttpAddRequestHeaders(hRequest, wKeyHeader, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    BOOL bResults = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        jsonBuf,
        (DWORD)strlen(jsonBuf),
        (DWORD)strlen(jsonBuf),
        0
    );

    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    free(jsonBuf);

    return bResults ? true : false;
}
