#include "../include/ominull_dpi.h"

BOOLEAN OminullDpiParseTlsSni(
    _In_reads_bytes_(Length) const UINT8* Buffer,
    _In_ SIZE_T Length,
    _Out_ POMINULL_DPI_RESULT Result
)
{
    if (!Buffer || Length < 44 || !Result) {
        return FALSE;
    }

    RtlZeroMemory(Result, sizeof(OMINULL_DPI_RESULT));

    // TLS Record Layer: ContentType == 22 (Handshake), Version >= TLS 1.0 (0x0301)
    if (Buffer[0] != 0x16 || Buffer[1] != 0x03) {
        return FALSE;
    }

    // Handshake Layer: HandshakeType == 1 (ClientHello)
    if (Buffer[5] != 0x01) {
        return FALSE;
    }

    SIZE_T pos = 43; // Skip Record (5) + Handshake (4) + ClientVersion (2) + Random (32)
    if (pos >= Length) return FALSE;

    // Skip Session ID
    UINT8 sessionIDLen = Buffer[pos++];
    pos += sessionIDLen;
    if (pos + 2 > Length) return FALSE;

    // Skip Cipher Suites
    UINT16 cipherSuitesLen = ((UINT16)Buffer[pos] << 8) | Buffer[pos + 1];
    pos += 2 + cipherSuitesLen;
    if (pos + 1 > Length) return FALSE;

    // Skip Compression Methods
    UINT8 compressionMethodsLen = Buffer[pos++];
    pos += compressionMethodsLen;
    if (pos + 2 > Length) return FALSE;

    // Extensions
    UINT16 extensionsLen = ((UINT16)Buffer[pos] << 8) | Buffer[pos + 1];
    pos += 2;

    SIZE_T extensionsEnd = pos + extensionsLen;
    if (extensionsEnd > Length) extensionsEnd = Length;

    while (pos + 4 <= extensionsEnd) {
        UINT16 extType = ((UINT16)Buffer[pos] << 8) | Buffer[pos + 1];
        UINT16 extLen = ((UINT16)Buffer[pos + 2] << 8) | Buffer[pos + 3];
        pos += 4;

        if (pos + extLen > extensionsEnd) break;

        // Extension 0x0000 = server_name (SNI)
        if (extType == 0x0000 && extLen >= 5) {
            SIZE_T sniPos = pos + 2; // Skip ServerNameListLength
            if (sniPos + 3 <= pos + extLen) {
                UINT8 nameType = Buffer[sniPos++]; // 0 = host_name
                UINT16 nameLen = ((UINT16)Buffer[sniPos] << 8) | Buffer[sniPos + 1];
                sniPos += 2;

                if (nameType == 0 && nameLen > 0 && sniPos + nameLen <= pos + extLen) {
                    if (nameLen >= OMINULL_MAX_DOMAIN_LEN) {
                        nameLen = OMINULL_MAX_DOMAIN_LEN - 1;
                    }
                    RtlCopyMemory(Result->DomainName, &Buffer[sniPos], nameLen);
                    Result->DomainName[nameLen] = '\0';
                    Result->DomainNameLen = nameLen;
                    Result->ProtocolType = 1; // TLS SNI
                    Result->Identified = TRUE;
                    return TRUE;
                }
            }
        }
        pos += extLen;
    }

    return FALSE;
}

BOOLEAN OminullDpiParseHttpHost(
    _In_reads_bytes_(Length) const UINT8* Buffer,
    _In_ SIZE_T Length,
    _Out_ POMINULL_DPI_RESULT Result
)
{
    if (!Buffer || Length < 10 || !Result) {
        return FALSE;
    }

    RtlZeroMemory(Result, sizeof(OMINULL_DPI_RESULT));

    // Check for HTTP Methods
    if (strncmp((const char*)Buffer, "GET ", 4) != 0 &&
        strncmp((const char*)Buffer, "POST ", 5) != 0 &&
        strncmp((const char*)Buffer, "HEAD ", 5) != 0 &&
        strncmp((const char*)Buffer, "CONNECT ", 8) != 0 &&
        strncmp((const char*)Buffer, "PUT ", 4) != 0) {
        return FALSE;
    }

    // Search for "Host: " header
    const char* str = (const char*)Buffer;
    SIZE_T maxSearch = (Length > 1024) ? 1024 : Length;

    for (SIZE_T i = 0; i + 6 < maxSearch; i++) {
        if ((str[i] == '\n' || str[i] == '\r') &&
            (_strnicmp(&str[i + 1], "Host:", 5) == 0 || _strnicmp(&str[i + 2], "Host:", 5) == 0)) {
            
            const char* hostStart = strstr(&str[i], "Host:");
            if (!hostStart) hostStart = strstr(&str[i], "host:");
            if (!hostStart) continue;

            hostStart += 5;
            while (*hostStart == ' ' || *hostStart == '\t') hostStart++;

            const char* hostEnd = hostStart;
            while (*hostEnd != '\r' && *hostEnd != '\n' && *hostEnd != ':' && (SIZE_T)(hostEnd - str) < maxSearch) {
                hostEnd++;
            }

            SIZE_T hostLen = hostEnd - hostStart;
            if (hostLen > 0 && hostLen < OMINULL_MAX_DOMAIN_LEN) {
                RtlCopyMemory(Result->DomainName, hostStart, hostLen);
                Result->DomainName[hostLen] = '\0';
                Result->DomainNameLen = (UINT16)hostLen;
                Result->ProtocolType = 2; // HTTP Host
                Result->Identified = TRUE;
                return TRUE;
            }
        }
    }

    return FALSE;
}

BOOLEAN OminullDpiParseDnsQuery(
    _In_reads_bytes_(Length) const UINT8* Buffer,
    _In_ SIZE_T Length,
    _Out_ POMINULL_DPI_RESULT Result
)
{
    if (!Buffer || Length < 14 || !Result) {
        return FALSE;
    }

    RtlZeroMemory(Result, sizeof(OMINULL_DPI_RESULT));

    // DNS Header is 12 bytes. Questions count is at bytes 4-5
    UINT16 qdCount = ((UINT16)Buffer[4] << 8) | Buffer[5];
    if (qdCount == 0) return FALSE;

    SIZE_T pos = 12;
    CHAR domain[OMINULL_MAX_DOMAIN_LEN] = {0};
    SIZE_T dPos = 0;

    while (pos < Length) {
        UINT8 labelLen = Buffer[pos++];
        if (labelLen == 0) {
            break; // End of domain
        }

        // Pointer / compression check
        if ((labelLen & 0xC0) != 0) {
            break;
        }

        if (pos + labelLen > Length) {
            return FALSE;
        }

        if (dPos > 0 && dPos < sizeof(domain) - 1) {
            domain[dPos++] = '.';
        }

        for (UINT8 i = 0; i < labelLen && dPos < sizeof(domain) - 1; i++) {
            CHAR c = (CHAR)Buffer[pos++];
            if (c >= 'A' && c <= 'Z') c += ('a' - 'A'); // lowercase
            domain[dPos++] = c;
        }
    }

    if (dPos > 0) {
        domain[dPos] = '\0';
        RtlCopyMemory(Result->DomainName, domain, dPos + 1);
        Result->DomainNameLen = (UINT16)dPos;
        Result->ProtocolType = 3; // DNS Query
        Result->Identified = TRUE;
        return TRUE;
    }

    return FALSE;
}

BOOLEAN OminullDpiInspectPayload(
    _In_reads_bytes_(Length) const UINT8* Buffer,
    _In_ SIZE_T Length,
    _In_ UINT16 Port,
    _Out_ POMINULL_DPI_RESULT Result
)
{
    if (!Buffer || Length == 0 || !Result) {
        return FALSE;
    }

    if (Port == 53 && OminullDpiParseDnsQuery(Buffer, Length, Result)) {
        return TRUE;
    }

    if ((Port == 443 || Buffer[0] == 0x16) && OminullDpiParseTlsSni(Buffer, Length, Result)) {
        return TRUE;
    }

    if ((Port == 80 || Port == 8080 || Buffer[0] == 'G' || Buffer[0] == 'P' || Buffer[0] == 'H' || Buffer[0] == 'C') &&
        OminullDpiParseHttpHost(Buffer, Length, Result)) {
        return TRUE;
    }

    if (OminullDpiParseDnsQuery(Buffer, Length, Result)) {
        return TRUE;
    }

    return FALSE;
}
