#ifndef OMINULL_DPI_H
#define OMINULL_DPI_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

// Parse TLS ClientHello SNI from raw payload buffer
static inline bool DPI_ParseTLSClientHello(const uint8_t* data, size_t len, char* outSni, size_t maxSniLen) {
    if (!data || len < 44 || !outSni || maxSniLen < 2) return false;

    // TLS Record Layer: ContentType 0x16 (Handshake), Version 0x03 0x01/02/03
    if (data[0] != 0x16 || data[1] != 0x03) return false;

    uint16_t recordLen = (data[3] << 8) | data[4];
    if (len < (size_t)(5 + recordLen) && len < 512) {
        // partial buffer is fine if we have enough bytes for header
    }

    size_t pos = 5;
    if (pos >= len || data[pos] != 0x01) return false; // HandshakeType: ClientHello (1)

    pos += 4; // Skip Handshake Type (1) + Length (3)
    pos += 2; // Skip Client Version (2)
    pos += 32; // Skip Random (32)

    if (pos >= len) return false;
    uint8_t sessionIDLen = data[pos++];
    pos += sessionIDLen;

    if (pos + 2 > len) return false;
    uint16_t cipherSuitesLen = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipherSuitesLen;

    if (pos + 1 > len) return false;
    uint8_t compMethodsLen = data[pos++];
    pos += compMethodsLen;

    if (pos + 2 > len) return false;
    uint16_t extensionsLen = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    size_t extEnd = pos + extensionsLen;
    if (extEnd > len) extEnd = len;

    while (pos + 4 <= extEnd) {
        uint16_t extType = (data[pos] << 8) | data[pos + 1];
        uint16_t extLen = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        if (extType == 0x0000) { // Server Name Indication (SNI)
            if (pos + 2 > extEnd) return false;
            // uint16_t serverNameListLen = (data[pos] << 8) | data[pos + 1];
            pos += 2;

            if (pos + 3 > extEnd) return false;
            uint8_t nameType = data[pos++]; // 0 = host_name
            uint16_t nameLen = (data[pos] << 8) | data[pos + 1];
            pos += 2;

            if (nameType == 0 && nameLen > 0 && pos + nameLen <= extEnd) {
                size_t copyLen = (nameLen < maxSniLen - 1) ? nameLen : (maxSniLen - 1);
                memcpy(outSni, data + pos, copyLen);
                outSni[copyLen] = '\0';
                // Validate printable characters
                for (size_t i = 0; i < copyLen; i++) {
                    if (!isprint((unsigned char)outSni[i])) {
                        outSni[0] = '\0';
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
        pos += extLen;
    }

    return false;
}

// Parse DNS Query Domain from raw UDP/TCP DNS payload
static inline bool DPI_ParseDNSQuery(const uint8_t* data, size_t len, char* outDomain, size_t maxDomainLen) {
    if (!data || len < 13 || !outDomain || maxDomainLen < 2) return false;

    // Check Question Count QDCOUNT >= 1 (offset 4, 5)
    uint16_t qdCount = (data[4] << 8) | data[5];
    if (qdCount < 1) return false;

    size_t pos = 12; // Skip 12-byte DNS Header
    size_t outIdx = 0;

    while (pos < len && data[pos] != 0) {
        uint8_t labelLen = data[pos++];
        if (labelLen > 63 || pos + labelLen > len) return false;

        if (outIdx > 0 && outIdx < maxDomainLen - 1) {
            outDomain[outIdx++] = '.';
        }

        for (uint8_t i = 0; i < labelLen && outIdx < maxDomainLen - 1; i++) {
            char c = (char)data[pos++];
            if (isprint((unsigned char)c)) {
                outDomain[outIdx++] = c;
            } else {
                return false;
            }
        }
    }

    if (outIdx == 0 || outIdx >= maxDomainLen) return false;
    outDomain[outIdx] = '\0';
    return true;
}

#endif // OMINULL_DPI_H
