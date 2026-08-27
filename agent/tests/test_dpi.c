#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/dpi.h"

int main() {
    printf("[*] Running DPI Engine Unit Tests...\n");

    // 1. Synthetic DNS Query Packet for "api.github.com"
    uint8_t dnsPacket[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'a', 'p', 'i',
        0x06, 'g', 'i', 't', 'h', 'u', 'b',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, 0x00, 0x01
    };

    char domain[256] = {0};
    bool dnsParsed = DPI_ParseDNSQuery(dnsPacket, sizeof(dnsPacket), domain, sizeof(domain));
    assert(dnsParsed);
    assert(strcmp(domain, "api.github.com") == 0);
    printf("  [+] DNS DPI Parsed Domain: %s\n", domain);

    // 2. Synthetic TLS 1.3 ClientHello Packet with SNI extension for "c2.threat-actor.org"
    const char* targetSni = "c2.threat-actor.org";
    uint16_t sniLen = (uint16_t)strlen(targetSni);

    uint8_t tlsPacket[256] = {0};
    tlsPacket[0] = 0x16; // Handshake
    tlsPacket[1] = 0x03; tlsPacket[2] = 0x03; // TLS 1.2
    tlsPacket[3] = 0x00; tlsPacket[4] = 0x60; // Record length

    tlsPacket[5] = 0x01; // ClientHello
    tlsPacket[6] = 0x00; tlsPacket[7] = 0x00; tlsPacket[8] = 0x5C; // Handshake length
    tlsPacket[9] = 0x03; tlsPacket[10] = 0x03; // Client version

    tlsPacket[43] = 0x00; // Session ID length (0)
    tlsPacket[44] = 0x00; tlsPacket[45] = 0x02; // Cipher suites len (2)
    tlsPacket[46] = 0xC0; tlsPacket[47] = 0x2F; // Cipher suite
    tlsPacket[48] = 0x01; // Compression methods len (1)
    tlsPacket[49] = 0x00; // Compression null

    uint16_t extLen = 4 + 2 + 3 + sniLen;
    tlsPacket[50] = (extLen >> 8) & 0xFF;
    tlsPacket[51] = extLen & 0xFF;

    tlsPacket[52] = 0x00; tlsPacket[53] = 0x00;
    uint16_t sniExtPayloadLen = 2 + 3 + sniLen;
    tlsPacket[54] = (sniExtPayloadLen >> 8) & 0xFF;
    tlsPacket[55] = sniExtPayloadLen & 0xFF;

    uint16_t snListLen = 3 + sniLen;
    tlsPacket[56] = (snListLen >> 8) & 0xFF;
    tlsPacket[57] = snListLen & 0xFF;

    tlsPacket[58] = 0x00;
    tlsPacket[59] = (sniLen >> 8) & 0xFF;
    tlsPacket[60] = sniLen & 0xFF;

    memcpy(&tlsPacket[61], targetSni, sniLen);

    char extractedSni[256] = {0};
    bool tlsParsed = DPI_ParseTLSClientHello(tlsPacket, 61 + sniLen, extractedSni, sizeof(extractedSni));
    assert(tlsParsed);
    assert(strcmp(extractedSni, targetSni) == 0);
    printf("  [+] TLS ClientHello DPI Parsed SNI: %s\n", extractedSni);

    printf("[+] All DPI Unit Tests Passed Successfully!\n");
    return 0;
}
