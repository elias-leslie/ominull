#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

typedef uint8_t  UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef size_t   SIZE_T;
typedef char     CHAR;
typedef int      BOOLEAN;
#define TRUE  1
#define FALSE 0
#define _In_reads_bytes_(x)
#define _In_
#define _Out_
#define RtlZeroMemory(dst, len) memset(dst, 0, len)
#define RtlCopyMemory(dst, src, len) memcpy(dst, src, len)
#define _strnicmp strncasecmp

#include "../driver/include/ominull_dpi.h"
#include "../driver/src/dpi.c"

void test_tls_sni_extraction() {
    printf("[*] Testing TLS SNI Extraction...\n");
    // Synthetic TLS 1.2 ClientHello with SNI "c2.evil-corp.com" (16 chars)
    uint8_t tlsPacket[] = {
        0x16, 0x03, 0x01, 0x00, 0x48, // TLS Record Header (Handshake, 72 bytes)
        0x01, 0x00, 0x00, 0x44,       // Handshake Header (ClientHello, 68 bytes)
        0x03, 0x03,                   // Version TLS 1.2
        // 32 bytes Random
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x00,                         // Session ID Length = 0
        0x00, 0x02, 0x00, 0x2f,       // Cipher Suites (1 suite: TLS_RSA_WITH_AES_128_CBC_SHA)
        0x01, 0x00,                   // Compression Methods (1 method: NULL)
        0x00, 0x19,                   // Extensions Length = 25 bytes
        // Extension 0: server_name (SNI)
        0x00, 0x00,                   // Extension Type: server_name (0x0000)
        0x00, 0x15,                   // Extension Length = 21 bytes
        0x00, 0x13,                   // Server Name List Length = 19 bytes
        0x00,                         // Name Type = 0 (host_name)
        0x00, 0x10,                   // Name Length = 16 bytes
        'c', '2', '.', 'e', 'v', 'i', 'l', '-', 'c', 'o', 'r', 'p', '.', 'c', 'o', 'm'
    };

    OMINULL_DPI_RESULT res;
    BOOLEAN ok = OminullDpiInspectPayload(tlsPacket, sizeof(tlsPacket), 443, &res);
    assert(ok == TRUE);
    assert(res.ProtocolType == 1);
    assert(strcmp(res.DomainName, "c2.evil-corp.com") == 0);
    printf("[+] Successfully extracted TLS SNI: %s\n", res.DomainName);
}

void test_http_host_extraction() {
    printf("[*] Testing HTTP Host Header Extraction...\n");
    const char* httpRequest = 
        "GET /login/auth HTTP/1.1\r\n"
        "Host: phishing-site.target.net:8080\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: */*\r\n\r\n";

    OMINULL_DPI_RESULT res;
    BOOLEAN ok = OminullDpiInspectPayload((const uint8_t*)httpRequest, strlen(httpRequest), 80, &res);
    assert(ok == TRUE);
    assert(res.ProtocolType == 2);
    assert(strcmp(res.DomainName, "phishing-site.target.net") == 0);
    printf("[+] Successfully extracted HTTP Host: %s\n", res.DomainName);
}

void test_dns_query_extraction() {
    printf("[*] Testing DNS Query Extraction...\n");
    // Standard DNS query packet for "beacon.apt29.ru"
    uint8_t dnsPacket[] = {
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: Standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Question: 6beacon5apt292ru0
        0x06, 'b', 'e', 'a', 'c', 'o', 'n',
        0x05, 'a', 'p', 't', '2', '9',
        0x02, 'r', 'u',
        0x00,       // End of name
        0x00, 0x01, // Type: A (1)
        0x00, 0x01  // Class: IN (1)
    };

    OMINULL_DPI_RESULT res;
    BOOLEAN ok = OminullDpiInspectPayload(dnsPacket, sizeof(dnsPacket), 53, &res);
    assert(ok == TRUE);
    assert(res.ProtocolType == 3);
    assert(strcmp(res.DomainName, "beacon.apt29.ru") == 0);
    printf("[+] Successfully extracted DNS Query: %s\n", res.DomainName);
}

int main() {
    printf("=== RUNNING OMINULL KERNEL DPI UNIT TESTS ===\n");
    test_tls_sni_extraction();
    test_http_host_extraction();
    test_dns_query_extraction();
    printf("=== ALL DPI UNIT TESTS PASSED ===\n");
    return 0;
}
