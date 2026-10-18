/* §6.5 pipe framing round trip for the Windows screen relay.
 * The agent relays bytes to/from the Rust helper as length-prefixed frames
 * (u8 kind + u32le len + bytes); the C side never parses the payload. These
 * are the pure encode/decode helpers, host-testable on Linux (the launcher and
 * WinHTTP relay in screen_windows.h compile only under _WIN32).
 *
 * Linux:   gcc -O2 -Wall -Wextra -Wformat=2 -Iagent/include agent/tests/test_screen_framing.c -o build/test_screen_framing
 * Windows: x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Iagent/include agent/tests/test_screen_framing.c -o build/test_screen_framing.exe */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/screen_windows.h"

static int failures = 0;

static void expect(const char* name, bool cond) {
    if (!cond) {
        printf("  [-] %s: FAIL\n", name);
        failures++;
    } else {
        printf("  [+] %s\n", name);
    }
}

/* Encodes a frame, then decodes it back and checks every field matches. */
static void roundtrip(const char* name, uint8_t kind, const unsigned char* payload, uint32_t len) {
    unsigned char buf[4096];
    size_t total = ScreenFrame_EncodeInto(buf, sizeof(buf), kind, payload, len);
    expect(name, total == (size_t)SCREEN_FRAME_HEADER_LEN + (size_t)len);
    if (total == 0) return;

    uint8_t dkind = 0xEE;
    const unsigned char* dpayload = NULL;
    uint32_t dlen = 0xDEADBEEF;
    size_t consumed = 0;
    bool ok = ScreenFrame_DecodeFrom(buf, total, &dkind, &dpayload, &dlen, &consumed);
    expect(name, ok && dkind == kind && dlen == len && consumed == total);
    if (len > 0) {
        expect(name, dpayload && memcmp(dpayload, payload, len) == 0);
    }
}

static void test_header_wire_format(void) {
    printf("[*] Header wire format: u8 kind + u32 little-endian length\n");
    /* A length within the 1 MiB cap that still exercises three length bytes. */
    const uint32_t sample_len = 0x000A0B0Cu; /* 658700 bytes */
    unsigned char hdr[SCREEN_FRAME_HEADER_LEN];
    ScreenFrame_EncodeHeader(SCREEN_FRAME_KIND_BINARY, sample_len, hdr);
    expect("kind byte", hdr[0] == SCREEN_FRAME_KIND_BINARY);
    expect("len is little-endian", hdr[1] == 0x0C && hdr[2] == 0x0B && hdr[3] == 0x0A && hdr[4] == 0x00);

    uint8_t kind = 0;
    uint32_t len = 0;
    expect("decode header", ScreenFrame_DecodeHeader(hdr, &kind, &len));
    expect("decoded kind", kind == SCREEN_FRAME_KIND_BINARY);
    expect("decoded len", len == sample_len);
}

static void test_roundtrip(void) {
    printf("[*] Encode/decode round trip across kinds and sizes\n");
    const unsigned char text[] = "{\"type\":\"input\",\"ev\":\"mouse\",\"x\":32768,\"y\":16384}";
    roundtrip("text control frame", SCREEN_FRAME_KIND_TEXT, text, (uint32_t)strlen((const char*)text));

    unsigned char jpeg[1024];
    for (size_t i = 0; i < sizeof(jpeg); i++) jpeg[i] = (unsigned char)(i * 31u + 7u);
    roundtrip("binary tile frame", SCREEN_FRAME_KIND_BINARY, jpeg, (uint32_t)sizeof(jpeg));

    roundtrip("zero-length text frame", SCREEN_FRAME_KIND_TEXT, NULL, 0);
    roundtrip("zero-length binary frame", SCREEN_FRAME_KIND_BINARY, (const unsigned char*)"", 0);

    /* Service request (§6.4/§6.5): a 1-byte opcode the agent acts on, never
     * relayed to the WS. */
    const unsigned char sas_op[] = { SCREEN_SERVICE_OP_SAS };
    roundtrip("service request frame (SAS opcode)", SCREEN_FRAME_KIND_SERVICE, sas_op, 1);

    /* Bytes that look like a header must survive as opaque payload. */
    unsigned char tricky[] = { 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };
    roundtrip("payload that mimics a header", SCREEN_FRAME_KIND_BINARY, tricky, (uint32_t)sizeof(tricky));
}

static void test_rejects_bad_headers(void) {
    printf("[*] Out-of-contract headers are rejected, never trusted\n");
    uint8_t kind = 0;
    uint32_t len = 0;

    unsigned char bad_kind[SCREEN_FRAME_HEADER_LEN] = { 0x03, 0, 0, 0, 0 };
    expect("unknown kind rejected", !ScreenFrame_DecodeHeader(bad_kind, &kind, &len));

    unsigned char service_kind[SCREEN_FRAME_HEADER_LEN] = { SCREEN_FRAME_KIND_SERVICE, 1, 0, 0, 0 };
    expect("service kind accepted", ScreenFrame_DecodeHeader(service_kind, &kind, &len) &&
           kind == SCREEN_FRAME_KIND_SERVICE && len == 1);

    unsigned char over_cap[SCREEN_FRAME_HEADER_LEN];
    ScreenFrame_EncodeHeader(SCREEN_FRAME_KIND_BINARY, SCREEN_FRAME_MAX_PAYLOAD + 1u, over_cap);
    expect("length over cap rejected", !ScreenFrame_DecodeHeader(over_cap, &kind, &len));

    unsigned char at_cap[SCREEN_FRAME_HEADER_LEN];
    ScreenFrame_EncodeHeader(SCREEN_FRAME_KIND_TEXT, SCREEN_FRAME_MAX_PAYLOAD, at_cap);
    expect("length exactly at cap accepted", ScreenFrame_DecodeHeader(at_cap, &kind, &len) && len == SCREEN_FRAME_MAX_PAYLOAD);
}

static void test_partial_and_streamed(void) {
    printf("[*] Partial buffers wait; back-to-back frames decode in order\n");
    unsigned char a_payload[] = "header-frame";
    unsigned char b_payload[] = "tile-bytes-here";
    unsigned char stream[128];
    size_t off = 0;
    off += ScreenFrame_EncodeInto(stream + off, sizeof(stream) - off, SCREEN_FRAME_KIND_TEXT,
                                  a_payload, (uint32_t)strlen((const char*)a_payload));
    off += ScreenFrame_EncodeInto(stream + off, sizeof(stream) - off, SCREEN_FRAME_KIND_BINARY,
                                  b_payload, (uint32_t)strlen((const char*)b_payload));

    /* A buffer shorter than one whole frame decodes nothing yet. */
    expect("incomplete header waits", !ScreenFrame_DecodeFrom(stream, 3, NULL, NULL, NULL, NULL));
    expect("header-only waits for payload",
           !ScreenFrame_DecodeFrom(stream, SCREEN_FRAME_HEADER_LEN, NULL, NULL, NULL, NULL));

    /* The header text frame, then the binary tile frame, from the same stream. */
    uint8_t kind = 0;
    const unsigned char* payload = NULL;
    uint32_t len = 0;
    size_t consumed = 0;
    size_t pos = 0;
    bool ok1 = ScreenFrame_DecodeFrom(stream + pos, off - pos, &kind, &payload, &len, &consumed);
    expect("first frame is the text header", ok1 && kind == SCREEN_FRAME_KIND_TEXT &&
           len == strlen((const char*)a_payload) && memcmp(payload, a_payload, len) == 0);
    pos += consumed;

    bool ok2 = ScreenFrame_DecodeFrom(stream + pos, off - pos, &kind, &payload, &len, &consumed);
    expect("second frame is the binary tile", ok2 && kind == SCREEN_FRAME_KIND_BINARY &&
           len == strlen((const char*)b_payload) && memcmp(payload, b_payload, len) == 0);
    pos += consumed;
    expect("stream fully consumed", pos == off);
}

static void test_encode_bounds(void) {
    printf("[*] Encoder refuses a buffer too small or a bad kind\n");
    unsigned char small[4];
    expect("too-small buffer refused", ScreenFrame_EncodeInto(small, sizeof(small), SCREEN_FRAME_KIND_TEXT,
                                                              (const unsigned char*)"x", 1) == 0);
    unsigned char ok[16];
    expect("unknown kind refused", ScreenFrame_EncodeInto(ok, sizeof(ok), 7,
                                                          (const unsigned char*)"x", 1) == 0);
}

int main(void) {
    printf("=== Ominull screen relay framing (REMOTE_SCREEN.md §6.5) ===\n");
    test_header_wire_format();
    test_roundtrip();
    test_rejects_bad_headers();
    test_partial_and_streamed();
    test_encode_bounds();
    if (failures) {
        printf("\n[-] %d framing assertion(s) failed\n", failures);
        return 1;
    }
    printf("\n[+] all screen framing assertions passed\n");
    return 0;
}
