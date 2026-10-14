/* Terminal wire helpers shared by the Linux and Windows workers.
 * Linux:   gcc -O2 -Wall -Wextra -Iagent/include agent/tests/test_terminal_frame.c -o build/test_terminal_frame
 * Windows: x86_64-w64-mingw32-gcc -O2 -Wall -Iagent/include agent/tests/test_terminal_frame.c -o build/test_terminal_frame.exe */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/terminal_frame.h"

static bool parse(const char* s, TermInFrame* f) { return TermFrame_Parse(s, strlen(s), f); }

static void test_frame_field_order_and_whitespace(void) {
    TermInFrame f;
    assert(parse("{\"type\":\"stdin\",\"data\":\"aGk=\"}", &f));
    assert(strcmp(f.type, "stdin") == 0 && f.data_len == 4 && memcmp(f.data, "aGk=", 4) == 0);

    /* Field order, whitespace, unknown fields (nested, arrays, escapes) and the hub's timestamp. */
    assert(parse(" {\n \"data\" : \"aGk=\" ,\t\"timestamp\":\"2026-10-14T20:00:00.123Z\", \"extra\":{\"a\":[1,{\"b\":\"}\"}],\"c\":null},"
                 " \"note\":\"quote \\\" and brace }\", \"type\" : \"stdin\" } ", &f));
    assert(strcmp(f.type, "stdin") == 0 && f.data_len == 4);

    /* A value containing the text "type":"close" must not be mistaken for the type. */
    assert(parse("{\"type\":\"stdin\",\"data\":\"aGk=\",\"x\":\"\\\"type\\\":\\\"close\\\"\"}", &f));
    assert(strcmp(f.type, "stdin") == 0);

    assert(parse("{\"cols\": 120 , \"type\":\"resize\", \"rows\":40, \"data\":null}", &f));
    assert(strcmp(f.type, "resize") == 0 && f.rows == 40 && f.cols == 120 && f.data_len == 0);

    assert(parse("{\"type\":\"close\"}", &f) && strcmp(f.type, "close") == 0);
    printf("[+] frame parser: order, whitespace, unknown and nested fields\n");
}

static void test_frame_malformed(void) {
    TermInFrame f;
    const char* bad[] = {
        "", "{", "[]", "{\"type\":\"stdin\"", "{\"type\":stdin}", "{\"type\":\"stdin\",}",
        "{\"type\":\"stdin\" \"data\":\"x\"}", "{\"type\":\"averyveryverylongtype\"}", "{\"type\":5}",
        "{\"data\":\"aGk=\"}", "{\"type\":\"stdin\"} trailing", "{\"type\":\"st\x01in\"}",
        "{\"a\":[[[[[[[[[[[[1]]]]]]]]]]]],\"type\":\"stdin\"}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (parse(bad[i], &f)) {
            fprintf(stderr, "accepted malformed frame %zu: %s\n", i, bad[i]);
            assert(0);
        }
    }
    /* Bounded by the given length: no read past it even without a NUL. */
    char buf[] = {'{', '"', 't', 'y', 'p', 'e', '"', ':', '"', 's'};
    assert(!TermFrame_Parse(buf, sizeof(buf), &f));
    printf("[+] frame parser: malformed input rejected\n");
}

static void test_payload(void) {
    char sid[64], prog[64], tok[128];
    assert(TermPayload_Parse("{ \"connect_token\" : \"tok-1\", \"program\":\"\\/bin\\/sh\", \"session_id\":\"s-1\", \"x\":{\"y\":1}}",
                             sid, sizeof(sid), prog, sizeof(prog), tok, sizeof(tok)));
    assert(strcmp(sid, "s-1") == 0 && strcmp(prog, "/bin/sh") == 0 && strcmp(tok, "tok-1") == 0);
    /* A token longer than the buffer fails instead of being truncated. */
    char longtok[300];
    memset(longtok, 'a', sizeof(longtok));
    char json[400];
    snprintf(json, sizeof(json), "{\"session_id\":\"s\",\"connect_token\":\"%.*s\"}", 200, longtok);
    assert(!TermPayload_Parse(json, sid, sizeof(sid), prog, sizeof(prog), tok, sizeof(tok)));
    printf("[+] offer payload parser\n");
}

static void test_base64(void) {
    unsigned char in[3000], out[3000];
    for (size_t i = 0; i < sizeof(in); i++) in[i] = (unsigned char)(i * 131 + 7);
    for (size_t n = 0; n < 40; n++) {
        char enc[8192];
        size_t el = TermB64_Encode(in, n, enc, sizeof(enc));
        assert(el == TermB64_EncodedLen(n));
        assert(TermB64_Decode(enc, el, out, sizeof(out)) == n);
        assert(memcmp(in, out, n) == 0);
    }
    char enc[8192];
    size_t el = TermB64_Encode(in, sizeof(in), enc, sizeof(enc));
    assert(TermB64_Decode(enc, el, out, sizeof(out)) == sizeof(in) && memcmp(in, out, sizeof(in)) == 0);
    /* JSON-escaped slash decodes like a plain one. */
    unsigned char a[4], b[4];
    assert(TermB64_Decode("\\/\\/8=", 6, a, sizeof(a)) == 2);
    assert(TermB64_Decode("//8=", 4, b, sizeof(b)) == 2 && memcmp(a, b, 2) == 0);
    printf("[+] base64 roundtrip\n");
}

int main(void) {
    printf("=== terminal frame helpers ===\n");
    test_frame_field_order_and_whitespace();
    test_frame_malformed();
    test_payload();
    test_base64();
    printf("=== terminal frame helpers passed ===\n");
    return 0;
}
