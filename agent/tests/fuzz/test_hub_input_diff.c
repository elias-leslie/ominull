/*
 * The Rust hub-input library against the C readers without a fuzzer, on Linux
 * and on Windows under wine (where long is 32 bits): a table of known quirks,
 * then every file in the directories given, then a fixed number of seeded
 * mutations of them. P-256 compares with openssl on Linux and CNG on Windows
 * when the directory in HUB_INPUT_P256 holds xy.bin, pub.pem, msg and sig.der.
 *
 *   test_hub_input_diff [--mutations N] DIR-OR-FILE...
 */
#include "hub_input_diff.h"
#include <dirent.h>
#include <sys/stat.h>
#ifdef _WIN32
#include "../../include/release_verify_win.h"
#else
#include "../../include/release_verify_posix.h"
#endif

#define BS "\\"
#define DIFF_MAX_INPUT (256 * 1024)

/* Inputs the readers treat in odd ways; each one pins a behaviour. */
static const char* const QUIRKS[] = {
    "", " ", "{", "}", "{}", "[]", "null", "\"", "\"\"", "{\"a\"", "{\"a\":", "{\"a\":1", "{\"a\":1,", "{\"a\":1,}", "{\"a\":1}x", "{,}",
    /* frames */
    "{\"type\":\"stdin\",\"data\":\"QQ==\"}", "{\"type\":\"resize\",\"rows\":40,\"cols\":120}",
    "{\"type\":\"resize\",\"rows\":2147483647,\"cols\":2147483648}", "{\"type\":\"resize\",\"rows\":4294967296,\"cols\":-1}",
    "{\"type\":\"resize\",\"rows\":9223372036854775807,\"cols\":9223372036854775808}", "{\"type\":\"resize\",\"rows\":1.5,\"cols\":1e3}",
    "{\"type\":\"resize\",\"rows\":99999999999999999999,\"cols\":0}", "{\"type\":\"resize\",\"rows\":+1,\"cols\":00012}",
    "{\"t" BS "u0079pe\":\"stdin\"}", "{\"TYPE\":\"stdin\"}", "{\"type\":\"stdin\",\"type\":\"close\"}", "{\"type\":\"st" BS "u0064in\"}",
    "{\"type\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
    /* strings: surrogates, escapes, control bytes, NUL by escape */
    "{\"session_id\":\"" BS "ud83d" BS "ude00\",\"program\":\"/bin/sh\",\"connect_token\":\"t\"}",
    "{\"session_id\":\"" BS "ud83d\",\"program\":\"/bin/sh\",\"connect_token\":\"t\"}",
    "{\"session_id\":\"" BS "ude00" BS "ud83d\",\"program\":\"/bin/sh\",\"connect_token\":\"t\"}",
    "{\"session_id\":\"" BS "u0000\",\"program\":\"/bin/sh\",\"connect_token\":\"t\"}",
    "{\"session_id\":\"" BS "x41\",\"program\":\"/bin/sh\",\"connect_token\":\"t\"}",
    "{\"session_id\":\"a" BS "/b" BS "bc" BS "fd" BS "ne" BS "rf" BS "tg\",\"program\":\"/bin/sh\",\"connect_token\":\"t\"}",
    "{\"session_id\":\"\x01\",\"program\":\"\x7f\",\"connect_token\":\"\xff\xfe\"}",
    "{\"session_id\":\"s\",\"s" BS "u0065ssion_id\":\"t\",\"program\":\"p\",\"connect_token\":\"t\"}",
    "{\"session_id\":\"s\",\"SESSION_ID\":\"t\",\"program\":\"p\",\"connect_token\":\"t\"}",
    /* screen */
    "{\"session_id\":\"s\",\"mode\":\"control\",\"connect_token\":\"t\",\"operator\":\"o\",\"unattended\":true,\"ask_first\":true}",
    "{\"session_id\":\"s\",\"unattended\":false}", "{\"session_id\":\"s\",\"unattended\":true,\"unattended\":true}", "{\"session_id\":\"s\",\"ask_first\":\"true\"}",
    /* forensic numbers */
    "{\"bundle_id\":\"b\",\"profile\":\"p\",\"max_bytes\":2147483648,\"timeout_seconds\":2147483648}",
    "{\"bundle_id\":\"b\",\"profile\":\"p\",\"max_bytes\":9223372036854775807,\"timeout_seconds\":4294967297}",
    "{\"bundle_id\":\"b\",\"profile\":\"p\",\"max_bytes\":9223372036854775808,\"timeout_seconds\":-1}",
    "{\"bundle_id\":\"b\",\"profile\":\"p\",\"max_bytes\":-9223372036854775809,\"timeout_seconds\":1.0}",
    "{\"bundle_id\":\"b\",\"max_bytes\":\"12\"}", "{\"bundle_id\":12}",
    /* script */
    "{\"script_id\":\"a\",\"script_version\":2147483647,\"script_digest\":\"d\",\"source\":\"x\",\"parameters\":{\"A\":\"1\",\"b\":2,\"c\":true},\"timeout_seconds\":3600,\"max_output_bytes\":1048576}",
    "{\"script_id\":\"a\",\"script_version\":2147483648,\"source\":\"x\"}", "{\"script_id\":\"a\",\"version\":3,\"source\":\"x\"}",
    "{\"script_version\":1,\"version\":3,\"source\":\"x\"}", "{\"source\":\"x\",\"timeout_seconds\":999999999999999999}", "{\"source\":\"x\",\"timeout_seconds\":9999999999999999999}",
    "{\"source\":\"x\",\"max_output_bytes\":-1}", "{\"source\":\"x\",\"max_output_bytes\":16}", "{\"source\":\"x\",\"max_output_bytes\":17}",
    "{\"source\":\"x\",\"parameters\":{\"a\":\"1\",\"A\":\"2\"}}", "{\"source\":\"x\",\"parameters\":{\"a b\":\"1\"}}", "{\"source\":\"x\",\"parameters\":{\"a\":[1]}}",
    "{\"source\":\"x\",\"parameters\":[]}", "{\"source\":\"\"}", "{\"source\":\"x\",\"sou" BS "u0072ce\":\"y\"}",
    /* the certificate object, and strstr finding keys in odd places */
    "{\"client_certificate\":{\"cert_pem_b64\":\"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==\"}}", "\"cert_pem_b64\":\"QQ==", "\"cert_pem_b64\" : \"QQ==\"", "\"cert_pem_b64\":\"\"",
    "LS0tLS1CRUdJTg==", "LS0tLS1CRUdJTg", "LS0t LS1CRUdJTg==", "====", "Q", "QQ", "QQ=", "QQ==", "QQ=Q", "QQ==QQ==", "Q Q = =", "\n\tQ\r\nQ==",
    /* grants and offers */
    "{\"grant\":{}}", "{\"response_offers\":[]}", "{\"response_offers\":[{}]}", "{\"response_offers\":[{\"job_id\":\"j\",\"kind\":\"k\",\"payload_json\":\"{}\"}]}",
    "{\"grant\":{\"version\":3,\"version\":3}}", "{\"grant\":{\"issued_at\":9223372036854775808}}", "{\"grant\":{\"issued_at\":-1}}", "{\"grant\":{\"issued_at\":1.5}}",
    /* the trust reader */
    "{\"route\":\"a\",\"body\":[1,2,{\"x\":\"y\"}]}", "{\"route\":\"a\",\"route\":\"b\"}", "{\"r" BS "u006fute\":\"a\"}", "{\"route\":\"" BS "u0061\"}",
    "[1,2,3]", "[\"10.0.0.1\",\"10.0.0.0/24\",\"::1\",\"fe80::1%eth0\"]", "[\"a\",\"b\",", "[\"a\" \"b\"]", "[[\"a\"]]",
    "9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809", "2147483648", "4294967296", "0", "-0", "00", "01", "1.0", "1e5", "+1", "-", "--1",
    "10.0.0.1", "10.0.0.256", "10.0.0.1/24", "10.0.0.1/33", "10.0.0.1/-1", "10.0.0", "010.0.0.1", "0x0a.0.0.1", "::", "::1", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "::ffff:10.0.0.1", "::ffff:8.8.8.8", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255", "8.8.8.8", "192.0.2.1", "::/0", "0.0.0.0/0", "2001:db8::/32", "2001:db8::/129", " 10.0.0.1", "10.0.0.1 ",
    "{\"rules\":[{\"service\":\"s\",\"destination\":\"10.0.0.1\",\"protocol\":\"tcp\",\"port\":443}]}",
    "[{\"service\":\"s\",\"destination\":\"10.0.0.1\",\"protocol\":\"tcp\",\"port\":65536}]", "[{\"service\":\"s\",\"destination\":\"10.0.0.1\",\"protocol\":\"udp\",\"port\":0}]",
    "[{\"service\":\"s\",\"destination\":\"10.0.0.1\",\"protocol\":\"tcp\",\"port\":4294967739}]", "[{\"service\":\"s\",\"destination\":\"8.8.8.8/32\",\"protocol\":\"TCP\",\"port\":53}]",
    "{\"targets\":[\"ep-1\",\"ep-2\"],\"baselines\":{\"ep-1\":[]}}", "{\"target_ip\":\"10.0.0.1\",\"endpoint_id\":\"ep-1\"}", "{\"version\":\"1.2.3\",\"sha256\":\"ab\"}", "{\"allow_ips\":[\"10.0.0.1\"]}",
    /* flat scrapes */
    "\"version\":\"1", "\"version\":\"\"", "\"version\":  \t\"1.2\"", "\"version\":\n\"1.2\"", "\"url\":\"a\"\"url\":\"b\"", "\"device_credential\":\"omd_0123456789012345678901234567890123456789012345678901234567890123\"", "\"device_credential\":\"omd_short\"",
    "\"threat_indicators\":[\"10.0.0.1\", 10.0.0.2 ,\"\",,\n\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]", "\"threat_indicators\":[", "\"threat_indicators\":[\"a",
    "10.0.0.0/08", "10.0.0.0/00", "10.0.0.0/8", "10.0.0.0/8 ", "2001:db8::/032", "2001:db8::/0", "10.0.0.0/",
    "203.0.113.1", "203.0.114.1", "203.1.113.1", "204.0.113.1", "198.51.100.1", "198.51.101.1", "198.18.0.1", "198.20.0.1", "192.0.0.1", "192.88.99.1", "100.64.0.1", "100.128.0.1", "172.16.0.1", "172.32.0.1", "240.0.0.1", "192.168.0.1", "192.169.0.1",
    "2001:db9::1", "2002::1", "64:ff9b::1", "fec0::1", "fd00::1", "100::1",
    /* just under, at and over the 64-byte address limit */
    "11111111111111111111111111111111111111111111111111111111111111", "111111111111111111111111111111111111111111111111111111111111111", "1111111111111111111111111111111111111111111111111111111111111111", "11111111111111111111111111111111111111111111111111111111111111111",
    /* a backslash at the very end of a string, for each reader */
    "\"" BS, "\"a" BS, "\"" BS "\"", "\"" BS BS "\"", "{\"a\":\"" BS, "{\"" BS,
    /* routine keys: in order, out of order, repeated, too many */
    "0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0000000000000002:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000002:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0000000000000002:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0000000000000003:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0000000000000004:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0000000000000002:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0000000000000003:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0000000000000004:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0000000000000005:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,", ",0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000001:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000001;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0000000000000001:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    /* hex */
    "0123456789abcdefABCDEF", "abc", "zz", "0x", "+1", " 1", "-1",
};

static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static uint32_t Rnd(uint32_t n) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return n ? (uint32_t)(g_rng % n) : 0;
}

static uint8_t** g_files;
static size_t* g_sizes;
static size_t g_count, g_cap;
static unsigned long long g_runs;

static void Run(const uint8_t* d, size_t n) {
    Diff_One(d, n);
    g_runs++;
}

static void AddFile(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return;
    uint8_t* b = (uint8_t*)malloc(DIFF_MAX_INPUT);
    size_t n = b ? fread(b, 1, DIFF_MAX_INPUT, f) : 0;
    fclose(f);
    if (!b) abort();
    if (g_count == g_cap) {
        g_cap = g_cap ? g_cap * 2 : 256;
        g_files = (uint8_t**)realloc(g_files, g_cap * sizeof(*g_files));
        g_sizes = (size_t*)realloc(g_sizes, g_cap * sizeof(*g_sizes));
    }
    g_files[g_count] = (uint8_t*)realloc(b, n ? n : 1);
    g_sizes[g_count++] = n;
    Run(g_files[g_count - 1], n);
}

static void AddPath(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) return;
    if (!S_ISDIR(st.st_mode)) {
        AddFile(path);
        return;
    }
    DIR* d = opendir(path);
    if (!d) return;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char sub[1024];
        snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
        AddPath(sub);
    }
    closedir(d);
}

static void Mutate(unsigned long long count) {
    static uint8_t buf[DIFF_MAX_INPUT];
    static const char* const tokens[] = {"\"", "\\", "{", "}", "[", "]", ",", ":", " ", "null", "true", "false", "-", "0", "2147483648", "9223372036854775808", "\"\"", "[]", "{}", "\x00", "\xff"};
    size_t nquirk = sizeof(QUIRKS) / sizeof(QUIRKS[0]);
    for (unsigned long long r = 0; r < count; r++) {
        size_t n;
        uint32_t pick = Rnd((uint32_t)(g_count + nquirk));
        if (pick < g_count) {
            n = g_sizes[pick] > sizeof(buf) / 2 ? sizeof(buf) / 2 : g_sizes[pick];
            memcpy(buf, g_files[pick], n);
        } else {
            n = strlen(QUIRKS[pick - g_count]);
            memcpy(buf, QUIRKS[pick - g_count], n);
        }
        for (uint32_t m = Rnd(4) + 1; m > 0; m--) {
            uint32_t at = Rnd((uint32_t)n + 1);
            switch (Rnd(6)) {
            case 0: if (at < n) buf[at] ^= (uint8_t)(1u << Rnd(8)); break;
            case 1: if (at < n) buf[at] = (uint8_t)Rnd(256); break;
            case 2: { /* delete a span */
                uint32_t len = Rnd(16) + 1;
                if (at + len <= n) { memmove(buf + at, buf + at + len, n - at - len); n -= len; }
                break;
            }
            case 3: { /* insert a token */
                const char* t = tokens[Rnd(sizeof(tokens) / sizeof(tokens[0]))];
                size_t len = strlen(t);
                if (len == 0) len = 1; /* the NUL token */
                if (n + len < sizeof(buf)) { memmove(buf + at + len, buf + at, n - at); memcpy(buf + at, t, len); n += len; }
                break;
            }
            case 4: n = at; break; /* truncate */
            case 5: { /* splice another file in */
                if (!g_count) break;
                uint32_t o = Rnd((uint32_t)g_count);
                uint32_t from = Rnd((uint32_t)g_sizes[o] + 1);
                size_t len = g_sizes[o] - from;
                if (len > 256) len = 256;
                if (n + len < sizeof(buf)) { memmove(buf + at + len, buf + at, n - at); memcpy(buf + at, g_files[o] + from, len); n += len; }
                break;
            }
            }
        }
        Run(buf, n);
    }
}

/* What the two sides can differ on, by design: C's Ed25519 takes S >= L, Go and
 * the library do not. No genuine signer produces one; the agent's only signer is
 * the hub. */
static void Ed25519_Tightening(void) {
    static const uint8_t L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
    uint8_t seed[32] = {7}, pub[32], priv[64], sig[64];
    const uint8_t msg[] = "message";
    DIFF(Ed25519_CreateKeypairFromSeed(pub, priv, seed), "test key");
    DIFF(Ed25519_Sign(sig, msg, sizeof(msg), priv), "test signature");
    DIFF(hi_ed25519_verify(sig, msg, sizeof(msg), pub), "genuine signature");
    unsigned carry = 0;
    for (int i = 0; i < 32; i++) {
        unsigned v = sig[32 + i] + L[i] + carry;
        sig[32 + i] = (uint8_t)v;
        carry = v >> 8;
    }
    DIFF(!hi_ed25519_verify(sig, msg, sizeof(msg), pub), "S+L must be refused");
}

/* Points the two verifiers could read differently: small-order, non-canonical and
 * off-curve encodings, as keys and as R, with S 0 and 1 (RFC 8032 cofactor cases,
 * "Taming the many EdDSAs"). Neither is strict about them; both must agree. */
static void Ed25519_Edges(void) {
    static const uint8_t pts[][32] = {
        {1},                                                                                                /* identity */
        {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},  /* order 2 */
        {0},                                                                                                /* order 4 */
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80},
        {0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
         0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},  /* order 8 */
        {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
         0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
        {0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},  /* y = p + 1, non-canonical identity */
        {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},  /* y = p */
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
        {2},                                                                                                /* off the curve */
        {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
         0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66},  /* the base point */
    };
    size_t n = sizeof(pts) / sizeof(pts[0]);
    const uint8_t msg[] = "edge";
    int accepted = 0;
    for (size_t k = 0; k < n; k++) {
        for (size_t r = 0; r < n; r++) {
            for (uint8_t s = 0; s < 2; s++) {
                uint8_t sig[64] = {0};
                memcpy(sig, pts[r], 32);
                sig[32] = s;
                bool c = Ed25519_Verify(sig, msg, sizeof(msg), pts[k]);
                bool rust = hi_ed25519_verify(sig, msg, sizeof(msg), pts[k]);
                if (c != rust) fprintf(stderr, "Ed25519 edge key %d R %d S %d: C %d library %d\n", (int)k, (int)r, (int)s, c, rust);
                DIFF(c == rust, "Ed25519 edge case");
                accepted += c;
            }
        }
    }
    DIFF(accepted > 0, "no Ed25519 edge case verified, so the comparison proves nothing");
}

/* A rule made directly from the input, not only ones the parser already passed. */
static void Rule_Edges(void) {
    static const char* const services[] = {"", "s", "ssh", "a b", "svc-1_x"};
    static const char* const dests[] = {"", "10.0.0.1", "10.0.0.0/24", "8.8.8.8", "::1", "2001:db8::/64", "nope"};
    static const char* const protos[] = {"", "tcp", "udp", "TCP", "icmp"};
    static const int ports[] = {-1, 0, 1, 443, 65535, 65536};
    for (size_t a = 0; a < 5; a++) for (size_t b = 0; b < 7; b++) for (size_t c = 0; c < 5; c++) for (size_t d = 0; d < 6; d++) {
        TrustRule r;
        memset(&r, 0, sizeof(r));
        snprintf(r.service, sizeof(r.service), "%s", services[a]);
        snprintf(r.destination, sizeof(r.destination), "%s", dests[b]);
        snprintf(r.protocol, sizeof(r.protocol), "%s", protos[c]);
        r.port = ports[d];
        DIFF(Trust_RuleValid(&r) == hi_trust_rule_valid(&r), "Trust_RuleValid on a crafted rule");
    }
}

static size_t ReadAll(const char* dir, const char* name, uint8_t* out, size_t cap) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(out, 1, cap, f);
    fclose(f);
    return n;
}

#ifdef _WIN32
static bool Der_Int_Minimal(const uint8_t* d, size_t n, size_t* i) {
    if (*i + 2 > n || d[*i] != 2) return false;
    size_t l = d[*i + 1];
    *i += 2;
    if (l == 0 || l > 33 || *i + l > n) return false;
    if (d[*i] & 0x80) return false;                  /* negative */
    if (l > 1 && d[*i] == 0 && !(d[*i + 1] & 0x80)) return false; /* a padding zero with no need */
    *i += l;
    return true;
}

static bool Der_Minimal(const uint8_t* d, size_t n) {
    size_t i = 2;
    if (n < 8 || d[0] != 0x30 || d[1] & 0x80 || d[1] != n - 2) return false;
    return Der_Int_Minimal(d, n, &i) && Der_Int_Minimal(d, n, &i) && i == n;
}
#endif

/* The reference verifier for one signature. Windows' reader is laxer about DER
 * than openssl and the library, so there the library may refuse what it took. */
static void P256_Compare(const uint8_t* xy, const char* pem, const char* msg, size_t mlen, const uint8_t* der, size_t dlen, const char* what, bool ref_ok) {
    bool rust_xy = hi_p256_verify_xy(xy, msg, mlen, der, dlen);
    bool rust_pem = hi_p256_verify_pem(pem, msg, mlen, der, dlen);
    uint8_t hash[32];
    hi_sha256_sum((const uint8_t*)msg, mlen, hash);
    bool rust_hash = hi_p256_verify_hash(xy, hash, der, dlen);
    DIFF(rust_xy == rust_pem && rust_xy == rust_hash, what);
    if (!ref_ok) return;
#ifdef _WIN32
    bool c = ReleaseVerifyWinMsg(xy, msg, mlen, der, dlen);
    if (rust_xy) DIFF(c, what);
    if (c && !rust_xy) {
        unsigned char raw[64];
        DIFF(DerToRawSignature(der, dlen, raw), what);
        DIFF(!Der_Minimal(der, dlen), what); /* the library refuses only what DER forbids */
    }
#else
    bool c = ReleaseVerifyPosixKey(pem, msg, mlen, der, dlen);
    /* The openssl command reads only a key's largest signature (72 bytes) from
     * the file, so it never sees bytes past that. The library does, and refuses. */
    if (dlen > 72 && c && !rust_xy) return;
    if (c != rust_xy) {
        fprintf(stderr, "P-256 %s: reference %d library %d on:", what, c, rust_xy);
        for (size_t i = 0; i < dlen; i++) fprintf(stderr, "%02x", der[i]);
        fprintf(stderr, "\n");
    }
    DIFF(c == rust_xy, what);
#endif
}

static void P256(const char* dir, int rounds) {
    static const uint8_t N[32] = {0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
    uint8_t xy[64], der[256], m[4096], mut[300];
    char pem[1024] = {0};
    if (ReadAll(dir, "xy.bin", xy, sizeof(xy)) != 64) return;
    size_t pl = ReadAll(dir, "pub.pem", (uint8_t*)pem, sizeof(pem) - 1);
    size_t ml = ReadAll(dir, "msg", m, sizeof(m));
    size_t dl = ReadAll(dir, "sig.der", der, sizeof(der));
    DIFF(pl && ml && dl, "P-256 fixture files");
#ifdef _WIN32
    bool ref_ok = ReleaseVerifyWinMsg(xy, (const char*)m, ml, der, dl);
    if (!ref_ok) printf("  [~] this wine's CNG can't check ECDSA; library checked on its own\n");
#else
    bool ref_ok = true;
    snprintf(g_ReleaseVerifyDir, sizeof(g_ReleaseVerifyDir), "%s", dir);
#endif
    DIFF(hi_p256_verify_xy(xy, (const char*)m, ml, der, dl), "genuine P-256 signature");
    P256_Compare(xy, pem, (const char*)m, ml, der, dl, "genuine signature", ref_ok);
    /* The high-S twin: both verifiers take it (P-256 has no low-S rule). */
    if (der[3] <= 33 && der[1] == dl - 2) {
        size_t si = 4u + der[3] + 2u, sl = der[5 + der[3]];
        uint8_t s[32] = {0}, hs[32];
        const uint8_t* sv = der + si;
        size_t svl = sl;
        while (svl > 0 && *sv == 0) { sv++; svl--; }
        memcpy(s + 32 - svl, sv, svl);
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int v = (int)N[i] - s[i] - borrow;
            borrow = v < 0;
            hs[i] = (uint8_t)v;
        }
        size_t skip = 0;
        while (skip < 31 && hs[skip] == 0) skip++;
        size_t hl = 32 - skip;
        int pad = hs[skip] & 0x80 ? 1 : 0;
        memcpy(mut, der, 4u + der[3]);
        size_t o = 4u + der[3];
        mut[o++] = 2;
        mut[o++] = (uint8_t)(hl + (size_t)pad);
        if (pad) mut[o++] = 0;
        memcpy(mut + o, hs + skip, hl);
        o += hl;
        mut[1] = (uint8_t)(o - 2);
        P256_Compare(xy, pem, (const char*)m, ml, mut, o, "high-S twin", ref_ok);
    }
    P256_Compare(xy, pem, "other", 5, der, dl, "wrong message", ref_ok);
    for (int r = 0; r < rounds; r++) {
        size_t n = dl;
        memcpy(mut, der, dl);
        switch (Rnd(6)) {
        case 0: mut[Rnd((uint32_t)n)] ^= (uint8_t)(1u << Rnd(8)); break;
        case 1: n = Rnd((uint32_t)n); break;
        case 2: mut[n++] = (uint8_t)Rnd(256); break;
        case 3: mut[1] = (uint8_t)Rnd(256); break;
        case 4: mut[3] = (uint8_t)Rnd(40); break;
        case 5: { /* a non-minimal integer: a padding zero the sign doesn't need */
            memmove(mut + 5, mut + 4, n - 4);
            mut[4] = 0;
            mut[3]++;
            mut[1]++;
            n++;
            break;
        }
        }
        if (n) P256_Compare(xy, pem, (const char*)m, ml, mut, n, "mutated signature", ref_ok);
    }
}

int main(int argc, char** argv) {
    unsigned long long mutations = 20000;
    Diff_Abi();
    Ed25519_Tightening();
    Ed25519_Edges();
    Rule_Edges();
    int a = 1;
    if (a + 1 < argc && strcmp(argv[a], "--mutations") == 0) {
        mutations = strtoull(argv[a + 1], NULL, 10);
        a += 2;
    }
    for (size_t i = 0; i < sizeof(QUIRKS) / sizeof(QUIRKS[0]); i++) Run((const uint8_t*)QUIRKS[i], strlen(QUIRKS[i]));
    for (; a < argc; a++) AddPath(argv[a]);
    unsigned long long loaded = g_runs;
    Mutate(mutations);
    const char* p256 = getenv("HUB_INPUT_P256");
    if (p256 && *p256) P256(p256, 300);
    printf("[+] hub-input differential: %llu inputs (%llu mutated) match on %d-bit long\n", g_runs, g_runs - loaded, (int)sizeof(long) * 8);
    return 0;
}
