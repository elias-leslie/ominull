/* The agents' gzip encoder must produce what the hub's Go gzip reader (and
 * any inflater) decodes back byte for byte: checked here against zlib on
 * empty, tiny, incompressible, long-run and telemetry-shaped input. */
#include <assert.h>
#include <stdio.h>
#include <zlib.h>
#include "gzip_encode.h"

static void roundtrip(const char *name, const uint8_t *data, size_t length, double minRatio) {
    size_t packedLength = 0;
    uint8_t *packed = Gzip_Encode(data, length, &packedLength);
    assert(packed && packedLength >= 18);
    assert(packed[0] == 0x1f && packed[1] == 0x8b && packed[2] == 8);
    uint8_t *back = malloc(length + 1);
    assert(back);
    z_stream z = {0};
    assert(inflateInit2(&z, 16 + MAX_WBITS) == Z_OK);
    z.next_in = packed;
    z.avail_in = (uInt)packedLength;
    z.next_out = back;
    z.avail_out = (uInt)length + 1;
    int rc = inflate(&z, Z_FINISH);
    assert(rc == Z_STREAM_END); /* also checks the CRC and size trailer */
    assert(z.total_out == length && z.avail_in == 0);
    assert(length == 0 || memcmp(back, data, length) == 0);
    inflateEnd(&z);
    double ratio = packedLength ? (double)length / (double)packedLength : 0;
    printf("[+] %s: %zu -> %zu bytes (%.2fx)\n", name, length, packedLength, ratio);
    assert(ratio >= minRatio);
    free(back);
    free(packed);
}

int main(void) {
    roundtrip("empty", (const uint8_t *)"", 0, 0);
    roundtrip("one byte", (const uint8_t *)"{", 1, 0);

    size_t n = 200000;
    uint8_t *buf = malloc(4u << 20);
    assert(buf);
    uint32_t x = 2463534242u;
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        buf[i] = (uint8_t)x;
    }
    roundtrip("random", buf, n, 0.85);

    memset(buf, 'a', 1u << 20);
    roundtrip("one megabyte run", buf, 1u << 20, 100);

    /* Telemetry shaped: one header, then events that repeat field names and
     * process identity with changing ports, counts and times. */
    size_t off = (size_t)snprintf((char *)buf, 4u << 20,
                                  "{\"type\":\"telemetry\",\"endpoint_id\":\"linux-host\",\"events\":[");
    for (int i = 0; i < 64; i++)
        off += (size_t)snprintf((char *)buf + off, (4u << 20) - off,
                                "%s{\"layer\":\"linux-socket-v1\",\"action\":\"PERMIT\",\"direction\":\"OUTBOUND\","
                                "\"protocol\":6,\"src_ip\":\"10.0.0.5\",\"dst_ip\":\"203.0.113.%d\",\"src_port\":%d,"
                                "\"dst_port\":443,\"bytes_in\":%d,\"bytes_out\":%d,\"process_path\":\"/usr/bin/python3.12\","
                                "\"process_id\":%d,\"command_line\":\"/usr/bin/python3 -m service.worker --queue %d\","
                                "\"executable_sha256\":\"e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f\","
                                "\"timestamp\":\"2026-10-15T14:01:%02dZ\"}",
                                i ? "," : "", i % 7, 40000 + i * 13, i * 97, i * 31, 4000 + i % 3, i % 3, i % 60);
    off += (size_t)snprintf((char *)buf + off, (4u << 20) - off, "]}");
    roundtrip("telemetry batch", buf, off, 6);

    /* Matches that reach back the whole window and span the 258-byte cap. */
    for (size_t i = 0; i < 300000; i++)
        buf[i] = (uint8_t)("ominull-window-test"[i % 19] + (i / 40000));
    roundtrip("window edges", buf, 300000, 20);
    free(buf);
    printf("[+] gzip encoder round trips through zlib.\n");
    return 0;
}
