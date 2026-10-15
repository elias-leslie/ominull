#ifndef OMINULL_GZIP_ENCODE_H
#define OMINULL_GZIP_ENCODE_H

/* A small gzip (RFC 1952) encoder for telemetry upload bodies, shared by the
 * Linux and Windows agents.
 *
 * The Windows toolchain has no zlib, and WinHTTP compresses only responses,
 * so the agents carry their own: LZ77 over a 32 KiB window with hash chains,
 * coded with deflate's fixed Huffman tables (RFC 1951 section 3.2.6). Fixed
 * tables cost a little ratio against zlib's dynamic ones on JSON, and save the
 * table builder, which is most of an encoder's code. Telemetry JSON repeats
 * field names, paths and command lines from event to event, which is what
 * LZ77 removes.
 *
 * Single-threaded, no global state: the caller passes the work memory. */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define GZ_WINDOW 32768u
#define GZ_HASH_BITS 15
#define GZ_HASH_SIZE (1u << GZ_HASH_BITS)
#define GZ_MIN_MATCH 3
#define GZ_MAX_MATCH 258
#define GZ_MAX_CHAIN 48

typedef struct {
    uint8_t *out;
    size_t cap, len;
    uint32_t bits;
    unsigned nbits;
    int overflow;
} GZ_BITS;

static void GzPutBits(GZ_BITS *b, uint32_t value, unsigned count) {
    b->bits |= value << b->nbits;
    b->nbits += count;
    while (b->nbits >= 8) {
        if (b->len < b->cap)
            b->out[b->len++] = (uint8_t)b->bits;
        else
            b->overflow = 1;
        b->bits >>= 8;
        b->nbits -= 8;
    }
}

/* Huffman codes go out most significant bit first. */
static void GzPutCode(GZ_BITS *b, uint32_t code, unsigned length) {
    uint32_t reversed = 0;
    for (unsigned i = 0; i < length; i++)
        reversed |= ((code >> i) & 1u) << (length - 1 - i);
    GzPutBits(b, reversed, length);
}

static void GzLiteral(GZ_BITS *b, unsigned symbol) {
    if (symbol < 144)
        GzPutCode(b, 0x30 + symbol, 8);
    else if (symbol < 256)
        GzPutCode(b, 0x190 + symbol - 144, 9);
    else if (symbol < 280)
        GzPutCode(b, symbol - 256, 7);
    else
        GzPutCode(b, 0xc0 + symbol - 280, 8);
}

static const uint16_t g_GzLengthBase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                            31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
static const uint8_t g_GzLengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                            2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const uint16_t g_GzDistBase[30] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,
                                          33,  49,  65,  97,  129, 193,  257,  385,  513,  769,
                                          1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t g_GzDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
                                          6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

static void GzMatch(GZ_BITS *b, unsigned length, unsigned distance) {
    unsigned l = 28;
    while (g_GzLengthBase[l] > length)
        l--;
    GzLiteral(b, 257 + l);
    if (g_GzLengthExtra[l])
        GzPutBits(b, length - g_GzLengthBase[l], g_GzLengthExtra[l]);
    unsigned d = 29;
    while (g_GzDistBase[d] > distance)
        d--;
    GzPutCode(b, d, 5);
    if (g_GzDistExtra[d])
        GzPutBits(b, distance - g_GzDistBase[d], g_GzDistExtra[d]);
}

static uint32_t GzCRC32(const uint8_t *data, size_t length) {
    static uint32_t table[256];
    static int ready;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        ready = 1;
    }
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < length; i++)
        crc = table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xffffffffu;
}

static unsigned GzHash(const uint8_t *p) {
    return ((uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]) * 2654435761u >> (32 - GZ_HASH_BITS);
}

/* Gzip_Encode compresses input into a newly allocated buffer and returns its
 * length in *outLength, or NULL when memory runs out. The result is never
 * larger than the input plus about an eighth, so a caller may still prefer
 * the plain body when it does not shrink. */
static uint8_t *Gzip_Encode(const void *input, size_t length, size_t *outLength) {
    const uint8_t *in = (const uint8_t *)input;
    if (outLength)
        *outLength = 0;
    if (!outLength || (length && !in) || length > 0x7fffffffu)
        return NULL;
    size_t cap = length + length / 8 + 64;
    int32_t *head = (int32_t *)malloc(GZ_HASH_SIZE * sizeof(int32_t));
    int32_t *prev = (int32_t *)malloc(GZ_WINDOW * sizeof(int32_t));
    uint8_t *out = (uint8_t *)malloc(cap);
    if (!head || !prev || !out) {
        free(head);
        free(prev);
        free(out);
        return NULL;
    }
    for (size_t i = 0; i < GZ_HASH_SIZE; i++)
        head[i] = -1;

    static const uint8_t header[10] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff};
    memcpy(out, header, sizeof(header));
    GZ_BITS b = {out, cap, sizeof(header), 0, 0, 0};
    GzPutBits(&b, 1, 1); /* BFINAL */
    GzPutBits(&b, 1, 2); /* BTYPE 01: fixed Huffman */

    size_t pos = 0;
    while (pos < length && !b.overflow) {
        unsigned bestLength = 0, bestDistance = 0;
        if (pos + GZ_MIN_MATCH <= length) {
            unsigned h = GzHash(in + pos);
            int32_t candidate = head[h];
            size_t limit = length - pos < GZ_MAX_MATCH ? length - pos : GZ_MAX_MATCH;
            for (unsigned chain = 0; candidate >= 0 && chain < GZ_MAX_CHAIN; chain++) {
                size_t distance = pos - (size_t)candidate;
                if (distance > GZ_WINDOW - 1)
                    break;
                const uint8_t *a = in + candidate, *c = in + pos;
                if (a[bestLength] == c[bestLength] && a[0] == c[0]) {
                    size_t n = 0;
                    while (n < limit && a[n] == c[n])
                        n++;
                    if (n > bestLength) {
                        bestLength = (unsigned)n;
                        bestDistance = (unsigned)distance;
                        if (n == limit)
                            break;
                    }
                }
                candidate = prev[candidate % GZ_WINDOW];
            }
            prev[pos % GZ_WINDOW] = head[h];
            head[h] = (int32_t)pos;
        }
        if (bestLength >= GZ_MIN_MATCH) {
            GzMatch(&b, bestLength, bestDistance);
            /* Index the positions the match covered, so later text can
             * refer back into it. */
            for (size_t i = pos + 1; i < pos + bestLength && i + GZ_MIN_MATCH <= length; i++) {
                unsigned h = GzHash(in + i);
                prev[i % GZ_WINDOW] = head[h];
                head[h] = (int32_t)i;
            }
            pos += bestLength;
        } else {
            GzLiteral(&b, in[pos]);
            pos++;
        }
    }
    GzLiteral(&b, 256);
    if (b.nbits)
        GzPutBits(&b, 0, 8 - b.nbits);
    free(head);
    free(prev);
    if (b.overflow || b.len + 8 > cap) {
        free(out);
        return NULL;
    }
    uint32_t crc = GzCRC32(in, length), size = (uint32_t)length;
    for (int i = 0; i < 4; i++)
        out[b.len++] = (uint8_t)(crc >> (8 * i));
    for (int i = 0; i < 4; i++)
        out[b.len++] = (uint8_t)(size >> (8 * i));
    *outLength = b.len;
    return out;
}

#endif
