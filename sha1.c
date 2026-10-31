// SHA-1, FIPS 180-4 section 6.1. sha1.h states the contract and why only
// a DNSSEC build holds it. The streaming code is sha256.c's, over SHA-1's
// five words and eighty rounds. Outside a DNSSEC build the file holds
// nothing, and sha1.h's type keeps the unit from being empty.
#include "sha1.h"

#include <string.h>

#ifdef CH_DNSSEC

static uint32_t rotate_left(uint32_t x, unsigned r) {
    return (x << r) | (x >> (32 - r));
}

// One block, FIPS 180-4 section 6.1.2: the 80-word schedule, then the
// rounds in four groups of twenty with their own function and constant.
static void compress(uint32_t h[5], const uint8_t p[SHA1_BLOCK]) {
    uint32_t w[80];
    for (size_t t = 0; t < 16; t++) {
        w[t] = (uint32_t)p[4 * t] << 24 | (uint32_t)p[4 * t + 1] << 16 |
               (uint32_t)p[4 * t + 2] << 8 | (uint32_t)p[4 * t + 3];
    }
    for (size_t t = 16; t < 80; t++) {
        w[t] = rotate_left(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }
    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    for (size_t t = 0; t < 80; t++) {
        uint32_t f;
        uint32_t k;
        if (t < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        } else if (t < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (t < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        uint32_t temp = rotate_left(a, 5) + f + e + k + w[t];
        e = d;
        d = c;
        c = rotate_left(b, 30);
        b = a;
        a = temp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

void sha1_init(sha1 *s) {
    s->h[0] = 0x67452301;
    s->h[1] = 0xefcdab89;
    s->h[2] = 0x98badcfe;
    s->h[3] = 0x10325476;
    s->h[4] = 0xc3d2e1f0;
    s->total_bytes = 0;
    s->fill = 0;
}

void sha1_update(sha1 *s, const uint8_t *in, size_t n) {
    s->total_bytes += n;
    if (s->fill > 0) {
        while (n > 0 && s->fill < SHA1_BLOCK) {
            s->block[s->fill++] = *in++;
            n--;
        }
        if (s->fill == SHA1_BLOCK) {
            compress(s->h, s->block);
            s->fill = 0;
        }
    }
    while (n >= SHA1_BLOCK) {
        compress(s->h, in);
        in += SHA1_BLOCK;
        n -= SHA1_BLOCK;
    }
    while (n > 0) {
        s->block[s->fill++] = *in++;
        n--;
    }
}

void sha1_final(sha1 *s, uint8_t out[SHA1_LEN]) {
    uint64_t bits = s->total_bytes * 8;
    // The padding goes into the block directly, FIPS 180-4 section 5.1.1:
    // the 0x80 byte, zeros to 56 bytes, a block more when the 0x80 byte
    // leaves no room for the length, and the 8-byte length. So a final
    // runs at most two compressions, where a byte-at-a-time update ran up
    // to 64 calls, each a compression in cbmc's formula.
    s->block[s->fill++] = 0x80;
    if (s->fill > SHA1_BLOCK - 8) {
        memset(s->block + s->fill, 0, SHA1_BLOCK - s->fill);
        compress(s->h, s->block);
        s->fill = 0;
    }
    memset(s->block + s->fill, 0, SHA1_BLOCK - 8 - s->fill);
    for (int i = 0; i < 8; i++) {
        s->block[SHA1_BLOCK - 8 + i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    compress(s->h, s->block);
    for (size_t i = 0; i < 5; i++) {
        out[4 * i] = (uint8_t)(s->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)s->h[i];
    }
}

#endif // CH_DNSSEC
