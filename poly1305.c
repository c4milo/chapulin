#include "poly1305.h"

#include "ch_assert.h"
#include "ct.h"

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void poly1305_init(poly1305 *p, const uint8_t key[POLY1305_KEY]) {
    // r is clamped per RFC 8439 §2.5.1; the masks below fold the clamp into
    // the 26-bit limb split.
    p->r[0] = load32(key + 0) & 0x3ffffff;
    p->r[1] = (load32(key + 3) >> 2) & 0x3ffff03;
    p->r[2] = (load32(key + 6) >> 4) & 0x3ffc0ff;
    p->r[3] = (load32(key + 9) >> 6) & 0x3f03fff;
    p->r[4] = (load32(key + 12) >> 8) & 0x00fffff;
    for (int i = 0; i < 5; i++) {
        p->h[i] = 0;
    }
    for (size_t i = 0; i < 4; i++) {
        p->pad[i] = load32(key + 16 + 4 * i);
    }
    p->fill = 0;
}

// Absorbs one 16-byte block. hibit is 1<<24 for full blocks, 0 for the
// padded final partial block (whose 0x01 terminator is already in place).
static void blocks(poly1305 *p, const uint8_t *m, size_t n, uint32_t hibit) {
    uint32_t r0 = p->r[0];
    uint32_t r1 = p->r[1];
    uint32_t r2 = p->r[2];
    uint32_t r3 = p->r[3];
    uint32_t r4 = p->r[4];
    uint32_t s1 = r1 * 5;
    uint32_t s2 = r2 * 5;
    uint32_t s3 = r3 * 5;
    uint32_t s4 = r4 * 5;
    uint32_t h0 = p->h[0];
    uint32_t h1 = p->h[1];
    uint32_t h2 = p->h[2];
    uint32_t h3 = p->h[3];
    uint32_t h4 = p->h[4];
    while (n >= 16) {
        h0 += load32(m + 0) & 0x3ffffff;
        h1 += (load32(m + 3) >> 2) & 0x3ffffff;
        h2 += (load32(m + 6) >> 4) & 0x3ffffff;
        h3 += (load32(m + 9) >> 6) & 0x3ffffff;
        h4 += (load32(m + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 +
                      (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 +
                      (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
                      (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 +
                      (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 +
                      (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint64_t c = d0 >> 26;
        h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c;
        c = d1 >> 26;
        h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c;
        c = d2 >> 26;
        h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c;
        c = d3 >> 26;
        h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c;
        c = d4 >> 26;
        h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += (uint32_t)c * 5;
        h1 += h0 >> 26;
        h0 &= 0x3ffffff;

        m += 16;
        n -= 16;
    }
    p->h[0] = h0;
    p->h[1] = h1;
    p->h[2] = h2;
    p->h[3] = h3;
    p->h[4] = h4;
}

void poly1305_update(poly1305 *p, const uint8_t *in, size_t n) {
    if (p->fill > 0) {
        while (n > 0 && p->fill < 16) {
            p->block[p->fill++] = *in++;
            n--;
        }
        if (p->fill == 16) {
            blocks(p, p->block, 16, (uint32_t)1 << 24);
            p->fill = 0;
        }
    }
    size_t whole = n & ~(size_t)15;
    if (whole > 0) {
        blocks(p, in, whole, (uint32_t)1 << 24);
        in += whole;
        n -= whole;
    }
    // Here either the buffer drained above (fill 0) or n ran out first; the
    // remainder is under a block. The assert makes the invariant checkable.
    CH_ASSERT(p->fill + n < 16);
    while (n > 0 && p->fill < sizeof p->block) {
        p->block[p->fill++] = *in++;
        n--;
    }
}

void poly1305_final(poly1305 *p, uint8_t tag[POLY1305_TAG]) {
    CH_ASSERT(p->fill < 16);
    if (p->fill > 0) {
        p->block[p->fill++] = 1;
        while (p->fill < 16) {
            p->block[p->fill++] = 0;
        }
        blocks(p, p->block, 16, 0);
    }
    uint32_t h0 = p->h[0];
    uint32_t h1 = p->h[1];
    uint32_t h2 = p->h[2];
    uint32_t h3 = p->h[3];
    uint32_t h4 = p->h[4];
    // Full carry, then h mod 2^130-5 via constant-time select of h or h-p.
    uint32_t c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    uint32_t g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - ((uint32_t)1 << 26);

    // mask = all-ones when h >= p (g4 didn't borrow), else zero.
    uint32_t mask = (g4 >> 31) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    // Repack 26-bit limbs into 128 bits and add the pad with carries.
    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    uint64_t f = (uint64_t)h0 + p->pad[0];
    h0 = (uint32_t)f;
    f = (uint64_t)h1 + p->pad[1] + (f >> 32);
    h1 = (uint32_t)f;
    f = (uint64_t)h2 + p->pad[2] + (f >> 32);
    h2 = (uint32_t)f;
    f = (uint64_t)h3 + p->pad[3] + (f >> 32);
    h3 = (uint32_t)f;

    const uint32_t hs[4] = {h0, h1, h2, h3};
    for (size_t i = 0; i < 4; i++) {
        tag[4 * i] = (uint8_t)hs[i];
        tag[4 * i + 1] = (uint8_t)(hs[i] >> 8);
        tag[4 * i + 2] = (uint8_t)(hs[i] >> 16);
        tag[4 * i + 3] = (uint8_t)(hs[i] >> 24);
    }
    ct_wipe(p, sizeof *p);
}
