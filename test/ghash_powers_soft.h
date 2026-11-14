// The powers a host object stores beside an AES-GCM key (suite.h,
// docs/decisions.md 234), computed here from the hash subkey with bit
// arithmetic alone: no carry-less multiply and no line of ghash_vector.h.
// A test hands them to an entry in place of the subkey, or compares them
// with the bytes ghash_hw.c's gcm_powers_hw wrote.
//
// The form. Power i, for i from 0 to 7, is H^(i + 1) times x^-1 in
// GF(2^128), 32 bytes at offset 32 * i:
//
//   bytes 0 to 7    the block's bytes 0 to 7 as a 64-bit integer, most
//                   significant first, stored as a little-endian word
//   bytes 8 to 15   the block's bytes 8 to 15, the same way
//   bytes 16 to 31  the exclusive-or of those two words, twice
//
// A host object is little-endian (cpu_cfg.h), so a word's bytes lie in the
// reverse of the block's order.
#ifndef CH_TEST_GHASH_POWERS_SOFT_H
#define CH_TEST_GHASH_POWERS_SOFT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GHASH_POWERS_SOFT_BLOCK ((size_t)16)
#define GHASH_POWERS_SOFT_COUNT ((size_t)8)
#define GHASH_POWERS_SOFT_LEN (GHASH_POWERS_SOFT_COUNT * 2 * GHASH_POWERS_SOFT_BLOCK)

// SP 800-38D §6.3, Algorithm 1: x = x * y. Bit i of a block, counted from
// the most significant bit of byte 0, is the coefficient of x^i.
static void ghash_powers_soft_multiply(uint8_t x[GHASH_POWERS_SOFT_BLOCK],
                                       const uint8_t y[GHASH_POWERS_SOFT_BLOCK]) {
    uint8_t product[GHASH_POWERS_SOFT_BLOCK] = {0};
    uint8_t multiple[GHASH_POWERS_SOFT_BLOCK];
    memcpy(multiple, y, sizeof multiple);
    for (size_t bit = 0; bit < 8 * GHASH_POWERS_SOFT_BLOCK; bit++) {
        if (((unsigned)x[bit / 8] >> (7 - bit % 8)) & 1U) {
            for (size_t i = 0; i < GHASH_POWERS_SOFT_BLOCK; i++) {
                product[i] ^= multiple[i];
            }
        }
        unsigned moved_out = multiple[GHASH_POWERS_SOFT_BLOCK - 1] & 1U;
        for (size_t i = GHASH_POWERS_SOFT_BLOCK - 1; i > 0; i--) {
            multiple[i] = (uint8_t)((multiple[i] >> 1) | (multiple[i - 1] << 7));
        }
        multiple[0] = (uint8_t)(multiple[0] >> 1);
        if (moved_out) {
            multiple[0] ^= 0xe1U;
        }
    }
    memcpy(x, product, sizeof product);
}

// out = in * x^-1. Each coefficient moves down one power. The coefficient
// of x^0 becomes that of x^-1, which is x^127 + x^6 + x + 1 modulo the
// field polynomial x^128 + x^7 + x^2 + x + 1.
static void ghash_powers_soft_inverse_x(uint8_t out[GHASH_POWERS_SOFT_BLOCK],
                                        const uint8_t in[GHASH_POWERS_SOFT_BLOCK]) {
    unsigned constant_term = (unsigned)in[0] >> 7;
    for (size_t i = 0; i < GHASH_POWERS_SOFT_BLOCK; i++) {
        unsigned next = i + 1 < GHASH_POWERS_SOFT_BLOCK ? (unsigned)in[i + 1] >> 7 : 0U;
        out[i] = (uint8_t)(((unsigned)in[i] << 1) | next);
    }
    if (constant_term) {
        out[0] ^= 0xc2U;
        out[GHASH_POWERS_SOFT_BLOCK - 1] ^= 0x01U;
    }
}

// powers = the stored form of subkey's first count powers, count at most
// GHASH_POWERS_SOFT_COUNT, and zeros after them.
static void ghash_powers_soft_first(uint8_t powers[GHASH_POWERS_SOFT_LEN],
                                    const uint8_t subkey[GHASH_POWERS_SOFT_BLOCK], size_t count) {
    uint8_t power[GHASH_POWERS_SOFT_BLOCK];
    memcpy(power, subkey, sizeof power);
    memset(powers, 0, GHASH_POWERS_SOFT_LEN);
    for (size_t i = 0; i < count; i++) {
        if (i > 0) {
            ghash_powers_soft_multiply(power, subkey);
        }
        uint8_t scaled[GHASH_POWERS_SOFT_BLOCK];
        ghash_powers_soft_inverse_x(scaled, power);
        uint8_t *at = &powers[i * 2 * GHASH_POWERS_SOFT_BLOCK];
        for (size_t j = 0; j < 8; j++) {
            at[j] = scaled[7 - j];
            at[8 + j] = scaled[15 - j];
            at[16 + j] = (uint8_t)(scaled[7 - j] ^ scaled[15 - j]);
            at[24 + j] = at[16 + j];
        }
    }
}

// powers = the stored form of subkey's first eight powers.
static void ghash_powers_soft(uint8_t powers[GHASH_POWERS_SOFT_LEN],
                              const uint8_t subkey[GHASH_POWERS_SOFT_BLOCK]) {
    ghash_powers_soft_first(powers, subkey, GHASH_POWERS_SOFT_COUNT);
}

#endif
