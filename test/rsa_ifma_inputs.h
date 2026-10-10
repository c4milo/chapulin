// Test code only: the inputs bin/rsa_ifma_model_test and
// bin/rsa_ifma_equiv_test draw, from one seeded generator, so that an
// ordinary run replays exactly and the nightly can vary
// CH_RSA_EQUIV_SEED, as test/rsa_equiv_test.c does. Each binary's main
// unit includes this file once. bin/rsa_avx2_model_test and
// bin/rsa_avx2_equiv_test draw the AVX2 kernel's inputs from it too
// (docs/decisions.md 122): the moduli, and the power of two by doubling.
#ifndef CH_TEST_RSA_IFMA_INPUTS_H
#define CH_TEST_RSA_IFMA_INPUTS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rsa_mont64.h"

// xorshift64, as test/rsa_equiv_test.c writes it and for its reasons: a
// fixed default seed, so a mismatch reproduces bit for bit, and an
// environment variable to vary it. Never time().
#define RSA_IFMA_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = RSA_IFMA_DEFAULT_SEED;

// Reads CH_RSA_EQUIV_SEED, if set, as the seed, and returns the seed in
// use. A value that is not a number, or zero, keeps the default:
// xorshift64 is all zeroes forever from zero.
static inline uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_RSA_EQUIV_SEED");
    if (text != NULL) {
        char *end = NULL;
        unsigned long long value = strtoull(text, &end, 0);
        if (end != text && *end == 0 && value != 0) {
            rng_state = (uint64_t)value;
        }
    }
    return rng_state;
}

static inline uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static inline void rng_fill(uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        bytes[i] = (uint8_t)(rng_next() >> 56);
    }
}

// The moduli of `words` words the kernel takes, by kind: random words with
// the top and bottom bits set, 2^(64k) - 1, 2^(64k - 1) + 1, and
// test/rsa_equiv_test.c's (B^(k + 1) + 1) / (B + 1) for B = 2^64 and an
// even k, whose words alternate between 0 and all ones above a low word of
// 1. It returns 0 for the last kind at an odd k, which has no such
// modulus, and 1 otherwise.
enum { RSA_IFMA_MODULUS_KINDS = 5 };
static inline int modulus_of_kind(uint8_t *n, size_t words, int kind) {
    size_t n_len = 8 * words;
    memset(n, 0, n_len);
    switch (kind) {
    case 0:
    case 1:
        rng_fill(n, n_len);
        n[0] |= 0x80;
        n[n_len - 1] |= 1;
        return 1;
    case 2:
        memset(n, 0xff, n_len);
        return 1;
    case 3:
        n[0] = 0x80;
        n[n_len - 1] = 1;
        return 1;
    default:
        if (words % 2 != 0) {
            return 0;
        }
        for (size_t word = 1; word < words; word += 2) {
            memset(n + n_len - 8 * (word + 1), 0xff, 8);
        }
        n[n_len - 1] = 1;
        return 1;
    }
}

// 2^exponent mod m by doubling from 1, which is below m: a computation
// that shares nothing with rsa_mont.c's division, which writes the same
// power for rsa_ifma_public.
static inline void power_of_two_by_doubling(uint64_t *power, const rsa_mont64_modulus *mod,
                                            size_t exponent) {
    memset(power, 0, mod->words * sizeof(uint64_t));
    power[0] = 1;
    for (size_t i = 0; i < exponent; i++) {
        rsa_mont64_add(power, power, power, mod);
    }
}

// Lanes that normalize_digits's rare steps act on: lanes at 2^52 - 1,
// which pass a carry on, in runs that cross a register's edge, lanes just
// below and just above 2^52, lanes with carry bits above 52 and all ones
// or nearly so below them, and random lanes of up to 64 bits. After the
// first pass of carries a random product leaves a lane at 2^52 or above
// with odds below 2^-40, so only lanes such as these test the second pass.
static inline uint64_t extreme_lane(void) {
    const uint64_t digit_mask = (UINT64_C(1) << 52) - 1;
    switch (rng_next() % 7) {
    case 0:
    case 1:
        return digit_mask;
    case 2:
        return digit_mask - (rng_next() & 3);
    case 3:
        return (UINT64_C(1) << 52) + (rng_next() & 3);
    case 4:
        return ((rng_next() & 0xfff) << 52) | (digit_mask - (rng_next() & 1));
    case 5:
        return rng_next() >> (rng_next() % 64);
    default:
        return rng_next();
    }
}

static inline void extreme_lanes(uint64_t *lanes, size_t count) {
    for (size_t j = 0; j < count; j++) {
        lanes[j] = extreme_lane();
    }
}

#endif
