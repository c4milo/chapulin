// The inverse's rows of bin/diff_p256_wide (test/diff_p256_wide_test.c, which includes this file
// after the driver's helpers): p256_wide_inverse and p256_wide_inverse_public against the spec's
// models of their rounds, spec/lean/Spec/P256WideInverse.lean, at the field prime and at the
// group order.
#ifndef CH_TEST_DIFF_P256_WIDE_INVERSE_H
#define CH_TEST_DIFF_P256_WIDE_INVERSE_H

#include "p256_wide_inverse.h"

// The two moduli p256_wide_inverse takes in a host object, each beside -m^-1 mod 2^64: the field
// prime of p256_wide_field.h and the group order of p256_wide_scalar.c.
static const p256_wide_modulus INVERSE_MODULI[2] = {
    {{UINT64_C(0xffffffffffffffff), UINT64_C(0x00000000ffffffff), UINT64_C(0x0000000000000000),
      UINT64_C(0xffffffff00000001)},
     UINT64_C(1)                 },
    {{UINT64_C(0xf3b9cac2fc632551), UINT64_C(0xbce6faada7179e84), UINT64_C(0xffffffffffffffff),
      UINT64_C(0xffffffff00000000)},
     UINT64_C(0xccd1c8aaee00bc4f)},
};

#define INVERSE_WORDS P256_WIDE_INVERSE_WORDS
#define INVERSE_BITS 256U
#define INVERSE_RANDOM_ROWS 200

// The four words as 32 big-endian bytes.
static void inverse_words_to_bytes(uint8_t out[8 * INVERSE_WORDS],
                                   const uint64_t w[INVERSE_WORDS]) {
    for (size_t i = 0; i < INVERSE_WORDS; i++) {
        for (size_t j = 0; j < 8; j++) {
            out[8 * (INVERSE_WORDS - 1 - i) + (7 - j)] = (uint8_t)(w[i] >> (8 * j));
        }
    }
}

static int inverse_words_below(const uint64_t a[INVERSE_WORDS], const uint64_t b[INVERSE_WORDS]) {
    for (size_t i = INVERSE_WORDS; i > 0; i--) {
        if (a[i - 1] != b[i - 1]) {
            return a[i - 1] < b[i - 1];
        }
    }
    return 0;
}

// p256_wide_inverse on y modulo m, the answer apart from y and over it, against the spec, and
// p256_wide_inverse_public on the same y against the spec's model of its rounds.
static void diff_inverse_row(const p256_wide_modulus *m, const uint64_t y[INVERSE_WORDS]) {
    uint8_t m_bytes[8 * INVERSE_WORDS];
    uint8_t y_bytes[8 * INVERSE_WORDS];
    uint8_t o_bytes[8 * INVERSE_WORDS];
    uint64_t apart[INVERSE_WORDS];
    uint64_t over[INVERSE_WORDS];
    char cmd[32 + 2 * HEX_LEN(8 * INVERSE_WORDS)];
    char want[HEX_LEN(8 * INVERSE_WORDS)];
    p256_wide_inverse(apart, y, m);
    memcpy(over, y, sizeof over);
    p256_wide_inverse(over, over, m);
    if (memcmp(apart, over, sizeof over) != 0) {
        die("p256_wide_inverse: the answer over y differs from the answer apart from it");
    }
    inverse_words_to_bytes(m_bytes, m->word);
    inverse_words_to_bytes(y_bytes, y);
    inverse_words_to_bytes(o_bytes, apart);
    size_t cmd_len = (size_t)snprintf(cmd, sizeof cmd, "p256_wide_inverse ");
    cmd_len += hex_encode(cmd + cmd_len, m_bytes, sizeof m_bytes);
    cmd[cmd_len++] = ' ';
    (void)hex_encode(cmd + cmd_len, y_bytes, sizeof y_bytes);
    (void)hex_encode(want, o_bytes, sizeof o_bytes);
    expect(cmd, want);
    uint64_t public_answer[INVERSE_WORDS];
    p256_wide_inverse_public(public_answer, y, m);
    inverse_words_to_bytes(o_bytes, public_answer);
    cmd_len = (size_t)snprintf(cmd, sizeof cmd, "p256_wide_inverse_public ");
    cmd_len += hex_encode(cmd + cmd_len, m_bytes, sizeof m_bytes);
    cmd[cmd_len++] = ' ';
    (void)hex_encode(cmd + cmd_len, y_bytes, sizeof y_bytes);
    (void)hex_encode(want, o_bytes, sizeof o_bytes);
    expect(cmd, want);
}

// y = m - k, for k at most m.
static void inverse_minus(uint64_t y[INVERSE_WORDS], const p256_wide_modulus *m, uint64_t k) {
    uint64_t borrow = k;
    for (size_t i = 0; i < INVERSE_WORDS; i++) {
        y[i] = m->word[i] - borrow;
        borrow = m->word[i] < borrow ? 1 : 0;
    }
}

// 0 to 3, and m - 1 to m - 3.
static void diff_inverse_edges(const p256_wide_modulus *m) {
    uint64_t y[INVERSE_WORDS];
    for (uint64_t k = 0; k < 4; k++) {
        memset(y, 0, sizeof y);
        y[0] = k;
        diff_inverse_row(m, y);
        if (k > 0) {
            inverse_minus(y, m, k);
            diff_inverse_row(m, y);
        }
    }
}

// Every power of two below 2^256, and every power of two less one: each below m.
static void diff_inverse_powers(const p256_wide_modulus *m) {
    uint64_t y[INVERSE_WORDS];
    for (unsigned bit = 0; bit < INVERSE_BITS; bit++) {
        memset(y, 0, sizeof y);
        y[bit / 64] = UINT64_C(1) << (bit % 64);
        diff_inverse_row(m, y);
        memset(y, 0, sizeof y);
        for (unsigned below = 0; below < bit; below++) {
            y[below / 64] |= UINT64_C(1) << (below % 64);
        }
        diff_inverse_row(m, y);
    }
}

// Random values below m, whole and cut to a random length.
static void diff_inverse_random(const p256_wide_modulus *m) {
    uint64_t y[INVERSE_WORDS];
    for (int row = 0; row < INVERSE_RANDOM_ROWS; row++) {
        do {
            for (size_t i = 0; i < INVERSE_WORDS; i++) {
                y[i] = rng_next();
            }
        } while (!inverse_words_below(y, m->word));
        diff_inverse_row(m, y);
        unsigned keep = (unsigned)rng_below(INVERSE_BITS);
        for (unsigned bit = keep; bit < INVERSE_BITS; bit++) {
            y[bit / 64] &= ~(UINT64_C(1) << (bit % 64));
        }
        diff_inverse_row(m, y);
    }
}

static void diff_inverse(void) {
    for (size_t which = 0; which < 2; which++) {
        diff_inverse_edges(&INVERSE_MODULI[which]);
        diff_inverse_powers(&INVERSE_MODULI[which]);
        diff_inverse_random(&INVERSE_MODULI[which]);
    }
}

#endif
