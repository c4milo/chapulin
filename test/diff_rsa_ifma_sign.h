// bin/diff_rsa_ifma's rows of RSA signing's two exponentiations,
// rsa_ifma_sign.c's rsa_ifma_sign_power_pair over the lane model, against
// spec/lean/Spec/RsaIfma.lean's signPower (docs/decisions.md 120).
// test/diff_rsa_ifma_test.c alone includes this file, after it defines
// WORDS_MAX, COMMAND_SIZE, HEX_LEN, modulus_of_kind, words_to_bytes,
// append_words and lane_count_of, and under CH_RSA_IFMA_MODEL.
#ifndef CH_TEST_DIFF_RSA_IFMA_SIGN_H
#define CH_TEST_DIFF_RSA_IFMA_SIGN_H

#include <stdio.h>
#include <string.h>

#include "rsa_ifma_sign.h"
#include "rsa_mont64.h"

#include "diff_driver.h"

// The exponent length of most signing rows, in bytes: eight digits, which
// run the table, the squares and every kind of step. The spec takes about
// 3 ms a product at 32 words, so a row of the 8k bytes rsa_sign64.c passes
// takes seconds there; one pair at RSA-2048's prime, 16 words, takes them.
#define SIGN_EXPONENT_LEN 4

// rsa_ifma_sign_power_pair's k words for one prime against the spec's
// signPower: base^e R mod m for the base in rsa_mont64.c's domain, below m,
// and the exponent's e_len bytes. The spec writes R mod m and m0inv from m.
static void diff_sign_row(const uint8_t *n, size_t k, const uint64_t *base, const uint8_t *e,
                          size_t e_len, const uint64_t *out) {
    static char cmd[COMMAND_SIZE];
    static char want[HEX_LEN(8 * WORDS_MAX)];
    uint8_t bytes[8 * WORDS_MAX];
    size_t len = (size_t)snprintf(cmd, sizeof cmd, "rsa_ifma_sign_power %zu ", k);
    len += hex_encode(cmd + len, n, 8 * k);
    len = append_words(cmd, len, base, k);
    cmd[len++] = ' ';
    (void)hex_encode(cmd + len, e, e_len);
    words_to_bytes(bytes, out, k);
    (void)hex_encode(want, bytes, 8 * k);
    expect(cmd, want);
}

// A base below m in rsa_mont64.c's domain, k words: 0, 1, m - 1, or a
// random number times R mod m, which one Montgomery product by r2 writes.
enum { SIGN_BASE_ZERO, SIGN_BASE_ONE, SIGN_BASE_M_LESS_ONE, SIGN_BASE_RANDOM };
static void sign_base(uint64_t *words, const rsa_mont64_modulus *mod, int which) {
    size_t k = mod->words;
    memset(words, 0, k * sizeof(uint64_t));
    switch (which) {
    case SIGN_BASE_ZERO:
        break;
    case SIGN_BASE_ONE:
        words[0] = 1;
        break;
    case SIGN_BASE_M_LESS_ONE:
        memcpy(words, mod->m, k * sizeof(uint64_t));
        words[0] -= 1; // m is odd
        break;
    default:
        for (size_t i = 0; i < k; i++) {
            words[i] = rng_next();
        }
        rsa_mont64_mont_mul(words, words, mod->r2, mod);
        break;
    }
}

// An exponent of e_len bytes: all ones, all zeros, 1, or random bytes.
enum { SIGN_EXPONENT_ONES, SIGN_EXPONENT_ZERO, SIGN_EXPONENT_ONE, SIGN_EXPONENT_RANDOM };
static void sign_exponent(uint8_t *e, size_t e_len, int which) {
    memset(e, which == SIGN_EXPONENT_ONES ? 0xff : 0, e_len);
    if (which == SIGN_EXPONENT_ONE) {
        e[e_len - 1] = 1;
    }
    if (which == SIGN_EXPONENT_RANDOM) {
        rng_fill(e, e_len);
    }
}

// One call of rsa_ifma_sign_power_pair, as both_powers makes it, on the
// prime n_p with the base and exponent kinds given and a random second
// prime of the same word count with a random base and exponent, both of
// e_len bytes, and a row for each half.
static void diff_sign_pair(const uint8_t *n_p, size_t k, int base_kind, int exponent_kind,
                           size_t e_len) {
    uint8_t n_q[8 * WORDS_MAX];
    rsa_mont64_modulus mod_p;
    rsa_mont64_modulus mod_q;
    uint64_t base_p[WORDS_MAX];
    uint64_t base_q[WORDS_MAX];
    uint64_t out_p[WORDS_MAX];
    uint64_t out_q[WORDS_MAX];
    uint8_t e_p[8 * WORDS_MAX];
    uint8_t e_q[8 * WORDS_MAX];
    (void)modulus_of_kind(n_q, k, 0);
    // Every kind of modulus has its top bit set, so its bit length is 64k.
    rsa_mont64_modulus_init(&mod_p, n_p, 8 * k, 64 * k);
    rsa_mont64_modulus_init(&mod_q, n_q, 8 * k, 64 * k);
    sign_base(base_p, &mod_p, base_kind);
    sign_base(base_q, &mod_q, SIGN_BASE_RANDOM);
    sign_exponent(e_p, e_len, exponent_kind);
    sign_exponent(e_q, e_len, SIGN_EXPONENT_RANDOM);
    rsa_ifma_sign_power_pair(out_p, base_p, e_p, &mod_p, out_q, base_q, e_q, &mod_q, e_len);
    diff_sign_row(n_p, k, base_p, e_p, e_len, out_p);
    diff_sign_row(n_q, k, base_q, e_q, e_len, out_q);
}

// Whether a prime of k words is a word count the edge rows run at: where
// the register count changes, RSA-3072's 24, and the first and the last.
static int sign_edge(size_t k) {
    size_t here = lane_count_of(k);
    return k == RSA_IFMA_SIGN_WORDS_MIN || k == RSA_IFMA_SIGN_WORDS_MAX || k == 24 ||
           lane_count_of(k - 1) != here || lane_count_of(k + 1) != here;
}

// The edge rows at k: every other kind of modulus with a random base and
// exponent, and the bases 0, 1 and m - 1 with the exponents of all ones,
// all zeros and 1 under a random modulus.
static void diff_sign_edge(size_t k) {
    uint8_t n[8 * WORDS_MAX];
    for (int kind = 1; kind < MODULUS_KINDS; kind++) {
        if (modulus_of_kind(n, k, kind)) {
            diff_sign_pair(n, k, SIGN_BASE_RANDOM, SIGN_EXPONENT_RANDOM, SIGN_EXPONENT_LEN);
        }
    }
    (void)modulus_of_kind(n, k, 0);
    diff_sign_pair(n, k, SIGN_BASE_ZERO, SIGN_EXPONENT_ONES, SIGN_EXPONENT_LEN);
    diff_sign_pair(n, k, SIGN_BASE_ONE, SIGN_EXPONENT_ZERO, SIGN_EXPONENT_LEN);
    diff_sign_pair(n, k, SIGN_BASE_M_LESS_ONE, SIGN_EXPONENT_ONE, SIGN_EXPONENT_LEN);
}

static void diff_signs(void) {
    uint8_t n[8 * WORDS_MAX];
    for (size_t k = RSA_IFMA_SIGN_WORDS_MIN; k <= RSA_IFMA_SIGN_WORDS_MAX; k++) {
        (void)modulus_of_kind(n, k, 0);
        diff_sign_pair(n, k, SIGN_BASE_RANDOM, SIGN_EXPONENT_RANDOM, SIGN_EXPONENT_LEN);
        if (sign_edge(k)) {
            diff_sign_edge(k);
        }
    }
    // RSA-2048's prime, with the exponent of 8k bytes rsa_sign64.c passes.
    size_t k = RSA_IFMA_SIGN_WORDS_MIN;
    (void)modulus_of_kind(n, k, 0);
    diff_sign_pair(n, k, SIGN_BASE_RANDOM, SIGN_EXPONENT_RANDOM, 8 * k);
}

#endif
