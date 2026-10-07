// The field half of bin/p384_equiv_test: p384_wide_field.c, the six
// 64-bit words a host object computes on, against p384_field.c, the twelve
// 32-bit words that stay the reference (docs/decisions.md 97). The two
// files hold the same routines, so each routine runs at both widths on the
// same 48 bytes and must leave the same number, and each constant must be
// the same number at both widths.
//
// The operands are thirteen values at the edges of each modulus, every
// pair of them, and random pairs below it. Each product, sum and
// difference runs in the four shapes of its arguments a caller uses: a
// third array for the result, the result over the left operand, over the
// right one, and one array as all three.
#include <stdio.h>
#include <string.h>

#include "p384_equiv.h"
#include "p384_field.h"
#include "p384_portable.h"
#include "p384_wide_field.h"

#define EDGES 13
#define RANDOM_PAIRS 150

typedef struct {
    const char *name;
    const p384_wide_modulus *wide;
    const p384_modulus *portable;
} moduli;

typedef void wide_op(uint64_t *o, const uint64_t *a, const uint64_t *b,
                     const p384_wide_modulus *mod);
typedef void portable_op(uint32_t *o, const uint32_t *a, const uint32_t *b,
                         const p384_modulus *mod);

static const struct {
    const char *name;
    wide_op *wide;
    portable_op *portable;
} OPS[] = {
    {"mod_add",  p384_wide_mod_add,  p384_mod_add },
    {"mod_sub",  p384_wide_mod_sub,  p384_mod_sub },
    {"mont_mul", p384_wide_mont_mul, p384_mont_mul},
    {"mod_mul",  p384_wide_mod_mul,  p384_mod_mul }
};
#define OP_COUNT (sizeof OPS / sizeof OPS[0])

static unsigned long comparisons = 0;
static int differences = 0;

static void expect(int same, const char *what, const moduli *mod) {
    comparisons++;
    if (!same) {
        differences++;
        (void)fprintf(stderr,
                      "p384_equiv: %s mod %s: the 64-bit words and the 32-bit words differ\n", what,
                      mod->name);
    }
}

static void wide_to_bytes(uint8_t b[P384_LEN], const uint64_t a[P384_WIDE_WORDS]) {
    for (int i = 0; i < P384_WIDE_WORDS; i++) {
        for (int j = 0; j < 8; j++) {
            b[P384_LEN - 1 - 8 * i - j] = (uint8_t)(a[i] >> (8 * j));
        }
    }
}

// 1 when the six words and the twelve are one number.
static int same_number(const uint64_t wide[P384_WIDE_WORDS], const uint32_t portable[P384_WORDS]) {
    uint8_t x[P384_LEN];
    uint8_t y[P384_LEN];
    wide_to_bytes(x, wide);
    p384_portable_to_bytes(y, portable);
    return memcmp(x, y, sizeof x) == 0;
}

static void constants(const moduli *mod) {
    expect(same_number(mod->wide->m, mod->portable->m), "the modulus", mod);
    expect(same_number(mod->wide->r2, mod->portable->r2), "r2", mod);
    expect((uint32_t)mod->wide->m0inv == mod->portable->m0inv, "the low half of m0inv", mod);
    // m0inv is -m^-1 modulo 2^64, so its product with m's low word is -1
    // there. The product wraps on purpose.
    expect(mod->wide->m0inv * mod->wide->m[0] == UINT64_MAX, "m0inv", mod);
}

// The reading of 48 bytes, the two predicates, and the plain sum and
// difference with the carry and the borrow they return.
static void plain(const moduli *mod, const uint8_t a_be[P384_LEN], const uint8_t b_be[P384_LEN]) {
    uint64_t wide_a[P384_WIDE_WORDS];
    uint64_t wide_b[P384_WIDE_WORDS];
    uint64_t wide_o[P384_WIDE_WORDS];
    uint32_t a[P384_WORDS];
    uint32_t b[P384_WORDS];
    uint32_t o[P384_WORDS];
    uint8_t back[P384_LEN];
    p384_wide_from_bytes(wide_a, a_be);
    p384_wide_from_bytes(wide_b, b_be);
    p384_from_bytes(a, a_be);
    p384_from_bytes(b, b_be);
    wide_to_bytes(back, wide_a);
    expect(memcmp(back, a_be, sizeof back) == 0, "from_bytes", mod);
    expect(p384_wide_is_zero(wide_a) == p384_is_zero(a), "is_zero", mod);
    expect(p384_wide_compare(wide_a, wide_b) == p384_compare(a, b), "compare", mod);
    expect(p384_wide_compare(wide_a, mod->wide->m) == p384_compare(a, mod->portable->m),
           "compare with the modulus", mod);
    uint64_t wide_carry = p384_wide_add_raw(wide_o, wide_a, wide_b);
    uint32_t carry = p384_add_raw(o, a, b);
    expect(wide_carry == carry && same_number(wide_o, o), "add_raw", mod);
    wide_carry = p384_wide_sub_raw(wide_o, wide_a, wide_b);
    carry = p384_sub_raw(o, a, b);
    expect(wide_carry == carry && same_number(wide_o, o), "sub_raw", mod);
    wide_carry = p384_wide_sub_raw(wide_a, wide_a, wide_b);
    carry = p384_sub_raw(a, a, b);
    expect(wide_carry == carry && same_number(wide_a, a), "sub_raw over its left operand", mod);
}

// One routine on (a, b) below the modulus, in one shape of its arguments:
// 0 writes a third array, 1 writes the left operand, 2 writes the right
// one, and 3 passes the left operand as all three.
static void routine(const moduli *mod, size_t op, int shape, const uint8_t a_be[P384_LEN],
                    const uint8_t b_be[P384_LEN]) {
    static const int RESULT[4] = {2, 0, 1, 0};
    static const int RIGHT[4] = {1, 1, 1, 0};
    uint64_t wide[3][P384_WIDE_WORDS] = {{0}};
    uint32_t portable[3][P384_WORDS] = {{0}};
    p384_wide_from_bytes(wide[0], a_be);
    p384_wide_from_bytes(wide[1], b_be);
    p384_from_bytes(portable[0], a_be);
    p384_from_bytes(portable[1], b_be);
    int result = RESULT[shape];
    int right = RIGHT[shape];
    OPS[op].wide(wide[result], wide[0], wide[right], mod->wide);
    OPS[op].portable(portable[result], portable[0], portable[right], mod->portable);
    expect(same_number(wide[result], portable[result]), OPS[op].name, mod);
}

// The inverse of a, which is not zero, into a second array and over a.
static void inverse(const moduli *mod, const uint8_t a_be[P384_LEN]) {
    uint64_t wide_a[P384_WIDE_WORDS];
    uint64_t wide_o[P384_WIDE_WORDS];
    uint32_t a[P384_WORDS];
    uint32_t o[P384_WORDS];
    p384_wide_from_bytes(wide_a, a_be);
    p384_from_bytes(a, a_be);
    p384_wide_mod_inverse(wide_o, wide_a, mod->wide);
    p384_mod_inverse(o, a, mod->portable);
    expect(same_number(wide_o, o), "mod_inverse", mod);
    p384_wide_mod_inverse(wide_a, wide_a, mod->wide);
    p384_mod_inverse(a, a, mod->portable);
    expect(same_number(wide_a, a), "mod_inverse over its operand", mod);
}

static void pair(const moduli *mod, const uint8_t a_be[P384_LEN], const uint8_t b_be[P384_LEN]) {
    static const uint8_t zero[P384_LEN] = {0};
    plain(mod, a_be, b_be);
    for (size_t op = 0; op < OP_COUNT; op++) {
        for (int shape = 0; shape < 4; shape++) {
            routine(mod, op, shape, a_be, b_be);
        }
    }
    if (memcmp(a_be, zero, sizeof zero) != 0) {
        inverse(mod, a_be);
    }
}

// Thirteen numbers below both moduli, or at the edge of this one: 0, 1,
// 2, m - 1, m - 2, 2^64 - 1, 2^64, 2^128 - 1, 2^192, 2^383, 2^383 - 1,
// r2 and a pattern of alternating bits.
static void edges(uint8_t out[EDGES][P384_LEN], const moduli *mod) {
    memset(out, 0, (size_t)EDGES * P384_LEN);
    out[1][P384_LEN - 1] = 1;
    out[2][P384_LEN - 1] = 2;
    // Both moduli end in a byte above 2, so neither subtraction borrows.
    p384_portable_to_bytes(out[3], mod->portable->m);
    out[3][P384_LEN - 1] -= 1;
    p384_portable_to_bytes(out[4], mod->portable->m);
    out[4][P384_LEN - 1] -= 2;
    memset(out[5] + P384_LEN - 8, 0xff, 8);
    out[6][P384_LEN - 9] = 1;
    memset(out[7] + P384_LEN - 16, 0xff, 16);
    out[8][P384_LEN - 25] = 1;
    out[9][0] = 0x80;
    memset(out[10], 0xff, P384_LEN);
    out[10][0] = 0x7f;
    p384_portable_to_bytes(out[11], mod->portable->r2);
    memset(out[12], 0x55, P384_LEN);
}

// 48 random bytes as a number below the modulus: one subtraction, because
// both moduli are above 2^383.
static void random_below(uint8_t out[P384_LEN], const moduli *mod) {
    uint32_t words[P384_WORDS];
    p384_equiv_rng_bytes(out, P384_LEN);
    p384_from_bytes(words, out);
    if (p384_compare(words, mod->portable->m) >= 0) {
        (void)p384_sub_raw(words, words, mod->portable->m);
    }
    p384_portable_to_bytes(out, words);
}

static void one_modulus(const moduli *mod) {
    uint8_t edge[EDGES][P384_LEN];
    uint8_t a[P384_LEN];
    uint8_t b[P384_LEN];
    constants(mod);
    edges(edge, mod);
    for (int i = 0; i < EDGES; i++) {
        for (int j = 0; j < EDGES; j++) {
            pair(mod, edge[i], edge[j]);
        }
    }
    for (int i = 0; i < RANDOM_PAIRS; i++) {
        random_below(a, mod);
        random_below(b, mod);
        pair(mod, a, b);
        pair(mod, a, edge[i % EDGES]);
    }
}

unsigned long p384_equiv_field(int *failures) {
    static const moduli modulo_p = {"p", &p384_wide_modp, &p384_modp};
    static const moduli modulo_n = {"n", &p384_wide_modn, &p384_modn};
    one_modulus(&modulo_p);
    one_modulus(&modulo_n);
    *failures += differences;
    return comparisons;
}
