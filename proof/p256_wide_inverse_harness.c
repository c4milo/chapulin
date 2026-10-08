// Proves, for p256_wide_inverse.c's combinations of a round:
//
//   combine_exact is memory-safe and wraps no unsigned value, for any four
//   words of x and of y and any two's complement words f and g: the
//   magnitudes, the products' signs and the five-word sum and its negation
//   all keep inside their words, and the shift reads the five it fills;
//
//   combine_modular is memory-safe and wraps no unsigned value, for any
//   modulus, any x and y and either negate mask, when |f| + |g| is at most
//   2^31, the bound p256_wide_inverse_steps_harness.c proves of every
//   round's factors: the operands m - x and m - y, the three sums into the
//   word above t's four, the multiplier q from the real 64x64 multiply, and
//   the final subtraction of m.
//
// Both run in the two shapes p256_wide_inverse calls them in: the output
// distinct from both inputs, and x and y distinct.
//
// The products are a row contract of this file's own, which keeps one more
// property than proof/p256_wide_stubs.h's: the word above the four is at
// most x. combine_modular adds three of those words, and the bound is what
// holds their sum inside a word. It follows from the row's value: four words
// plus x times four words is below (x + 1) 2^256. That value is a product's,
// which no harness here proves, as proof/p256_wide_row_harness.c says;
// bin/p256_equiv_test and the vectors hold it.
//
// Not proven here: the values. Equality of two multipliers is the SAT
// instance docs/proofs.md says does not converge, so the sums' values rest on
// spec/lean/Spec/P256WideInverse.lean for the algorithm, on
// bin/diff_p256_wide for the C against that model, and on
// bin/p256_equiv_test for the C against p256_field.c's and p256_scalar.c's
// Fermat inverses.
#include "harness.h"

#define P256_WIDE_CARRY P256_WIDE_CARRY_BUILTIN
#include "p256_wide_word.h"
#define p256_wide_mul_row stub_mul_row_bounded

uint64_t nondet_u64(void);

// p256_wide_mul_row writes any four words and returns any word up to x.
static uint64_t stub_mul_row_bounded(uint64_t *t0, uint64_t *t1, uint64_t *t2, uint64_t *t3,
                                     uint64_t x, uint64_t b0, uint64_t b1, uint64_t b2,
                                     uint64_t b3) {
    (void)b0;
    (void)b1;
    (void)b2;
    (void)b3;
    __CPROVER_assert(__CPROVER_w_ok(t0, sizeof *t0) && __CPROVER_w_ok(t1, sizeof *t1) &&
                         __CPROVER_w_ok(t2, sizeof *t2) && __CPROVER_w_ok(t3, sizeof *t3),
                     "p256_wide_mul_row: the four words are writable");
    *t0 = nondet_u64();
    *t1 = nondet_u64();
    *t2 = nondet_u64();
    *t3 = nondet_u64();
    uint64_t above = nondet_u64();
    __CPROVER_assume(above <= x);
    return above;
}

#include "p256_wide_inverse.c"

static void words_nondet(uint64_t x[WORDS]) {
    for (size_t i = 0; i < WORDS; i++) {
        x[i] = nondet_u64();
    }
}

// A factor pair with |f| + |g| at most 2^31, as two's complement words.
static void factors_nondet(uint64_t *f, uint64_t *g) {
    int64_t sf = nondet_i64();
    int64_t sg = nondet_i64();
    int64_t bound = (int64_t)1 << STEPS;
    __CPROVER_assume(sf >= -bound && sf <= bound && sg >= -bound && sg <= bound);
    __CPROVER_assume((sf < 0 ? -sf : sf) + (sg < 0 ? -sg : sg) <= bound);
    *f = (uint64_t)sf;
    *g = (uint64_t)sg;
}

static void prove_combine_exact(void) {
    uint64_t x[WORDS];
    uint64_t y[WORDS];
    uint64_t o[WORDS];
    words_nondet(x);
    words_nondet(y);
    uint64_t negative = combine_exact(o, x, y, nondet_u64(), nondet_u64());
    __CPROVER_assert(negative == 0 || negative == UINT64_MAX,
                     "combine_exact: the sign it returns is a mask");
}

static void prove_combine_modular(void) {
    p256_wide_modulus m;
    words_nondet(m.word);
    m.negated_inverse = nondet_u64();
    uint64_t x[WORDS];
    uint64_t y[WORDS];
    uint64_t o[WORDS];
    words_nondet(x);
    words_nondet(y);
    uint64_t f;
    uint64_t g;
    factors_nondet(&f, &g);
    uint64_t negate = nondet_u64();
    __CPROVER_assume(negate == 0 || negate == UINT64_MAX);
    combine_modular(o, x, y, f, g, negate, &m);
}

int main(void) {
    prove_combine_exact();
    prove_combine_modular();
    return 0;
}
