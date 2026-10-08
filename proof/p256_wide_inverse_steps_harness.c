// Proves, for p256_wide_inverse.c, over every input and on the real bodies:
//
//   nonzero_mask gives all ones for every word but zero, and zero for zero;
//
//   approximations against a reference that finds the bit length n of a | b
//   with a loop over its 256 bits and reads the 33 bits from n - 33 up one bit
//   at a time: for any a and b, both approximations are the reference's, a's
//   and b's low words when n is at most 64 and otherwise their 31 low bits
//   beside those 33;
//
//   step against a reference step that branches and keeps the four factors
//   as signed 64-bit integers, each in its own variable: from any xa, any odd
//   xb, any factors that leave the reference no overflow, the pairs packed
//   from them, and odd the mask of xa's low bit, step leaves the reference's
//   xa and xb, an odd xb, the pairs packed from the reference's factors, and
//   odd the mask of the new xa's low bit;
//
//   unpack_factors, for any four factors between -(2^31 - 1) and 2^31,
//   returns each one from the two pairs packed from them.
//
// With p256_wide_inverse_range_harness.c, which proves that the reference's
// 31 steps from f0 = g1 = 1 and f1 = g0 = 0 end with every factor in that
// range for any xa and any odd xb, those give step_factors for every input:
// it starts from the packed pairs of 1, 0, 0 and 1 and the mask of xa's low
// bit, the state the step property starts from, so after each of its 31
// steps its pairs are the packed factors of as many reference steps; the
// reference's factors end in the range, and unpack_factors returns them.
//
// The line runs without --unsigned-overflow-check, because the code these
// properties cover wraps on purpose: nonzero_mask negates x, and the packed
// pairs compute modulo 2^64. The equalities above fix every value they
// compute, wraps included. The reference's factors are signed, and
// --signed-overflow-check, which every full line carries, proves that none
// of their sums and doublings overflows.
//
// p256_wide_inverse_harness.c proves the combinations of a round, and
// p256_wide_inverse_round_harness.c runs one round whole.
// spec/lean/Spec/P256WideInverse.lean proves that the reference's steps,
// applied as p256_wide_inverse applies them, invert y.
#include "harness.h"

#define P256_WIDE_CARRY P256_WIDE_CARRY_BUILTIN

#include "p256_wide_inverse.c"

#include "p256_wide_inverse_reference.h"

uint64_t nondet_u64(void);

static void words_nondet(uint64_t x[WORDS]) {
    for (size_t i = 0; i < WORDS; i++) {
        x[i] = nondet_u64();
    }
}

static void prove_nonzero_mask(void) {
    uint64_t x = nondet_u64();
    __CPROVER_assert(nonzero_mask(x) == (x != 0 ? UINT64_MAX : 0),
                     "nonzero_mask: all ones exactly when the word is not zero");
}

// Bit i of x, for i below 256.
static uint64_t reference_bit(const uint64_t x[WORDS], unsigned i) {
    return (x[i >> 6] >> (i & 63)) & 1;
}

static unsigned reference_length(const uint64_t a[WORDS], const uint64_t b[WORDS]) {
    unsigned n = 0;
    for (unsigned i = 0; i < 64 * WORDS; i++) {
        if (reference_bit(a, i) != 0 || reference_bit(b, i) != 0) {
            n = i + 1;
        }
    }
    return n;
}

static uint64_t reference_approximation(const uint64_t x[WORDS], unsigned n) {
    if (n <= 64) {
        return x[0];
    }
    uint64_t top = 0;
    for (unsigned i = 0; i < 33; i++) {
        top |= reference_bit(x, n - 33 + i) << i;
    }
    return (x[0] & LOW_BITS) | (top << STEPS);
}

static void prove_approximations(void) {
    uint64_t a[WORDS];
    uint64_t b[WORDS];
    words_nondet(a);
    words_nondet(b);
    uint64_t xa;
    uint64_t xb;
    approximations(&xa, &xb, a, b);
    unsigned n = reference_length(a, b);
    __CPROVER_assert(xa == reference_approximation(a, n),
                     "approximations: a's is the reference's for the bit length of a | b");
    __CPROVER_assert(xb == reference_approximation(b, n),
                     "approximations: b's is the reference's for the bit length of a | b");
}

// A factor no reference step can overflow from: 2^61 in size at most.
static int64_t factor_nondet(void) {
    int64_t f = nondet_i64();
    __CPROVER_assume(f >= -((int64_t)1 << 61) && f <= ((int64_t)1 << 61));
    return f;
}

static void prove_step(void) {
    reference_state s;
    s.xa = nondet_u64();
    s.xb = nondet_u64();
    __CPROVER_assume((s.xb & 1) == 1);
    s.f0 = factor_nondet();
    s.g0 = factor_nondet();
    s.f1 = factor_nondet();
    s.g1 = factor_nondet();
    uint64_t xa = s.xa;
    uint64_t xb = s.xb;
    uint64_t pair0 = reference_pack(s.f0, s.g0);
    uint64_t pair1 = reference_pack(s.f1, s.g1);
    uint64_t odd = p256_wide_mask(xa & 1);
    step(&xa, &xb, &pair0, &pair1, &odd);
    reference_step(&s);
    __CPROVER_assert(xa == s.xa && xb == s.xb, "step: the reference's xa and xb");
    __CPROVER_assert((xb & 1) == 1, "step: xb stays odd");
    __CPROVER_assert(pair0 == reference_pack(s.f0, s.g0) && pair1 == reference_pack(s.f1, s.g1),
                     "step: the pairs packed from the reference's factors");
    __CPROVER_assert(odd == p256_wide_mask(xa & 1), "step: odd is the mask of xa's low bit");
}

// A factor of the range unpack_factors reads.
static int64_t ranged_factor_nondet(void) {
    int64_t f = nondet_i64();
    __CPROVER_assume(f > -((int64_t)1 << STEPS) && f <= ((int64_t)1 << STEPS));
    return f;
}

static void prove_unpack_factors(void) {
    int64_t f0 = ranged_factor_nondet();
    int64_t g0 = ranged_factor_nondet();
    int64_t f1 = ranged_factor_nondet();
    int64_t g1 = ranged_factor_nondet();
    uint64_t factor[4];
    unpack_factors(factor, reference_pack(f0, g0), reference_pack(f1, g1));
    __CPROVER_assert(factor[0] == (uint64_t)f0 && factor[1] == (uint64_t)g0 &&
                         factor[2] == (uint64_t)f1 && factor[3] == (uint64_t)g1,
                     "unpack_factors: the four factors the pairs were packed from");
}

int main(void) {
    prove_nonzero_mask();
    prove_approximations();
    prove_step();
    prove_unpack_factors();
    return 0;
}
