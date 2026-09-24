// The contract x25519_wide_step and x25519_wide_tail replace the 64x64->128
// multiply with, and the limb bounds both harnesses share. They prove the
// X25519=wide ladder keeps every limb inside INV-34's bounds, the way
// proof/x25519_stubs.h serves the 16-limb ladder.
//
// Why this exists: one ladder step runs 190 products, each a 64x64
// multiplier widened to 128 bits, and the step formula over the real
// products is the shape docs/proofs.md says does not converge. So the one
// multiply x25519_wide.c calls, ct_mul128, is the contract below. The
// harness reads ct.h first under its own name, the #define renames every
// later use, and ct.h's include guard keeps x25519_wide.c's own #include
// from reading the real definition again.
//
// WHAT THE STUB MODELS: ct_mul128 asserts its first operand is under 2^55
// and its second under 2^60, and returns any value under 2^115. That domain
// is what mul, sqr and mul_a24 hand the multiply when their operands' limbs
// are under 2^54: a limb or a doubled limb first, and a limb, a doubled
// limb, 19 times a limb, 38 times a limb or a24 second. The bound is bit
// structure, a shift of an unconstrained value, rather than a comparison,
// for the reason docs/proofs.md gives.
//
// WHAT DISCHARGES THE CONTRACT: x25519_wide_mul128_harness.c proves the real
// ct_mul128 returns a product under 2^115 for every operand pair in that
// domain, with every check on. Nothing in x25519_wide_step or
// x25519_wide_tail reads a product's value beyond that bound: every
// property is a bound, so a proof over every value under 2^115 covers the
// real products.
//
// What the contract gives up: its bound is looser than the real products,
// which are under 38 * 2^108 for the same operands. So the limb-1 bound these
// two harnesses carry, 2^51 + 2^20, is looser than the 2^51 + 2^13 that
// x25519_wide_mul_harness.c and x25519_wide_sqr_harness.c prove on the real
// multiply. Both are INV-34's; the looser one is what the induction uses.
#ifndef CH_X25519_WIDE_STUBS_H
#define CH_X25519_WIDE_STUBS_H

#include "harness.h"

#include "ct.h"
// From here on the multiply x25519_wide.c calls is the contract below.
#define ct_mul128 stub_mul128

#define MUL128_FIRST ((uint64_t)1 << 55)
#define MUL128_SECOND ((uint64_t)1 << 60)

ct_u128 nondet_u128(void);
uint64_t nondet_u64(void);

static ct_u128 stub_mul128(uint64_t a, uint64_t b) {
    __CPROVER_assert(a < MUL128_FIRST, "ct_mul128's first operand is under 2^55");
    __CPROVER_assert(b < MUL128_SECOND, "ct_mul128's second operand is under 2^60");
    return nondet_u128() >> 13;
}

#include "x25519_wide.c"

// The ladder's state between steps, INV-34: limbs 0, 2, 3 and 4 under 2^51
// and limb 1 under 2^51 + 2^20, the form carry_columns leaves under the
// contract above.
#define LIMB ((uint64_t)1 << 51)
#define LIMB1 (((uint64_t)1 << 51) + ((uint64_t)1 << 20))

// A state limb: 51 unconstrained bits for limbs 0, 2, 3 and 4, and for limb 1
// one more bit, cut back under LIMB1.
static void assume_state(fe f) {
    for (size_t i = 0; i < 5; i++) {
        f[i] = nondet_u64() >> 13;
    }
    uint64_t limb1 = nondet_u64() >> 12;
    __CPROVER_assume(limb1 < LIMB1);
    f[1] = limb1;
}

#define ASSERT_STATE(f, what)                                                                      \
    do {                                                                                           \
        __CPROVER_assert((f)[0] < LIMB && (f)[2] < LIMB && (f)[3] < LIMB && (f)[4] < LIMB, what);  \
        __CPROVER_assert((f)[1] < LIMB1, what);                                                    \
    } while (0)

#endif
