// The contract x25519_step and x25519_tail replace mul's multiply with,
// and the limb bounds both harnesses share. They prove the ladder keeps
// every limb inside the range the x25519 field-op proofs assume
// (https://github.com/c4milo/chapulin/issues/50).
//
// Why this exists: mul runs 256 multiplies per call and one ladder step
// calls it ten times, the shape docs/proofs.md says never converges. A
// step over the real products returned no verdict past 14 GB. So the
// one multiply mul() calls, ct_widemul_s, is the contract below. The
// harness reads ct.h first under its own name, the #define renames every
// later use, and ct.h's include guard keeps x25519.c's own #include from
// reading the real definition again.
//
// WHAT THE STUB MODELS: ct_widemul_s asserts both operands lie in
// (-2^18, 2^18) and returns any value in [-2^36, 2^36). The bound is a
// 37-bit sign extension rather than two comparisons: the same step
// formula proved in 540 s and 2.4 GB that way, and in 1328 s and 4.1 GB
// with the bound written as `p > -2^36 && p < 2^36`.
//
// WHAT THE HARNESSES DO NOT PROVE: that the real product of two such
// operands lies in that range. x25519_mul_harness.c proves it on the
// real ct_widemul_s with every check on, and ctwidemul proves the
// decomposed multiply computes the same function. Nothing in either
// harness reads the product's value: every property is a bound, so the
// bound is all the composition needs.
//
// One thing the stub cannot see: mul narrows each limb to int32 before
// the multiply, so the stub checks the narrowed operand. Every limb that
// reaches mul is an entry limb (assumed under 2^17), a mul output (under
// 2^16 + 38, x25519_tail's first block) or one add or sub of two of those
// (overflow-checked, under 2^18), and a value under 2^31 narrows exactly.
// So the operand the stub checks is the limb itself.
#ifndef CH_X25519_STUBS_H
#define CH_X25519_STUBS_H

#include "harness.h"

#include "ct.h"
// From here on the multiply mul() calls is the contract below.
#define ct_widemul_s stub_widemul_s

#define LIMB ((int64_t)1 << 17)   // the invariant: every limb in (-LIMB, LIMB)
#define MUL_IN ((int64_t)1 << 18) // one add or sub of two LIMB values

uint64_t nondet_u64(void);

static int64_t stub_widemul_s(int32_t a, int32_t b) {
    __CPROVER_assert(a > -MUL_IN && a < MUL_IN, "mul operand a is under 2^18");
    __CPROVER_assert(b > -MUL_IN && b < MUL_IN, "mul operand b is under 2^18");
    return (int64_t)(nondet_u64() << 27) >> 27;
}

#include "x25519.c"

static void assume_range(fe f, int64_t bound) {
    for (size_t i = 0; i < 16; i++) {
        f[i] = nondet_i64();
        __CPROVER_assume(f[i] > -bound && f[i] < bound);
    }
}

#define ASSERT_LIMB(f, what)                                                                       \
    for (size_t i = 0; i < 16; i++) {                                                              \
        __CPROVER_assert((f)[i] > -LIMB && (f)[i] < LIMB, what);                                   \
    }

#endif
