// Proves: rsa_mont64.h's rsa_mont64_mul_add_add, the step of a Montgomery
// multiplication's and a square's inner loops, returns the two words of
// x * y + a + b for every x, y, a and b. That is the 128-bit sum
// proof/rsa_mont64_stubs.h puts in the step's place, so what the harnesses
// over that file prove of the sum holds of the step.
//
// The step has two forms, and the compiler picks one (RSA_MONT64_STEP in
// the header). cbmc takes its preprocessor from the machine it runs on,
// clang's on a Mac and gcc's on a runner, so this harness names its form:
// the compare form, which clang compiles. rsa_mont64_step_sum_harness.c is
// this harness once more on the sum form, which gcc compiles.
//
// The multiply is a contract that keeps the product it returns: any
// value at or below (2^64 - 1)^2, the bound rsa_mont64_mul128_harness.c
// proves of the real multiply. The step's adds are what this proves, for
// every product the bound admits. On the real multiply, which the sum
// must then compute a second time, the proof took 92 s where this takes
// a second.
//
// The compare form's two adds wrap on purpose, and the compare after each
// is its carry, so its launch line runs without --unsigned-overflow-check,
// as rsa_mont64_init's does for neg_inverse. The sum form wraps nothing,
// and its line runs with the check. The sum here wraps nothing either: a
// product at or below the bound and two words make at most 2^128 - 1.
#ifndef RSA_MONT64_STEP
#define RSA_MONT64_STEP RSA_MONT64_STEP_COMPARE
#endif

#include "harness.h"

#include "ct.h"
// From here on the multiply the step calls is the contract below.
#define ct_mul128 recorded_mul128

ct_u128 nondet_u128(void);
uint64_t nondet_u64(void);

static ct_u128 recorded_product;

static ct_u128 recorded_mul128(uint64_t a, uint64_t b) {
    (void)a;
    (void)b;
    recorded_product = nondet_u128();
    __CPROVER_assume(recorded_product <= ((((ct_u128)(UINT64_MAX - 1)) << 64) | 1));
    return recorded_product;
}

#include "rsa_mont64.h"

int main(void) {
    uint64_t x = nondet_u64();
    uint64_t y = nondet_u64();
    uint64_t a = nondet_u64();
    uint64_t b = nondet_u64();
    rsa_mont64_sum step = rsa_mont64_mul_add_add(x, y, a, b);
    ct_u128 value = recorded_product + a + b;
    __CPROVER_assert(step.low == (uint64_t)value, "the step's low word is that of x * y + a + b");
    __CPROVER_assert(step.high == (uint64_t)(value >> 64),
                     "the step's high word is that of x * y + a + b");
    return 0;
}
