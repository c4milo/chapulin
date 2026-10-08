// Proves, for proof/p256_wide_inverse_reference.h's reference step, which
// p256_wide_inverse_steps_harness.c holds p256_wide_inverse.c's step to: from
// f0 = g1 = 1 and f1 = g0 = 0, its 31 steps on any xa and any odd xb end with
// every factor above -2^31 and at most 2^31, the range in which
// p256_wide_inverse.c's unpack_factors separates the two factors of a word.
// So step_factors returns the reference's factors for every input.
//
// The bound |f| + |g| <= 2^t holds step by step. That no factor ends at -2^31
// does not: it rests on the whole run, since a factor of -2^31 would have to
// make an approximation below zero or an odd one zero. That is why the line
// runs all 31 steps in one formula, and why it is in the slow tier.
// spec/lean/Spec/P256WideInverse.lean's proofs do not read this bound: its
// model keeps every factor in an integer of its own.
#include "harness.h"

#include "p256_wide_inverse_reference.h"

uint64_t nondet_u64(void);

int main(void) {
    reference_state s;
    s.xa = nondet_u64();
    s.xb = nondet_u64();
    __CPROVER_assume((s.xb & 1) == 1);
    s.f0 = 1;
    s.g0 = 0;
    s.f1 = 0;
    s.g1 = 1;
    for (int i = 0; i < 31; i++) {
        reference_step(&s);
    }
    int64_t bound = (int64_t)1 << 31;
    __CPROVER_assert(s.f0 > -bound && s.f0 <= bound && s.g0 > -bound && s.g0 <= bound &&
                         s.f1 > -bound && s.f1 <= bound && s.g1 > -bound && s.g1 <= bound,
                     "the reference's factors end between -(2^31 - 1) and 2^31");
    return 0;
}
