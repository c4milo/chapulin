// Proves: one step of the X25519=wide ladder keeps every limb inside
// INV-34's bounds, starting from any state inside them -- the inductive step
// for x25519_wide.c, as x25519_step_harness.c is for the 16-limb field.
//
// The invariant, from proof/x25519_wide_stubs.h: limbs 0, 2, 3 and 4 of a,
// b, c and d under 2^51, limb 1 under 2^51 + 2^20, and every limb of x under
// 2^51. Base case, by inspection of x25519_wide_ladder()'s prologue: a = d =
// 1, c = 0, and b = x, where unpack leaves every limb under 2^51
// (x25519_wide_ops asserts it). Step, proven here on the shipped step(): from
// any such state and either scalar bit, the step hands ct_mul128 only
// operands inside the contract's domain, wraps no unsigned value
// (--unsigned-overflow-check, which covers every a + 2p - b sub computes),
// and leaves a, b, c and d inside the bounds again. Induction carries that through all
// 255 steps, and x25519_wide_tail carries it through invert() and pack().
//
// The multiply is the contract in proof/x25519_wide_stubs.h, which
// x25519_wide_mul128 discharges on the real ct_mul128.
#include "x25519_wide_stubs.h"

static void havoc(fe f) {
    for (size_t i = 0; i < 5; i++) {
        f[i] = nondet_u64();
    }
}

int main(void) {
    fe a;
    fe b;
    fe c;
    fe d;
    fe e;
    fe f;
    fe x;

    assume_state(a);
    assume_state(b);
    assume_state(c);
    assume_state(d);
    for (size_t i = 0; i < 5; i++) {
        x[i] = nondet_u64() >> 13;
    }
    // Scratch the step writes before it reads, so it starts unconstrained.
    havoc(e);
    havoc(f);
    uint64_t r = nondet_u64();
    __CPROVER_assume(r == 0 || r == 1);
    step(a, b, c, d, e, f, x, r);
    ASSERT_STATE(a, "a is inside INV-34's bounds after the step");
    ASSERT_STATE(b, "b is inside INV-34's bounds after the step");
    ASSERT_STATE(c, "c is inside INV-34's bounds after the step");
    ASSERT_STATE(d, "d is inside INV-34's bounds after the step");
    return 0;
}
