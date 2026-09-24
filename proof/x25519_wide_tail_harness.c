// Proves: what the X25519=wide ladder does after its loop keeps every limb
// inside INV-34's bounds, and the output form of mul, sqr and mul_a24 under
// the multiply contract -- the rest of the induction x25519_wide_step starts.
//
// First block: from operands whose limbs are under 2^54, mul, sqr and mul_a24
// hand ct_mul128 only operands inside the contract's domain, wrap nothing,
// and leave limbs 0, 2, 3 and 4 under 2^51 and limb 1 under 2^51 + 2^20. The
// products are the contract's, so the form holds whatever the operands'
// values are, and one instance of each covers every call the ladder makes.
// mul runs with its output aliasing each input, the shapes invert() uses.
//
// Then the ladder after the loop, from values inside the state bounds, which
// x25519_wide_step proves the loop leaves and x25519_wide_invert proves
// invert() keeps: the final mul(a, a, c) and pack(out, a) run with every
// check on. invert() is a harness of its own because its 265 products cost
// more than this whole formula: 55 s and 3.9 GB, against about 2 s here.
#include "x25519_wide_stubs.h"

// Operand limbs under 2^54, the domain of mul, sqr and mul_a24.
static void assume_operand(fe f) {
    for (size_t i = 0; i < 5; i++) {
        f[i] = nondet_u64() >> 10;
    }
}

int main(void) {
    fe a;
    fe b;
    fe c;
    uint8_t out[X25519_LEN];

    // The output form of each product, from any operands under 2^54.
    assume_operand(a);
    assume_operand(b);
    mul(c, a, b);
    ASSERT_STATE(c, "mul leaves INV-34's form");
    assume_operand(a);
    assume_operand(b);
    mul(a, a, b);
    ASSERT_STATE(a, "mul(a, a, b) leaves INV-34's form");
    assume_operand(a);
    assume_operand(b);
    mul(b, a, b);
    ASSERT_STATE(b, "mul(b, a, b) leaves INV-34's form");
    assume_operand(a);
    sqr(c, a);
    ASSERT_STATE(c, "sqr leaves INV-34's form");
    assume_operand(a);
    sqr(a, a);
    ASSERT_STATE(a, "sqr(a, a) leaves INV-34's form");
    assume_operand(a);
    mul_a24(c, a);
    ASSERT_STATE(c, "mul_a24 leaves INV-34's form");

    // The loop's a times the inverse, then pack.
    assume_state(a);
    assume_state(c);
    mul(a, a, c);
    pack(out, a);
    return 0;
}
