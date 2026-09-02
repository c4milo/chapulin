// Proves: what the x25519 ladder does after its loop keeps every limb
// inside the range the field-op proofs assume, and mul's own output
// form -- the rest of the induction x25519_step starts
// (https://github.com/c4milo/chapulin/issues/50).
//
// First block, mul's postcondition: with its products bounded by the
// contract in proof/x25519_stubs.h, the shipped accumulate, 38x fold and
// two carry passes leave limb 0 in [-38, 2^16 + 38) and limbs 1..15 in
// [0, 2^16). The products are havocked, so that form does not depend on
// mul's operands, and one instance covers every mul call the ladder
// makes. It is what closes the int32 narrowing the stub cannot see (the
// header says how).
//
// Then the ladder after the loop, from any values that satisfy LIMB,
// which x25519_step proves the loop leaves: one invert() round --
// sqr(c, c), then the mul(c, c, a) all but two rounds run -- keeps c
// inside LIMB, so induction carries it through all 254 rounds; and the
// final mul(a, a, c) and pack(out, a) run without leaving the range
// their proofs assume. pack is the real function: its input here is
// inside the 2^24 x25519_ops proves it at.
#include "x25519_stubs.h"

int main(void) {
    fe a;
    fe c;
    uint8_t out[X25519_LEN];

    // mul's postcondition, from any operands the stub admits.
    assume_range(a, MUL_IN);
    assume_range(c, MUL_IN);
    mul(c, c, a);
    __CPROVER_assert(c[0] >= -38 && c[0] < ((int64_t)1 << 16) + 38,
                     "mul leaves limb 0 in [-38, 2^16 + 38)");
    for (size_t i = 1; i < 16; i++) {
        __CPROVER_assert(c[i] >= 0 && c[i] < (int64_t)1 << 16,
                         "mul leaves limbs 1..15 in [0, 2^16)");
    }

    // One invert round.
    assume_range(c, LIMB);
    assume_range(a, LIMB);
    sqr(c, c);
    ASSERT_LIMB(c, "c satisfies LIMB after invert's square");
    mul(c, c, a);
    ASSERT_LIMB(c, "c satisfies LIMB after invert's multiply");

    // The loop's a times the inverse, then pack.
    assume_range(a, LIMB);
    assume_range(c, LIMB);
    mul(a, a, c);
    pack(out, a);
    return 0;
}
