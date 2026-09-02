// Proves: one step of the x25519 ladder keeps every limb inside the
// range the field-op proofs assume, starting from any state inside that
// range -- the inductive step the other x25519 harnesses rest on and,
// until this one, nothing checked
// (https://github.com/c4milo/chapulin/issues/50).
//
// The invariant, LIMB: every limb of a, b, c, d and x lies in
// (-2^17, 2^17). Base case, by inspection of ladder()'s prologue: a = d
// = 1, c = 0, and b = x, where unpack leaves every limb in [0, 2^16)
// (x25519_ops asserts "unpack is carried"). Step, proven here on the
// shipped step(), not a copy: from any a, b, c, d, x that satisfy
// LIMB and either scalar bit, the step hands mul only operands in
// (-2^18, 2^18), overflows nothing, and leaves a, b, c, d satisfying LIMB
// again. Induction carries that through all 255 steps, and x25519_tail
// carries it through invert() and pack(). Every operand is therefore
// inside the 2^24 the mul and pack proofs assume, with six bits to
// spare. The bound is tight enough to notice one dropped carry: two
// carried values add to at most 2^17 + 74, which is outside LIMB.
//
// The step's ten mul calls are the whole cost of this formula, so it
// holds nothing else; mul's postcondition, invert's round and the final
// multiply are x25519_tail. proof/x25519_stubs.h holds the multiply
// contract both rest on and what it gives up.
#include "x25519_stubs.h"

static void havoc(fe f) {
    for (size_t i = 0; i < 16; i++) {
        f[i] = nondet_i64();
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

    assume_range(a, LIMB);
    assume_range(b, LIMB);
    assume_range(c, LIMB);
    assume_range(d, LIMB);
    assume_range(x, LIMB);
    // Scratch the step writes before it reads, so it starts unconstrained.
    havoc(e);
    havoc(f);
    int64_t r = nondet_i64();
    __CPROVER_assume(r == 0 || r == 1);
    step(a, b, c, d, e, f, x, r);
    ASSERT_LIMB(a, "a satisfies LIMB after the step");
    ASSERT_LIMB(b, "b satisfies LIMB after the step");
    ASSERT_LIMB(c, "c satisfies LIMB after the step");
    ASSERT_LIMB(d, "d satisfies LIMB after the step");
    return 0;
}
