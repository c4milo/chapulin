// Proves: one step of the x25519 ladder keeps every word inside the
// range the field-op proofs assume, starting from any state inside that
// range -- the inductive step the other x25519 harnesses rest on and,
// until this one, nothing checked
// (https://github.com/c4milo/chapulin/issues/50).
//
// The invariant, WORD: every word of a, b, c, d and x lies in
// (-2^17, 2^17). Base case, by inspection of ladder()'s prologue: a = d
// = 1, c = 0, and b = x, where unpack leaves every word in [0, 2^16)
// (x25519_ops asserts "unpack is carried"). Step, proven here on the
// shipped step(), not a copy: from any a, b, c, d, x that satisfy
// WORD and either scalar bit, the step hands mul only operands in
// (-2^18, 2^18), overflows nothing, and leaves a, b, c, d satisfying WORD
// again. Induction carries that through all 255 steps, and x25519_tail
// carries it through invert() and pack(). Every operand is therefore
// inside the 2^24 the mul and pack proofs assume, with six bits to
// spare. The bound is tight enough to notice one dropped carry: two
// carried values add to at most 2^17 + 74, which is outside WORD.
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

    assume_range(a, WORD);
    assume_range(b, WORD);
    assume_range(c, WORD);
    assume_range(d, WORD);
    assume_range(x, WORD);
    // Scratch the step writes before it reads, so it starts unconstrained.
    havoc(e);
    havoc(f);
    int64_t r = nondet_i64();
    __CPROVER_assume(r == 0 || r == 1);
    step(a, b, c, d, e, f, x, r);
    ASSERT_WORD(a, "a satisfies WORD after the step");
    ASSERT_WORD(b, "b satisfies WORD after the step");
    ASSERT_WORD(c, "c satisfies WORD after the step");
    ASSERT_WORD(d, "d satisfies WORD after the step");
    return 0;
}
