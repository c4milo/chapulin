// Proves: the whole of x25519_wide.c's invert(), 254 squarings and 11
// multiplies in the fixed chain, run in place as x25519_wide_ladder() runs
// it, takes a c inside INV-34's state bounds to a c inside them again,
// hands ct_mul128 only operands inside the contract's domain and wraps no
// unsigned value. The multiply is the contract in proof/x25519_wide_stubs.h.
//
// x25519_wide_tail proves the output form of one mul and one sqr, and every
// value the chain multiplies is its input or such an output, so this formula
// checks by machine what that argument says by inspection: that no link in
// the chain hands a product an operand the per-call proofs never covered.
// It is its own harness because it is the costliest formula of the field:
// in one formula with x25519_wide_tail's blocks it took 55 s and 3.9 GB, and
// alone it takes 18 s and 2.7 GB, measured under run.sh's flags.
#include "x25519_wide_stubs.h"

int main(void) {
    fe c;
    assume_state(c);
    invert(c, c);
    ASSERT_STATE(c, "invert leaves INV-34's form");
    return 0;
}
