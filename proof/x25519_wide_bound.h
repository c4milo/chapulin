// The bound the multiply contract in proof/x25519_wide_stubs.h gives a
// product, and which proof/x25519_wide_mul128_harness.c proves the real
// ct_mul128 meets. Both files include it, so the stub and its proof read
// one definition.
//
// width_of(x) is the least k of 53, 54, 55, 59 and 60 with x < 2^k, for an
// x under 2^60. A product of a and b is under 2^(width_of(a) +
// width_of(b)). Each comparison is of x shifted by a constant, so the solver
// reads it as a test of x's top bits (docs/proofs.md).
//
// The five widths are the fewest that keep the columns below under 2^115.
// Every k from 51 to 60 gave the same proofs, and x25519_wide_invert took
// 271 s and 4.2 GB on a GitHub runner under it, where these five take 131 s
// and 3.5 GB: in invert() every word is under 2^53, so every operand but a
// multiple of 19 or 38 takes one width (docs/decisions.md 152).
//
// Why the contract needs it: x25519_wide.c's carry_columns() adds the
// carries out of columns 1 to 4 as 64-bit words, and the fold of column 4's
// carry times 19 is a 64-bit word too. A column under 2^115 is what keeps
// those exact, and five products under 2^115 each, the bound the contract
// gave before docs/decisions.md 152, do not sum to that. This bound does,
// for columns 1 to 4 of mul and sqr over operand words under 2^54: their
// products of a word by 19 times a word are under 2^(54 + 59), and column 4
// holds none. Column 0 holds four such products, which sum past 2^115 under
// this bound, so carry_columns() keeps its carry 128 bits wide.
#ifndef CH_X25519_WIDE_BOUND_H
#define CH_X25519_WIDE_BOUND_H

#include <stdint.h>

static unsigned width_of(uint64_t x) {
    return 53U + (unsigned)((x >> 53) != 0) + (unsigned)((x >> 54) != 0) +
           4U * (unsigned)((x >> 55) != 0) + (unsigned)((x >> 59) != 0);
}

#endif
