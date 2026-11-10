// Proves: no sum wraps in the two functions that rsa_mont_division.h's
// division step in blocks adds with (docs/decisions.md 208), with
// --unsigned-overflow-check on, so each sum is a property.
//
// rsa_mont64_block_add (rsa_mont64_blocks.h), over any four words, any
// multiplier, any four words it multiplies and any carry word: the two
// chains and the word it returns. rsa_mont64_blocks_sums proves the same
// sums for the words rsa_mont64_blocks.c's rows hand it. The division
// hands it the words of a remainder and of R - m, which no row computes,
// so this harness takes every input.
//
// add_modulus_blocks, over any remainder and any modulus of 8 words, two
// blocks: each 128-bit sum, the sum of the two chains' carries, and that
// the carry it returns is 0 or 1.
//
// The products are the contract in proof/rsa_mont64_stubs.h, which
// rsa_mont64_mul128_harness.c discharges on the real multiply. Under it
// the block's sum is at most 2^256 - 1 + (2^64 - 1)^2 (2^256 - 1) /
// (2^64 - 1) + 2^64 - 1 = 2^320 - 1, which five words hold.
//
// What it does not prove: the words. bin/diff_rsa_division holds the
// step's words to spec/lean/Spec/RsaDivision.lean, and
// bin/rsa_equiv_test_blocks holds rsa_vp1's bytes to the 32-bit arm. The
// step itself wraps a word on purpose, so rsa_mont_host_blocks runs it
// with this check off.
#define RSA_MONT64_BLOCKS 1
#include "rsa_mont64_stubs.h"

#include "rsa_mont.c"

#define SUM_WORDS 8

int main(void) {
    uint64_t t[4];
    havoc_words(t, 4);
    uint64_t top = rsa_mont64_block_add(t, nondet_u64(), nondet_u64(), nondet_u64(), nondet_u64(),
                                        nondet_u64(), nondet_u64());
    (void)top;

    uint64_t rem[SUM_WORDS];
    uint64_t m[SUM_WORDS];
    havoc_words(rem, SUM_WORDS);
    havoc_words(m, SUM_WORDS);
    uint64_t carry = add_modulus_blocks(rem, m, SUM_WORDS);
    __CPROVER_assert(carry <= 1, "add_modulus_blocks: the carry out is 0 or 1");
    return 0;
}
