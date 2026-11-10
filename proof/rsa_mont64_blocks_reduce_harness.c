// Proves: rsa_mont64_blocks_reduce, the last subtraction in blocks of four
// words (docs/decisions.md 209), writes the words reduce_once writes, for
// every value, every word above it and every modulus, at four words and at
// eight. reduce_once is rsa_mont64.c's last subtraction, which every other
// build runs and which rsa_mont64_ops proves at the bound. The two differ
// in form: reduce_once compares in one pass and subtracts under a mask in
// a second, and the blocks subtract down two carry chains a block and
// then select. Neither multiplies, so the formula is three adders and a
// comparison of words, which a SAT solver decides.
//
// Four words run one block, whose first chain takes the carry that makes
// the complement a negation. Eight run two, where the second block takes
// the first's carry, down its second chain. More words repeat the second
// block's sums.
//
// --unsigned-overflow-check is on the launch line, so each sum of the two
// chains and the sum of their carries is a property too.
//
// What it does not prove: the memory accesses at the bound, which
// rsa_mont64_blocks proves through rsa_mont64_mont_mul and
// rsa_mont64_mont_square, and constant time, which lint-wide-multiply's
// count of the file's branches holds.
#define RSA_MONT64_BLOCKS 1
#include "rsa_mont64_stubs.h"

#include "rsa_mont64_blocks.c"

static void prove_at(size_t k) {
    rsa_mont64_modulus mod;
    uint64_t a[RSA_MONT64_WORDS_MAX];
    uint64_t loops[RSA_MONT64_WORDS_MAX];
    uint64_t blocks[RSA_MONT64_WORDS_MAX];
    havoc_modulus(&mod, k);
    havoc_words(a, k);
    uint64_t top = nondet_u64();
    reduce_once(loops, a, top, mod.m, k);
    rsa_mont64_blocks_reduce(blocks, a, top, &mod);
    for (size_t i = 0; i < k; i++) {
        __CPROVER_assert(blocks[i] == loops[i],
                         "rsa_mont64_blocks_reduce writes reduce_once's words");
    }
}

int main(void) {
    prove_at(4);
    prove_at(8);
    return 0;
}
