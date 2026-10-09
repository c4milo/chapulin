// Proves: no sum in rsa_mont64_addcarry.c's multiplication or square wraps, for any operands,
// any modulus and any m0inv. The check is --unsigned-overflow-check on the launch line, which
// makes every unsigned +, - and * a property: each sum of a product and a word of the running
// sum, each add of a block's carry chain, the word a block returns, a row's tail, the steps
// that add a row's carry word above the row, the doubling and the squares of the square, and
// each step of its reduction.
//
// RSA_MONT64_ADDCARRY is 1 here whatever compiler preprocesses the harness, and the add with
// carry is its 128-bit sum form, which CBMC reads; the _addcarry_u64 form a gcc build for
// x86-64 runs is held to it by bin/rsa_addcarry_equiv_test on x86-64 (docs/decisions.md 122).
// The products are the contract in proof/rsa_mont64_stubs.h: any value at or below
// (2^64 - 1)^2, which rsa_mont64_mul128_harness.c proves of the real multiply. Under it a
// block's sum is at most (2^64 - 1) * (2^256 - 1) + 2^64 - 1 + 2^256 - 1 = 2^320 - 1, as
// rsa_mont64_addcarry.c's header states.
//
// It runs both routines through rsa_mont64_mont_mul and rsa_mont64_mont_square at four words
// and at eight. Four words run a row of one block, whose carry word starts at zero, and the
// square's rows of three words down to one, tails alone. Eight run a row of two blocks, where
// the second takes the first's carry word, and the square's rows of seven words down to one,
// each with a block and a tail, a block alone or a tail alone. Each sum reads values that are
// unconstrained there or that the routine computed from such values, so more words repeat the
// same sums over the same ranges, as in rsa_mont64_sums_harness.c.
#define RSA_MONT64_ADDCARRY 1
#define RSA_MONT64_CARRY RSA_MONT64_CARRY_SUM
#include "rsa_mont64_stubs.h"

#include "rsa_mont64_addcarry.c"

static void run_at(size_t k) {
    rsa_mont64_modulus mod;
    uint64_t a[RSA_MONT64_WORDS_MAX];
    uint64_t b[RSA_MONT64_WORDS_MAX];
    uint64_t o[RSA_MONT64_WORDS_MAX];

    havoc_modulus(&mod, k);
    havoc_words(a, k);
    havoc_words(b, k);
    rsa_mont64_mont_mul(o, a, b, &mod);

    havoc_modulus(&mod, k);
    havoc_words(a, k);
    rsa_mont64_mont_mul(a, a, a, &mod);

    havoc_modulus(&mod, k);
    havoc_words(a, k);
    rsa_mont64_mont_square(o, a, &mod);

    havoc_modulus(&mod, k);
    havoc_words(a, k);
    rsa_mont64_mont_square(a, a, &mod);
}

int main(void) {
    run_at(4);
    run_at(8);
    return 0;
}
