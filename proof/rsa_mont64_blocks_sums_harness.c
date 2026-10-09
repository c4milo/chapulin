// Proves: no sum in rsa_mont64_blocks.c's multiplication or square wraps, for any operands, any
// modulus and any m0inv. The check is --unsigned-overflow-check on the launch line, which makes
// every unsigned +, - and * a property: each sum in a block's two carry chains, the word a block
// returns, a row's tail, the top step of a multiplication's round, the doubling and the squares
// of the square, and each step of its reduction.
//
// RSA_MONT64_BLOCKS is 1 here whatever compiler preprocesses the harness. The products are the
// contract in proof/rsa_mont64_stubs.h: any value at or below (2^64 - 1)^2, which
// rsa_mont64_mul128_harness.c proves of the real multiply. Under it a block's sum is at most
// (2^64 - 1) * (2^256 - 1) + 2^64 - 1 + 2^256 - 1 = 2^320 - 1, as rsa_mont64_blocks.c's header
// states.
//
// It runs both routines at four words and at eight: the multiplication through
// rsa_mont64_mont_mul and rsa_mont64_mont_square, which runs a square of up to
// RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX words as the blocks' multiplication of a by itself, and the
// square through rsa_mont64_blocks_square itself. Four words run a round of one block, whose
// carry words start at zero. Eight run a round of two, where the second block takes the first's
// carry words, and the square's rows of seven words down to one, each with a block and a tail or
// a tail alone. Each sum reads values that are unconstrained there or that the routine computed
// from such values, so more words repeat the same sums over the same ranges, as in
// rsa_mont64_sums_harness.c.
#define RSA_MONT64_BLOCKS 1
#include "rsa_mont64_stubs.h"

#include "rsa_mont64_blocks.c"

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

    havoc_modulus(&mod, k);
    havoc_words(a, k);
    (void)rsa_mont64_blocks_square(o, a, &mod);
}

int main(void) {
    run_at(4);
    run_at(8);
    return 0;
}
