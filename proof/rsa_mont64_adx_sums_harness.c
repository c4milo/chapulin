// Proves: no sum in rsa_mont64_adx.c's multiplication or square wraps, over
// test/rsa_mont64_adx_model.h, for any operands, any modulus and any m0inv
// (docs/decisions.md 183). The check is --unsigned-overflow-check on the
// launch line, which makes every unsigned +, - and * a property: each word of
// a row, the top word a row stores or adds its carry into, the doubling and
// the squares of the square, and each word of the final subtraction, which
// the model writes as t + ~m + the carry.
//
// The products are the contract in proof/rsa_mont64_stubs.h: any value at or
// below (2^64 - 1)^2. Under it a row's word is at most that product plus two
// words, 2^128 - 1, and a doubled word plus a square's half and a carry of at
// most 2 stays below 2^66.
//
// It runs both at four words and at eight. Four run the reduction's rows of
// one block and the square's rows of three words down to one, the 1-word
// loop alone. Eight run rows of two blocks, and the square's rows of seven
// words down to one, each with blocks and the 1-word loop, blocks alone or
// the 1-word loop alone. More words repeat the same sums over the same
// ranges.
#define CH_RSA_MONT64_ADX_MODEL 1
#include "rsa_mont64_stubs.h"

#include "rsa_mont64_adx.c"

static void run_at(size_t k) {
    rsa_mont64_modulus mod;
    uint64_t a[RSA_MONT64_WORDS_MAX];
    uint64_t b[RSA_MONT64_WORDS_MAX];
    uint64_t o[RSA_MONT64_WORDS_MAX];

    havoc_modulus(&mod, k);
    havoc_words(a, k);
    havoc_words(b, k);
    rsa_mont64_adx_mul(o, a, b, &mod);

    havoc_modulus(&mod, k);
    havoc_words(a, k);
    rsa_mont64_adx_square(o, a, &mod);
}

int main(void) {
    run_at(4);
    run_at(8);
    return 0;
}
