// Proves: rsa_mont64_blocks.c's multiplication and square, through rsa_mont64_mont_mul and
// rsa_mont64_mont_square, which run them for a word count that is a multiple of 4, at the
// largest word count the build admits (48 for the device bound of RSA-3072; 64 for RSA-4096 in
// the rsa_mont64_blocks_webpki variant, which sets CH_TRUST_WEBPKI), over any operands, any
// modulus and any m0inv, read and write inside their arrays. The largest count is the binding
// case for every index: a smaller multiple of 4 only shortens the same loops.
//
// RSA_MONT64_BLOCKS is 1 here whatever compiler preprocesses the harness, so the blocks run as
// a clang build for arm64 runs them (docs/decisions.md 118). The products are the contract in
// proof/rsa_mont64_stubs.h, which rsa_mont64_mul128_harness.c discharges on the real multiply.
//
// The calls are rsa_mont64_mul_harness.c's: the multiplication in the four aliasing shapes its
// callers use and the square in its two, every operand havocked before each. The square runs as
// the blocks' square at the largest count, and as their multiplication of a by itself at
// RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX words, the largest count that does, in the same two shapes.
//
// This line runs without --unsigned-overflow-check. That every sum in the blocks stays inside
// 128 bits is rsa_mont64_blocks_sums_harness.c's claim, at four and eight words.
//
// What this does not prove: that the result is the Montgomery product, or that it is below the
// modulus. bin/rsa_blocks_equiv_test holds the words to rsa_mont64.c's loops, which
// bin/rsa_equiv_test_compare and bin/rsa_equiv_test_sum hold to rsa_mont.c's 32-bit arithmetic.
#define RSA_MONT64_BLOCKS 1
#include "rsa_mont64_stubs.h"

#include "rsa_mont64_blocks.c"

int main(void) {
    rsa_mont64_modulus mod;
    uint64_t a[RSA_MONT64_WORDS_MAX];
    uint64_t b[RSA_MONT64_WORDS_MAX];
    uint64_t o[RSA_MONT64_WORDS_MAX];

    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    havoc_words(a, RSA_MONT64_WORDS_MAX);
    havoc_words(b, RSA_MONT64_WORDS_MAX);
    rsa_mont64_mont_mul(o, a, b, &mod);

    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    havoc_words(a, RSA_MONT64_WORDS_MAX);
    havoc_words(b, RSA_MONT64_WORDS_MAX);
    rsa_mont64_mont_mul(b, a, b, &mod);

    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    havoc_words(a, RSA_MONT64_WORDS_MAX);
    havoc_words(b, RSA_MONT64_WORDS_MAX);
    rsa_mont64_mont_mul(a, a, b, &mod);

    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    havoc_words(a, RSA_MONT64_WORDS_MAX);
    rsa_mont64_mont_mul(a, a, a, &mod);

    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    havoc_words(a, RSA_MONT64_WORDS_MAX);
    rsa_mont64_mont_square(o, a, &mod);

    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    havoc_words(a, RSA_MONT64_WORDS_MAX);
    rsa_mont64_mont_square(a, a, &mod);

    havoc_modulus(&mod, RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX);
    havoc_words(a, RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX);
    rsa_mont64_mont_square(o, a, &mod);

    havoc_modulus(&mod, RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX);
    havoc_words(a, RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX);
    rsa_mont64_mont_square(a, a, &mod);
    return 0;
}
