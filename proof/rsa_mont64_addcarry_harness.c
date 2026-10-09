// Proves: rsa_mont64_addcarry.c's multiplication and square, through rsa_mont64_mont_mul and
// rsa_mont64_mont_square, which run them at every word count, at the largest word count the
// build admits (48 for the device bound of RSA-3072; 64 for RSA-4096 in the
// rsa_mont64_addcarry_webpki variant, which sets CH_TRUST_WEBPKI), over any operands, any
// modulus and any m0inv, read and write inside their arrays. The largest count is the binding
// case for every index: a smaller count only shortens the same loops.
//
// RSA_MONT64_ADDCARRY is 1 here whatever compiler preprocesses the harness, so the rows run as
// a gcc build for x86-64 runs them, on the 128-bit sum form of the add with carry, which CBMC
// reads (docs/decisions.md 122). The products are the contract in proof/rsa_mont64_stubs.h,
// which rsa_mont64_mul128_harness.c discharges on the real multiply.
//
// The calls are rsa_mont64_mul_harness.c's: the multiplication in the four aliasing shapes its
// callers use and the square in its two, every operand havocked before each.
//
// This line runs without --unsigned-overflow-check. That every sum in the rows stays inside
// 128 bits is rsa_mont64_addcarry_sums_harness.c's claim, at four and eight words.
//
// What this does not prove: that the result is the Montgomery product, or that it is below the
// modulus. bin/rsa_addcarry_equiv_test holds the words to rsa_mont64.c's loops, which
// bin/rsa_equiv_test_compare and bin/rsa_equiv_test_sum hold to rsa_mont.c's 32-bit arithmetic.
#define RSA_MONT64_ADDCARRY 1
#define RSA_MONT64_CARRY RSA_MONT64_CARRY_SUM
#include "rsa_mont64_stubs.h"

#include "rsa_mont64_addcarry.c"

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
    return 0;
}
