// Proves: rsa_mont64_mont_mul and rsa_mont64_mont_square, each whole, at
// the largest word count the build admits (48 for the device bound of
// RSA-3072; 64 for RSA-4096 in the rsa_mont64_mul_webpki variant, which
// sets CH_TRUST_WEBPKI), over any operands, any modulus and any m0inv,
// read and write inside their arrays. The largest count is the binding
// case for every index: a smaller one only shortens the same loops.
//
// The products are the contract in proof/rsa_mont64_stubs.h, which
// rsa_mont64_mul128_harness.c discharges on the real multiply.
//
// One call per aliasing shape the callers use, with every operand
// havocked before each: the output apart from both operands, as the
// first product of rsa_mont64_public writes it; the output on the second
// operand, as its last product does; the output on the first operand, as
// rsa_sign64_power multiplies its running power by a table entry; and all
// three the same array, as a squaring is called.
//
// rsa_mont64_mont_square runs in its two shapes: the output apart from the
// operand, as message_mod_prime squares R^2, and on it, as the public
// operation, the setup and the signer's exponentiation square.
//
// rsa_mont64_mul_add, the plain product and sum, runs once at half the
// largest word count, a prime's, which is the largest its one caller
// passes: its output is twice its operands' words.
//
// This line runs without --unsigned-overflow-check. That every sum in
// the function stays inside 128 bits is rsa_mont64_sums_harness.c's
// claim, at four words: the whole function at 48 words with that check
// on returned no verdict in five minutes and 8.5 GB.
//
// What this does not prove: that the result is the Montgomery product, or
// that it is below the modulus. Both are claims about values, which the
// contract gives up. bin/rsa_equiv_test holds them against rsa_mont.c's
// 32-bit arithmetic, and the published vectors hold them against openssl.
#include "rsa_mont64_stubs.h"

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

    uint64_t product[RSA_MONT64_WORDS_MAX];
    havoc_words(a, RSA_MONT64_WORDS_MAX / 2);
    havoc_words(b, RSA_MONT64_WORDS_MAX / 2);
    havoc_words(o, RSA_MONT64_WORDS_MAX / 2);
    rsa_mont64_mul_add(product, a, b, o, RSA_MONT64_WORDS_MAX / 2);
    return 0;
}
