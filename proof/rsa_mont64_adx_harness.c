// Proves: rsa_mont64_adx.c's multiplication and square, compiled over
// test/rsa_mont64_adx_model.h, at the largest word count the build admits
// (48 for the device bound of RSA-3072; 64 for RSA-4096 in the
// rsa_mont64_adx_webpki variant, which sets CH_TRUST_WEBPKI), over any
// operands, any modulus and any m0inv, read and write inside their arrays
// and commit no undefined behavior (docs/decisions.md 183). The largest count
// is the binding case for every index: a smaller count only shortens the same
// loops.
//
// The model writes the words the assembly writes, which
// bin/rsa_mont64_adx_test holds on an x86-64 CPU with BMI2 and ADX. The
// products are the contract in proof/rsa_mont64_stubs.h, which
// rsa_mont64_mul128_harness.c discharges on the real multiply.
//
// The calls are the window's: the multiplication into a third array and in
// place, and the square into a third array and in place, every operand
// havocked before each.
//
// This line runs without --unsigned-overflow-check. That no sum wraps is
// rsa_mont64_adx_sums_harness.c's claim, at four and eight words.
//
// What this does not prove: that the result is the Montgomery product, or
// that it is below the modulus. spec/lean/Spec/RsaMont64Adx.lean proves both
// on its model of the C, bin/diff_rsa_mont64_adx holds the C to that model,
// and bin/rsa_mont64_adx_test holds the words to rsa_mont64.c's.
#define CH_RSA_MONT64_ADX_MODEL 1
#include "rsa_mont64_stubs.h"

#include "rsa_mont64_adx.c"

int main(void) {
    rsa_mont64_modulus mod;
    uint64_t a[RSA_MONT64_WORDS_MAX];
    uint64_t b[RSA_MONT64_WORDS_MAX];
    uint64_t o[RSA_MONT64_WORDS_MAX];

    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    havoc_words(a, RSA_MONT64_WORDS_MAX);
    havoc_words(b, RSA_MONT64_WORDS_MAX);
    rsa_mont64_adx_mul(o, a, b, &mod);

    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    havoc_words(a, RSA_MONT64_WORDS_MAX);
    havoc_words(b, RSA_MONT64_WORDS_MAX);
    rsa_mont64_adx_mul(a, a, b, &mod);

    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    havoc_words(a, RSA_MONT64_WORDS_MAX);
    rsa_mont64_adx_square(o, a, &mod);

    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    havoc_words(a, RSA_MONT64_WORDS_MAX);
    rsa_mont64_adx_square(a, a, &mod);
    return 0;
}
