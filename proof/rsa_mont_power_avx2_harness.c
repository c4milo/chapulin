// Proves: base_times_power_of_two_mod, the division rsa_vp1_cpu runs for
// rsa_avx2_public's base 2^(Dn) mod m, reads and writes inside its arrays,
// divides by no zero and shifts by no amount outside a word, over any base
// bytes and any modulus words whose top word has its top bit set and whose
// bottom word is odd, and any m0inv, at the word counts and with the
// exponents rsa_vp1_cpu passes: RSA_AVX2_WORDS_MIN words, 32 (RSA-2048,
// 2^2072), and the build's largest count, 48 (RSA-3072, 2^3080), or 64
// (RSA-4096, 2^4104) in the rsa_mont_power_avx2_webpki variant, which sets
// CH_TRUST_WEBPKI. That is the base's words and its one subtraction, 33
// and 49 steps of times_word_mod, or 33 and 65, and divide_by_power_of_two
// by 2^40 and 2^56. rsa_mont_power_harness.c runs power_of_two_mod with
// the exponents of rsa_ifma_public, 2^(104n).
//
// The power and the base are arrays of exactly the word count and of 8
// bytes a word, so a read or a write past either fails. rsa_mont.c
// compiles the function in an x86-64 host object and under
// CH_RSA_AVX2_MODEL, which the launch line passes, and the products are
// the contract in proof/rsa_mont64_stubs.h, as in rsa_mont_power_harness.c,
// which says why the line runs without --unsigned-overflow-check.
//
// What it does not prove: that the words it writes are base 2^(Dn) mod m.
// spec/lean/Spec/RsaAvx2.lean proves that of its model, as
// baseTimesPowerOfTwoMod_spec, bin/diff_rsa_avx2 holds the C to the model,
// and bin/rsa_avx2_model_test holds the public operation that reads the
// words against rsa_mont64.c at every word count from 32 to 64.
#include "rsa_mont64_stubs.h"

#include "rsa_mont.c"

static void prove_words(uint64_t *power, uint8_t *base, size_t word_count) {
    rsa_mont64_modulus mod;
    havoc_modulus(&mod, word_count);
    mod.m[0] |= 1;
    mod.m[word_count - 1] |= (uint64_t)1 << 63;
    __CPROVER_havoc_object(base);
    base_times_power_of_two_mod(power, base, 8 * word_count, &mod, rsa_avx2_r_exponent(word_count));
}

int main(void) {
    uint64_t power_min[RSA_AVX2_WORDS_MIN];
    uint8_t base_min[8 * RSA_AVX2_WORDS_MIN];
    prove_words(power_min, base_min, RSA_AVX2_WORDS_MIN);
    uint64_t power_max[RSA_MONT64_WORDS_MAX];
    uint8_t base_max[8 * RSA_MONT64_WORDS_MAX];
    prove_words(power_max, base_max, RSA_MONT64_WORDS_MAX);
    return 0;
}
