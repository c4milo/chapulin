// Proves: the conversions in rsa_avx2_number.h read and write inside their
// arrays at every word count rsa_avx2_public takes in the build: any count
// from 32 to 48, or to 64 under CH_TRUST_WEBPKI in the
// rsa_avx2_number_webpki variant.
//   - modulus_from_words reads the k words of the modulus and writes the
//     record, its digit width, digit count and group count included;
//   - words_to_digits reads the k words of a number, as rsa_avx2_public
//     reads digit_r2 and multiply_by_base reads the base's words, and
//     writes a number's lanes;
//   - digits_to_words reads a number's n digits and writes k words and the
//     word above them, as write_result does.
// Each array of words is a heap object of exactly the words the call reads
// or writes, so a read or a write one word past the count fails at every
// count, as docs/proofs.md says of a read at p[n]: digit_r2's k words, and
// write_result's k + 1. The modulus's words sit in rsa_mont64_modulus,
// whose array holds the build's largest count, so there a read past the
// count fails at that count, which the range holds.
//
// The word count is any value in the range, not a literal, so one line
// covers every digit count and both digit widths under CH_TRUST_WEBPKI.
// No lane operation runs.
//
// What it does not prove: any value. bin/rsa_avx2_model_test runs the
// conversions at every word count from 32 to 64, and
// spec/lean/Spec/RsaAvx2.lean's toDigits is the conversion the model
// takes.
#include "rsa_avx2_stubs.h"

#include "rsa_avx2.c"

#include <stdlib.h>

int main(void) {
    size_t words = nondet_size_t();
    __CPROVER_assume(words >= RSA_AVX2_WORDS_MIN && words <= RSA_MONT64_WORDS_MAX);
    rsa_mont64_modulus mod;
    rsa_avx2_modulus modulus;
    havoc_modulus(&mod, words);
    modulus_from_words(&modulus, &mod);

    uint64_t *digit_r2 = malloc(words * sizeof(uint64_t));
    __CPROVER_assume(digit_r2 != NULL);
    havoc_words(digit_r2, words);
    _Alignas(32) uint64_t number[NUMBER_LANES];
    words_to_digits(number, digit_r2, words, modulus.digit_count, modulus.bits);

    uint64_t *out = malloc((words + 1) * sizeof(uint64_t));
    __CPROVER_assume(out != NULL);
    havoc_digits(number, NUMBER_LANES, modulus.bits);
    digits_to_words(out, words, number, modulus.digit_count, modulus.bits);
    return 0;
}
