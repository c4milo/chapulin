// Proves: state_setup and state_finish, the two ends of each
// exponentiation in rsa_ifma_sign.c, read and write inside their arrays at
// every prime word count the kernel takes, from RSA_IFMA_SIGN_WORDS_MIN to
// RSA_IFMA_SIGN_WORDS_MAX, over any prime's words, any r2 and m0inv, any
// base and any power: state_setup's record of the prime in digits, R mod m
// by rsa_mont64.c's product, its spare doublings, the base's, and the
// conversions of the three into digits; state_finish's conversion of the
// power's digits into the words and the word above them, and its
// subtraction. The webpki variant, rsa_ifma_sign_setup_webpki, runs the
// word counts up to 32 under CH_TRUST_WEBPKI.
//
// It also proves the two conversions inverse at each of those word
// counts, on their own text: words_to_digits of any k words, then
// digits_to_words of those digits, writes the k words back and a zero above
// them. Each is shifts, ands and ors, which enter the formula as they are.
//
// The three rsa_mont64.c entries the file calls are the contracts of
// proof/rsa_ifma_sign_stubs.h, which the rsa_mont64 harnesses discharge,
// and the lane operations are proof/rsa_ifma_stubs.h's contracts, which
// this harness calls none of.
//
// What it does not prove: that the digits are the numbers in the
// rsa_mont64.c domain that rsa_sign64_power takes. bin/rsa_ifma_sign_model_test
// holds every exponentiation to that window.
#define RSA_IFMA_STUB_EVERY_LANE_OPERATION 1
#include "rsa_ifma_stubs.h"

#include "rsa_ifma_sign_stubs.h"

// rsa_ifma_stubs.h compiles rsa_mont64.c, whose static mask_of_bit has
// the name of rsa_ifma_sign.c's own, so this one translation unit renames
// the second.
#define mask_of_bit sign_mask_of_bit
#include "rsa_ifma_sign.c"

size_t nondet_size_t(void);

int main(void) {
    size_t k = nondet_size_t();
    __CPROVER_assume(k >= RSA_IFMA_SIGN_WORDS_MIN && k <= RSA_IFMA_SIGN_WORDS_MAX);
    size_t n = RSA_IFMA_DIGIT_COUNT(k);

    static sign_state state;
    rsa_mont64_modulus mod;
    uint64_t base[RSA_IFMA_SIGN_WORDS_MAX];
    havoc_modulus(&mod, k);
    havoc_words(base, k);
    state_setup(&state, base, &mod);

    uint64_t o[RSA_IFMA_SIGN_WORDS_MAX];
    havoc_modulus(&mod, k);
    havoc_digits(state.power, SIGN_LANES_MAX);
    state.modulus.digit_count = n;
    state_finish(o, &state, &mod);

    uint64_t words[RSA_IFMA_SIGN_WORDS_MAX];
    uint64_t digits[SIGN_LANES_MAX];
    uint64_t back[RSA_IFMA_SIGN_WORDS_MAX + 1];
    havoc_words(words, k);
    words_to_digits(digits, words, k, n, SIGN_LANES_MAX);
    digits_to_words(back, k, digits, n);
    for (size_t i = 0; i < k; i++) {
        __CPROVER_assert(back[i] == words[i], "the conversions write each word back");
    }
    __CPROVER_assert(back[k] == 0, "the word above a number of k words is zero");
    return 0;
}
