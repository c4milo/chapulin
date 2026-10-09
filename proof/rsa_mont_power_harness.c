// Proves: power_of_two_mod, the division rsa_vp1_cpu runs for
// rsa_ifma_public's 2^(104n) mod m, reads and writes inside its arrays and
// divides by no zero, over any modulus words whose top word has its top bit
// set and whose bottom word is odd, at the word counts and with the
// exponents rsa_vp1_cpu passes: RSA_IFMA_WORDS_MIN words, 32 (RSA-2048),
// and the build's largest count, 48 (RSA-3072), or 64 (RSA-4096) in the
// rsa_mont_power_webpki variant, which sets CH_TRUST_WEBPKI. That is 34
// and 50 steps of times_word_mod, or 34 and 65, each with its quotient
// estimate, its subtraction and the passes that add the modulus back.
//
// The remainder and the modulus are arrays of exactly the word count, so
// a read or a write past either fails. The top bit is what the division's
// quotient estimate needs: it divides by the modulus's top word. rsa_mont.c
// compiles the function in an x86-64 host object and under
// CH_RSA_IFMA_MODEL, which the launch line passes.
//
// The products are the contract in proof/rsa_mont64_stubs.h, which
// rsa_mont64_mul128_harness.c discharges on the real multiply.
//
// This line runs without --unsigned-overflow-check: the word above the k
// in a step of the division wraps to zero on purpose when a pass adds the
// modulus back, as rsa_mont_host_harness.c says of the same step.
//
// What it does not prove: that the words it writes are 2^exponent mod m.
// rsa_mont_power_value_harness.c proves that at two words, and
// bin/rsa_ifma_model_test holds the public operation that reads them
// against rsa_mont64.c at every word count from 32 to 64.
#include "rsa_mont64_stubs.h"

#include "rsa_mont.c"

static void prove_words(uint64_t *rem, uint64_t *m, size_t word_count) {
    havoc_words(rem, word_count);
    havoc_words(m, word_count);
    m[0] |= 1;
    m[word_count - 1] |= (uint64_t)1 << 63;
    power_of_two_mod(rem, m, word_count, 104 * rsa_ifma_digit_count(word_count));
}

int main(void) {
    uint64_t rem_min[RSA_IFMA_WORDS_MIN];
    uint64_t m_min[RSA_IFMA_WORDS_MIN];
    prove_words(rem_min, m_min, RSA_IFMA_WORDS_MIN);
    uint64_t rem_max[RSA_MONT64_WORDS_MAX];
    uint64_t m_max[RSA_MONT64_WORDS_MAX];
    prove_words(rem_max, m_max, RSA_MONT64_WORDS_MAX);
    return 0;
}
