// Proves: almost_montgomery_product, the switch and the copies of the
// product between the smallest and the largest register count a build
// admits, read and write inside their arrays, over any operand digits, any
// modulus words and any m0inv. rsa_ifma_public_harness.c runs the whole
// public operation, with its eighteen products, at 5 and 8 registers and,
// under CH_TRUST_WEBPKI, at 10. This line runs the copies for 6 and 7
// registers, and its rsa_ifma_product_webpki variant runs, under
// CH_TRUST_WEBPKI, the copies for 8 and 9, whose cases in that build's
// switch differ from the default build's.
//
// Each count runs at the largest word count it holds, which gives it its
// most digits: 38 words in 6 registers and 45 in 7, and 51 in 8 and 58 in
// 9 under CH_TRUST_WEBPKI. modulus_from_words writes the record from the
// modulus's words, as rsa_ifma_public does, so the digit count, the
// register count and the switch's case are the ones that call computes.
//
// Each count runs the two aliasing shapes rsa_ifma_public calls: the
// output on the second operand, as its first and last products write, and
// all three the same array, as its squares do. The operands are arrays of
// the lanes rsa_ifma_public gives them.
//
// The lane operations are the contracts proof/rsa_ifma_stubs.h states
// under RSA_IFMA_STUB_EVERY_LANE_OPERATION: a load reads eight words, a
// store writes eight, and every value is any value.
//
// What it does not prove: any value. rsa_ifma_sums_harness.c proves that
// no sum wraps at 1 and 2 registers, and bin/rsa_ifma_model_test holds the
// products' values against rsa_mont64.c.
#define RSA_IFMA_STUB_EVERY_LANE_OPERATION 1
#include "rsa_ifma_stubs.h"

#include "rsa_ifma.c"

static void prove_words(size_t word_count) {
    rsa_mont64_modulus mod;
    rsa_ifma_modulus modulus;
    uint64_t a[LANE_COUNT_MAX];
    uint64_t power[LANE_COUNT_MAX];

    havoc_modulus(&mod, word_count);
    modulus_from_words(&modulus, &mod);
    havoc_digits(a, LANE_COUNT_MAX);
    havoc_digits(power, LANE_COUNT_MAX);
    almost_montgomery_product(power, a, power, &modulus);

    havoc_modulus(&mod, word_count);
    modulus_from_words(&modulus, &mod);
    havoc_digits(power, LANE_COUNT_MAX);
    almost_montgomery_product(power, power, power, &modulus);
}

int main(void) {
#ifdef CH_TRUST_WEBPKI
    prove_words(51);
    prove_words(58);
#else
    prove_words(38);
    prove_words(45);
#endif
    return 0;
}
