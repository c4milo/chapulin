// Proves: product_pair, the switch and the copies of the two products
// side by side for every register count a build admits, read and write
// inside their arrays, over any operand digits, any primes' digits and any
// m0inv, in each aliasing shape rsa_ifma_sign_power_pair calls them in.
// This line runs the copies for 3 and 4 registers, the counts of a default
// build, and its rsa_ifma_sign_pair_webpki variant, under CH_TRUST_WEBPKI,
// the copy for 5, whose case only that build's switch holds.
//
// Each count runs at the largest prime word count it holds, which gives it
// its most digits: 19 words in 3 registers and 24 in 4, and 32 in 5 under
// CH_TRUST_WEBPKI. The records are written as state_setup writes them: the
// digit count of the word count, the register count of the digits, any
// m0inv below 2^52 and any digits below 2^52, then zeros, in arrays of the
// lanes the build's largest prime takes.
//
// The shapes are the ones rsa_ifma_sign_power_pair calls: the table's,
// each output an array apart from both operands, which are one array for
// the table's third entry and two after it; the squares', output and both
// operands one array; the step's and the last product's, the output on the
// first operand and the second apart. Each runs both primes, with the
// second prime's arrays apart from the first's.
//
// The lane operations are the contracts proof/rsa_ifma_stubs.h states
// under RSA_IFMA_STUB_EVERY_LANE_OPERATION: a load reads eight words, a
// store writes eight, and every value is any value. No index or branch in
// the copies reads a lane, so the contracts cost the proof nothing it
// claims.
//
// What it does not prove: any value. rsa_ifma_sums_harness.c proves that
// no sum of rsa_ifma_product.h's round wraps, which pair_core runs once
// for each prime, and bin/rsa_ifma_sign_model_test holds every
// exponentiation to rsa_sign64.c's window.
#define RSA_IFMA_STUB_EVERY_LANE_OPERATION 1
#include "rsa_ifma_stubs.h"

// rsa_ifma_stubs.h compiles rsa_mont64.c, whose static mask_of_bit has
// the name of rsa_ifma_sign.c's own, so this one translation unit renames
// the second.
#define mask_of_bit sign_mask_of_bit
#include "rsa_ifma_sign.c"

// A record of a prime of k words whose digits and m0inv are any values
// below 2^52, as state_setup writes one.
static void havoc_record(sign_modulus *record, size_t k) {
    size_t n = RSA_IFMA_DIGIT_COUNT(k);
    havoc_digits(record->digits, n);
    for (size_t i = n; i < SIGN_LANES_MAX; i++) {
        record->digits[i] = 0;
    }
    record->m0inv = nondet_u64() & STUB_DIGIT_MASK;
    record->digit_count = n;
    record->registers = (n + DIGITS_PER_REGISTER - 1) / DIGITS_PER_REGISTER;
}

static void prove_words(size_t k) {
    sign_modulus mod_p;
    sign_modulus mod_q;
    uint64_t out_p[SIGN_LANES_MAX];
    uint64_t a_p[SIGN_LANES_MAX];
    uint64_t b_p[SIGN_LANES_MAX];
    uint64_t out_q[SIGN_LANES_MAX];
    uint64_t a_q[SIGN_LANES_MAX];
    uint64_t b_q[SIGN_LANES_MAX];

    // The table's shape: every array apart.
    havoc_record(&mod_p, k);
    havoc_record(&mod_q, k);
    havoc_digits(a_p, SIGN_LANES_MAX);
    havoc_digits(b_p, SIGN_LANES_MAX);
    havoc_digits(a_q, SIGN_LANES_MAX);
    havoc_digits(b_q, SIGN_LANES_MAX);
    product_pair(out_p, a_p, b_p, &mod_p, out_q, a_q, b_q, &mod_q);

    // The table's third entry: both operands one array, the output apart.
    havoc_record(&mod_p, k);
    havoc_record(&mod_q, k);
    havoc_digits(a_p, SIGN_LANES_MAX);
    havoc_digits(a_q, SIGN_LANES_MAX);
    product_pair(out_p, a_p, a_p, &mod_p, out_q, a_q, a_q, &mod_q);

    // The squares' shape: output and both operands one array.
    havoc_record(&mod_p, k);
    havoc_record(&mod_q, k);
    havoc_digits(a_p, SIGN_LANES_MAX);
    havoc_digits(a_q, SIGN_LANES_MAX);
    product_pair(a_p, a_p, a_p, &mod_p, a_q, a_q, a_q, &mod_q);

    // The step's and the last product's shape: the output on the first
    // operand.
    havoc_record(&mod_p, k);
    havoc_record(&mod_q, k);
    havoc_digits(a_p, SIGN_LANES_MAX);
    havoc_digits(b_p, SIGN_LANES_MAX);
    havoc_digits(a_q, SIGN_LANES_MAX);
    havoc_digits(b_q, SIGN_LANES_MAX);
    product_pair(a_p, a_p, b_p, &mod_p, a_q, a_q, b_q, &mod_q);
}

int main(void) {
#ifdef CH_TRUST_WEBPKI
    prove_words(32);
#else
    prove_words(19);
    prove_words(24);
#endif
    return 0;
}
