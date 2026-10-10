// Proves: rsa_ifma_sign_power_pair, whole, reads and writes inside its
// arrays, over any two primes' words, any r2 and m0inv, any bases and any
// exponent bytes, at the smallest and the largest prime word count of each
// build: 16 and 24 words, and 16 and 32 under CH_TRUST_WEBPKI in its
// rsa_ifma_sign_power_webpki variant. That is state_setup's record of each
// prime and its first two table entries, the fourteen products that fill
// the tables, the steps over the exponents' digits with their squares,
// table_select's reads and the products by the entry, the last product,
// state_finish's conversion back to words and its subtraction, and the
// wipes of the two states. Each word count runs with the output written
// over its base, as rsa_sign64.c calls it, and the exponents are one byte
// long, two steps: a step's statements are the same whatever its index,
// and the exponent's length counts the steps alone. The wipe of the stack
// below the caller is rsa_ifma_sign_wipe_harness.c's.
//
// The lane operations are the contracts proof/rsa_ifma_stubs.h states
// under RSA_IFMA_STUB_EVERY_LANE_OPERATION, and the three rsa_mont64.c
// entries the file calls are the contracts of proof/rsa_ifma_sign_stubs.h,
// which the rsa_mont64 harnesses discharge.
//
// What it does not prove: any value. bin/rsa_ifma_sign_model_test holds
// every exponentiation to rsa_sign64.c's window, over every shape of prime,
// base and exponent it tries.
#define RSA_IFMA_STUB_EVERY_LANE_OPERATION 1
#include "rsa_ifma_stubs.h"

#include "rsa_ifma_sign_stubs.h"

// rsa_ifma_stubs.h compiles rsa_mont64.c, whose static mask_of_bit has
// the name of rsa_ifma_sign.c's own, so this one translation unit renames
// the second.
#define mask_of_bit sign_mask_of_bit
#include "rsa_ifma_sign.c"

static void prove_words(size_t k) {
    rsa_mont64_modulus mod_p;
    rsa_mont64_modulus mod_q;
    uint64_t base_p[RSA_IFMA_SIGN_WORDS_MAX];
    uint64_t base_q[RSA_IFMA_SIGN_WORDS_MAX];
    uint8_t e_p[1];
    uint8_t e_q[1];
    havoc_modulus(&mod_p, k);
    havoc_modulus(&mod_q, k);
    havoc_words(base_p, RSA_IFMA_SIGN_WORDS_MAX);
    havoc_words(base_q, RSA_IFMA_SIGN_WORDS_MAX);
    e_p[0] = nondet_u8();
    e_q[0] = nondet_u8();
    rsa_ifma_sign_power_pair(base_p, base_p, e_p, &mod_p, base_q, base_q, e_q, &mod_q, 1);
}

int main(void) {
    prove_words(RSA_IFMA_SIGN_WORDS_MIN);
    prove_words(RSA_IFMA_SIGN_WORDS_MAX);
    return 0;
}
