// Proves: rsa_sign64_power reads and writes inside its arrays, at each of
// its two bounds. Its loops have two lengths that no index combines: the
// digits it reads, two for each byte of the exponent, and the words each
// step handles. So the harness makes two calls.
//
// The exponent's bound: the longest exponent a key has, half the largest
// modulus the build admits (192 bytes; 256 in the rsa_sign64_power_webpki
// variant, which sets CH_TRUST_WEBPKI), over a modulus of one word. Every
// digit of every byte is read, and every step squares four times, reads
// the table and multiplies.
//
// The words' bound: the largest prime's word count (24; 32 in the
// variant), which the function's CH_ASSERT holds its callers to, under an
// exponent of two bytes. The table's sixteen rows, the entry a step
// reads, the running power and the two wipes are at their full sizes,
// with the output apart from the base and then on it, which rsa_sign64.h
// allows.
//
// The whole call at both bounds at once is not run: at the bounds this
// file had before the primes, 768 steps of 48 words, it returned no
// verdict in fifteen minutes with cbmc still unwinding. No index in the
// function is computed from both lengths, so the two calls cover every
// access it makes: the exponent's bytes by its length, the table, the
// entry and the power by the word count.
//
// The calls into rsa_mont64.c are the contracts in
// proof/rsa_sign64_stubs.h, which the rsa_mont64 harnesses discharge on
// the real entries. Each contract asserts what the real entry needs, so
// the proof also holds every multiplication rsa_sign64_power makes to a
// word count inside the arrays and operands of that many words.
//
// What it does not prove: that the words it writes are the power.
// bin/rsa_sign_equiv_test holds that against rsa_sign.c's ladder and
// against a square-and-multiply that keeps no table.
#include "rsa_sign64_stubs.h"

#define STEPS_WORDS 1
#define STEPS_EXPONENT_LEN (CH_RSA_MODULUS_MAX / 2)
#define WORDS_EXPONENT_LEN 2

static void havoc_modulus(rsa_mont64_modulus *mod, size_t k) {
    havoc_words(mod->m, k);
    havoc_words(mod->r2, k);
    mod->m0inv = nondet_u64();
    mod->words = k;
}

static void prove_exponent_bound(void) {
    rsa_mont64_modulus mod;
    uint8_t e[STEPS_EXPONENT_LEN];
    uint64_t base[PRIME_WORDS_MAX];
    uint64_t o[PRIME_WORDS_MAX];
    havoc_modulus(&mod, STEPS_WORDS);
    fill_nondet(e, sizeof e);
    havoc_words(base, STEPS_WORDS);
    rsa_sign64_power(o, base, e, sizeof e, &mod);
}

static void prove_word_bound(void) {
    rsa_mont64_modulus mod;
    uint8_t e[WORDS_EXPONENT_LEN];
    uint64_t base[PRIME_WORDS_MAX];
    uint64_t o[PRIME_WORDS_MAX];

    havoc_modulus(&mod, PRIME_WORDS_MAX);
    fill_nondet(e, sizeof e);
    havoc_words(base, PRIME_WORDS_MAX);
    rsa_sign64_power(o, base, e, sizeof e, &mod);

    havoc_modulus(&mod, PRIME_WORDS_MAX);
    fill_nondet(e, sizeof e);
    havoc_words(base, PRIME_WORDS_MAX);
    rsa_sign64_power(base, base, e, sizeof e, &mod);
}

int main(void) {
    prove_exponent_bound();
    prove_word_bound();
    return 0;
}
