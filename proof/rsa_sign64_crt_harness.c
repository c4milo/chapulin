// Proves: the four pieces of a CRT signature that rsa_sign64_sp1 joins
// read and write inside their arrays, over any key bytes, any words and
// any encoded message, at the largest length the build admits (384 bytes;
// 512 in the rsa_sign64_crt_webpki variant, which sets CH_TRUST_WEBPKI)
// and, where a length decides an index, at 8 bytes below it. There each
// prime is half a word past a whole number of 64-bit words, so twice a
// prime's words is one word more than the modulus has. Those are the two
// shapes the word counts take, and the largest of each is the binding
// case for every index.
//
// The reduction. message_mod_prime splits the message into its low words
// and the words above them, k of them or k - 1, for a prime of the
// largest word count, at both shapes.
//
// The recombination. crt_combine runs Garner's formula over any two
// halves and any qinv bytes, into twice a prime's words.
//
// The key test. rsa_sign64_key_ok multiplies any two primes into twice
// their words and compares the product with the modulus, zero-extended to
// that many words, at both shapes. It admits a key exactly when every
// word of the product is the word of the modulus: no word is left out of
// the comparison.
//
// The check. signature_verifies raises the candidate, every byte of it,
// modulo the key's modulus, and answers 1 exactly when every byte of the
// power is the byte of the encoded message, at both shapes: no byte is
// left out of the comparison.
//
// The write. write_if_verified leaves sig as it was, every byte, unless
// the check passed, and then sig holds the candidate. So no byte of a
// candidate that failed its check is written to a caller.
//
// The power and the product are what the contracts wrote, which
// proof/rsa_sign64_stubs.h keeps. So the three statements above are about
// which bytes and words are compared and copied, for any power and any
// product, and not about what the power or the product is.
//
// The calls into rsa_mont64.c are the contracts in
// proof/rsa_sign64_stubs.h, which the rsa_mont64 harnesses discharge on
// the real entries. Each contract asserts what the real entry needs, so
// the proof also holds every call these pieces make to those needs.
//
// What it does not drive: rsa_sign64_sp1 itself. Its own statements are
// two modulus setups, the message's marshalling, these pieces, two calls
// of rsa_sign64_power, which rsa_sign64_power_harness.c proves at each of
// its bounds, and seven wipes, over arrays of the largest word count. Run
// whole it is that exponentiation at both bounds at once, twice.
//
// What it does not prove: any value. That the signature is em^d mod n
// rests on bin/rsa_sign_equiv_test, which holds it against rsa_sign.c's
// ladder, on the published vectors and the Wycheproof suite, and on the
// call's own check with the public exponent at every signature.
#include "rsa_sign64_stubs.h"

// The ch_cfg.cpu value the check runs under: the multiply bit without
// CH_CPU_AVX512_IFMA, which takes its rsa_mont64_public arm on every
// target, the arm the stubs above model.
#define HARNESS_CPU (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY)

static void havoc_modulus(rsa_mont64_modulus *mod, size_t k) {
    havoc_words(mod->m, k);
    havoc_words(mod->r2, k);
    mod->m0inv = nondet_u64();
    mod->words = k;
}

// em_words is twice the prime's words, or one less.
static void prove_reduction(size_t em_words) {
    rsa_mont64_modulus mod;
    uint64_t em[RSA_MONT64_WORDS_MAX];
    uint64_t o[PRIME_WORDS_MAX];
    havoc_modulus(&mod, PRIME_WORDS_MAX);
    havoc_words(em, em_words);
    message_mod_prime(o, em, em_words, &mod);
}

static void prove_recombination(void) {
    rsa_mont64_modulus mod_p;
    rsa_mont64_modulus mod_q;
    uint64_t m1[PRIME_WORDS_MAX];
    uint64_t m2[PRIME_WORDS_MAX];
    uint64_t s[2 * PRIME_WORDS_MAX];
    uint8_t qinv[CH_RSA_MODULUS_MAX / 2];
    havoc_modulus(&mod_p, PRIME_WORDS_MAX);
    havoc_modulus(&mod_q, PRIME_WORDS_MAX);
    havoc_words(m1, PRIME_WORDS_MAX);
    havoc_words(m2, PRIME_WORDS_MAX);
    fill_nondet(qinv, sizeof qinv);
    crt_combine(s, m1, m2, qinv, sizeof qinv, &mod_p, &mod_q);
}

static ch_rsa_priv key;

// A key of n_len bytes with every integer unconstrained but the two bytes
// rsa_pss_sign_key_ok reads, which are as a key it admits has them: an
// odd modulus with its top bit set.
static void havoc_key(size_t n_len) {
    fill_nondet(key.n, sizeof key.n);
    fill_nondet(key.d, sizeof key.d);
    fill_nondet(key.p, sizeof key.p);
    fill_nondet(key.q, sizeof key.q);
    fill_nondet(key.dp, sizeof key.dp);
    fill_nondet(key.dq, sizeof key.dq);
    fill_nondet(key.qinv, sizeof key.qinv);
    key.n_len = n_len;
    key.n[0] |= 0x80;
    key.n[n_len - 1] |= 1;
}

static void prove_key_test(size_t n_len) {
    havoc_key(n_len);
    int admitted = rsa_sign64_key_ok(&key);

    // The product is the one stub_mul_add wrote, and the modulus's words
    // the ones stub_from_bytes wrote in its last call, which read key.n.
    size_t words = (n_len / 2 + 7) >> 3;
    __CPROVER_assert(stub_mul_add_words == words, "the product is of two primes' words");
    __CPROVER_assert(stub_from_bytes_bytes == key.n && stub_from_bytes_len == n_len &&
                         stub_from_bytes_count == 2 * words,
                     "the modulus is read whole, into the product's words");
    int equal = 1;
    for (size_t i = 0; i < 2 * words; i++) {
        if (stub_mul_add_out[i] != stub_from_bytes_out[i]) {
            equal = 0;
        }
    }
    __CPROVER_assert(admitted == equal,
                     "the key test admits exactly when every word of p * q is the modulus's");
}

// Whether the bytes stub_public last wrote are the n_len bytes of em.
static int power_is_message(const uint8_t *em, size_t n_len) {
    int same = 1;
    for (size_t i = 0; i < n_len; i++) {
        if (stub_public_out[i] != em[i]) {
            same = 0;
        }
    }
    return same;
}

// What the check must have asked of rsa_mont64.c: the key's modulus,
// whole, and the candidate, whole.
static void assert_check_arguments(const uint8_t *candidate) {
    __CPROVER_assert(stub_init_modulus == key.n && stub_init_len == key.n_len,
                     "the check's modulus is the key's, every byte of it");
    __CPROVER_assert(stub_public_base == candidate && stub_public_len == key.n_len,
                     "the check raises the candidate, every byte of it");
}

static void prove_check(size_t n_len) {
    uint8_t em[CH_RSA_MODULUS_MAX];
    uint8_t candidate[CH_RSA_MODULUS_MAX];
    havoc_key(n_len);
    fill_nondet(em, sizeof em);
    fill_nondet(candidate, sizeof candidate);
    int verified = signature_verifies(HARNESS_CPU, &key, em, candidate);
    assert_check_arguments(candidate);
    __CPROVER_assert(verified == power_is_message(em, n_len),
                     "the check passes exactly when every byte of the power is the message's");
}

static void prove_write(size_t n_len) {
    uint8_t em[CH_RSA_MODULUS_MAX];
    uint8_t candidate[CH_RSA_MODULUS_MAX];
    uint8_t sig[CH_RSA_MODULUS_MAX];
    uint8_t before[CH_RSA_MODULUS_MAX];
    havoc_key(n_len);
    fill_nondet(em, sizeof em);
    fill_nondet(candidate, sizeof candidate);
    fill_nondet(sig, sizeof sig);
    for (size_t i = 0; i < sizeof sig; i++) {
        before[i] = sig[i];
    }
    int wrote = write_if_verified(HARNESS_CPU, &key, em, candidate, sig);
    assert_check_arguments(candidate);
    __CPROVER_assert(wrote == power_is_message(em, n_len),
                     "a signature is written exactly when its check passed");
    for (size_t i = 0; i < sizeof sig; i++) {
        uint8_t want = (wrote && i < n_len) ? candidate[i] : before[i];
        __CPROVER_assert(sig[i] == want,
                         "sig holds the candidate after a check that passed, and what it "
                         "held before after one that failed");
    }
}

int main(void) {
    prove_reduction(2 * PRIME_WORDS_MAX);
    prove_reduction(2 * PRIME_WORDS_MAX - 1);
    prove_recombination();
    prove_key_test(CH_RSA_MODULUS_MAX);
    prove_key_test(CH_RSA_MODULUS_MAX - 8);
    prove_check(CH_RSA_MODULUS_MAX);
    prove_check(CH_RSA_MODULUS_MAX - 8);
    prove_write(CH_RSA_MODULUS_MAX);
    prove_write(CH_RSA_MODULUS_MAX - 8);
    return 0;
}
