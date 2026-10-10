// Proves: rsa_sign64.c's AVX-512 IFMA arm, the path a session whose
// ch_cfg.cpu holds CH_CPU_AVX512_IFMA and the multiply bit takes
// (docs/decisions.md 120), calls the kernels with the key's integers and
// wipes after each, and its check and its write keep rsa_sign64_crt's
// statements. At the largest length the build admits and at 8 bytes below
// it, the two shapes rsa_sign64_crt_harness.c names, and under
// CH_TRUST_WEBPKI in the rsa_sign64_ifma_webpki variant:
//
//   - both_powers runs rsa_ifma_sign_power_pair once, on m1 and m2 in
//     place, with dp and dq, both primes' records and the primes' length
//     in bytes, and rsa_ifma_sign_wipe_below once after it.
//   - check_power runs rsa_vp1_cpu once, under the session's value, on
//     the key's modulus, every byte of it, and the candidate, every byte
//     of it, and rsa_ifma_sign_wipe_below once after it.
//   - signature_verifies answers 1 exactly when every byte rsa_vp1_cpu
//     wrote is the byte of the encoded message.
//   - write_if_verified leaves sig as it was, every byte, unless the check
//     passed, and then sig holds the candidate.
//
// The launch line passes -DCH_RSA_IFMA_MODEL, under which rsa_sign64.c
// compiles the arm on any target, as bin/rsa_ifma_sign_model_test compiles
// it. The kernels and the wipe are the contracts below, each asserting
// what the real entry needs of its arguments: rsa_ifma_sign_power_pair
// needs two records of one word count inside the kernel's range and
// readable bases and exponents, and writes the outputs' words;
// rsa_vp1_cpu needs a readable modulus and signature of n_len bytes and
// writes n_len bytes. rsa_ifma_sign_power_harness.c and the rsa_ifma
// harnesses prove the real kernels' memory accesses over every argument
// these contracts admit, and rsa_ifma_sign_wipe_harness.c the wipe's.
// rsa_mont64.c's entries are proof/rsa_sign64_stubs.h's contracts.
//
// Over the model the vector registers hold nothing, so the arm's wipe of
// them is empty here. bin/x86_kernels_test counts that wipe on x86-64.
//
// What it does not prove: any value of the kernels. bin/rsa_ifma_sign_model_test
// and bin/rsa_sign_equiv_test hold them to the window and the ladder.
#include "rsa_sign64_stubs.h"

// The values the IFMA arm runs under, and the window's.
#define IFMA_CPU (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY | CH_CPU_AVX512_IFMA)

// What the contracts saw: the number of calls, and the arguments of the
// last one.
static unsigned long pair_calls;
static unsigned long wipe_calls;
static unsigned long vp1_calls;
static const uint64_t *pair_o_p;
static const uint64_t *pair_base_p;
static const uint8_t *pair_e_p;
static const rsa_mont64_modulus *pair_mod_p;
static const uint64_t *pair_o_q;
static const uint64_t *pair_base_q;
static const uint8_t *pair_e_q;
static const rsa_mont64_modulus *pair_mod_q;
static size_t pair_e_len;
static uint32_t vp1_cpu;
static const uint8_t *vp1_n;
static size_t vp1_n_len;
static const uint8_t *vp1_sig;
static uint8_t vp1_out[CH_RSA_MODULUS_MAX];

void rsa_ifma_sign_power_pair(uint64_t *o_p, const uint64_t *base_p, const uint8_t *e_p,
                              const rsa_mont64_modulus *mod_p, uint64_t *o_q,
                              const uint64_t *base_q, const uint8_t *e_q,
                              const rsa_mont64_modulus *mod_q, size_t e_len) {
    size_t k = mod_p->words;
    __CPROVER_assert(k >= RSA_IFMA_SIGN_WORDS_MIN && k <= RSA_IFMA_SIGN_WORDS_MAX &&
                         mod_q->words == k,
                     "rsa_ifma_sign_power_pair: two records of one word count in its range");
    __CPROVER_assert(__CPROVER_r_ok(base_p, k * sizeof(uint64_t)) &&
                         __CPROVER_r_ok(base_q, k * sizeof(uint64_t)),
                     "rsa_ifma_sign_power_pair: the bases hold the primes' words");
    __CPROVER_assert(__CPROVER_r_ok(e_p, e_len) && __CPROVER_r_ok(e_q, e_len),
                     "rsa_ifma_sign_power_pair: the exponents are readable");
    pair_calls++;
    pair_o_p = o_p;
    pair_base_p = base_p;
    pair_e_p = e_p;
    pair_mod_p = mod_p;
    pair_o_q = o_q;
    pair_base_q = base_q;
    pair_e_q = e_q;
    pair_mod_q = mod_q;
    pair_e_len = e_len;
    havoc_words(o_p, k);
    havoc_words(o_q, k);
}

void rsa_ifma_sign_wipe_below(void) {
    wipe_calls++;
}

void rsa_vp1_cpu(uint32_t cpu, const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em) {
    __CPROVER_assert(n_len >= 1 && n_len <= CH_RSA_MODULUS_MAX && __CPROVER_r_ok(n, n_len) &&
                         __CPROVER_r_ok(sig, n_len),
                     "rsa_vp1_cpu: the modulus and the signature are readable");
    vp1_calls++;
    vp1_cpu = cpu;
    vp1_n = n;
    vp1_n_len = n_len;
    vp1_sig = sig;
    for (size_t i = 0; i < n_len; i++) {
        em[i] = nondet_u8();
        vp1_out[i] = em[i];
    }
}

static ch_rsa_priv key;

// A key of n_len bytes with every integer unconstrained, as
// rsa_sign64_crt_harness.c writes one.
static void havoc_key(size_t n_len) {
    fill_nondet(key.n, sizeof key.n);
    fill_nondet(key.d, sizeof key.d);
    fill_nondet(key.p, sizeof key.p);
    fill_nondet(key.q, sizeof key.q);
    fill_nondet(key.dp, sizeof key.dp);
    fill_nondet(key.dq, sizeof key.dq);
    fill_nondet(key.qinv, sizeof key.qinv);
    key.n_len = n_len;
}

static void havoc_record(rsa_mont64_modulus *mod, size_t k) {
    havoc_words(mod->m, k);
    havoc_words(mod->r2, k);
    mod->m0inv = nondet_u64();
    mod->words = k;
}

static void prove_powers(size_t n_len) {
    size_t half_len = n_len / 2;
    size_t k = (half_len + 7) >> 3;
    rsa_mont64_modulus mod_p;
    rsa_mont64_modulus mod_q;
    uint64_t m1[PRIME_WORDS_MAX];
    uint64_t m2[PRIME_WORDS_MAX];
    havoc_key(n_len);
    havoc_record(&mod_p, k);
    havoc_record(&mod_q, k);
    havoc_words(m1, PRIME_WORDS_MAX);
    havoc_words(m2, PRIME_WORDS_MAX);
    pair_calls = 0;
    wipe_calls = 0;
    both_powers(IFMA_CPU, m1, m2, &key, half_len, &mod_p, &mod_q);
    __CPROVER_assert(pair_calls == 1 && wipe_calls == 1,
                     "the exponentiations run on the kernel once, and the wipe follows them");
    __CPROVER_assert(pair_o_p == m1 && pair_base_p == m1 && pair_o_q == m2 && pair_base_q == m2,
                     "each half is raised in place");
    __CPROVER_assert(pair_e_p == key.dp && pair_e_q == key.dq && pair_e_len == half_len,
                     "the exponents are dp and dq, every byte of each");
    __CPROVER_assert(pair_mod_p == &mod_p && pair_mod_q == &mod_q, "each half under its prime");
}

// Whether the bytes rsa_vp1_cpu last wrote are the n_len bytes of em.
static int power_is_message(const uint8_t *em, size_t n_len) {
    int same = 1;
    for (size_t i = 0; i < n_len; i++) {
        if (vp1_out[i] != em[i]) {
            same = 0;
        }
    }
    return same;
}

// What the check must have asked of the public operation: one call under
// the session's value, on the key's modulus, whole, and the candidate,
// whole, and one wipe after it.
static void assert_check_arguments(const uint8_t *candidate) {
    __CPROVER_assert(vp1_calls == 1 && wipe_calls == 1,
                     "the check runs the public operation once, and the wipe follows it");
    __CPROVER_assert(vp1_cpu == IFMA_CPU, "the check runs under the session's value");
    __CPROVER_assert(vp1_n == key.n && vp1_n_len == key.n_len,
                     "the check's modulus is the key's, every byte of it");
    __CPROVER_assert(vp1_sig == candidate, "the check raises the candidate");
}

static void prove_check(size_t n_len) {
    uint8_t em[CH_RSA_MODULUS_MAX];
    uint8_t candidate[CH_RSA_MODULUS_MAX];
    havoc_key(n_len);
    fill_nondet(em, sizeof em);
    fill_nondet(candidate, sizeof candidate);
    vp1_calls = 0;
    wipe_calls = 0;
    int verified = signature_verifies(IFMA_CPU, &key, em, candidate);
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
    vp1_calls = 0;
    wipe_calls = 0;
    int wrote = write_if_verified(IFMA_CPU, &key, em, candidate, sig);
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
    prove_powers(CH_RSA_MODULUS_MAX);
    prove_powers(CH_RSA_MODULUS_MAX - 8);
    prove_check(CH_RSA_MODULUS_MAX);
    prove_check(CH_RSA_MODULUS_MAX - 8);
    prove_write(CH_RSA_MODULUS_MAX);
    prove_write(CH_RSA_MODULUS_MAX - 8);
    return 0;
}
