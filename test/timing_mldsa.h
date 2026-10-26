// bin/timing_mldsa's rows: ML-DSA-87 key generation and signing
// (docs/decisions.md 159). test/timing_test.c includes it in place of its
// own main under -DTEST_MLDSA, after it defines measure and report. The
// rows sit in a header of their own, so that file stays under the 500
// lines lint-size holds.
//
// The binary is built with -DCH_CT_WIDEMUL, as bin/timing is: ct.h's 16x16
// decomposition, the multiply a host object runs for a session without
// CH_CPU_CONSTANT_TIME_MULTIPLY, and the one mldsa_sign_poly.c runs in this
// commit.
//
// Key generation times one fixed seed against fresh random seeds. Signing
// times one round of the rejection loop: the count of rounds is public
// (mldsa_signer.h), so each sample signs an input that takes one round
// alone. Before the rows run, the binary draws keys and rnd values and
// keeps 256 pairs that sign mu in one round. Class 0 signs the first pair
// every time, and class 1 a random pair from all 256: other keys, other
// rnd, and so other y, c and hints. Each sample copies its pair to one
// buffer before the timed call, so both classes read the same addresses.
#ifndef CH_TEST_TIMING_MLDSA_H
#define CH_TEST_TIMING_MLDSA_H

#include "mldsa_signer.h"

#define MLDSA_KEYGEN_N 2000
#define MLDSA_SIGN_N 4000
#define MLDSA_POOL 256
#define MLDSA_POOL_KEYS 16

typedef struct {
    uint8_t sk[MLDSA87_SK_LEN];
    uint8_t pk[MLDSA87_PK_LEN];
    uint8_t rnd[MLDSA87_RND_LEN];
} mldsa_timing_pair;

static uint8_t mldsa_seed_fixed[MLDSA87_SEED_LEN];
static uint8_t mldsa_seed[MLDSA87_SEED_LEN];
static uint8_t mldsa_sk[MLDSA87_SK_LEN];
static uint8_t mldsa_pk[MLDSA87_PK_LEN];
static uint8_t mldsa_sig[MLDSA87_SIG_LEN];
static uint8_t mldsa_mu[MLDSA_MU_LEN];
static mldsa_timing_pair mldsa_pool[MLDSA_POOL];
static mldsa_timing_pair mldsa_now;

static void mldsa_keygen_prep(int class_id) {
    if (class_id == 0) {
        memcpy(mldsa_seed, mldsa_seed_fixed, sizeof mldsa_seed);
    } else {
        ch_rand_bytes(mldsa_seed, sizeof mldsa_seed);
    }
}

static void mldsa_keygen_run(void) {
    sink ^= (uint32_t)mldsa87_keygen(mldsa_sk, mldsa_pk, mldsa_seed);
    sink ^= mldsa_pk[MLDSA87_PK_LEN - 1];
}

static void mldsa_sign_prep(int class_id) {
    size_t at = class_id == 0 ? 0 : (size_t)(rng64() % MLDSA_POOL);
    memcpy(&mldsa_now, &mldsa_pool[at], sizeof mldsa_now);
}

static void mldsa_sign_run(void) {
    sink ^= mldsa87_sign_mu(mldsa_sig, mldsa_now.sk, mldsa_now.pk, mldsa_mu, mldsa_now.rnd);
    sink ^= mldsa_sig[0];
}

// Fills the pool with MLDSA_POOL pairs that sign mldsa_mu in one round,
// over MLDSA_POOL_KEYS keys. Returns 0 when a key fails to expand.
static int mldsa_fill_pool(void) {
    size_t kept = 0;
    for (size_t k = 0; k < MLDSA_POOL_KEYS; k++) {
        uint8_t seed[MLDSA87_SEED_LEN];
        ch_rand_bytes(seed, sizeof seed);
        if (!mldsa87_keygen(mldsa_sk, mldsa_pk, seed)) {
            return 0;
        }
        size_t end = kept + MLDSA_POOL / MLDSA_POOL_KEYS;
        while (kept < end) {
            mldsa_timing_pair *p = &mldsa_pool[kept];
            memcpy(p->sk, mldsa_sk, sizeof p->sk);
            memcpy(p->pk, mldsa_pk, sizeof p->pk);
            ch_rand_bytes(p->rnd, sizeof p->rnd);
            if (mldsa87_sign_mu(mldsa_sig, p->sk, p->pk, mldsa_mu, p->rnd) == 1) {
                kept++;
            }
        }
    }
    return kept == MLDSA_POOL;
}

int main(void) {
    ch_rand_bytes((uint8_t *)&rng_state, sizeof rng_state);
    rng_state |= 1;
    ch_rand_bytes(mldsa_seed_fixed, sizeof mldsa_seed_fixed);
    ch_rand_bytes(mldsa_mu, sizeof mldsa_mu);
    report("mldsa_keygen", measure(mldsa_keygen_prep, mldsa_keygen_run, MLDSA_KEYGEN_N, 16));
    if (!mldsa_fill_pool()) {
        (void)fprintf(stderr, "timing: the ML-DSA-87 pool did not fill\n");
        return 1;
    }
    report("mldsa_sign1", measure(mldsa_sign_prep, mldsa_sign_run, MLDSA_SIGN_N, 16));
    return failures ? 1 : 0;
}

#endif
