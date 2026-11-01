// bin/mldsa_runtime_test: which ML-DSA-87 calls of a host object run on
// mldsa_vector.c's lanes under each ch_cfg.cpu value (docs/decisions.md
// 172). On arm64 the verifier runs its transforms and products on the
// lanes in every session, and the signer runs them there for a value that
// holds CH_CPU_CONSTANT_TIME_MULTIPLY alone. On x86-64 the object holds no
// lanes, and no call runs them. The two paths compute the same values, so
// no output can tell which ran: test/mldsa_vector_count.c counts the calls
// into the lanes instead, and runs each on mldsa_poly.c's loop.
//
// Every row runs under each value the bits of TEST_CPU_ALL make beside
// CH_CPU_PROBED. Each row must make the count of calls below, entry for
// entry, and write the bytes the call that takes no value writes:
//
//   - mldsa87_keygen_cpu: KEYGEN_CALLS under the bit, and none without it;
//   - mldsa87_sign_mu_cpu: ROUND_CALLS for each round the signature took
//     under the bit, and none without it, then CHALLENGE_CALLS for the
//     check of the signature under every value;
//   - mldsa87_sign_cpu: as mldsa87_sign_mu_cpu, with the whole
//     verification's calls, which are CHALLENGE_CALLS, after the rounds.
//     Its rounds are the rounds mldsa87_sign_mu takes for the message's
//     mu, which the test computes as FIPS 204 Algorithm 7, step 6 does;
//   - mldsa87_verify, which takes no value: CHALLENGE_CALLS.
//
// So a dispatcher that reads another bit fails under the values that hold
// one bit and not the other, a step left on the loops fails its count, and
// a signer that runs the lanes without the bit fails under the values
// without it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "mldsa.h"
#include "mldsa_poly.h"
#include "mldsa_signer.h"
#include "mldsa_vector.h"
#include "mldsa_vector_count.h"
#include "sha3.h"
#include "test_cpu.h"

#if !defined(CH_CPU_RUNTIME) || !defined(CH_MLDSA_SIGN_TEST)
#error "bin/mldsa_runtime_test is a host object's signer: -DCH_CPU_RUNTIME -DCH_MLDSA_SIGN_TEST"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// Key generation: NTT(s1), seven transforms, then each of the eight rows of
// A s1, seven products, the first a pointwise product and six sums, and
// one inverse transform.
static const mldsa_vector_calls KEYGEN_CALLS = {MLD_L, MLD_K, MLD_K,
                                                (unsigned long)MLD_K * (MLD_L - 1)};

// One round of the rejection loop. mlds_commit: NTT(y), seven transforms,
// the eight rows of A y as in key generation, and NTT(c). mlds_response:
// for each of the seven polynomials of s1, NTT(s1[j]) and c s1[j], one
// pointwise product and one inverse transform. mlds_hint_row: for each of
// the eight rows, the same three for s2[i] and then for t0[i].
static const mldsa_vector_calls ROUND_CALLS = {
    MLD_L + 1 + MLD_L + 2UL * MLD_K,
    MLD_K + MLD_L + 2UL * MLD_K,
    MLD_K + MLD_L + 2UL * MLD_K,
    (unsigned long)MLD_K * (MLD_L - 1),
};

// mldsa87_challenge, which mldsa87_verify runs whole: NTT(z), seven
// transforms, and NTT(c), then for each of the eight rows the row of A z,
// NTT(t1[i] 2^d), its product with NTT(c), and one inverse transform.
static const mldsa_vector_calls CHALLENGE_CALLS = {
    MLD_L + 1 + MLD_K,
    MLD_K,
    2UL * MLD_K,
    (unsigned long)MLD_K * (MLD_L - 1),
};

static const mldsa_vector_calls NO_CALLS = {0, 0, 0, 0};

static int failures;

// rounds times each count of round, plus each count of after. In an object
// without the lanes every count is 0.
static mldsa_vector_calls expected(mldsa_vector_calls round, unsigned long rounds,
                                   mldsa_vector_calls after) {
    mldsa_vector_calls want = {0, 0, 0, 0};
#if MLD_VECTOR
    want.ntt = rounds * round.ntt + after.ntt;
    want.invntt = rounds * round.invntt + after.invntt;
    want.pointwise = rounds * round.pointwise + after.pointwise;
    want.pointwise_acc = rounds * round.pointwise_acc + after.pointwise_acc;
#else
    (void)round;
    (void)rounds;
    (void)after;
#endif
    return want;
}

static void check_counts(const char *row, uint32_t cpu, mldsa_vector_calls want) {
    const mldsa_vector_calls *got = &mldsa_vector_counted;
    if (got->ntt != want.ntt || got->invntt != want.invntt || got->pointwise != want.pointwise ||
        got->pointwise_acc != want.pointwise_acc) {
        failures++;
        (void)fprintf(stderr,
                      "mldsa runtime: %s under 0x%x made %lu, %lu, %lu and %lu calls into the "
                      "lanes (ntt, invntt, pointwise, pointwise_acc), not %lu, %lu, %lu and %lu\n",
                      row, (unsigned)cpu, got->ntt, got->invntt, got->pointwise, got->pointwise_acc,
                      want.ntt, want.invntt, want.pointwise, want.pointwise_acc);
    }
}

static void check_bytes(const char *row, uint32_t cpu, int same) {
    if (!same) {
        failures++;
        (void)fprintf(stderr,
                      "mldsa runtime: %s under 0x%x wrote other bytes than the call that takes "
                      "no value\n",
                      row, (unsigned)cpu);
    }
}

static uint8_t sk[MLDSA87_SK_LEN];
static uint8_t pk[MLDSA87_PK_LEN];
static uint8_t want_sk[MLDSA87_SK_LEN];
static uint8_t want_pk[MLDSA87_PK_LEN];
static uint8_t sig[MLDSA87_SIG_LEN];
static uint8_t want_mu_sig[MLDSA87_SIG_LEN];
static uint8_t want_sig[MLDSA87_SIG_LEN];

static const uint8_t SEED[MLDSA87_SEED_LEN] = {0x5a, 1, 2, 3};
static const uint8_t RND[MLDSA87_RND_LEN] = {0xa5, 4, 5, 6};
static const uint8_t MU[MLDSA_MU_LEN] = {0x3c, 7, 8, 9};
static const uint8_t MSG[] = "CertificateVerify";

// FIPS 204 Algorithm 7, step 6, over Algorithm 2's M' with an empty
// context: SHAKE256(tr || 0 || 0 || MSG), with tr from sk.
static void message_mu(uint8_t mu[MLDSA_MU_LEN], const uint8_t key[MLDSA87_SK_LEN]) {
    static const uint8_t prefix[2] = {0, 0};
    shake h;
    shake256_init(&h);
    shake_absorb(&h, key + 64, 64);
    shake_absorb(&h, prefix, sizeof prefix);
    shake_absorb(&h, MSG, sizeof MSG);
    shake_squeeze(&h, mu, MLDSA_MU_LEN);
}

// The rows under one value. lanes says whether the signer runs on the
// lanes under it. mu_rounds and msg_rounds are the rounds the signatures
// over MU and over MSG take.
static void rows(uint32_t cpu, unsigned mu_rounds, unsigned msg_rounds, int lanes) {
    unsigned long signer = lanes ? 1 : 0;
    memset(&mldsa_vector_counted, 0, sizeof mldsa_vector_counted);
    int keygen_ok = mldsa87_keygen_cpu(cpu, sk, pk, SEED);
    check_counts("mldsa87_keygen_cpu", cpu, expected(KEYGEN_CALLS, signer, NO_CALLS));
    check_bytes("mldsa87_keygen_cpu", cpu,
                keygen_ok == 1 && memcmp(sk, want_sk, sizeof sk) == 0 &&
                    memcmp(pk, want_pk, sizeof pk) == 0);

    memset(&mldsa_vector_counted, 0, sizeof mldsa_vector_counted);
    unsigned rounds = mldsa87_sign_mu_cpu(cpu, sig, sk, pk, MU, RND);
    check_counts("mldsa87_sign_mu_cpu", cpu,
                 expected(ROUND_CALLS, signer * rounds, CHALLENGE_CALLS));
    check_bytes("mldsa87_sign_mu_cpu", cpu,
                rounds == mu_rounds && memcmp(sig, want_mu_sig, sizeof sig) == 0);

    memset(&mldsa_vector_counted, 0, sizeof mldsa_vector_counted);
    int sign_ok =
        mldsa87_sign_cpu(cpu, sig, sk, sizeof sk, pk, sizeof pk, MSG, sizeof MSG, NULL, 0, RND);
    check_counts("mldsa87_sign_cpu", cpu,
                 expected(ROUND_CALLS, signer * msg_rounds, CHALLENGE_CALLS));
    check_bytes("mldsa87_sign_cpu", cpu, sign_ok == 1 && memcmp(sig, want_sig, sizeof sig) == 0);

    memset(&mldsa_vector_counted, 0, sizeof mldsa_vector_counted);
    int verified = mldsa87_verify(pk, sizeof pk, MSG, sizeof MSG, NULL, 0, sig, sizeof sig);
    check_counts("mldsa87_verify", cpu, expected(NO_CALLS, 0, CHALLENGE_CALLS));
    check_bytes("mldsa87_verify", cpu, verified == 1);
}

int main(void) {
    if (mldsa87_keygen(want_sk, want_pk, SEED) != 1) {
        (void)fprintf(stderr, "mldsa runtime: mldsa87_keygen refused the seed\n");
        return 1;
    }
    unsigned mu_rounds = mldsa87_sign_mu(want_mu_sig, want_sk, want_pk, MU, RND);
    uint8_t msg_mu[MLDSA_MU_LEN];
    message_mu(msg_mu, want_sk);
    unsigned msg_rounds = mldsa87_sign_mu(want_sig, want_sk, want_pk, msg_mu, RND);
    if (mu_rounds == 0 || msg_rounds == 0 ||
        mldsa87_sign(want_sig, want_sk, sizeof want_sk, want_pk, sizeof want_pk, MSG, sizeof MSG,
                     NULL, 0, RND) != 1) {
        (void)fprintf(stderr, "mldsa runtime: the calls that take no value did not sign\n");
        return 1;
    }
    // Every value the defined bits make beside CH_CPU_PROBED.
    uint32_t bits = TEST_CPU_ALL & ~(uint32_t)CH_CPU_PROBED;
    unsigned values = 0;
    uint32_t subset = 0;
    do {
        uint32_t cpu = CH_CPU_PROBED | subset;
        rows(cpu, mu_rounds, msg_rounds, MLD_VECTOR && (cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0);
        values++;
        subset = (subset - bits) & bits;
    } while (subset != 0);
    if (failures != 0) {
        (void)fprintf(stderr, "mldsa runtime: %d row(s) failed\n", failures);
        return 1;
    }
    (void)printf("mldsa runtime: keygen, sign by mu, sign and verify under %u ch_cfg.cpu values, "
                 "%s\n",
                 values,
                 MLD_VECTOR ? "the signer on the lanes under the multiply bit alone and the "
                              "verifier on them under every value"
                            : "no call on the lanes, which this object does not hold");
    return 0;
}
