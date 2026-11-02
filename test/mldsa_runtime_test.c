// bin/mldsa_runtime_test: which ML-DSA-87 calls of a host object run on
// mldsa_vector.c's lanes under each ch_cfg.cpu value (docs/decisions.md
// 172 and 174). On arm64 the verifier runs its transforms and products on
// the lanes in every session, and the signer runs them there for a value
// that holds CH_CPU_CONSTANT_TIME_MULTIPLY. On x86-64 both need
// CH_CPU_AVX2 beside that: the verifier runs the lanes for a value that
// holds CH_CPU_AVX2, and the signer for a value that holds both bits. The
// two paths compute the same values, so no output can tell which ran:
// test/mldsa_vector_count.c counts the calls into the lanes instead, and
// runs each on mldsa_poly.c's loop. So the binary runs no AVX2
// instruction, and it gives the same verdict on every CPU.
//
// Every row runs under each value the bits of TEST_CPU_ALL make beside
// CH_CPU_PROBED. Each row must make the count of calls below, entry for
// entry, and write the bytes the call that takes no value writes. "The
// signer's bits" and "the verifier's bits" are the bits named above, and
// lanes_expected states them apart from mldsa_vector.h's mld_vector_runs:
//
//   - mldsa87_keygen_cpu: KEYGEN_CALLS under the signer's bits, and none
//     without them;
//   - mldsa87_sign_mu_cpu: ROUND_CALLS for each round the signature took
//     under the signer's bits, and none without them, then
//     CHALLENGE_CALLS for the check of the signature under the verifier's
//     bits;
//   - mldsa87_sign_cpu: as mldsa87_sign_mu_cpu, with the whole
//     verification's calls, which are CHALLENGE_CALLS, after the rounds.
//     Its rounds are the rounds mldsa87_sign_mu takes for the message's
//     mu, which the test computes as FIPS 204 Algorithm 7, step 6 does;
//   - mldsa87_verify_cpu: CHALLENGE_CALLS under the verifier's bits;
//   - mldsa87_verify, which takes no value and so passes 0:
//     CHALLENGE_CALLS on arm64, and none on x86-64.
//
// So a dispatcher that reads another bit fails under the values that hold
// one bit and not the other, a step left on the loops fails its count, and
// a call that runs the lanes without its bits fails under the values
// without them.
//
// The same rows count the calls into mldsa_avx2.c's four-way sampler of
// A (test/mldsa_avx2_count.h, docs/decisions.md 178). On x86-64 every row
// of A runs there for a value that holds CH_CPU_AVX2, the signer's and
// the verifier's alike, because A is public: two calls a row, which
// sample four entries and then three. So key generation makes
// AVX2_ROW_CALLS, each round of a signature as many, and each
// verification as many, and a value without the bit makes none. On arm64
// no call runs there.
//
// The same rows count the SHAKE calls (test/mldsa_sha3_count.h). Under
// CH_CPU_PROBED alone each row makes its calls on sha3.c, and their counts
// are the row's reference. In an arm64 host object that clang compiled, a
// value that holds CH_CPU_CONSTANT_TIME_SHA3 must make every one of them
// on the path of sha3_hw.c and none on sha3.c, and a value without it must
// make them all on sha3.c. In every other object, and for mldsa87_verify,
// which takes no value, every call runs on sha3.c. So a hash left on
// sha3.c under the bit fails its count, and so does a hash that reads
// another bit (docs/decisions.md 173).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "mldsa.h"
#include "mldsa_avx2_count.h"
#include "mldsa_poly.h"
#include "mldsa_sha3_count.h"
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

// The calls into the four-way sampler for the eight rows of A, and the
// entries they sample.
static const mldsa_avx2_calls AVX2_ROW_CALLS = {2UL * MLD_K, (unsigned long)MLD_K * MLD_L};

static int failures;

// Whether a row of A runs on the four-way sampler for cpu, written apart
// from the callers' own test.
static unsigned long avx2_expected(uint32_t cpu) {
#ifdef __x86_64__
    return (cpu & CH_CPU_AVX2) != 0;
#else
    (void)cpu;
    return 0;
#endif
}

// rows times each count of AVX2_ROW_CALLS.
static void check_avx2(const char *row, uint32_t cpu, unsigned long rows) {
    const mldsa_avx2_calls *got = &mldsa_avx2_counted;
    unsigned long calls = rows * AVX2_ROW_CALLS.calls;
    unsigned long entries = rows * AVX2_ROW_CALLS.entries;
    if (got->calls != calls || got->entries != entries) {
        failures++;
        (void)fprintf(stderr,
                      "mldsa runtime: %s under 0x%x made %lu calls into the four-way sampler for "
                      "%lu entries of A, not %lu for %lu\n",
                      row, (unsigned)cpu, got->calls, got->entries, calls, entries);
    }
}

// Whether a call runs the lanes for cpu: this test's own statement of the
// bits each needs, written apart from mld_vector_runs so that a wrong test
// there fails a row. secret is 1 for the signer and 0 for the verifier.
static int lanes_expected(uint32_t cpu, int secret) {
#if !MLD_VECTOR
    (void)cpu;
    (void)secret;
    return 0;
#else
#ifdef __x86_64__
    if ((cpu & CH_CPU_AVX2) == 0) {
        return 0;
    }
#endif
    return !secret || (cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0;
#endif
}

// rounds times each count of round, plus afters times each count of
// after.
static mldsa_vector_calls expected(mldsa_vector_calls round, unsigned long rounds,
                                   mldsa_vector_calls after, unsigned long afters) {
    mldsa_vector_calls want;
    want.ntt = rounds * round.ntt + afters * after.ntt;
    want.invntt = rounds * round.invntt + afters * after.invntt;
    want.pointwise = rounds * round.pointwise + afters * after.pointwise;
    want.pointwise_acc = rounds * round.pointwise_acc + afters * after.pointwise_acc;
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

// The rows whose SHAKE counts are recorded under CH_CPU_PROBED alone.
enum { ROW_KEYGEN, ROW_SIGN_MU, ROW_SIGN, ROW_VERIFY_CPU, ROW_VERIFY, ROW_COUNT };
static mldsa_sha3_calls sha3_reference[ROW_COUNT];

static void reset_counts(void) {
    memset(&mldsa_vector_counted, 0, sizeof mldsa_vector_counted);
    memset(&mldsa_sha3_counted, 0, sizeof mldsa_sha3_counted);
    memset(&mldsa_avx2_counted, 0, sizeof mldsa_avx2_counted);
}

// The reference under CH_CPU_PROBED; under every other value, the
// reference's calls on the path takes_value names for this cpu.
static void check_sha3(const char *row, unsigned at, uint32_t cpu, int takes_value) {
    const mldsa_sha3_calls *got = &mldsa_sha3_counted;
    if (cpu == CH_CPU_PROBED) {
        sha3_reference[at] = *got;
    }
    const mldsa_sha3_calls *ref = &sha3_reference[at];
    mldsa_sha3_calls want = {ref->absorb, ref->squeeze, 0, 0};
#ifdef CH_KECCAK_INSTRUCTIONS
    if (takes_value && (cpu & CH_CPU_CONSTANT_TIME_SHA3) != 0) {
        want = (mldsa_sha3_calls){0, 0, ref->absorb, ref->squeeze};
    }
#else
    (void)takes_value;
#endif
    if (ref->absorb == 0 || ref->squeeze == 0 || ref->absorb_hw != 0 || ref->squeeze_hw != 0 ||
        got->absorb != want.absorb || got->squeeze != want.squeeze ||
        got->absorb_hw != want.absorb_hw || got->squeeze_hw != want.squeeze_hw) {
        failures++;
        (void)fprintf(stderr,
                      "mldsa runtime: %s under 0x%x made %lu and %lu SHAKE calls on sha3.c and "
                      "%lu and %lu on the instructions' path (absorb, squeeze), not %lu, %lu, %lu "
                      "and %lu\n",
                      row, (unsigned)cpu, got->absorb, got->squeeze, got->absorb_hw,
                      got->squeeze_hw, want.absorb, want.squeeze, want.absorb_hw, want.squeeze_hw);
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

// The rows under one value. mu_rounds and msg_rounds are the rounds the
// signatures over MU and over MSG take.
static void rows(uint32_t cpu, unsigned mu_rounds, unsigned msg_rounds) {
    unsigned long signer = (unsigned long)lanes_expected(cpu, 1);
    unsigned long verifier = (unsigned long)lanes_expected(cpu, 0);
    unsigned long no_value = (unsigned long)lanes_expected(0, 0);
    unsigned long avx2 = avx2_expected(cpu);
    reset_counts();
    int keygen_ok = mldsa87_keygen_cpu(cpu, sk, pk, SEED);
    check_counts("mldsa87_keygen_cpu", cpu, expected(KEYGEN_CALLS, signer, NO_CALLS, 0));
    check_avx2("mldsa87_keygen_cpu", cpu, avx2);
    check_sha3("mldsa87_keygen_cpu", ROW_KEYGEN, cpu, 1);
    check_bytes("mldsa87_keygen_cpu", cpu,
                keygen_ok == 1 && memcmp(sk, want_sk, sizeof sk) == 0 &&
                    memcmp(pk, want_pk, sizeof pk) == 0);

    reset_counts();
    unsigned rounds = mldsa87_sign_mu_cpu(cpu, sig, sk, pk, MU, RND);
    check_counts("mldsa87_sign_mu_cpu", cpu,
                 expected(ROUND_CALLS, signer * rounds, CHALLENGE_CALLS, verifier));
    check_avx2("mldsa87_sign_mu_cpu", cpu, avx2 * (rounds + 1UL));
    check_sha3("mldsa87_sign_mu_cpu", ROW_SIGN_MU, cpu, 1);
    check_bytes("mldsa87_sign_mu_cpu", cpu,
                rounds == mu_rounds && memcmp(sig, want_mu_sig, sizeof sig) == 0);

    reset_counts();
    int sign_ok =
        mldsa87_sign_cpu(cpu, sig, sk, sizeof sk, pk, sizeof pk, MSG, sizeof MSG, NULL, 0, RND);
    check_counts("mldsa87_sign_cpu", cpu,
                 expected(ROUND_CALLS, signer * msg_rounds, CHALLENGE_CALLS, verifier));
    check_avx2("mldsa87_sign_cpu", cpu, avx2 * (msg_rounds + 1UL));
    check_sha3("mldsa87_sign_cpu", ROW_SIGN, cpu, 1);
    check_bytes("mldsa87_sign_cpu", cpu, sign_ok == 1 && memcmp(sig, want_sig, sizeof sig) == 0);

    reset_counts();
    int verified_cpu =
        mldsa87_verify_cpu(cpu, pk, sizeof pk, MSG, sizeof MSG, NULL, 0, sig, sizeof sig);
    check_counts("mldsa87_verify_cpu", cpu, expected(NO_CALLS, 0, CHALLENGE_CALLS, verifier));
    check_avx2("mldsa87_verify_cpu", cpu, avx2);
    check_sha3("mldsa87_verify_cpu", ROW_VERIFY_CPU, cpu, 1);
    check_bytes("mldsa87_verify_cpu", cpu, verified_cpu == 1);

    reset_counts();
    int verified = mldsa87_verify(pk, sizeof pk, MSG, sizeof MSG, NULL, 0, sig, sizeof sig);
    check_counts("mldsa87_verify", cpu, expected(NO_CALLS, 0, CHALLENGE_CALLS, no_value));
    check_avx2("mldsa87_verify", cpu, 0);
    check_sha3("mldsa87_verify", ROW_VERIFY, cpu, 0);
    check_bytes("mldsa87_verify", cpu, verified == 1);
}

// What a passing run says about the lanes.
#if !MLD_VECTOR
#define LANES_SUMMARY "no call on the lanes, which this object does not hold"
#elif defined(__x86_64__)
#define LANES_SUMMARY                                                                              \
    "the signer on the lanes under CH_CPU_AVX2 and the multiply bit alone, and the verifier on "   \
    "them under CH_CPU_AVX2 alone"
#else
#define LANES_SUMMARY                                                                              \
    "the signer on the lanes under the multiply bit alone and the verifier on them under every "   \
    "value"
#endif

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
        rows(cpu, mu_rounds, msg_rounds);
        values++;
        subset = (subset - bits) & bits;
    } while (subset != 0);
    if (failures != 0) {
        (void)fprintf(stderr, "mldsa runtime: %d row(s) failed\n", failures);
        return 1;
    }
    (void)printf("mldsa runtime: keygen, sign by mu, sign and verify under %u ch_cfg.cpu values, "
                 "each SHAKE call on the path the SHA-3 bit names, and %s\n",
                 values, LANES_SUMMARY);
    return 0;
}
