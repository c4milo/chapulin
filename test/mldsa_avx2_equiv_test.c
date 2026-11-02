// bin/mldsa_avx2_equiv_test: holds mldsa_avx2.c, an x86-64 host object's
// four-way sampler of ML-DSA-87's matrix A, to mld_sample_ntt, the code
// CBMC proves (docs/decisions.md 178). bin/mlkem_avx2_equiv_test holds the
// four-way Keccak under it to sha3.c.
//
// For random seeds rho it compares:
//
//   - each entry mld_sample_ntt_avx2 samples, for every row i, every first
//     entry and every count a call takes, with the entry mld_sample_ntt
//     samples, coefficient for coefficient, and the two results;
//   - mldsa87_keygen_cpu, mldsa87_sign_cpu and mldsa87_verify_cpu under
//     each value the bits CH_CPU_AVX2 and CH_CPU_CONSTANT_TIME_MULTIPLY
//     make beside CH_CPU_PROBED, with the calls that take no value: the
//     keys, the signature, the verdict, and the verdict on the signature
//     with one bit changed.
//
// Four SHAKE128 blocks hold 224 groups, fewer than 256, so every entry
// reads a fifth block, and the loop that permutes the four states runs
// in every call. An entry needs a sixth block when more than 24 of its
// 280 groups fall at or above q, which is far too rare for a test to
// reach: no case here reads one.
//
// On another architecture this binary says so and passes. On an x86-64 CPU
// without AVX2 it skips, unless CH_REQUIRE_X86_KERNELS is 1
// (test/x86_kernels_cpu.h), which CI's x86-64 kernel job sets.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "x86_kernels_cpu.h"

#if !defined(CH_CPU_RUNTIME) || !defined(CH_MLDSA_SIGN_TEST)
#error                                                                                             \
    "bin/mldsa_avx2_equiv_test links a host object's signer: -DCH_CPU_RUNTIME -DCH_MLDSA_SIGN_TEST"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#ifndef __x86_64__

int main(void) {
    (void)printf("SKIP mldsa avx2 equivalence: an x86-64 host object alone holds the four-way "
                 "sampler (mldsa_avx2.h)\n");
    return 0;
}

#else

#include "mldsa.h"
#include "mldsa_avx2.h"
#include "mldsa_poly.h"
#include "mldsa_signer.h"

#define SAMPLE_CASES 40
#define SIGN_CASES 8

// xorshift64 from a fixed seed, so a run replays the same cases.
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static void rng_bytes(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        out[i] = (uint8_t)(rng_state >> 32);
    }
}

static int failures = 0;
static unsigned long compared = 0;

static void check(int same, const char *what) {
    compared++;
    if (!same) {
        failures++;
        (void)fprintf(stderr, "mldsa avx2 equivalence: %s differs from the portable path\n", what);
    }
}

// Every call the callers can make for row i of the matrix rho expands to.
static void compare_row(const uint8_t rho[MLD_RHO_BYTES], unsigned i) {
    for (unsigned first = 0; first < MLD_L; first++) {
        unsigned most = MLD_L - first < MLD_AVX2_ENTRIES ? MLD_L - first : MLD_AVX2_ENTRIES;
        for (unsigned count = 1; count <= most; count++) {
            mld_poly four[MLD_AVX2_ENTRIES];
            int sampled = mld_sample_ntt_avx2(four, rho, i, first, count);
            check(sampled == 1, "mld_sample_ntt_avx2's result");
            for (unsigned k = 0; k < count; k++) {
                mld_poly want;
                int want_sampled = mld_sample_ntt(&want, rho, (uint8_t)(first + k), (uint8_t)i);
                check(want_sampled == 1 && memcmp(&want, &four[k], sizeof want) == 0,
                      "an entry of A");
            }
        }
    }
}

static void sample_cases(void) {
    for (int c = 0; c < SAMPLE_CASES; c++) {
        uint8_t rho[MLD_RHO_BYTES];
        rng_bytes(rho, sizeof rho);
        for (unsigned i = 0; i < MLD_K; i++) {
            compare_row(rho, i);
        }
    }
}

static uint8_t sk[MLDSA87_SK_LEN];
static uint8_t pk[MLDSA87_PK_LEN];
static uint8_t sk_cpu[MLDSA87_SK_LEN];
static uint8_t pk_cpu[MLDSA87_PK_LEN];
static uint8_t sig[MLDSA87_SIG_LEN];
static uint8_t sig_cpu[MLDSA87_SIG_LEN];

// One key, one signature and its verification under cpu, against the
// calls that take no value.
static void compare_calls(uint32_t cpu, const uint8_t seed[MLDSA87_SEED_LEN],
                          const uint8_t rnd[MLDSA87_RND_LEN], const uint8_t msg[32]) {
    check(mldsa87_keygen(sk, pk, seed) == 1 && mldsa87_keygen_cpu(cpu, sk_cpu, pk_cpu, seed) == 1,
          "the key generation's result");
    check(memcmp(sk, sk_cpu, sizeof sk) == 0 && memcmp(pk, pk_cpu, sizeof pk) == 0, "the keys");
    check(mldsa87_sign(sig, sk, sizeof sk, pk, sizeof pk, msg, 32, NULL, 0, rnd) == 1 &&
              mldsa87_sign_cpu(cpu, sig_cpu, sk, sizeof sk, pk, sizeof pk, msg, 32, NULL, 0, rnd) ==
                  1,
          "the signature's result");
    check(memcmp(sig, sig_cpu, sizeof sig) == 0, "the signature");
    check(mldsa87_verify_cpu(cpu, pk, sizeof pk, msg, 32, NULL, 0, sig, sizeof sig) == 1,
          "the verdict on the signature");
    sig[msg[0] % MLDSA87_SIG_LEN] ^= 0x01;
    check(mldsa87_verify_cpu(cpu, pk, sizeof pk, msg, 32, NULL, 0, sig, sizeof sig) == 0,
          "the verdict on a changed signature");
}

static void sign_cases(void) {
    const uint32_t values[4] = {
        CH_CPU_PROBED | CH_CPU_AVX2 | CH_CPU_CONSTANT_TIME_MULTIPLY,
        CH_CPU_PROBED | CH_CPU_AVX2,
        CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY,
        CH_CPU_PROBED,
    };
    for (int c = 0; c < SIGN_CASES; c++) {
        uint8_t seed[MLDSA87_SEED_LEN];
        uint8_t rnd[MLDSA87_RND_LEN];
        uint8_t msg[32];
        rng_bytes(seed, sizeof seed);
        rng_bytes(rnd, sizeof rnd);
        rng_bytes(msg, sizeof msg);
        for (unsigned v = 0; v < 4; v++) {
            compare_calls(values[v], seed, rnd, msg);
        }
    }
}

int main(void) {
    if (!x86_cpu_has_avx2()) {
        if (x86_kernels_required()) {
            (void)fprintf(stderr, "mldsa avx2 equivalence: this CPU lacks AVX2, and "
                                  "CH_REQUIRE_X86_KERNELS is 1\n");
            return 1;
        }
        (void)printf("SKIP mldsa avx2 equivalence: this CPU lacks AVX2\n");
        return 0;
    }
    sample_cases();
    sign_cases();
    if (failures != 0) {
        (void)fprintf(stderr, "mldsa avx2 equivalence: %d of %lu comparisons differ\n", failures,
                      compared);
        return 1;
    }
    (void)printf("mldsa avx2 equivalence: %lu comparisons of the four-way sampler, the keys, the "
                 "signatures and the verdicts match the portable path\n",
                 compared);
    return 0;
}

#endif // __x86_64__
