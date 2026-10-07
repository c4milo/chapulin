// bin/mlkem_avx2_equiv_test: holds keccak_avx2.c and mlkem_avx2.c, an
// x86-64 host object's four-way Keccak and ML-KEM's copy over it, to
// sha3.c and mlkem.c, the code CBMC proves (docs/decisions.md 107). The
// copy is mlkem.c's own text compiled once more but for its row sampler, so
// this binary checks that the sampler reads each entry's stream as
// mlk_sample_ntt reads it and that the two paths write the same bytes.
//
// For random seeds it compares:
//
//   - the four SHAKE128 streams keccak_avx2.c starts, ten blocks of each,
//     the most the row sampler reads, with sha3.c's SHAKE128 over the same
//     34 bytes. Each case gives each state an index pair of its own, drawn
//     at random;
//   - key generation, encapsulation and decapsulation on the copy and on
//     mlkem.c, under each answer a compression runs under (widemul.h): the
//     keys, the ciphertext and the shared secret, the secret a
//     decapsulation recovers, and the one it writes for a ciphertext with
//     one bit changed, which is FIPS 203's implicit rejection;
//   - the three calls a session makes, under a ch_cfg.cpu value with
//     CH_CPU_AVX2 and one without.
//
// The row sampler reads a fourth block of an entry's stream for about one
// entry in a hundred. The binary counts, from sha3.c's streams, the
// entries its cases sample that need one, and fails if none did, so the
// cases run that path.
//
// On another architecture this binary says so and passes. On an x86-64 CPU
// without AVX2 it skips, unless CH_REQUIRE_X86_KERNELS is 1
// (test/x86_kernels_cpu.h), which CI's x86-64 kernel job sets.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mlkem.h"
#include "x86_kernels_cpu.h"

#ifndef CH_CPU_RUNTIME
#error "bin/mlkem_avx2_equiv_test links a host object's ML-KEM sources: -DCH_CPU_RUNTIME"
#endif

#ifndef __x86_64__

int main(void) {
    (void)printf("SKIP mlkem avx2 equivalence: an x86-64 host object alone holds the four-way "
                 "Keccak (keccak_avx2.h)\n");
    return 0;
}

#else

#include "keccak_avx2.h"
#include "mlkem_poly.h"
#include "widemul.h"

#define STREAM_CASES 200
#define KEM_CASES 200
// The most blocks of one stream the row sampler reads: the tenth carries
// the last of mlk_sample_ntt's MLK_SAMPLE_GROUPS groups.
#define STREAM_BLOCKS 10

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
        (void)fprintf(stderr, "mlkem avx2 equivalence: %s differs from the portable path\n", what);
    }
}

static void shake128_entry(shake *s, const uint8_t seed[32], uint8_t x0, uint8_t x1) {
    const uint8_t index[2] = {x0, x1};
    shake128_init(s);
    shake_absorb(s, seed, 32);
    shake_absorb(s, index, 2);
}

// The four streams keccak_avx2.c starts for seed and the index pairs, block
// by block, against sha3.c's.
static void compare_streams(const uint8_t seed[32], const uint8_t x0[4], const uint8_t x1[4]) {
    static uint8_t expected[4][STREAM_BLOCKS * SHAKE128_RATE];
    for (unsigned k = 0; k < 4; k++) {
        shake s;
        shake128_entry(&s, seed, x0[k], x1[k]);
        shake_squeeze(&s, expected[k], sizeof expected[k]);
    }
    keccak_x4 state;
    keccak_avx2_shake128_start(&state, seed, x0, x1);
    for (unsigned block = 0; block < STREAM_BLOCKS; block++) {
        if (block > 0) {
            keccak_avx2_permute(&state);
        }
        for (unsigned k = 0; k < 4; k++) {
            uint8_t got[SHAKE128_RATE];
            keccak_avx2_block(got, &state, k);
            check(memcmp(got, expected[k] + (size_t)block * SHAKE128_RATE, SHAKE128_RATE) == 0,
                  "a block of a four-way SHAKE128 stream");
        }
    }
}

static void stream_cases(void) {
    for (int c = 0; c < STREAM_CASES; c++) {
        uint8_t seed[32];
        uint8_t x0[4];
        uint8_t x1[4];
        rng_bytes(seed, sizeof seed);
        rng_bytes(x0, sizeof x0);
        rng_bytes(x1, sizeof x1);
        compare_streams(seed, x0, x1);
    }
}

// The bytes of the entry's stream mlk_sample_ntt reads: the stream sha3.c
// squeezes, run through mlk_sample_groups one group at a time until the
// entry holds 256 coefficients.
static size_t entry_bytes(const uint8_t seed[32], uint8_t x0, uint8_t x1) {
    shake s;
    mlk_poly p;
    unsigned j = 0;
    size_t read = 0;
    shake128_entry(&s, seed, x0, x1);
    while (j < 256 && read < 3 * (size_t)MLK_SAMPLE_GROUPS) {
        uint8_t group[3];
        shake_squeeze(&s, group, sizeof group);
        j = mlk_sample_groups(&p, j, group, 1);
        read += sizeof group;
    }
    return read;
}

static unsigned long fourth_block_entries = 0;

// Counts the entries of the matrix that seed expands to whose stream the
// sampler reads past three blocks.
static void count_long_entries(const uint8_t seed[32]) {
    for (uint8_t x0 = 0; x0 < 3; x0++) {
        for (uint8_t x1 = 0; x1 < 3; x1++) {
            if (entry_bytes(seed, x0, x1) > 3 * (size_t)SHAKE128_RATE) {
                fourth_block_entries++;
            }
        }
    }
}

// One case's keys, ciphertext and secrets on the copy and on mlkem.c,
// under the answer widemul.
static void compare_kem(uint8_t widemul) {
    uint8_t d[32];
    uint8_t z[32];
    uint8_t m[32];
    rng_bytes(d, sizeof d);
    rng_bytes(z, sizeof z);
    rng_bytes(m, sizeof m);
    static uint8_t ek[MLKEM_EK_LEN];
    static uint8_t dk[MLKEM_DK_LEN];
    static uint8_t ek_avx2[MLKEM_EK_LEN];
    static uint8_t dk_avx2[MLKEM_DK_LEN];
    mlkem_keygen_derand(ek, dk, d, z);
    mlkem_keygen_derand_avx2(ek_avx2, dk_avx2, d, z);
    check(memcmp(ek, ek_avx2, sizeof ek) == 0, "the encapsulation key");
    check(memcmp(dk, dk_avx2, sizeof dk) == 0, "the decapsulation key");
    count_long_entries(ek + MLKEM_EK_LEN - 32);

    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ct_avx2[MLKEM_CT_LEN];
    uint8_t ss[MLKEM_SS_LEN];
    uint8_t ss_avx2[MLKEM_SS_LEN];
    int rc = mlkem_encaps_derand(widemul, ct, ss, ek, m);
    int rc_avx2 = mlkem_encaps_derand_avx2(widemul, ct_avx2, ss_avx2, ek, m);
    check(rc == 0 && rc_avx2 == 0, "the encapsulation's result");
    check(memcmp(ct, ct_avx2, sizeof ct) == 0, "the ciphertext");
    check(memcmp(ss, ss_avx2, sizeof ss) == 0, "the encapsulated secret");

    uint8_t back[MLKEM_SS_LEN];
    uint8_t back_avx2[MLKEM_SS_LEN];
    mlkem_decaps(widemul, back, ct, dk);
    mlkem_decaps_avx2(widemul, back_avx2, ct, dk);
    check(memcmp(back, back_avx2, sizeof back) == 0 && memcmp(back, ss, sizeof back) == 0,
          "the decapsulated secret");

    ct[d[0]] ^= 0x01;
    mlkem_decaps(widemul, back, ct, dk);
    mlkem_decaps_avx2(widemul, back_avx2, ct, dk);
    check(memcmp(back, back_avx2, sizeof back) == 0, "the implicit-reject secret");
}

// The three calls a session makes, under a value with CH_CPU_AVX2 and one
// without, against the calls they are named for.
static void compare_session_calls(void) {
    const uint32_t values[2] = {CH_CPU_PROBED | CH_CPU_AVX2, CH_CPU_PROBED};
    uint8_t d[32];
    uint8_t z[32];
    uint8_t m[32];
    rng_bytes(d, sizeof d);
    rng_bytes(z, sizeof z);
    rng_bytes(m, sizeof m);
    static uint8_t dk[MLKEM_DK_LEN];
    static uint8_t dk_cpu[MLKEM_DK_LEN];
    mlkem_keygen_dk(dk, d, z);
    const uint8_t *ek = dk + 1152;
    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ss[MLKEM_SS_LEN];
    uint8_t back[MLKEM_SS_LEN];
    (void)mlkem_encaps_derand(WIDEMUL_NOT_STATED, ct, ss, ek, m);
    mlkem_decaps(WIDEMUL_NOT_STATED, back, ct, dk);
    for (unsigned v = 0; v < 2; v++) {
        uint8_t ct_cpu[MLKEM_CT_LEN];
        uint8_t ss_cpu[MLKEM_SS_LEN];
        uint8_t back_cpu[MLKEM_SS_LEN];
        mlkem_keygen_dk_cpu(values[v], dk_cpu, d, z);
        check(memcmp(dk, dk_cpu, sizeof dk) == 0, "mlkem_keygen_dk_cpu's key");
        check(mlkem_encaps_derand_cpu(values[v], WIDEMUL_NOT_STATED, ct_cpu, ss_cpu, ek, m) == 0,
              "mlkem_encaps_derand_cpu's result");
        check(memcmp(ct, ct_cpu, sizeof ct) == 0 && memcmp(ss, ss_cpu, sizeof ss) == 0,
              "mlkem_encaps_derand_cpu's ciphertext and secret");
        mlkem_decaps_cpu(values[v], WIDEMUL_NOT_STATED, back_cpu, ct, dk);
        check(memcmp(back, back_cpu, sizeof back) == 0, "mlkem_decaps_cpu's secret");
    }
}

int main(void) {
    if (!x86_cpu_has_avx2()) {
        if (x86_kernels_required()) {
            (void)fprintf(stderr, "mlkem avx2 equivalence: this CPU lacks AVX2, and "
                                  "CH_REQUIRE_X86_KERNELS is 1\n");
            return 1;
        }
        (void)printf("SKIP mlkem avx2 equivalence: this CPU lacks AVX2\n");
        return 0;
    }
    stream_cases();
    for (int c = 0; c < KEM_CASES; c++) {
        compare_kem(WIDEMUL_CONSTANT_TIME);
        compare_kem(WIDEMUL_NOT_STATED);
    }
    compare_session_calls();
    if (fourth_block_entries == 0) {
        failures++;
        (void)fprintf(stderr, "mlkem avx2 equivalence: no case sampled an entry whose stream "
                              "needs a fourth block\n");
    }
    if (failures != 0) {
        (void)fprintf(stderr, "mlkem avx2 equivalence: %d of %lu comparisons differ\n", failures,
                      compared);
        return 1;
    }
    (void)printf("mlkem avx2 equivalence: %lu comparisons agree with sha3.c and mlkem.c, and %lu "
                 "sampled entries needed a fourth block\n",
                 compared, fourth_block_entries);
    return 0;
}

#endif // __x86_64__
