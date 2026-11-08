// bin/keccak_neon_equiv_test: holds keccak_neon.c, an arm64 host object's two-way Keccak, and
// the two samplers over it, mlkem_neon.c and mldsa_neon.c, to sha3.c, mlk_sample_ntt and
// mld_sample_ntt, the code CBMC proves (docs/decisions.md 198). It runs each check once for
// each form of the permutation: plain NEON, and the form on the SHA-3 instructions where the
// object holds it (CH_KECCAK_INSTRUCTIONS) and the CPU has them.
//
// For random seeds it compares:
//
//   - the two SHAKE128 streams keccak_neon.c starts, ten blocks of each, the most a sampler
//     reads, with sha3.c's SHAKE128 over the same 34 bytes. Each case gives each state an
//     index pair of its own, drawn at random;
//   - the two forms of the permutation on two states of random lanes, all 25 lanes of each;
//   - each pair of entries mlk_sample_pair_neon samples, for each row and each first entry of
//     ML-KEM-768's and ML-KEM-1024's matrices and of their transposes, with mlk_sample_ntt's;
//   - each entry mld_sample_ntt_neon samples, one or two a call, for each row and each first
//     entry of ML-DSA-87's A, with mld_sample_ntt's, and the result each call returns.
//
// ML-KEM's sampler reads a fourth block of an entry's stream for about one entry in a hundred.
// The binary counts the entries its cases sample that need one, and fails if none did, so the
// cases run that path.
//
// On another architecture this binary says so and passes. On a CPU without the SHA-3
// instructions it runs the plain form alone, unless CH_REQUIRE_HASH_INSTRUCTIONS is 1
// (test/hash_instructions_cpu.h).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash_instructions_cpu.h"
#include "sha3.h"

#ifndef CH_CPU_RUNTIME
#error "bin/keccak_neon_equiv_test links a host object's Keccak sources: -DCH_CPU_RUNTIME"
#endif

#ifndef __aarch64__

int main(void) {
    (void)printf("SKIP keccak neon equivalence: an arm64 host object alone holds the two-way "
                 "Keccak (keccak_neon.h)\n");
    return 0;
}

#else

#include "keccak_neon.h"
#include "mldsa_neon.h"
#include "mldsa_poly.h"
#include "mlkem_neon.h"
#include "mlkem_poly.h"

#define STREAM_CASES 200
#define SAMPLE_CASES 40
// The most blocks of one stream a sampler reads: the tenth carries the last of
// mlk_sample_ntt's MLK_SAMPLE_GROUPS groups, and MLD_SAMPLE_BLOCKS is smaller.
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

static void check(int same, const char *what, uint32_t cpu) {
    compared++;
    if (!same) {
        failures++;
        (void)fprintf(stderr,
                      "keccak neon equivalence: %s differs from the portable path, "
                      "ch_cfg.cpu 0x%x\n",
                      what, (unsigned)cpu);
    }
}

static void shake128_entry(shake *s, const uint8_t seed[32], uint8_t x0, uint8_t x1) {
    const uint8_t index[2] = {x0, x1};
    shake128_init(s);
    shake_absorb(s, seed, 32);
    shake_absorb(s, index, 2);
}

// The two streams keccak_neon.c starts for seed and the index pairs, block by block, against
// sha3.c's.
static void compare_streams(uint32_t cpu, const uint8_t seed[32], const uint8_t x0[2],
                            const uint8_t x1[2]) {
    static uint8_t expected[2][STREAM_BLOCKS * SHAKE128_RATE];
    for (unsigned k = 0; k < 2; k++) {
        shake s;
        shake128_entry(&s, seed, x0[k], x1[k]);
        shake_squeeze(&s, expected[k], sizeof expected[k]);
    }
    keccak_x2 state;
    keccak_neon_shake128_start(&state, seed, x0, x1, cpu);
    for (unsigned block = 0; block < STREAM_BLOCKS; block++) {
        if (block > 0) {
            keccak_neon_permute_cpu(&state, cpu);
        }
        for (unsigned k = 0; k < 2; k++) {
            uint8_t got[SHAKE128_RATE];
            keccak_neon_block(got, &state, k);
            check(memcmp(got, expected[k] + (size_t)block * SHAKE128_RATE, SHAKE128_RATE) == 0,
                  "a block of a two-way SHAKE128 stream", cpu);
        }
    }
}

static void stream_cases(uint32_t cpu) {
    for (int c = 0; c < STREAM_CASES; c++) {
        uint8_t seed[32];
        uint8_t x0[2];
        uint8_t x1[2];
        rng_bytes(seed, sizeof seed);
        rng_bytes(x0, sizeof x0);
        rng_bytes(x1, sizeof x1);
        compare_streams(cpu, seed, x0, x1);
    }
}

// The two forms on the same two states of random lanes. A stream reads the 21 lanes of the
// rate, so this compares the four lanes of the capacity as well.
static void compare_forms(void) {
#ifdef CH_KECCAK_INSTRUCTIONS
    for (int c = 0; c < STREAM_CASES; c++) {
        keccak_x2 plain;
        rng_bytes((uint8_t *)(void *)plain.lane, sizeof plain.lane);
        keccak_x2 sha3 = plain;
        keccak_neon_permute(&plain);
        keccak_neon_permute_sha3(&sha3);
        check(memcmp(plain.lane, sha3.lane, sizeof plain.lane) == 0,
              "a permutation on the SHA-3 instructions", CH_CPU_CONSTANT_TIME_SHA3);
    }
#endif
}

static unsigned long fourth_block_entries = 0;

// The bytes of an entry's stream mlk_sample_ntt reads: the stream sha3.c squeezes, run through
// mlk_sample_groups one group at a time until the entry holds 256 coefficients.
static size_t mlk_entry_bytes(const uint8_t seed[32], uint8_t x0, uint8_t x1) {
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

// The pair of entries first and first + 1 of row i of the matrix seed expands to, or of its
// transpose.
static void compare_mlkem_pair(uint32_t cpu, const uint8_t seed[32], unsigned i, int transposed,
                               unsigned first) {
    mlk_poly got[MLK_NEON_ENTRIES];
    mlk_sample_pair_neon(got, seed, i, transposed, first, cpu);
    for (unsigned k = 0; k < MLK_NEON_ENTRIES; k++) {
        uint8_t x0 = transposed ? (uint8_t)i : (uint8_t)(first + k);
        uint8_t x1 = transposed ? (uint8_t)(first + k) : (uint8_t)i;
        mlk_poly want;
        mlk_sample_ntt(&want, seed, x0, x1);
        check(memcmp(&got[k], &want, sizeof want) == 0, "an entry of ML-KEM's matrix", cpu);
        if (cpu == 0 && transposed == 0 && first == 0 &&
            mlk_entry_bytes(seed, x0, x1) > 3 * (size_t)SHAKE128_RATE) {
            fourth_block_entries++;
        }
    }
}

// Each pair of entries of the rank x rank matrix that seed expands to, and of its transpose.
static void compare_mlkem(uint32_t cpu, const uint8_t seed[32], unsigned rank) {
    for (unsigned i = 0; i < rank; i++) {
        for (int transposed = 0; transposed < 2; transposed++) {
            for (unsigned first = 0; first + MLK_NEON_ENTRIES <= rank; first++) {
                compare_mlkem_pair(cpu, seed, i, transposed, first);
            }
        }
    }
}

// Each entry of A that seed expands to, sampled one or two a call.
static void compare_mldsa(uint32_t cpu, const uint8_t rho[MLD_RHO_BYTES]) {
    for (unsigned i = 0; i < MLD_K; i++) {
        for (unsigned first = 0; first < MLD_L; first++) {
            for (unsigned count = 1; count <= MLD_NEON_ENTRIES && first + count <= MLD_L; count++) {
                mld_poly got[MLD_NEON_ENTRIES];
                int ok = mld_sample_ntt_neon(cpu, got, rho, i, first, count);
                int want_ok = 1;
                for (unsigned k = 0; k < count; k++) {
                    mld_poly want;
                    want_ok &= mld_sample_ntt(&want, rho, (uint8_t)(first + k), (uint8_t)i);
                    check(memcmp(&got[k], &want, sizeof want) == 0, "an entry of ML-DSA-87's A",
                          cpu);
                }
                check(ok == want_ok, "the result of mld_sample_ntt_neon", cpu);
            }
        }
    }
}

static void sample_cases(uint32_t cpu) {
    for (int c = 0; c < SAMPLE_CASES; c++) {
        uint8_t seed[32];
        rng_bytes(seed, sizeof seed);
        compare_mlkem(cpu, seed, 3);
        compare_mlkem(cpu, seed, 4);
        compare_mldsa(cpu, seed);
    }
}

static void run_form(uint32_t cpu) {
    stream_cases(cpu);
    sample_cases(cpu);
}

// Whether the SHA-3 form runs here. 1 where it does, 0 where the binary skips it, and -1 where
// it must run and cannot.
static int sha3_form_runs(void) {
#ifdef CH_KECCAK_INSTRUCTIONS
    if (cpu_has_sha3_instructions()) {
        return 1;
    }
#endif
    return hash_instructions_required() ? -1 : 0;
}

int main(void) {
    int sha3 = sha3_form_runs();
    if (sha3 < 0) {
        (void)fprintf(stderr, "keccak neon equivalence: the SHA-3 form cannot run here, and "
                              "CH_REQUIRE_HASH_INSTRUCTIONS is 1\n");
        return 1;
    }
    run_form(0);
    if (sha3 == 1) {
        run_form(CH_CPU_CONSTANT_TIME_SHA3);
        compare_forms();
    } else {
        (void)printf("SKIP keccak neon equivalence: the form on the SHA-3 instructions, which "
                     "this object or this CPU lacks\n");
    }
    if (fourth_block_entries == 0) {
        failures++;
        (void)fprintf(stderr, "keccak neon equivalence: no ML-KEM entry read a fourth block\n");
    }
    if (failures != 0) {
        (void)fprintf(stderr, "keccak neon equivalence: %d failure(s)\n", failures);
        return 1;
    }
    (void)printf("keccak neon equivalence: %lu values agree with sha3.c, mlk_sample_ntt and "
                 "mld_sample_ntt, %lu ML-KEM entries read a fourth block\n",
                 compared, fourth_block_entries);
    return 0;
}

#endif // __aarch64__
