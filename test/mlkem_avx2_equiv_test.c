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
//     CH_CPU_AVX2 and one without;
//   - the rejection step on AVX2, mlk_sample_groups_avx2, with
//     mlk_sample_groups (docs/decisions.md 225): the count and the
//     coefficients below it, for every pattern of kept and dropped
//     candidates in each half of a step of eight groups, candidates at
//     0, 1, q - 2, q - 1, q, q + 1, 4094 and 4095, from counts on both
//     sides of 240, the last count at which a step runs, and on counts
//     of groups that leave a tail; then random blocks. It also computes
//     each entry of mlkem_rejection_table.h by the rule the header states;
//   - ByteDecode12 on AVX2, mlk_poly_frombytes_avx2, with
//     mlk_poly_frombytes on random bytes and on bytes of one value, each
//     of the 256 (docs/decisions.md 232);
//   - the modulus check on AVX2, mlk_field_at_or_above_q_avx2, through
//     the copy's encapsulation, against mlkem.c's: at each of the 768
//     fields of an ek's t-hat in turn, with the field at q - 1, which
//     both take, and at q, q + 1 and 4095, which both refuse.
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
#include "mlkem_rejection_table.h"
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

// Candidates on each side of q: the two lowest and the two highest kept,
// and the two lowest and the two highest dropped.
static const uint16_t KEPT[] = {0, 1, MLKEM_Q - 2, MLKEM_Q - 1};
static const uint16_t DROPPED[] = {MLKEM_Q, MLKEM_Q + 1, 4094, 4095};

// Group g of buf with the candidates d1 and d2, as mlk_sample_groups reads
// them.
static void put_group(uint8_t *buf, size_t g, uint16_t d1, uint16_t d2) {
    buf[3 * g] = (uint8_t)d1;
    buf[3 * g + 1] = (uint8_t)((d1 >> 8) | ((d2 & 0x0f) << 4));
    buf[3 * g + 2] = (uint8_t)(d2 >> 4);
}

// A candidate kept where keep is 1 and dropped where it is 0, of the four
// on that side.
static uint16_t candidate(unsigned keep) {
    uint8_t draw;
    rng_bytes(&draw, 1);
    return keep ? KEPT[draw & 3] : DROPPED[draw & 3];
}

// mlk_sample_groups_avx2 against mlk_sample_groups on groups groups at buf
// from the count j: the same count, and the same coefficients below it,
// which holds the ones below j that neither may write.
static void compare_rejection(const uint8_t *buf, size_t groups, unsigned j) {
    mlk_poly portable;
    mlk_poly vector;
    rng_bytes((uint8_t *)portable.coeffs, sizeof portable.coeffs);
    vector = portable;
    unsigned count = mlk_sample_groups(&portable, j, buf, groups);
    unsigned count_avx2 = mlk_sample_groups_avx2(&vector, j, buf, groups);
    check(count == count_avx2 &&
              memcmp(portable.coeffs, vector.coeffs, sizeof portable.coeffs[0] * count) == 0,
          "the rejection step on AVX2");
}

// The first count at which the AVX2 step stops, MLKEM_N - 16 + 1, is the
// boundary: 240 runs a step of eight groups and 241 none.
#define START_CASES 13
static const unsigned STARTS[START_CASES] = {0,   1,   2,   100, 224, 239, 240,
                                             241, 247, 248, 249, 255, 256};
#define GROUP_CASES 11
static const size_t GROUP_COUNTS[GROUP_CASES] = {0, 1, 7, 8, 9, 15, 16, 17, 48, 55, 56};

// Every pattern of kept and dropped candidates in each half of a step: the
// first half of step s of mask m keeps candidate k where bit k of m is set,
// and the second half where bit k of m + 37 s + 101 is, so each mask meets
// many others in one step. Each pattern runs from every count in STARTS on
// every count of groups in GROUP_COUNTS. Then random blocks of 56 groups,
// as the row sampler hands over, from random counts.
static void rejection_cases(void) {
    static uint8_t buf[3 * 56];
    for (unsigned mask = 0; mask < 256; mask++) {
        for (size_t step = 0; step < 7; step++) {
            unsigned first = mask;
            unsigned second = (mask + 37 * (unsigned)step + 101) & 0xffU;
            for (unsigned k = 0; k < 4; k++) {
                put_group(buf, 8 * step + k, candidate((first >> (2 * k)) & 1),
                          candidate((first >> (2 * k + 1)) & 1));
                put_group(buf, 8 * step + 4 + k, candidate((second >> (2 * k)) & 1),
                          candidate((second >> (2 * k + 1)) & 1));
            }
        }
        for (size_t s = 0; s < START_CASES; s++) {
            for (size_t g = 0; g < GROUP_CASES; g++) {
                compare_rejection(buf, GROUP_COUNTS[g], STARTS[s]);
            }
        }
    }
    for (int c = 0; c < 4000; c++) {
        uint8_t start;
        rng_bytes(buf, sizeof buf);
        rng_bytes(&start, 1);
        compare_rejection(buf, 56, start);
    }
}

// Each entry of mlkem_rejection_table.h against the rule its comment
// states: the bytes 2k and 2k + 1 of each kept candidate k in turn, then
// 0x80, and the count of set bits.
static void table_cases(void) {
    for (unsigned mask = 0; mask < 256; mask++) {
        uint8_t order[16];
        size_t kept = 0;
        memset(order, 0x80, sizeof order);
        for (unsigned k = 0; k < 8; k++) {
            if ((mask >> k) & 1U) {
                order[2 * kept] = (uint8_t)(2 * k);
                order[2 * kept + 1] = (uint8_t)(2 * k + 1);
                kept++;
            }
        }
        check(memcmp(order, MLK_REJECTION_ORDER[mask], sizeof order) == 0 &&
                  kept == MLK_REJECTION_COUNT[mask],
              "an entry of mlkem_rejection_table.h");
    }
}

// mlk_poly_frombytes_avx2 against mlk_poly_frombytes: random bytes, and
// bytes of one value, each of the 256, so every field holds each value its
// bytes can spell in each of its two places.
static void frombytes_cases(void) {
    uint8_t bytes[MLK_POLY_BYTES];
    for (int c = 0; c < 1000 + 256; c++) {
        if (c < 1000) {
            rng_bytes(bytes, sizeof bytes);
        } else {
            memset(bytes, c - 1000, sizeof bytes);
        }
        mlk_poly portable;
        mlk_poly vector;
        mlk_poly_frombytes(&portable, bytes);
        mlk_poly_frombytes_avx2(&vector, bytes);
        check(memcmp(&portable, &vector, sizeof portable) == 0, "ByteDecode12 on AVX2");
    }
}

// Field second of the three bytes at group set to value, as ByteDecode12
// reads it: the first field from byte 0 and the low half of byte 1, and
// the second from the high half of byte 1 and byte 2.
static void put_field(uint8_t group[3], int second, uint16_t value) {
    if (!second) {
        group[0] = (uint8_t)value;
        group[1] = (uint8_t)((group[1] & 0xf0) | (value >> 8));
    } else {
        group[1] = (uint8_t)((group[1] & 0x0f) | ((value & 0x0f) << 4));
        group[2] = (uint8_t)(value >> 4);
    }
}

// The copy's modulus check against mlkem.c's, through the encapsulation
// each runs it in: at each field of t-hat, q - 1 is taken and q, q + 1
// and 4095 are refused by both, so the boundary sits at q on AVX2 too.
static void modulus_check_cases(void) {
    uint8_t d[32];
    uint8_t z[32];
    uint8_t m[32];
    rng_bytes(d, sizeof d);
    rng_bytes(z, sizeof z);
    rng_bytes(m, sizeof m);
    static uint8_t ek[MLKEM_EK_LEN];
    static uint8_t dk[MLKEM_DK_LEN];
    mlkem_keygen_derand(ek, dk, d, z);
    static const uint16_t values[4] = {MLKEM_Q - 1, MLKEM_Q, MLKEM_Q + 1, 4095};
    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ss[MLKEM_SS_LEN];
    for (size_t at = 0; at < (size_t)MLKEM_K * MLK_POLY_BYTES; at += 3) {
        for (int second = 0; second < 2; second++) {
            uint8_t saved[3];
            memcpy(saved, ek + at, sizeof saved);
            for (size_t v = 0; v < 4; v++) {
                put_field(ek + at, second, values[v]);
                int refused = mlkem_encaps_derand(WIDEMUL_NOT_STATED, ct, ss, ek, m) != 0;
                int refused_avx2 = mlkem_encaps_derand_avx2(WIDEMUL_NOT_STATED, ct, ss, ek, m) != 0;
                check(refused == (values[v] >= MLKEM_Q) && refused_avx2 == refused,
                      "the modulus check on AVX2");
            }
            memcpy(ek + at, saved, sizeof saved);
        }
    }
}

#if MLK_HOLDS_768
// Compress_10 and Compress_4 on AVX2 against the native copy's, which runs the same formula on
// the scalar multiply: every coefficient from -(q - 1) to q - 1 at every lane position, in 27
// polynomials that run through them in turn, then random polynomials of reduced coefficients.
static void compress_poly_case(const mlk_poly *p) {
    uint8_t want[320];
    uint8_t got[320];
    mlk_poly_compress_du_native(want, p, MLKEM_RANK_768);
    mlk_poly_compress_10_avx2(got, p);
    check(memcmp(want, got, sizeof want) == 0, "Compress_10 on AVX2");
    mlk_poly_compress_native(want, p, MLKEM_RANK_768);
    mlk_poly_compress_4_avx2(got, p);
    check(memcmp(want, got, 128) == 0, "Compress_4 on AVX2");
}

static void compress_cases(void) {
    mlk_poly p;
    int16_t value = -(MLKEM_Q - 1);
    for (int k = 0; k < 27; k++) {
        for (size_t i = 0; i < MLKEM_N; i++) {
            p.coeffs[i] = value;
            value = value == MLKEM_Q - 1 ? (int16_t)-(MLKEM_Q - 1) : (int16_t)(value + 1);
        }
        compress_poly_case(&p);
    }
    for (int k = 0; k < 2000; k++) {
        uint8_t bytes[2 * MLKEM_N];
        rng_bytes(bytes, sizeof bytes);
        for (size_t i = 0; i < MLKEM_N; i++) {
            p.coeffs[i] = (int16_t)(bytes[2 * i] | (bytes[2 * i + 1] << 8));
        }
        mlk_poly_reduce(&p);
        compress_poly_case(&p);
    }
}
#endif

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
    const uint8_t *ek = dk + (size_t)MLKEM_K * 384; // FIPS 203: dk = dkpke || ek || ...
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
    table_cases();
    rejection_cases();
    frombytes_cases();
    modulus_check_cases();
#if MLK_HOLDS_768
    compress_cases();
#endif
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
