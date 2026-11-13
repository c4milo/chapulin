// bin/mlkem_vector_equiv_test: holds mlkem_vector.c, a host object's NTT
// arithmetic on eight 16-bit lanes, to mlkem_poly.c's loops, the code CBMC
// proves. CBMC cannot read an intrinsic, so this binary is what holds the
// vector path. mlkem_poly.c compiles to the same code in a host object as
// in a device object (test/widemul-builds.sh), so its mlk_poly_ntt,
// mlk_poly_invntt and mlk_poly_basemul here are the loops a device object
// runs.
//
// Each case runs a transform or a product both ways on the same
// coefficients and compares the results coefficient for coefficient.
// Every lane formula in mlkem_vector.c is exact for every int16 input, so
// the cases draw from all of int16, wider than any caller passes, as
// proof/mlkem_ntt_harness.c does. The inputs, for the forward and the
// inverse transform each:
//
//   - every coefficient at 0, 1, -1, INT16_MAX and INT16_MIN;
//   - one coefficient at 1, -1, INT16_MAX or INT16_MIN and the rest at 0,
//     at each of the 256 positions, so every position's path through the
//     three passes runs alone;
//   - CASES polynomials with every coefficient drawn from all of int16,
//     CASES from [0, q), the range a decoded or sampled polynomial holds,
//     and CASES from [-2, 2], the range of the noise.
//
// And for the product: every pair of the five values above, each filling
// a whole polynomial, which multiplies INT16_MIN by INT16_MIN, the one
// product NEON's doubling multiply would saturate; one coefficient of a
// at an edge value at each position, against a b at another; and CASES
// pairs from all of int16 and CASES with a from (-q/2, q/2], an NTT's
// output range, and b from [0, q), a sampled matrix entry's.
//
// And for the sum: the same pairs, with the output apart from both
// operands, on the first and on the second, which is how mlkem.c calls it.
//
// And for the reduction: mlk_vector_reduce against mlk_poly_reduce on
// every int16 value, 256 polynomials whose coefficients run through all
// 65,536 in turn; and for the message expansion: mlk_vector_frommsg
// against mlk_poly_frommsg on 256 messages, the kth of which holds byte
// value k + i at each position i, so each position takes every value
// (docs/decisions.md 232).
//
// And for the noise: mlk_vector_noise over the PRF stream of each of
// NOISE_SEEDS random seeds and each of the 256 nonces, against
// mlk_sample_cbd on the same seed and nonce (docs/decisions.md 225). Each
// pair of coefficients comes from one byte of the stream, so the binary
// requires that the streams held every byte value at every one of the
// MLK_CBD_BYTES positions.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mlkem_poly.h"
#include "mlkem_vector.h"
#include "sha3.h"

#ifndef CH_CPU_RUNTIME
#error "bin/mlkem_vector_equiv_test links a host object's ML-KEM sources: -DCH_CPU_RUNTIME"
#endif

#define CASES 2000
#define NOISE_SEEDS 100

// xorshift64 from a fixed seed, so a run replays the same cases.
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static unsigned long compared = 0;
static int failures = 0;

// Runs one transform both ways on p and compares the results.
static void compare(const char *what, const mlk_poly *p, int forward) {
    mlk_poly portable = *p;
    mlk_poly vector = *p;
    if (forward) {
        mlk_poly_ntt(&portable);
        mlk_vector_ntt(&vector);
    } else {
        mlk_poly_invntt(&portable);
        mlk_vector_invntt(&vector);
    }
    compared++;
    for (size_t i = 0; i < MLKEM_N; i++) {
        if (portable.coeffs[i] != vector.coeffs[i]) {
            failures++;
            (void)fprintf(stderr,
                          "mlkem vector equivalence: %s %s: coefficient %zu is %d on the "
                          "vector path and %d on the portable loops\n",
                          forward ? "ntt" : "invntt", what, i, vector.coeffs[i],
                          portable.coeffs[i]);
            return;
        }
    }
}

static void compare_both(const char *what, const mlk_poly *p) {
    compare(what, p, 1);
    compare(what, p, 0);
}

// Runs the product both ways on a and b and compares the results.
static void compare_product(const char *what, const mlk_poly *a, const mlk_poly *b) {
    mlk_poly portable;
    mlk_poly vector;
    memset(&portable, 0, sizeof portable);
    memset(&vector, 0, sizeof vector);
    mlk_poly_basemul(&portable, a, b);
    mlk_vector_basemul(&vector, a, b);
    compared++;
    for (size_t i = 0; i < MLKEM_N; i++) {
        if (portable.coeffs[i] != vector.coeffs[i]) {
            failures++;
            (void)fprintf(stderr,
                          "mlkem vector equivalence: basemul %s: coefficient %zu is %d on the "
                          "vector path and %d on the portable loop\n",
                          what, i, vector.coeffs[i], portable.coeffs[i]);
            return;
        }
    }
}

static void require_same(const char *what, const char *shape, const mlk_poly *portable,
                         const mlk_poly *vector) {
    compared++;
    for (size_t i = 0; i < MLKEM_N; i++) {
        if (portable->coeffs[i] != vector->coeffs[i]) {
            failures++;
            (void)fprintf(stderr,
                          "mlkem vector equivalence: %s, %s: coefficient %zu is %d on the "
                          "vector path and %d on the portable loop\n",
                          what, shape, i, vector->coeffs[i], portable->coeffs[i]);
            return;
        }
    }
}

// Runs the sum both ways on a and b, in each shape mlkem.c calls it, and
// compares the results.
static void compare_sum(const char *what, const mlk_poly *a, const mlk_poly *b) {
    mlk_poly portable;
    mlk_poly vector;
    memset(&portable, 0, sizeof portable);
    memset(&vector, 0, sizeof vector);
    mlk_poly_add(&portable, a, b);
    mlk_vector_add(&vector, a, b);
    require_same(what, "sum, output apart", &portable, &vector);
    vector = *a;
    mlk_vector_add(&vector, &vector, b);
    require_same(what, "sum, output on the first operand", &portable, &vector);
    vector = *b;
    mlk_vector_add(&vector, a, &vector);
    require_same(what, "sum, output on the second operand", &portable, &vector);
}

// Every int16 value through both reductions: polynomial k holds the
// 256 values from 256 k - 32768 up.
static void reduce_cases(void) {
    for (int k = 0; k < 256; k++) {
        mlk_poly portable;
        mlk_poly vector;
        for (size_t i = 0; i < MLKEM_N; i++) {
            portable.coeffs[i] = (int16_t)(256 * k + (int)i - 32768);
            vector.coeffs[i] = portable.coeffs[i];
        }
        mlk_poly_reduce(&portable);
        mlk_vector_reduce(&vector);
        require_same("every int16 value", "reduction", &portable, &vector);
    }
}

// Each byte value at each of the 32 positions of a message, through both
// expansions.
static void message_cases(void) {
    for (int k = 0; k < 256; k++) {
        uint8_t msg[32];
        for (size_t i = 0; i < sizeof msg; i++) {
            msg[i] = (uint8_t)(k + (int)i);
        }
        mlk_poly portable;
        mlk_poly vector;
        mlk_poly_frommsg(&portable, msg);
        mlk_vector_frommsg(&vector, msg);
        require_same("every byte at every position", "message expansion", &portable, &vector);
    }
}

static void fill(mlk_poly *p, int16_t value) {
    for (size_t i = 0; i < MLKEM_N; i++) {
        p->coeffs[i] = value;
    }
}

static const int16_t EDGES[] = {1, -1, INT16_MAX, INT16_MIN};
#define EDGE_COUNT (sizeof EDGES / sizeof EDGES[0])

static void constant_cases(void) {
    mlk_poly p;
    memset(&p, 0, sizeof p);
    compare_both("all zero", &p);
    for (size_t e = 0; e < EDGE_COUNT; e++) {
        for (size_t i = 0; i < MLKEM_N; i++) {
            p.coeffs[i] = EDGES[e];
        }
        compare_both("every coefficient at one edge value", &p);
    }
}

static void single_coefficient_cases(void) {
    for (size_t e = 0; e < EDGE_COUNT; e++) {
        for (size_t position = 0; position < MLKEM_N; position++) {
            mlk_poly p;
            memset(&p, 0, sizeof p);
            p.coeffs[position] = EDGES[e];
            compare_both("one coefficient at an edge value", &p);
        }
    }
}

static const int16_t VALUES[] = {0, 1, -1, INT16_MAX, INT16_MIN};
#define VALUE_COUNT (sizeof VALUES / sizeof VALUES[0])

static void product_edge_cases(void) {
    mlk_poly a;
    mlk_poly b;
    for (size_t i = 0; i < VALUE_COUNT; i++) {
        for (size_t j = 0; j < VALUE_COUNT; j++) {
            fill(&a, VALUES[i]);
            fill(&b, VALUES[j]);
            compare_product("two constant polynomials", &a, &b);
        }
    }
    for (size_t e = 0; e < EDGE_COUNT; e++) {
        fill(&b, EDGES[EDGE_COUNT - 1 - e]);
        for (size_t position = 0; position < MLKEM_N; position++) {
            fill(&a, 0);
            a.coeffs[position] = EDGES[e];
            compare_product("one coefficient at an edge value", &a, &b);
        }
    }
}

// A 16-bit draw times n keeps its top bits: a value in [0, n), with no
// division (INV-23).
static int16_t below(uint64_t draw, uint32_t n) {
    return (int16_t)(((uint32_t)(uint16_t)draw * n) >> 16);
}

static void product_random_cases(void) {
    for (int c = 0; c < CASES; c++) {
        mlk_poly a_wide;
        mlk_poly b_wide;
        mlk_poly a_centered;
        mlk_poly b_reduced;
        memset(&a_wide, 0, sizeof a_wide);
        memset(&b_wide, 0, sizeof b_wide);
        memset(&a_centered, 0, sizeof a_centered);
        memset(&b_reduced, 0, sizeof b_reduced);
        for (size_t i = 0; i < MLKEM_N; i++) {
            uint64_t draw = rng_next();
            a_wide.coeffs[i] = (int16_t)(uint16_t)draw;
            b_wide.coeffs[i] = (int16_t)(uint16_t)(draw >> 16);
            // [0, q) less 1664, (q - 1) / 2: the range (-q/2, q/2].
            a_centered.coeffs[i] = (int16_t)(below(draw >> 32, MLKEM_Q) - 1664);
            b_reduced.coeffs[i] = below(draw >> 48, MLKEM_Q);
        }
        compare_product("over all of int16", &a_wide, &b_wide);
        compare_product("over an NTT's output and a matrix entry", &a_centered, &b_reduced);
        compare_sum("over all of int16", &a_wide, &b_wide);
        compare_sum("over an NTT's output and a matrix entry", &a_centered, &b_reduced);
    }
}

static void random_cases(void) {
    for (int c = 0; c < CASES; c++) {
        mlk_poly wide;
        mlk_poly reduced;
        mlk_poly noise;
        memset(&wide, 0, sizeof wide);
        memset(&reduced, 0, sizeof reduced);
        memset(&noise, 0, sizeof noise);
        for (size_t i = 0; i < MLKEM_N; i++) {
            uint64_t draw = rng_next();
            wide.coeffs[i] = (int16_t)(uint16_t)draw;
            reduced.coeffs[i] = below(draw >> 16, MLKEM_Q);
            noise.coeffs[i] = (int16_t)(below(draw >> 32, 5) - 2);
        }
        compare_both("over all of int16", &wide);
        compare_both("over [0, q)", &reduced);
        compare_both("over [-2, 2]", &noise);
    }
}

// mlk_sample_cbd's PRF stream for seed and nonce: SHAKE256(seed || nonce).
static void noise_stream(uint8_t out[MLK_CBD_BYTES], const uint8_t seed[32], uint8_t nonce) {
    shake s;
    shake256_init(&s);
    shake_absorb(&s, seed, 32);
    shake_absorb(&s, &nonce, 1);
    shake_squeeze(&s, out, MLK_CBD_BYTES);
}

static uint8_t noise_seen[MLK_CBD_BYTES][256];

static void noise_cases(void) {
    for (int c = 0; c < NOISE_SEEDS; c++) {
        uint8_t seed[32];
        for (size_t i = 0; i < sizeof seed; i++) {
            seed[i] = (uint8_t)rng_next();
        }
        for (unsigned nonce = 0; nonce < 256; nonce++) {
            uint8_t stream[MLK_CBD_BYTES];
            mlk_poly portable;
            mlk_poly vector;
            noise_stream(stream, seed, (uint8_t)nonce);
            for (size_t i = 0; i < MLK_CBD_BYTES; i++) {
                noise_seen[i][stream[i]] = 1;
            }
            memset(&portable, 0, sizeof portable);
            memset(&vector, 0x5a, sizeof vector);
            mlk_sample_cbd(&portable, seed, (uint8_t)nonce);
            mlk_vector_noise(&vector, stream);
            require_same("the noise of a random seed", "one nonce", &portable, &vector);
        }
    }
    for (size_t i = 0; i < MLK_CBD_BYTES; i++) {
        for (size_t value = 0; value < 256; value++) {
            if (!noise_seen[i][value]) {
                (void)fprintf(stderr,
                              "mlkem vector equivalence: no stream held byte value %zu at "
                              "position %zu; raise NOISE_SEEDS\n",
                              value, i);
                failures++;
                return;
            }
        }
    }
}

int main(void) {
    constant_cases();
    single_coefficient_cases();
    random_cases();
    product_edge_cases();
    product_random_cases();
    reduce_cases();
    message_cases();
    noise_cases();
    if (failures != 0) {
        (void)fprintf(stderr,
                      "mlkem vector equivalence: %d of %lu transforms, products, sums, "
                      "reductions, messages and noise polynomials differ\n",
                      failures, compared);
        return 1;
    }
    (void)printf("mlkem vector equivalence: %lu transforms, products, sums, reductions, messages "
                 "and noise polynomials, the same coefficients on the vector path and the portable "
                 "loops\n",
                 compared);
    return 0;
}
