// bin/mldsa_vector_equiv_test: holds mldsa_vector.c, a host object's
// ML-DSA-87 NTT arithmetic on 32-bit lanes, NEON's four on arm64 and
// AVX2's eight on x86-64, to the loops CBMC proves: the verifier's in
// mldsa_poly.c and the signer's in mldsa_sign_poly.c (docs/decisions.md
// 172 and 174). CBMC cannot read an intrinsic, so this binary is what
// holds the vector path.
//
// Each case runs a function on the lanes, on the verifier's loop and on
// the signer's loop over the same coefficients, and compares the three
// results coefficient for coefficient. Every function takes every int32
// value (mldsa_poly.h), and every lane formula in mldsa_vector.c is exact
// for every int32 input, so the cases draw from all of int32, as
// proof/mldsa_ntt_harness.c does. The inputs, for each transform:
//
//   - every coefficient at 0 or at one edge value: 1, -1, INT32_MAX,
//     INT32_MIN, q, -q, 2^22, -2^22, 2^22 - 1 and -2^22 - 1, where the
//     rounding of mld_reduce32 changes;
//   - one coefficient at an edge value and the rest at 0, at each of the
//     256 positions, so every position's path through the passes runs
//     alone;
//   - CASES polynomials over all of int32, CASES over [0, q), the range of
//     a sampled entry of A, CASES over (-q/2, q/2], a centered value, and
//     CASES over [-2^27, 2^27], the range of an NTT's output.
//
// And for each product: every pair of the edge values, each filling a
// whole polynomial; one coefficient of a at an edge value at each
// position; CASES triples over all of int32 and CASES over [0, q) and
// [-2^27, 2^27]; and each output written over an operand, the aliases
// mldsa.c and the signer pass.
//
// On x86-64 the lanes run only on a CPU with AVX2. Without AVX2 the binary
// compares the two loops alone and says so, unless CH_REQUIRE_X86_KERNELS
// is 1 in its environment, which makes it fail (test/x86_kernels_cpu.h).
// With AVX2 it also reads ymm0 to ymm15 back as zero after each entry,
// because the signer's lanes hold secrets there (test/avx2_registers.h).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mldsa_poly.h"
#include "mldsa_sign_poly.h"
#include "mldsa_vector.h"
#include "x86_kernels_cpu.h"

#ifndef CH_CPU_RUNTIME
#error "bin/mldsa_vector_equiv_test links a host object's ML-DSA sources: -DCH_CPU_RUNTIME"
#endif

#define CASES 2000

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

enum operation { NTT, INVNTT, POINTWISE, POINTWISE_ACC };

static const char *const OPERATION_NAMES[] = {"ntt", "invntt_tomont", "pointwise", "pointwise_acc"};

typedef void (*transform_fn)(mld_poly *p);
typedef void (*product_fn)(mld_poly *r, const mld_poly *a, const mld_poly *b);

// Each function on the verifier's loop (path 0), the signer's (path 1)
// and, where the object holds them, the lanes (path 2).
static const transform_fn NTTS[] = {mld_poly_ntt, mlds_poly_ntt,
#if MLD_VECTOR
                                    mld_vector_ntt
#endif
};
static const transform_fn INVNTTS[] = {mld_poly_invntt_tomont, mlds_poly_invntt_tomont,
#if MLD_VECTOR
                                       mld_vector_invntt_tomont
#endif
};
static const product_fn POINTWISES[] = {mld_poly_pointwise, mlds_poly_pointwise,
#if MLD_VECTOR
                                        mld_vector_pointwise
#endif
};
static const product_fn POINTWISE_ACCS[] = {mld_poly_pointwise_acc, mlds_poly_pointwise_acc,
#if MLD_VECTOR
                                            mld_vector_pointwise_acc
#endif
};

// The operation on one path. out holds acc on entry for POINTWISE_ACC.
static void run(int path, enum operation op, mld_poly *out, const mld_poly *a, const mld_poly *b) {
    switch (op) {
    case NTT:
        *out = *a;
        NTTS[path](out);
        break;
    case INVNTT:
        *out = *a;
        INVNTTS[path](out);
        break;
    case POINTWISE:
        POINTWISES[path](out, a, b);
        break;
    case POINTWISE_ACC:
        POINTWISE_ACCS[path](out, a, b);
        break;
    }
}

// The paths this run compares: 3 where the object holds the lanes and
// this CPU runs them, and 2 elsewhere. main sets it.
static int paths = 2;
static const char *const PATH_NAMES[] = {"the verifier's loop", "the signer's loop", "the lanes"};

// Runs op on every path from the same inputs and compares each result with
// the verifier's loop. acc is the accumulator's value on entry, read by
// POINTWISE_ACC alone.
static void compare(const char *what, enum operation op, const mld_poly *a, const mld_poly *b,
                    const mld_poly *acc) {
    mld_poly want;
    want = *acc;
    run(0, op, &want, a, b);
    for (int path = 1; path < paths; path++) {
        mld_poly got = *acc;
        run(path, op, &got, a, b);
        compared++;
        for (size_t i = 0; i < MLD_N; i++) {
            if (got.coeffs[i] != want.coeffs[i]) {
                failures++;
                (void)fprintf(stderr,
                              "mldsa vector equivalence: %s %s: coefficient %zu is %d on %s and "
                              "%d on %s\n",
                              OPERATION_NAMES[op], what, i, got.coeffs[i], PATH_NAMES[path],
                              want.coeffs[i], PATH_NAMES[0]);
                break;
            }
        }
    }
}

static void compare_transforms(const char *what, const mld_poly *p) {
    compare(what, NTT, p, p, p);
    compare(what, INVNTT, p, p, p);
}

static void compare_products(const char *what, const mld_poly *a, const mld_poly *b,
                             const mld_poly *acc) {
    compare(what, POINTWISE, a, b, acc);
    compare(what, POINTWISE_ACC, a, b, acc);
}

// Each product with its output written over an operand, on every path.
static void compare_aliases(const mld_poly *a, const mld_poly *b) {
    mld_poly want_r;
    mld_poly want_acc = *b;
    mld_poly_pointwise(&want_r, a, b);
    mld_poly_pointwise_acc(&want_acc, a, b);
    for (int path = 0; path < paths; path++) {
        mld_poly over_a = *a;
        mld_poly over_b = *b;
        mld_poly acc_b = *b;
        // r = a o b with r at a, then at b, and acc = b + a o b with acc at b.
        POINTWISES[path](&over_a, &over_a, b);
        POINTWISES[path](&over_b, a, &over_b);
        POINTWISE_ACCS[path](&acc_b, a, &acc_b);
        compared += 3;
        if (memcmp(&over_a, &want_r, sizeof want_r) != 0 ||
            memcmp(&over_b, &want_r, sizeof want_r) != 0 ||
            memcmp(&acc_b, &want_acc, sizeof want_acc) != 0) {
            failures++;
            (void)fprintf(stderr,
                          "mldsa vector equivalence: a product written over an operand differs "
                          "on %s\n",
                          PATH_NAMES[path]);
        }
    }
}

static void fill(mld_poly *p, int32_t value) {
    for (size_t i = 0; i < MLD_N; i++) {
        p->coeffs[i] = value;
    }
}

static const int32_t EDGES[] = {1,      -1,      INT32_MAX,  INT32_MIN,     MLD_Q,
                                -MLD_Q, 1 << 22, -(1 << 22), (1 << 22) - 1, -(1 << 22) - 1};
#define EDGE_COUNT (sizeof EDGES / sizeof EDGES[0])

static void constant_cases(void) {
    mld_poly p;
    fill(&p, 0);
    compare_transforms("all zero", &p);
    for (size_t e = 0; e < EDGE_COUNT; e++) {
        fill(&p, EDGES[e]);
        compare_transforms("every coefficient at one edge value", &p);
    }
}

static void single_coefficient_cases(void) {
    for (size_t e = 0; e < EDGE_COUNT; e++) {
        for (size_t position = 0; position < MLD_N; position++) {
            mld_poly p;
            fill(&p, 0);
            p.coeffs[position] = EDGES[e];
            compare_transforms("one coefficient at an edge value", &p);
        }
    }
}

// A 32-bit draw times n keeps its top bits: a value in [0, n), with no
// division (INV-23).
static int32_t below(uint64_t draw, uint32_t n) {
    return (int32_t)(((uint64_t)(uint32_t)draw * n) >> 32);
}

static void random_cases(void) {
    for (int c = 0; c < CASES; c++) {
        mld_poly wide;
        fill(&wide, 0);
        mld_poly reduced;
        fill(&reduced, 0);
        mld_poly centered;
        fill(&centered, 0);
        mld_poly transformed;
        fill(&transformed, 0);
        for (size_t i = 0; i < MLD_N; i++) {
            uint64_t draw = rng_next();
            uint64_t second = rng_next();
            wide.coeffs[i] = (int32_t)(uint32_t)draw;
            reduced.coeffs[i] = below(draw >> 32, MLD_Q);
            centered.coeffs[i] = below(second, MLD_Q) - (MLD_Q - 1) / 2;
            transformed.coeffs[i] = below(second >> 32, (1U << 28) + 1) - (1 << 27);
        }
        compare_transforms("over all of int32", &wide);
        compare_transforms("over [0, q)", &reduced);
        compare_transforms("over (-q/2, q/2]", &centered);
        compare_transforms("over [-2^27, 2^27]", &transformed);
    }
}

static void product_edge_cases(void) {
    mld_poly a;
    mld_poly b;
    mld_poly acc;
    for (size_t i = 0; i <= EDGE_COUNT; i++) {
        for (size_t j = 0; j <= EDGE_COUNT; j++) {
            fill(&a, i == EDGE_COUNT ? 0 : EDGES[i]);
            fill(&b, j == EDGE_COUNT ? 0 : EDGES[j]);
            fill(&acc, EDGES[(i + j) % EDGE_COUNT]);
            compare_products("constant polynomials", &a, &b, &acc);
        }
    }
    for (size_t e = 0; e < EDGE_COUNT; e++) {
        fill(&b, EDGES[EDGE_COUNT - 1 - e]);
        fill(&acc, EDGES[e]);
        for (size_t position = 0; position < MLD_N; position++) {
            fill(&a, 0);
            a.coeffs[position] = EDGES[e];
            compare_products("one coefficient at an edge value", &a, &b, &acc);
        }
    }
}

static void product_random_cases(void) {
    for (int c = 0; c < CASES; c++) {
        mld_poly a_wide;
        fill(&a_wide, 0);
        mld_poly b_wide;
        fill(&b_wide, 0);
        mld_poly acc_wide;
        fill(&acc_wide, 0);
        mld_poly a_entry;
        fill(&a_entry, 0);
        mld_poly b_transformed;
        fill(&b_transformed, 0);
        for (size_t i = 0; i < MLD_N; i++) {
            uint64_t draw = rng_next();
            uint64_t second = rng_next();
            a_wide.coeffs[i] = (int32_t)(uint32_t)draw;
            b_wide.coeffs[i] = (int32_t)(uint32_t)(draw >> 32);
            acc_wide.coeffs[i] = (int32_t)(uint32_t)second;
            a_entry.coeffs[i] = below(second >> 32, MLD_Q);
            b_transformed.coeffs[i] = below(draw, (1U << 28) + 1) - (1 << 27);
        }
        compare_products("over all of int32", &a_wide, &b_wide, &acc_wide);
        compare_products("over an entry of A and an NTT's output", &a_entry, &b_transformed,
                         &acc_wide);
        compare_aliases(&a_wide, &b_wide);
        compare_aliases(&a_entry, &b_transformed);
    }
}

#if MLD_VECTOR && defined(__x86_64__)
#include "avx2_registers.h"

// What each entry leaves in ymm0 to ymm15. The signer's lanes hold s1, s2,
// t0, y and c there, so each entry ends with VZEROALL (docs/decisions.md
// 174). The block of assembly runs first with no call, and its stores
// must hold every bit set, so a zero after a call is the call's.
static void avx2_registers_cases(void) {
    static mld_poly r;
    static mld_poly a;
    static mld_poly b;
    for (size_t i = 0; i < MLD_N; i++) {
        uint64_t draw = rng_next();
        r.coeffs[i] = (int32_t)(uint32_t)draw;
        a.coeffs[i] = (int32_t)(uint32_t)(draw >> 32);
        b.coeffs[i] = (int32_t)(uint32_t)rng_next();
    }
    static const struct {
        const char *name;
        avx2_function call;
    } entries[] = {
        {"mld_vector_ntt",           (avx2_function)mld_vector_ntt          },
        {"mld_vector_invntt_tomont", (avx2_function)mld_vector_invntt_tomont},
        {"mld_vector_pointwise",     (avx2_function)mld_vector_pointwise    },
        {"mld_vector_pointwise_acc", (avx2_function)mld_vector_pointwise_acc},
    };
    size_t at = 0;
    avx2_call c = {
        NULL, {(uintptr_t)&r, (uintptr_t)&a, (uintptr_t)&b, 0, 0, 0}
    };
    avx2_set_call_store(&c, 0);
    compared++;
    if (!avx2_registers_hold(UINT64_MAX, &at)) {
        failures++;
        (void)fprintf(stderr,
                      "mldsa vector equivalence: registers: the block of assembly left ymm%zu "
                      "word %zu unset, so it tests nothing\n",
                      at / AVX2_REGISTER_WORDS, at % AVX2_REGISTER_WORDS);
        return;
    }
#ifdef TEST_ADDRESS_SANITIZER
    printf("mldsa vector equivalence: SKIP the registers after the AVX2 entries: this binary "
           "runs under AddressSanitizer, whose code at an entry's return writes a vector "
           "register after VZEROALL\n");
    return;
#endif
    for (size_t e = 0; e < sizeof entries / sizeof entries[0]; e++) {
        c.call = entries[e].call;
        avx2_set_call_store(&c, 0);
        compared++;
        if (!avx2_registers_hold(0, &at)) {
            failures++;
            (void)fprintf(stderr,
                          "mldsa vector equivalence: registers: ymm%zu word %zu holds "
                          "0x%016llx after %s\n",
                          at / AVX2_REGISTER_WORDS, at % AVX2_REGISTER_WORDS,
                          (unsigned long long)avx2_register_word(at), entries[e].name);
        }
    }
}
#endif

// Whether this run compares the lanes: where the object holds them, and on
// x86-64 where this CPU has AVX2. Returns -1 where the environment
// requires the lanes and this CPU lacks AVX2.
static int lanes_run(void) {
#if MLD_VECTOR && defined(__x86_64__)
    if (x86_cpu_has_avx2()) {
        return 1;
    }
    if (x86_kernels_required()) {
        (void)fprintf(stderr, "mldsa vector equivalence: this CPU lacks AVX2, and "
                              "CH_REQUIRE_X86_KERNELS is 1\n");
        return -1;
    }
    printf("mldsa vector equivalence: SKIP the AVX2 lanes: this CPU lacks AVX2\n");
    return 0;
#else
    return MLD_VECTOR;
#endif
}

int main(void) {
    int lanes = lanes_run();
    if (lanes < 0) {
        return 1;
    }
    paths = lanes ? 3 : 2;
#if MLD_VECTOR && defined(__x86_64__)
    if (lanes) {
        avx2_registers_cases();
    }
#endif
    constant_cases();
    single_coefficient_cases();
    random_cases();
    product_edge_cases();
    product_random_cases();
    if (failures != 0) {
        (void)fprintf(stderr,
                      "mldsa vector equivalence: %d of %lu transforms and products differ\n",
                      failures, compared);
        return 1;
    }
    (void)printf("mldsa vector equivalence: %lu transforms and products, the same coefficients on "
                 "%s\n",
                 compared,
                 lanes ? "the lanes and both loops" : "both loops (this run has no lanes)");
    return 0;
}
