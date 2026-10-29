// x25519_adx.c's assembly against its model, on an x86-64 CPU with BMI2 and
// ADX (docs/decisions.md 165). First each of the five operations and the
// final reduction, word for word against test/x25519_adx_model.h, on edge
// values and on random words. Then test/x25519_equiv_test.c's cases with the
// assembly build as the field under test, against the 16-word field.
//
// On another architecture it prints SKIP. On an x86-64 CPU without BMI2 or
// ADX it prints SKIP too, unless CH_REQUIRE_BMI2_ADX is 1: a CI job that
// runs it on such a CPU on purpose sets it, so a runner that lacks the
// instructions fails rather than passes without a check.
#include <stdint.h>
#include <stdio.h>

#ifdef __x86_64__
#include <stdlib.h>
#include <string.h>

#include "x25519.h"
#include "x25519_adx.h"
#include "x86_kernels_cpu.h"

void x25519_adx_model_test_mul(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]);
void x25519_adx_model_test_sqr(uint64_t o[4], const uint64_t a[4]);
void x25519_adx_model_test_add(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]);
void x25519_adx_model_test_sub(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]);
void x25519_adx_model_test_mul_a24(uint64_t o[4], const uint64_t a[4]);
void x25519_adx_model_test_reduce(uint64_t a[4]);

static int adx_before(void);

#define X25519_EQUIV_FIELD x25519_adx
#define X25519_EQUIV_NAME "x25519_adx_equiv"
#define X25519_EQUIV_WHAT "the radix-2^64 field's assembly"
#define X25519_EQUIV_LADDER_ONLY 1
#define X25519_EQUIV_BEFORE adx_before
#include "x25519_equiv_test.c"

// Words that sit at the ends of the carries: 0, 1, 37, 38, 39, 2^63, 2^64 -
// 39, 2^64 - 38 and 2^64 - 1, and the words of p and of 2p.
static const uint64_t EDGE_WORDS[] = {
    0,
    1,
    37,
    38,
    39,
    UINT64_C(0x8000000000000000),
    UINT64_C(0xffffffffffffffd9),
    UINT64_C(0xffffffffffffffda),
    UINT64_C(0xffffffffffffffff),
    UINT64_C(0xffffffffffffffed),
    UINT64_C(0x7fffffffffffffff),
    UINT64_C(0xffffffffffffffdb),
};
#define EDGE_COUNT (sizeof EDGE_WORDS / sizeof EDGE_WORDS[0])

static void fill_edge(uint64_t w[4], size_t i) {
    for (size_t k = 0; k < 4; k++) {
        w[k] = EDGE_WORDS[(i + 3 * k) % EDGE_COUNT];
    }
}

static void fill_random(uint64_t w[4]) {
    for (size_t k = 0; k < 4; k++) {
        w[k] = rng_next();
    }
}

static void check(const char *name, const uint64_t got[4], const uint64_t want[4],
                  const uint64_t a[4], const uint64_t b[4]) {
    if (memcmp(got, want, 4 * sizeof got[0]) == 0) {
        compared++;
        return;
    }
    failures++;
    (void)fprintf(stderr, "FAIL %s: assembly %016llx%016llx%016llx%016llx\n", name,
                  (unsigned long long)got[3], (unsigned long long)got[2],
                  (unsigned long long)got[1], (unsigned long long)got[0]);
    (void)fprintf(stderr, "  model %016llx%016llx%016llx%016llx\n", (unsigned long long)want[3],
                  (unsigned long long)want[2], (unsigned long long)want[1],
                  (unsigned long long)want[0]);
    (void)fprintf(stderr, "  a %016llx%016llx%016llx%016llx b %016llx%016llx%016llx%016llx\n",
                  (unsigned long long)a[3], (unsigned long long)a[2], (unsigned long long)a[1],
                  (unsigned long long)a[0], (unsigned long long)b[3], (unsigned long long)b[2],
                  (unsigned long long)b[1], (unsigned long long)b[0]);
}

// Each operation on a and b, the assembly against the model.
static void compare_operations(const uint64_t a[4], const uint64_t b[4]) {
    uint64_t got[4];
    uint64_t want[4];
    x25519_adx_test_mul(got, a, b);
    x25519_adx_model_test_mul(want, a, b);
    check("mul", got, want, a, b);
    x25519_adx_test_sqr(got, a);
    x25519_adx_model_test_sqr(want, a);
    check("sqr", got, want, a, a);
    x25519_adx_test_add(got, a, b);
    x25519_adx_model_test_add(want, a, b);
    check("add", got, want, a, b);
    x25519_adx_test_sub(got, a, b);
    x25519_adx_model_test_sub(want, a, b);
    check("sub", got, want, a, b);
    x25519_adx_test_mul_a24(got, a);
    x25519_adx_model_test_mul_a24(want, a);
    check("mul_a24", got, want, a, a);
    memcpy(got, a, sizeof got);
    memcpy(want, a, sizeof want);
    x25519_adx_test_reduce(got);
    x25519_adx_model_test_reduce(want);
    check("reduce", got, want, a, a);
}

static int adx_before(void) {
    if (!x86_cpu_has_bmi2_adx()) {
        if (x86_bmi2_adx_required()) {
            (void)printf("x25519_adx_equiv: FAIL: CH_REQUIRE_BMI2_ADX=1 and this CPU lacks BMI2 or "
                         "ADX\n");
            exit(1);
        }
        (void)printf("x25519_adx_equiv: SKIP: this CPU lacks BMI2 or ADX\n");
        return 0;
    }
    uint64_t a[4];
    uint64_t b[4];
    for (size_t i = 0; i < EDGE_COUNT * EDGE_COUNT; i++) {
        fill_edge(a, i / EDGE_COUNT);
        fill_edge(b, i);
        compare_operations(a, b);
    }
    for (int i = 0; i < 100000; i++) {
        fill_random(a);
        fill_random(b);
        compare_operations(a, b);
    }
    return 1;
}

#else

int main(void) {
    (void)printf("x25519_adx_equiv: SKIP: not x86-64\n");
    return 0;
}

#endif
