// p256_arm64_field.c's assembly against its model, on arm64
// (docs/decisions.md 215). First the product and the square, word for word
// against test/p256_arm64_model.h, on edge elements and on random elements
// below p, with the output apart from the inputs and over the first. Then
// test/p256_equiv_test.c's cases with the arm64 field's copy of the wide
// files on the assembly, against the files under their own names, and
// test/p256_equiv_residue.h's checks of the stack the assembly's callers
// leave.
//
// On another architecture it prints SKIP. Every arm64 core has the
// instructions, so this test has no CPU probe.
#include <stdint.h>
#include <stdio.h>

#ifdef __aarch64__

static int arm64_before(void);

#define P256_EQUIV_ARM64 1
#define P256_EQUIV_NAME "p256_arm64_equiv"
#define P256_EQUIV_BEFORE arm64_before
#include "p256_equiv_test.c"

// The model's p256_arm64_mul_mont and p256_arm64_sqr_mont, static in this
// unit, beside the assembly's, which p256_arm64_fe_mul and p256_arm64_fe_sqr
// run in p256_arm64_field.c.
#include "p256_arm64_model.h"

// Elements below p at the ends of the carries and the rounds:
// test/p256_adx_equiv_test.c's: 0, 1, 2, p - 1, p - 2, 2^256 mod p,
// (p - 1) / 2, 2^255, the largest value with a top word of 2^64 - 2^32, and
// one all-ones word at each place.
static const uint64_t EDGE[][4] = {
    {0,                            0,                            0,                            0                           },
    {1,                            0,                            0,                            0                           },
    {2,                            0,                            0,                            0                           },
    {UINT64_C(0xfffffffffffffffe), UINT64_C(0x00000000ffffffff), 0,                            UINT64_C(0xffffffff00000001)},
    {UINT64_C(0xfffffffffffffffd), UINT64_C(0x00000000ffffffff), 0,                            UINT64_C(0xffffffff00000001)},
    {1,                            UINT64_C(0xffffffff00000000), UINT64_C(0xffffffffffffffff), UINT64_C(0x00000000fffffffe)},
    {UINT64_C(0xffffffffffffffff), UINT64_C(0x000000007fffffff), UINT64_C(0x8000000000000000),
     UINT64_C(0x7fffffff80000000)                                                                                          },
    {0,                            0,                            0,                            UINT64_C(0x8000000000000000)},
    {UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff),
     UINT64_C(0xffffffff00000000)                                                                                          },
    {UINT64_C(0xffffffffffffffff), 0,                            0,                            0                           },
    {0,                            UINT64_C(0xffffffffffffffff), 0,                            0                           },
    {0,                            0,                            UINT64_C(0xffffffffffffffff), 0                           },
    {0,                            0,                            0,                            UINT64_C(0xffffffff00000000)},
};
#define EDGE_COUNT (sizeof EDGE / sizeof EDGE[0])

// Whether the four words are below p, compared from the top word down.
static int below_p(const uint64_t w[4]) {
    static const uint64_t p[4] = {P256_ADX_MODEL_P0, P256_ADX_MODEL_P1, P256_ADX_MODEL_P2,
                                  P256_ADX_MODEL_P3};
    for (int i = 3; i >= 0; i--) {
        if (w[i] != p[i]) {
            return w[i] < p[i];
        }
    }
    return 0;
}

static void random_below_p(uint64_t w[4]) {
    do {
        for (size_t k = 0; k < 4; k++) {
            w[k] = rng_next();
        }
    } while (!below_p(w));
}

static void check_words(const char *name, const uint64_t got[4], const uint64_t want[4],
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

// The product and the square of a and b, the assembly against the model,
// with the output apart from the inputs, then over a, then over b.
static void compare_operations(const uint64_t a[4], const uint64_t b[4]) {
    p256_wide_fe wa;
    p256_wide_fe wb;
    p256_wide_fe got;
    uint64_t want[4];
    memcpy(wa.word, a, sizeof wa.word);
    memcpy(wb.word, b, sizeof wb.word);
    p256_arm64_mul_mont(want, a, b);
    p256_arm64_fe_mul(&got, &wa, &wb);
    check_words("mul", got.word, want, a, b);
    got = wa;
    p256_arm64_fe_mul(&got, &got, &wb);
    check_words("mul over a", got.word, want, a, b);
    got = wb;
    p256_arm64_fe_mul(&got, &wa, &got);
    check_words("mul over b", got.word, want, a, b);
    p256_arm64_sqr_mont(want, a);
    p256_arm64_fe_sqr(&got, &wa);
    check_words("sqr", got.word, want, a, a);
    got = wa;
    p256_arm64_fe_sqr(&got, &got);
    check_words("sqr over a", got.word, want, a, a);
}

static int arm64_before(void) {
    uint64_t a[4];
    uint64_t b[4];
    for (size_t i = 0; i < EDGE_COUNT; i++) {
        for (size_t j = 0; j < EDGE_COUNT; j++) {
            compare_operations(EDGE[i], EDGE[j]);
        }
    }
    for (int i = 0; i < 200000; i++) {
        random_below_p(a);
        random_below_p(b);
        compare_operations(a, b);
    }
    return 1;
}

#else

#include <stdlib.h>
#include <stdnoreturn.h>

#include "ch_assert.h"

// The signer the binary links names the assertion's handler, which
// test/p256_equiv_test.c defines on arm64.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

int main(void) {
    (void)printf("p256_arm64_equiv: SKIP: not arm64\n");
    return 0;
}

#endif
