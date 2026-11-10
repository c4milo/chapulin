// The arm64 P-256 field's arm of the differential oracle: p256_arm64_field.c
// compiled over test/p256_arm64_model.h, as bin/p256_arm64_model_test
// compiles it, against spec/lean/Spec/P256Adx.lean in the same Lean spec
// process test/diff_test.c drives. The model's rows are p256_wide_mul_row's
// and p256_wide_sqr_product's, and its rounds are test/p256_adx_model.h's
// model_reduce, so that module's mulMont is the model's value too, and its
// proofs that the result lands below p and is the Montgomery product hold of
// it. These rows are what make those proofs about this C: each compares the
// four words the C writes with mulMont's value (docs/decisions.md 215).
//
// Its own main, for bin/diff_p256_adx's reason: only a unit that defines
// CH_P256_ARM64_MODEL compiles the field on every host, and no row of
// bin/diff reads it. The model is portable C, so these rows run on every
// machine, and bin/p256_arm64_equiv_test holds the assembly to the model on
// arm64.
//
// The product and the square run on every pair of test/p256_adx_equiv_test.c's
// edge elements, then on 20,000 pairs of random elements below p.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "p256_arm64.h"
#include "p256_arm64_model.h"

#include "diff_driver.h"

#ifndef CH_P256_ARM64_MODEL
#error "test/diff_p256_arm64_test.c reads the model: build it with -DCH_P256_ARM64_MODEL"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// test/p256_adx_equiv_test.c's edge elements: 0, 1, 2, p - 1, p - 2,
// 2^256 mod p, (p - 1) / 2, 2^255, the largest value with a top word of
// 2^64 - 2^32, and one all-ones word at each place.
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

// Whether the four words, least significant first, are below p.
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

// n words as the spec reads them: 8n big-endian bytes in hex, the top word
// first.
static void words_hex(char *hex, const uint64_t *w, size_t n) {
    uint8_t bytes[64];
    for (size_t k = 0; k < n; k++) {
        for (size_t j = 0; j < 8; j++) {
            bytes[8 * (n - 1 - k) + (7 - j)] = (uint8_t)(w[k] >> (8 * j));
        }
    }
    (void)hex_encode(hex, bytes, 8 * n);
}

static void diff_product(const uint64_t a[4], const uint64_t b[4]) {
    p256_wide_fe wa;
    p256_wide_fe wb;
    p256_wide_fe o;
    memcpy(wa.word, a, sizeof wa.word);
    memcpy(wb.word, b, sizeof wb.word);
    char a_hex[2 * 32 + 1];
    char b_hex[2 * 32 + 1];
    char want[2 * 32 + 1];
    char cmd[256];
    words_hex(a_hex, a, 4);
    words_hex(b_hex, b, 4);
    p256_arm64_fe_mul(&o, &wa, &wb);
    words_hex(want, o.word, 4);
    (void)snprintf(cmd, sizeof cmd, "p256_arm64_mul %s %s", a_hex, b_hex);
    expect(cmd, want);
    p256_arm64_fe_sqr(&o, &wa);
    words_hex(want, o.word, 4);
    (void)snprintf(cmd, sizeof cmd, "p256_arm64_mul %s %s", a_hex, a_hex);
    expect(cmd, want);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff p256 arm64: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    for (size_t i = 0; i < EDGE_COUNT; i++) {
        for (size_t j = 0; j < EDGE_COUNT; j++) {
            diff_product(EDGE[i], EDGE[j]);
        }
    }
    uint64_t a[4];
    uint64_t b[4];
    for (int i = 0; i < 20000; i++) {
        random_below_p(a);
        random_below_p(b);
        diff_product(a, b);
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff p256 arm64: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
