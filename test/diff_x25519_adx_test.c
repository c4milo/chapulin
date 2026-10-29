// The radix-2^64 field's arm of the differential oracle: x25519_adx.c compiled
// over test/x25519_adx_model.h, as bin/x25519_adx_model_test compiles it,
// against spec/lean/Spec/X25519Adx.lean in the same Lean spec process
// test/diff_test.c drives. That module models the five operations and the
// final reduction from the C, one element in a Nat, and proves the bounds of
// the fold by 38, each operation's value mod p and that adx_reduce writes
// a mod p. These rows are what make those proofs about the C: each compares
// the four words the C writes with the model's value, so an error in the
// transcription on either side fails a row (docs/decisions.md 165).
//
// Its own main, for bin/diff_x25519_wide's reason: only a unit that defines
// CH_X25519_ADX_MODEL compiles the field on every host, and no row of
// bin/diff reads it. The model is portable C, so these rows run on every
// machine, and bin/x25519_adx_equiv_test holds the assembly to the model on
// a CPU with BMI2 and ADX.
//
// Each operation runs on every pair of elements built from
// test/x25519_adx_equiv_test.c's edge words, then on 20,000 pairs of random
// elements below 2^256. The reduction runs on the same elements. Then 1,000
// shared secrets of random scalars and points run against
// spec/lean/Spec/X25519.lean's x25519.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "x25519.h"

#include "diff_driver.h"

#ifndef CH_X25519_ADX_TEST
#error                                                                                             \
    "test/diff_x25519_adx_test.c calls the field's test entries: build it with -DCH_X25519_ADX_TEST"
#endif

// test/x25519_adx_model.c's names for x25519_adx.c's entries.
int x25519_adx_model(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                     const uint8_t point[X25519_LEN]);
void x25519_adx_model_test_mul(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]);
void x25519_adx_model_test_add(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]);
void x25519_adx_model_test_sub(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]);
void x25519_adx_model_test_mul_a24(uint64_t o[4], const uint64_t a[4]);
void x25519_adx_model_test_reduce(uint64_t a[4]);

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// The words at the ends of the carries, as test/x25519_adx_equiv_test.c
// lists them: 0, 1, 37, 38, 39, 2^63, 2^64 - 39, 2^64 - 38 and 2^64 - 1, and
// the words of p and of 2p.
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

// An element's four words as the spec reads one: 32 big-endian bytes in
// hex, word 3 first.
static void element_hex(char hex[2 * 32 + 1], const uint64_t w[4]) {
    uint8_t bytes[32];
    for (size_t k = 0; k < 4; k++) {
        for (size_t j = 0; j < 8; j++) {
            bytes[8 * (3 - k) + (7 - j)] = (uint8_t)(w[k] >> (8 * j));
        }
    }
    (void)hex_encode(hex, bytes, sizeof bytes);
}

static void expect_binary(const char *name, const uint64_t a[4], const uint64_t b[4],
                          const uint64_t o[4]) {
    char a_hex[2 * 32 + 1];
    char b_hex[2 * 32 + 1];
    char want[2 * 32 + 1];
    element_hex(a_hex, a);
    element_hex(b_hex, b);
    element_hex(want, o);
    char cmd[256];
    (void)snprintf(cmd, sizeof cmd, "x25519_adx_%s %s %s", name, a_hex, b_hex);
    expect(cmd, want);
}

static void expect_unary(const char *name, const uint64_t a[4], const uint64_t o[4]) {
    char a_hex[2 * 32 + 1];
    char want[2 * 32 + 1];
    element_hex(a_hex, a);
    element_hex(want, o);
    char cmd[256];
    (void)snprintf(cmd, sizeof cmd, "x25519_adx_%s %s", name, a_hex);
    expect(cmd, want);
}

static void diff_operations(const uint64_t a[4], const uint64_t b[4]) {
    uint64_t o[4];
    x25519_adx_model_test_mul(o, a, b);
    expect_binary("mul", a, b, o);
    x25519_adx_model_test_add(o, a, b);
    expect_binary("add", a, b, o);
    x25519_adx_model_test_sub(o, a, b);
    expect_binary("sub", a, b, o);
    x25519_adx_model_test_mul_a24(o, a);
    expect_unary("mul_a24", a, o);
    memcpy(o, a, sizeof o);
    x25519_adx_model_test_reduce(o);
    expect_unary("reduce", a, o);
}

static void diff_shared_secret(void) {
    uint8_t scalar[X25519_LEN];
    uint8_t point[X25519_LEN];
    uint8_t out[X25519_LEN];
    rng_fill(scalar, sizeof scalar);
    rng_fill(point, sizeof point);
    (void)x25519_adx_model(out, scalar, point); // 0 = all-zero out; still comparable
    char scalar_hex[2 * X25519_LEN + 1];
    char point_hex[2 * X25519_LEN + 1];
    char want[2 * X25519_LEN + 1];
    (void)hex_encode(scalar_hex, scalar, sizeof scalar);
    (void)hex_encode(point_hex, point, sizeof point);
    (void)hex_encode(want, out, sizeof out);
    char cmd[256];
    (void)snprintf(cmd, sizeof cmd, "x25519 %s %s", scalar_hex, point_hex);
    expect(cmd, want);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff x25519 adx: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    uint64_t a[4];
    uint64_t b[4];
    for (size_t i = 0; i < EDGE_COUNT * EDGE_COUNT; i++) {
        fill_edge(a, i / EDGE_COUNT);
        fill_edge(b, i);
        diff_operations(a, b);
    }
    for (int i = 0; i < 20000; i++) {
        fill_random(a);
        fill_random(b);
        diff_operations(a, b);
    }
    for (int i = 0; i < 1000; i++) {
        diff_shared_secret();
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff x25519 adx: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
