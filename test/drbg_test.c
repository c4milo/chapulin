// The reference generator: deterministic under a fixed seed, distinct
// across consecutive requests, key erased between them, and equal to the
// construction it claims to be (the key is the SHA-256 of the seed; the
// ChaCha20 keystream's first 32 bytes rekey, output after). Its own
// binary because drbg.c defines ch_rand_bytes, which the other test
// binaries define themselves.
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "chacha20.h"
#include "diff_driver.h"
#include "drbg.h"
#include "rand.h"
#include "sha256.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// check_seed_floor expects CH_ASSERT to fire. While expect_assert is
// set, ch_assert_fail jumps back to it instead of aborting.
static jmp_buf assert_return;
static volatile int expect_assert;

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    if (expect_assert) {
        expect_assert = 0;
        longjmp(assert_return, 1);
    }
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// Seeds the generator and returns how many times CH_ASSERT fired: 0, or
// 1 when ch_drbg_seed refused the seed.
static int seed_count_asserts(const uint8_t *seed, size_t seed_len) {
    if (setjmp(assert_return) != 0) {
        return 1;
    }
    expect_assert = 1;
    ch_drbg_seed(seed, seed_len);
    expect_assert = 0;
    return 0;
}

// Known answers, computed outside this tree: the key with Python's
// hashlib, and each request's keystream with both the cryptography
// package's ChaCha20 and `openssl enc -chacha20`, which agreed. Each
// seed is the bytes 0, 1, 2, ... of its length; each request draws 40
// bytes.
typedef struct {
    size_t seed_len;
    uint8_t first[40];  // the first request's output
    uint8_t second[40]; // the second request's, from the rekeyed state
} drbg_vector;

static const drbg_vector vectors[] = {
    // CH_DRBG_SEED_MIN bytes, the shortest seed ch_drbg_seed takes.
    {32,
     {0x63, 0x56, 0x85, 0xc5, 0x19, 0xc9, 0xdf, 0x60, 0x82, 0x6a, 0xa2, 0x59, 0xcb, 0xf1,
      0x62, 0x43, 0xd8, 0xdc, 0x7d, 0x9b, 0xd4, 0xd0, 0x20, 0xea, 0x9c, 0xc4, 0x55, 0x25,
      0xfd, 0x9b, 0x43, 0x93, 0x42, 0x57, 0x1d, 0x0b, 0x57, 0x31, 0xb6, 0x1b},
     {0x86, 0x1e, 0x28, 0x29, 0x8a, 0x13, 0x98, 0x0e, 0xc0, 0x35, 0x3f, 0x68, 0xde, 0xea,
      0x85, 0xdf, 0xa9, 0xaf, 0x77, 0x87, 0xd6, 0x60, 0x15, 0xd2, 0x61, 0x97, 0x81, 0x5d,
      0x40, 0x3a, 0x3b, 0x53, 0xdc, 0xd7, 0xeb, 0xfe, 0x63, 0xaf, 0x44, 0xd6}},
    // Three 32-byte sources, the layered seed docs/entropy.md asks for.
    {96,
     {0x70, 0xff, 0x98, 0xd9, 0x41, 0xe7, 0xf2, 0xe3, 0xf4, 0xc1, 0x78, 0x04, 0xe2, 0x2a,
      0x39, 0x05, 0xaa, 0x6d, 0x50, 0x81, 0xbd, 0xc1, 0x8c, 0x02, 0x59, 0x73, 0x24, 0x12,
      0xaf, 0x9e, 0x57, 0x51, 0x62, 0xe0, 0xee, 0x1f, 0x27, 0x46, 0xd4, 0x81},
     {0x0a, 0x07, 0x21, 0xc7, 0xb7, 0x1f, 0x84, 0x98, 0x01, 0xba, 0x5b, 0xd3, 0x0e, 0x06,
      0xc5, 0xf8, 0x10, 0x06, 0xa4, 0xec, 0x24, 0xfd, 0xae, 0xe4, 0x07, 0x44, 0x18, 0x4b,
      0x82, 0x1d, 0x7b, 0xbf, 0xfa, 0x97, 0x2b, 0x18, 0xe2, 0x1f, 0x6a, 0x4c}},
};

// The longest seed any check here passes.
#define SEED_TEST_MAX 96

static void counting_seed(uint8_t *seed, size_t seed_len) {
    for (size_t i = 0; i < seed_len; i++) {
        seed[i] = (uint8_t)i;
    }
}

static void check_vectors(void) {
    for (size_t v = 0; v < sizeof vectors / sizeof vectors[0]; v++) {
        uint8_t seed[SEED_TEST_MAX];
        counting_seed(seed, vectors[v].seed_len);
        uint8_t got[40];
        CHECK(seed_count_asserts(seed, vectors[v].seed_len) == 0);
        ch_rand_bytes(got, sizeof got);
        CHECK(memcmp(got, vectors[v].first, sizeof got) == 0);
        ch_rand_bytes(got, sizeof got);
        CHECK(memcmp(got, vectors[v].second, sizeof got) == 0);
    }
}

// The floor is exact: a seed of CH_DRBG_SEED_MIN bytes is taken, and
// one byte fewer fires CH_ASSERT.
static void check_seed_floor(void) {
    uint8_t seed[CH_DRBG_SEED_MIN];
    counting_seed(seed, sizeof seed);
    CHECK(seed_count_asserts(seed, CH_DRBG_SEED_MIN) == 0);
    CHECK(seed_count_asserts(seed, CH_DRBG_SEED_MIN - 1) == 1);
}

static void check_construction(void) {
    uint8_t seed[SEED_TEST_MAX];
    counting_seed(seed, sizeof seed);

    // Deterministic: the same seed yields the same stream.
    uint8_t a[100];
    uint8_t b[100];
    ch_drbg_seed(seed, sizeof seed);
    ch_rand_bytes(a, sizeof a);
    ch_drbg_seed(seed, sizeof seed);
    ch_rand_bytes(b, sizeof b);
    CHECK(memcmp(a, b, sizeof a) == 0);

    // Consecutive requests differ: the key moved.
    ch_rand_bytes(b, sizeof b);
    CHECK(memcmp(a, b, sizeof b) != 0);

    // The construction is what the header claims: the key is the SHA-256
    // of the whole seed, and output bytes are the ChaCha20 keystream
    // under it, zero nonce, skipping the 32 bytes that became the next
    // key.
    uint8_t key[SHA256_LEN];
    sha256_of(seed, sizeof seed, key);
    uint8_t stream[CHACHA20_BLOCK * 3] = {0};
    uint8_t nonce[CHACHA20_NONCE] = {0};
    chacha20_xor(key, nonce, 0, stream, stream, sizeof stream);
    CHECK(memcmp(a, stream + 32, sizeof a) == 0);

    // And the second request came from the rekeyed state: key = first 32
    // stream bytes, output again offset by its own rekey block.
    uint8_t stream2[CHACHA20_BLOCK * 3] = {0};
    chacha20_xor(stream, nonce, 0, stream2, stream2, sizeof stream2);
    CHECK(memcmp(b, stream2 + 32, sizeof b) == 0);
}

// Sends one request and decodes its reply, "<next-key-hex> <out-hex>".
// Returns 0 when the reply does not have that shape.
static int spec_request(const char *cmd, uint8_t next_key[32], uint8_t *out, size_t n) {
    char reply[512];
    query(cmd, reply, sizeof reply);
    char *space = strchr(reply, ' ');
    if (space == NULL) {
        return 0;
    }
    *space = 0;
    return hex_decode(next_key, reply, 32) && hex_decode(out, space + 1, n);
}

// Differential leg against the Lean spec, when its binary exists: for
// random seeds of CH_DRBG_SEED_MIN to SEED_TEST_MAX bytes and random
// request sizes, the C generator's output and the spec's must agree,
// across two consecutive requests.
static void check_against_spec(void) {
    if (access("spec/lean/.lake/build/bin/diffspec", X_OK) != 0) {
        (void)printf("drbg_test: spec comparisons skipped (build spec/lean/ first)\n");
        return;
    }
    spawn_spec("spec/lean/.lake/build/bin/diffspec");
    for (int i = 0; i < 50; i++) {
        uint8_t seed[SEED_TEST_MAX];
        size_t seed_len = CH_DRBG_SEED_MIN + rng_below(SEED_TEST_MAX - CH_DRBG_SEED_MIN + 1);
        rng_fill(seed, seed_len);
        size_t n = 1 + rng_below(96);
        char cmd[320];
        char hex[2 * SEED_TEST_MAX + 1];
        hex_encode(hex, seed, seed_len);
        (void)snprintf(cmd, sizeof cmd, "drbg_seed %s %zu", hex, n);
        uint8_t next_key[32] = {0};
        uint8_t want[96] = {0};
        int answered = spec_request(cmd, next_key, want, n);
        CHECK(answered);
        if (!answered) {
            break;
        }
        uint8_t got[96];
        ch_drbg_seed(seed, seed_len);
        ch_rand_bytes(got, n);
        CHECK(memcmp(got, want, n) == 0);
        // The second request must match the spec continuing from its
        // next key, which proves the C rekeyed exactly as specified.
        hex_encode(hex, next_key, sizeof next_key);
        (void)snprintf(cmd, sizeof cmd, "drbg %s %zu", hex, n);
        answered = spec_request(cmd, next_key, want, n);
        CHECK(answered);
        if (!answered) {
            break;
        }
        ch_rand_bytes(got, n);
        CHECK(memcmp(got, want, n) == 0);
        comparisons += 2;
    }
    (void)printf("drbg_test: %ld spec comparisons, C == spec\n", comparisons);
}

int main(void) {
    check_vectors();
    check_seed_floor();
    check_construction();
    check_against_spec();
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("drbg_test: all checks passed\n");
    return 0;
}
