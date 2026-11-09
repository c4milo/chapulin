// The 64-bit-limb Poly1305 arm of the differential oracle: poly1305_wide.h's
// block step, which aead_avx2.c's one pass runs between the AVX2 ChaCha20
// rounds, against spec/lean/Spec/Poly1305Wide.lean's `block`, through the
// same Lean spec process test/diff_test.c drives (docs/decisions.md 206).
// The module proves that a step computes (h + m + 2^128) r modulo
// 2^130 - 5. These rows hold the C to the model limb for limb, so an error
// in the transcription on either side fails a row.
//
//   blocks: one to BLOCKS_MAX blocks from a random accumulator whose h2 is
//   0 to 4, under random clamped keys over random bytes, and under the
//   largest clamped key from the largest accumulator over blocks of all
//   ones bits, whose sums are the largest the step adds.
//
// Its own main, as test/diff_poly1305_vector_test.c is: the step exists in
// a host object alone, under CH_CPU_RUNTIME, and no file bin/diff compiles
// is one.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "poly1305_wide.h"

#include "diff_driver.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define BLOCKS_MAX 40
#define BLOCK 16
#define ROWS_PER_SHAPE 16
#define COMMAND_SIZE (64 + 2 * (16 + 24 + BLOCKS_MAX * BLOCK))
#define REPLY_SIZE (2 * 24 + 1)

// The clamp of RFC 8439 §2.5.1 on r's two limbs.
#define CLAMP_LOW UINT64_C(0x0ffffffc0fffffff)
#define CLAMP_HIGH UINT64_C(0x0ffffffc0ffffffc)

// Limbs as the spec reads them: each 8 big-endian bytes, in hex.
static size_t append_limbs(char *out, const uint64_t *limb, size_t count) {
    uint8_t bytes[24] = {0};
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < 8; j++) {
            bytes[8 * i + j] = (uint8_t)(limb[i] >> (8 * (7 - j)));
        }
    }
    return hex_encode(out, bytes, 8 * count);
}

static void diff_row(poly1305_wide_key k, poly1305_wide_acc a, const uint8_t *message,
                     size_t blocks) {
    static char cmd[COMMAND_SIZE];
    static char want[REPLY_SIZE];
    size_t len = (size_t)snprintf(cmd, sizeof cmd, "poly1305_wide_blocks ");
    const uint64_t key_limbs[2] = {k.r0, k.r1};
    len += append_limbs(cmd + len, key_limbs, 2);
    cmd[len++] = ' ';
    const uint64_t acc_limbs[3] = {a.h0, a.h1, a.h2};
    len += append_limbs(cmd + len, acc_limbs, 3);
    cmd[len++] = ' ';
    (void)hex_encode(cmd + len, message, blocks * BLOCK);
    for (size_t i = 0; i < blocks; i++) {
        poly1305_wide_block(&a, &k, message + BLOCK * i);
    }
    const uint64_t out_limbs[3] = {a.h0, a.h1, a.h2};
    (void)append_limbs(want, out_limbs, 3);
    expect(cmd, want);
}

static poly1305_wide_key key_of(uint64_t r0, uint64_t r1) {
    poly1305_wide_key k = {r0 & CLAMP_LOW, r1 & CLAMP_HIGH, 0};
    k.s1 = k.r1 + (k.r1 >> 2);
    return k;
}

static void diff_blocks(void) {
    static uint8_t message[BLOCKS_MAX * BLOCK];
    for (size_t blocks = 1; blocks <= BLOCKS_MAX; blocks++) {
        for (int row = 0; row < ROWS_PER_SHAPE; row++) {
            poly1305_wide_acc a = {rng_next(), rng_next(), rng_next() % 5};
            rng_fill(message, sizeof message);
            diff_row(key_of(rng_next(), rng_next()), a, message, blocks);
        }
        memset(message, 0xff, sizeof message);
        poly1305_wide_acc a = {UINT64_MAX, UINT64_MAX, 4};
        diff_row(key_of(UINT64_MAX, UINT64_MAX), a, message, blocks);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff poly1305 wide: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    diff_blocks();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff poly1305 wide: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
