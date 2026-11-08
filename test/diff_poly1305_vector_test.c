// The vector Poly1305 arm of the differential oracle: poly1305_vector.c's
// entry, poly1305_vector_blocks, on this host's own instructions, NEON or
// SSE2, against the same Lean spec process test/diff_test.c drives.
// spec/lean/Spec/Poly1305Vector.lean models the entry from the C and proves
// what a pass computes: its value modulo 2^130 - 5, and the bounds that
// keep every product's operands inside 32 bits, every sum inside 64 bits
// and the words a carry leaves inside the bounds the next pass takes, for
// passes of two and of four pairs of blocks. These rows are what make
// those proofs about the C: an error in the transcription on either side
// fails a row, because each row compares the accumulator's five words, not
// only their value.
//
// Its own main, as test/diff_poly1305_ifma_test.c is: the entry exists only
// in a host object's native copy, which test/poly1305_equiv_vector.c
// compiles, and no file bin/diff compiles is one. A NEON host runs passes of
// four pairs from 2,048 bytes on and an SSE2 host passes of two, so each
// row names the width this host's object runs.
//
//   blocks: one group to GROUPS_MAX groups, which crosses the NEON path's
//   2,048 bytes with an odd count of groups and an even one on each side,
//   from the accumulator that zero to four blocks left, over random bytes
//   and over blocks of all ones bits under a key of all ones bits, whose
//   words are the largest.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#define CH_CPU_RUNTIME
#include "poly1305.h"
#include "poly1305_vector.h"
#undef CH_CPU_RUNTIME

#include "diff_driver.h"

// test/poly1305_equiv_vector.c's native copy of poly1305_init, which no
// header declares.
void poly1305_init_native(poly1305 *p, const uint8_t key[POLY1305_KEY]);

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define GROUPS_MAX 40
#define GROUP_BYTES 64
#define PREFIX_MAX 64
#define MESSAGE_MAX (PREFIX_MAX + GROUPS_MAX * GROUP_BYTES)
#define ROWS_PER_SHAPE 16

// The pairs a pass of this host's object takes from 2,048 bytes on.
#ifdef __ARM_NEON
#define PAIRS_MAX 4
#else
#define PAIRS_MAX 2
#endif

#define COMMAND_SIZE (64 + 2 * 2 * 20 + 2 * MESSAGE_MAX + 8)
#define REPLY_SIZE (2 * 20 + 1)

// Five words as the spec reads them: word i is 4 big-endian bytes, in hex.
static size_t append_words(char *out, const uint32_t w[5]) {
    uint8_t bytes[20];
    for (size_t i = 0; i < 5; i++) {
        for (size_t j = 0; j < 4; j++) {
            bytes[4 * i + j] = (uint8_t)(w[i] >> (8 * (3 - j)));
        }
    }
    return hex_encode(out, bytes, sizeof bytes);
}

static void diff_row(const uint8_t key[POLY1305_KEY], const uint8_t *message, size_t prefix,
                     size_t groups) {
    static char cmd[COMMAND_SIZE];
    static char want[REPLY_SIZE];
    poly1305 p;
    poly1305_init_native(&p, key);
    poly1305_update_native(&p, message, prefix);
    size_t len = (size_t)snprintf(cmd, sizeof cmd, "poly1305_vector_blocks %d ", PAIRS_MAX);
    len += append_words(cmd + len, p.r);
    cmd[len++] = ' ';
    len += append_words(cmd + len, p.h);
    cmd[len++] = ' ';
    (void)hex_encode(cmd + len, message + prefix, groups * GROUP_BYTES);
    poly1305_vector_blocks_native(&p, message + prefix, groups * GROUP_BYTES);
    (void)append_words(want, p.h);
    expect(cmd, want);
}

static void diff_blocks(void) {
    static uint8_t message[MESSAGE_MAX];
    uint8_t key[POLY1305_KEY];
    for (size_t groups = 1; groups <= GROUPS_MAX; groups++) {
        for (int row = 0; row < ROWS_PER_SHAPE; row++) {
            size_t prefix = 16 * (size_t)(rng_next() % 5);
            rng_fill(key, sizeof key);
            rng_fill(message, sizeof message);
            diff_row(key, message, prefix, groups);
        }
        memset(key, 0xff, sizeof key);
        memset(message, 0xff, sizeof message);
        diff_row(key, message, PREFIX_MAX, groups);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff poly1305 vector: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    diff_blocks();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff poly1305 vector: %ld comparisons, C == spec, passes of up to %d pairs\n",
                 comparisons, PAIRS_MAX);
    return 0;
}
