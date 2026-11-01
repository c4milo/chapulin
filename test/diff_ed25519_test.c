// The DNSSEC Ed25519 check's arm of the differential oracle: reduce_step
// and reduce_mod_l in x25519_wide_ed25519.h, against the same Lean spec
// process test/diff_test.c drives. spec/lean/Spec/Ed25519ModL.lean models
// both from the C and proves that a step from a remainder below L stays
// below L and that the reduction writes h mod L. These rows are what make
// those proofs about the C: an error in the transcription on either side
// fails a row.
//
// Its own main, as test/diff_x25519_test.c is: the two functions are
// static in a header that x25519_wide.c includes under CH_DNSSEC alone, so
// this unit includes x25519_wide.c itself.
//
// reduce_step takes each bit from the remainders 0, 1, 2^252 - 1, 2^252,
// (L - 1) / 2, (L + 1) / 2 and L - 1, from random ones below 2^252 and
// from random ones just below L. reduce_mod_l takes the hashes 0,
// 2^512 - 1, L - 1, L, L + 1 and random ones.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"

#include "diff_driver.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#if !defined(CH_CPU_RUNTIME) || !defined(CH_DNSSEC)
#error "test/diff_ed25519_test.c diffs the wide field's Ed25519 code: build it with -DCH_CPU_RUNTIME -DCH_DNSSEC"
#endif
#include "x25519_wide.c"

// The random remainders and hashes each kind takes.
#define RANDOM_ROWS 200

#define COMMAND_SIZE (64 + 2 * 64)

// words[0..4) as 32 little-endian bytes.
static void words_to_bytes(uint8_t b[32], const uint64_t w[4]) {
    for (size_t i = 0; i < 32; i++) {
        b[i] = (uint8_t)(w[i / 8] >> (8 * (i % 8)));
    }
}

static void diff_step(const uint64_t o[4], uint64_t bit) {
    char cmd[COMMAND_SIZE];
    char want[65];
    uint8_t bytes[32];
    words_to_bytes(bytes, o);
    size_t at = (size_t)snprintf(cmd, sizeof cmd, "ed25519_reduce_step ");
    at += hex_encode(cmd + at, bytes, 32);
    (void)snprintf(cmd + at, sizeof cmd - at, " %u", (unsigned)bit);
    uint64_t out[4];
    memcpy(out, o, sizeof out);
    reduce_step(out, bit);
    words_to_bytes(bytes, out);
    (void)hex_encode(want, bytes, 32);
    expect(cmd, want);
}

static void diff_mod_l(const uint8_t h[64]) {
    char cmd[COMMAND_SIZE];
    char want[65];
    size_t at = (size_t)snprintf(cmd, sizeof cmd, "ed25519_mod_l ");
    (void)hex_encode(cmd + at, h, 64);
    uint64_t out[4];
    reduce_mod_l(out, h);
    uint8_t bytes[32];
    words_to_bytes(bytes, out);
    (void)hex_encode(want, bytes, 32);
    expect(cmd, want);
}

// L less a, for a below L's word 0, which leaves words 1 to 3 as L's.
static void l_less(uint64_t o[4], uint64_t a) {
    memcpy(o, ED25519_L, 4 * sizeof o[0]);
    o[0] -= a;
}

static void diff_steps(void) {
    static const uint64_t fixed[][4] = {
        {0, 0, 0, 0},
        {1, 0, 0, 0},
        {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_C(0x0fffffffffffffff)},
        {0, 0, 0, UINT64_C(0x1000000000000000)},
    };
    uint64_t o[4];
    for (uint64_t bit = 0; bit < 2; bit++) {
        for (size_t i = 0; i < sizeof fixed / sizeof fixed[0]; i++) {
            diff_step(fixed[i], bit);
        }
        // (L - 1) / 2 and (L + 1) / 2: L is odd, so a shift of L down by
        // one is the first, and the first plus 1 the second.
        for (size_t i = 0; i < 4; i++) {
            o[i] = ED25519_L[i] >> 1 | (i < 3 ? ED25519_L[i + 1] << 63 : 0);
        }
        diff_step(o, bit);
        o[0]++;
        diff_step(o, bit);
        l_less(o, 1);
        diff_step(o, bit);
        for (int r = 0; r < RANDOM_ROWS; r++) {
            for (size_t i = 0; i < 4; i++) {
                o[i] = rng_next();
            }
            o[3] &= UINT64_C(0x0fffffffffffffff);
            diff_step(o, bit);
            l_less(o, 1 + rng_next() % (UINT64_C(1) << 32));
            diff_step(o, bit);
        }
    }
}

static void diff_reductions(void) {
    uint8_t h[64] = {0};
    diff_mod_l(h);
    memset(h, 0xff, sizeof h);
    diff_mod_l(h);
    for (uint64_t delta = 0; delta < 3; delta++) {
        uint64_t l_words[4];
        memcpy(l_words, ED25519_L, sizeof l_words);
        // L - 1, L and L + 1: word 0 of L ends in 0xed, so none carries.
        l_words[0] = l_words[0] - 1 + delta;
        memset(h, 0, sizeof h);
        words_to_bytes(h, l_words);
        diff_mod_l(h);
    }
    for (int r = 0; r < RANDOM_ROWS; r++) {
        rng_fill(h, sizeof h);
        diff_mod_l(h);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff ed25519: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    diff_steps();
    diff_reductions();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff ed25519: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
