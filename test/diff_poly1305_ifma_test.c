// The AVX-512 IFMA Poly1305 arm of the differential oracle: poly1305_ifma.c's
// group step and compute_powers, compiled over the lane model as
// bin/poly1305_equiv_test compiles them (test/poly1305_ifma_model.c),
// against the same Lean spec process test/diff_test.c drives.
// spec/lean/Spec/Poly1305Ifma.lean models the kernel's arithmetic from the
// C and proves what it computes: a group step's value modulo 2^130 - 5, the
// bounds that keep every lane inside 64 bits, and the power of r each lane
// of each multiplier holds. These rows are what make those proofs about the
// C: an error in the transcription on either side fails a row.
//
// Its own main, as test/diff_rsa_ifma_test.c is: the kernel compiles over
// the model only in a unit that defines CH_POLY1305_IFMA_MODEL, which no
// file bin/diff compiles does. The model is each instruction in portable C,
// so these rows run on every host, and bin/poly1305_equiv_test holds the
// instructions to poly1305.c's loop on a CPU that has AVX-512 IFMA.
//
//   group: one group of sixteen blocks on the eight lanes, from digits and
//   multipliers anywhere inside the bounds the spec's Fits names, the
//   largest of them among the rows, and from the multipliers compute_powers
//   writes for a random key, over random blocks and blocks of all ones bits;
//
//   powers: the four multipliers compute_powers writes, for random keys and
//   for r's words all 0, all 2^26 - 1 and random below 2^26.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "poly1305_ifma_model.h"

#include "diff_driver.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define GROUP_ROWS 3000
#define POWER_ROWS 1000
#define GROUP_BYTES 256
#define DIGIT_BOUND ((UINT64_C(1) << 44) + (UINT64_C(1) << 17))
#define TOP_BOUND ((UINT64_C(1) << 42) + (UINT64_C(1) << 17))
#define WORD_BOUND (UINT32_C(1) << 26)

// A register in hex: 24 lanes of 8 bytes.
#define REGISTER_HEX (2 * 24 * 8)
// A group command holds three registers and 256 bytes; a reply holds four
// registers at most.
#define COMMAND_SIZE (64 + 3 * (REGISTER_HEX + 1) + 2 * GROUP_BYTES + 1)
#define REPLY_SIZE (4 * REGISTER_HEX + 1)

// A number below bound: the largest, one of the four below it, 0, or a
// random one, so the rows meet each bound the spec's proofs take.
static uint64_t digit_below(uint64_t bound) {
    switch (rng_next() % 6) {
    case 0:
        return bound - 1;
    case 1:
        return bound - 1 - (rng_next() & 3);
    case 2:
        return 0;
    default:
        return rng_next() % bound;
    }
}

static void random_register(poly1305_ifma_model_register *r) {
    for (int l = 0; l < 8; l++) {
        r->digit[0][l] = digit_below(DIGIT_BOUND);
        r->digit[1][l] = digit_below(DIGIT_BOUND);
        r->digit[2][l] = digit_below(TOP_BOUND);
    }
}

// Appends a register as the spec reads one: digit 0 of lanes 0 to 7 first,
// each lane 8 big-endian bytes in hex.
static size_t append_register(char *out, const poly1305_ifma_model_register *r) {
    uint8_t bytes[24 * 8];
    for (size_t i = 0; i < 3; i++) {
        for (size_t l = 0; l < 8; l++) {
            for (size_t j = 0; j < 8; j++) {
                bytes[8 * (8 * i + l) + j] = (uint8_t)(r->digit[i][l] >> (8 * (7 - j)));
            }
        }
    }
    return hex_encode(out, bytes, sizeof bytes);
}

// The multipliers compute_powers writes for a random key.
static void random_powers(poly1305_ifma_model_register powers[4]) {
    uint8_t key[POLY1305_KEY];
    rng_fill(key, sizeof key);
    poly1305 p;
    poly1305_ifma_model_init(&p, key);
    poly1305_ifma_model_powers(powers, p.r);
}

static void diff_group(void) {
    static char cmd[COMMAND_SIZE];
    static char want[REPLY_SIZE];
    for (int row = 0; row < GROUP_ROWS; row++) {
        poly1305_ifma_model_register h;
        poly1305_ifma_model_register first;
        poly1305_ifma_model_register second;
        poly1305_ifma_model_register out;
        uint8_t m[GROUP_BYTES];
        random_register(&h);
        if (row % 2 == 0) {
            random_register(&first);
            random_register(&second);
        } else {
            poly1305_ifma_model_register powers[4];
            random_powers(powers);
            // last_first and last_second, or by_16 and by_8.
            size_t pair = 2 * (rng_next() % 2);
            first = powers[pair];
            second = powers[pair + 1];
        }
        if (rng_next() % 8 == 0) {
            memset(m, 0xff, sizeof m);
        } else {
            rng_fill(m, sizeof m);
        }
        poly1305_ifma_model_group_step(&out, &h, m, &first, &second);
        size_t len = (size_t)snprintf(cmd, sizeof cmd, "poly1305_ifma_group ");
        len += append_register(cmd + len, &h);
        cmd[len++] = ' ';
        len += hex_encode(cmd + len, m, sizeof m);
        cmd[len++] = ' ';
        len += append_register(cmd + len, &first);
        cmd[len++] = ' ';
        (void)append_register(cmd + len, &second);
        (void)append_register(want, &out);
        expect(cmd, want);
    }
}

// r's words for a row: random below 2^26, all 2^26 - 1, all 0, or a random
// key's, which the clamp shapes.
static void power_words(uint32_t r[5], int row) {
    switch (row % 4) {
    case 0:
        for (size_t i = 0; i < 5; i++) {
            r[i] = WORD_BOUND - 1;
        }
        break;
    case 1:
        for (size_t i = 0; i < 5; i++) {
            r[i] = (uint32_t)(rng_next() % WORD_BOUND);
        }
        break;
    case 2: {
        uint8_t key[POLY1305_KEY];
        rng_fill(key, sizeof key);
        poly1305 p;
        poly1305_ifma_model_init(&p, key);
        memcpy(r, p.r, sizeof p.r);
        break;
    }
    default:
        for (size_t i = 0; i < 5; i++) {
            r[i] = (uint32_t)(rng_next() % 3 == 0 ? 0 : rng_next() % WORD_BOUND);
        }
        break;
    }
}

static void diff_powers(void) {
    static char cmd[COMMAND_SIZE];
    static char want[REPLY_SIZE];
    for (int row = 0; row < POWER_ROWS; row++) {
        uint32_t r[5];
        power_words(r, row);
        uint8_t words[20];
        for (size_t i = 0; i < 5; i++) {
            for (size_t j = 0; j < 4; j++) {
                words[4 * i + j] = (uint8_t)(r[i] >> (8 * (3 - j)));
            }
        }
        poly1305_ifma_model_register powers[4];
        poly1305_ifma_model_powers(powers, r);
        size_t len = (size_t)snprintf(cmd, sizeof cmd, "poly1305_ifma_powers ");
        (void)hex_encode(cmd + len, words, sizeof words);
        size_t at = 0;
        for (size_t k = 0; k < 4; k++) {
            at += append_register(want + at, &powers[k]);
        }
        expect(cmd, want);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff poly1305 ifma: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    diff_powers();
    diff_group();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff poly1305 ifma: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
