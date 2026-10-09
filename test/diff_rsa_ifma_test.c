// The AVX-512 IFMA arm of the differential oracle: rsa_ifma.c's kernel and
// rsa_mont.c's power_of_two_mod, compiled over the lane model as
// bin/rsa_ifma_model_test compiles them (test/rsa_ifma_model.c), against the
// same Lean spec process test/diff_test.c drives. spec/lean/Spec/RsaIfma.lean
// models the kernel's arithmetic from the C and proves what it computes: a
// product below 2m and congruent to a b 2^(-52n) mod m, normalize_digits
// keeping the number its lanes hold, power_of_two_mod writing 2^e mod m and
// rsa_ifma_public writing base^65537 mod m. These rows are what make those
// proofs about the C: an error in the transcription on either side fails a
// row.
//
// Its own main, as test/diff_p256_wide_test.c is: the kernel compiles only
// in a host object, and over the model only in a unit that defines
// CH_RSA_IFMA_MODEL, which no file bin/diff compiles does. The model is
// each instruction in portable C, so these rows run on every machine, and
// bin/rsa_ifma_equiv_test holds the instructions to the model on a CPU that
// has AVX-512 IFMA.
//
// At every word count from RSA_IFMA_WORDS_MIN to RSA_MONT64_WORDS_MAX, under
// the kinds of modulus test/rsa_ifma_inputs.h draws:
//
//   product: every lane almost_montgomery_product writes, for the operands 0,
//   1, m - 1 and 2m - 1 and for random ones below m and below 2m;
//
//   power: the words power_of_two_mod writes for the exponent rsa_vp1_cpu
//   passes, 104 n, for 64 (k - 1), the exponent of no step, for
//   64 (k - 1) + 63, whose start is m's top bit, and for a random exponent.
//
// At the word counts where the register count changes, and at the first and
// the last, rsa_ifma_public's bytes, for a random base and in turn for 0, 1,
// m - 1, m and 2^(64k) - 1, with the digit_r2 power_of_two_mod writes, as
// rsa_vp1_cpu runs them. At RSA-2048, RSA-3072 and RSA-4096, each product of
// rsa_ifma_public's chain for a random base. And normalize_digits on lanes
// chosen for its carries, at every register count up to ten.
#define CH_RSA_IFMA_MODEL 1

#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "cpu_cfg.h"
#include "rsa_ifma.h"
#include "rsa_ifma_test.h"
#include "rsa_mont64.h"

#include "diff_driver.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

_Static_assert(
    RSA_MONT64_WORDS_MAX == 64,
    "bin/diff_rsa_ifma builds at the 512-byte bound, the most registers the kernel takes");

#define WORDS_MAX RSA_MONT64_WORDS_MAX
#define DIGIT_MASK ((UINT64_C(1) << 52) - 1)
#define HEX_LEN(n) (2 * (n) + 1)
#define NORMALIZE_ROWS 2000

// A random exponent of a power row is at most this much above 64 (k - 1),
// inside the spec's bound of 64 (k + 128).
#define EXPONENT_SPAN ((size_t)64 * 128)

// A command holds an operation, two numbers and three numbers of up to
// WORDS_MAX + 1 words in hex; a reply holds RSA_IFMA_TEST_LANES lanes of 8
// bytes in hex.
#define COMMAND_SIZE (64 + 3 * HEX_LEN(8 * (WORDS_MAX + 1)))
#define REPLY_SIZE HEX_LEN(8 * RSA_IFMA_TEST_LANES)

// The kinds of modulus test/rsa_ifma_inputs.h draws, from this file's
// generator, whose names that header also defines: random words with the
// top and bottom bits set, 2^(64k) - 1, 2^(64k - 1) + 1, and at an even k
// test/rsa_equiv_test.c's (B^(k + 1) + 1) / (B + 1) for B = 2^64. It returns
// 0 for the last kind at an odd k, which has no such modulus.
enum { MODULUS_KINDS = 5 };
static int modulus_of_kind(uint8_t *n, size_t words, int kind) {
    size_t n_len = 8 * words;
    memset(n, 0, n_len);
    switch (kind) {
    case 0:
    case 1:
        rng_fill(n, n_len);
        n[0] |= 0x80;
        n[n_len - 1] |= 1;
        return 1;
    case 2:
        memset(n, 0xff, n_len);
        return 1;
    case 3:
        n[0] = 0x80;
        n[n_len - 1] = 1;
        return 1;
    default:
        if (words % 2 != 0) {
            return 0;
        }
        for (size_t word = 1; word < words; word += 2) {
            memset(n + n_len - 8 * (word + 1), 0xff, 8);
        }
        n[n_len - 1] = 1;
        return 1;
    }
}

// words[0..count) as 8 * count big-endian bytes.
static void words_to_bytes(uint8_t *bytes, const uint64_t *words, size_t count) {
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < 8; j++) {
            bytes[8 * (count - 1 - i) + (7 - j)] = (uint8_t)(words[i] >> (8 * j));
        }
    }
}

// Appends a space and words[0..count) in hex to the command at cmd[len].
static size_t append_words(char *cmd, size_t len, const uint64_t *words, size_t count) {
    uint8_t bytes[8 * (WORDS_MAX + 1)];
    words_to_bytes(bytes, words, count);
    cmd[len++] = ' ';
    return len + hex_encode(cmd + len, bytes, 8 * count);
}

// The reply the spec writes for lanes[0..count): each lane as 8 big-endian
// bytes in hex, lane 0 first.
static void lanes_reply(char *want, const uint64_t *lanes, size_t count) {
    uint8_t bytes[8 * RSA_IFMA_TEST_LANES] = {0};
    for (size_t j = 0; j < count; j++) {
        words_to_bytes(bytes + 8 * j, &lanes[j], 1);
    }
    (void)hex_encode(want, bytes, 8 * count);
}

static size_t lane_count_of(size_t k) {
    return 8 * ((rsa_ifma_digit_count(k) + 7) / 8);
}

// One product: the lanes the kernel writes for the digits a_digits and
// b_digits, against the spec's product of the numbers a and b, k + 1 words
// each, under the modulus record's m and m0inv. The spec refuses an m0inv
// that is not -m^-1 mod 2^52 and operands at or above 2m.
static void diff_product_row(const rsa_mont64_modulus *mod, const uint64_t *a,
                             const uint64_t *a_digits, const uint64_t *b, const uint64_t *b_digits,
                             uint64_t *out) {
    static char cmd[COMMAND_SIZE];
    static char want[REPLY_SIZE];
    size_t k = mod->words;
    rsa_ifma_model_product(out, a_digits, b_digits, mod);
    size_t len = (size_t)snprintf(cmd, sizeof cmd, "rsa_ifma_product %zu %llu", k,
                                  (unsigned long long)(mod->m0inv & DIGIT_MASK));
    len = append_words(cmd, len, mod->m, k);
    len = append_words(cmd, len, a, k + 1);
    (void)append_words(cmd, len, b, k + 1);
    lanes_reply(want, out, lane_count_of(k));
    expect(cmd, want);
}

// A product of operands given as k + 1 words, which the row converts to
// digits with words_to_digits.
static void diff_product(const rsa_mont64_modulus *mod, const uint64_t *a, const uint64_t *b) {
    size_t k = mod->words;
    uint64_t a_digits[RSA_IFMA_TEST_LANES];
    uint64_t b_digits[RSA_IFMA_TEST_LANES];
    uint64_t out[RSA_IFMA_TEST_LANES];
    rsa_ifma_model_to_digits(a_digits, a, k + 1, k);
    rsa_ifma_model_to_digits(b_digits, b, k + 1, k);
    diff_product_row(mod, a, a_digits, b, b_digits, out);
}

// o = x + y over k + 1 words, for a sum that fits them.
static void add_words(uint64_t *o, const uint64_t *x, const uint64_t *y, size_t count) {
    ct_u128 carry = 0;
    for (size_t i = 0; i < count; i++) {
        carry += (ct_u128)x[i] + y[i];
        o[i] = (uint64_t)carry;
        carry >>= 64;
    }
}

// The operands of a row, k + 1 words each: 0, 1, m - 1 and 2m - 1, and a
// random number below m and the same number plus m, below 2m.
enum {
    OPERAND_ZERO,
    OPERAND_ONE,
    OPERAND_M_LESS_ONE,
    OPERAND_TWO_M_LESS_ONE,
    OPERAND_RANDOM,
    OPERAND_RANDOM_PLUS_M
};
static void operand(uint64_t *words, const rsa_mont64_modulus *mod, int which) {
    size_t k = mod->words;
    uint64_t m[WORDS_MAX + 1];
    memcpy(m, mod->m, k * sizeof(uint64_t));
    m[k] = 0;
    memset(words, 0, (k + 1) * sizeof(uint64_t));
    switch (which) {
    case OPERAND_ZERO:
        break;
    case OPERAND_ONE:
        words[0] = 1;
        break;
    case OPERAND_M_LESS_ONE:
        memcpy(words, m, (k + 1) * sizeof(uint64_t));
        words[0] -= 1; // m is odd
        break;
    case OPERAND_TWO_M_LESS_ONE:
        add_words(words, m, m, k + 1);
        words[0] -= 1; // 2m is even, and its low word is at least 2
        break;
    default:
        for (size_t i = 0; i < k; i++) {
            words[i] = rng_next();
        }
        words[k - 1] %= m[k - 1];
        if (which == OPERAND_RANDOM_PLUS_M) {
            add_words(words, words, m, k + 1);
        }
        break;
    }
}

static void diff_products(const rsa_mont64_modulus *mod) {
    static const int PAIRS[][2] = {
        {OPERAND_ZERO,           OPERAND_M_LESS_ONE    },
        {OPERAND_ONE,            OPERAND_TWO_M_LESS_ONE},
        {OPERAND_TWO_M_LESS_ONE, OPERAND_TWO_M_LESS_ONE},
        {OPERAND_RANDOM,         OPERAND_RANDOM_PLUS_M },
        {OPERAND_RANDOM_PLUS_M,  OPERAND_RANDOM_PLUS_M },
    };
    for (size_t i = 0; i < sizeof PAIRS / sizeof PAIRS[0]; i++) {
        uint64_t a[WORDS_MAX + 1];
        uint64_t b[WORDS_MAX + 1];
        operand(a, mod, PAIRS[i][0]);
        operand(b, mod, PAIRS[i][1]);
        diff_product(mod, a, b);
    }
}

// power_of_two_mod's k words for one exponent against the spec's.
static void diff_power_row(const rsa_mont64_modulus *mod, size_t exponent, uint64_t *rem) {
    static char cmd[COMMAND_SIZE];
    static char want[HEX_LEN(8 * WORDS_MAX)];
    size_t k = mod->words;
    uint8_t bytes[8 * WORDS_MAX];
    rsa_ifma_model_power_of_two_mod(rem, mod->m, k, exponent);
    size_t len = (size_t)snprintf(cmd, sizeof cmd, "rsa_ifma_power_of_two %zu", k);
    len = append_words(cmd, len, mod->m, k);
    (void)snprintf(cmd + len, sizeof cmd - len, " %zu", exponent);
    words_to_bytes(bytes, rem, k);
    (void)hex_encode(want, bytes, 8 * k);
    expect(cmd, want);
}

static void diff_powers(const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t rem[WORDS_MAX];
    diff_power_row(mod, 104 * rsa_ifma_digit_count(k), rem);
    diff_power_row(mod, 64 * (k - 1), rem);
    diff_power_row(mod, 64 * (k - 1) + 63, rem);
    diff_power_row(mod, 64 * (k - 1) + rng_below(EXPONENT_SPAN), rem);
}

// rsa_ifma_public's n_len bytes for one base against the spec's, with the
// digit_r2 power_of_two_mod writes: rsa_vp1_cpu's two calls under
// CH_CPU_AVX512_IFMA, each made here, so that the row runs the kernel
// whatever the dispatch decides. rsa_vp1_cpu itself must then write the
// same bytes, so the row holds its arguments to the two calls too.
static void diff_public_row(const uint8_t *n, const rsa_mont64_modulus *mod, const uint8_t *base) {
    static char cmd[COMMAND_SIZE];
    static char want[HEX_LEN(8 * WORDS_MAX)];
    size_t k = mod->words;
    size_t n_len = 8 * k;
    uint64_t digit_r2[WORDS_MAX];
    uint8_t out[8 * WORDS_MAX];
    uint8_t dispatched[8 * WORDS_MAX];
    rsa_ifma_model_power_of_two_mod(digit_r2, mod->m, k, 104 * rsa_ifma_digit_count(k));
    rsa_ifma_model_public(out, base, n_len, mod, digit_r2);
    size_t len = (size_t)snprintf(cmd, sizeof cmd, "rsa_ifma_public %zu ", k);
    len += hex_encode(cmd + len, n, n_len);
    cmd[len++] = ' ';
    (void)hex_encode(cmd + len, base, n_len);
    (void)hex_encode(want, out, n_len);
    expect(cmd, want);
    rsa_ifma_model_vp1_cpu(CH_CPU_PROBED | CH_CPU_AVX512_IFMA, n, n_len, base, dispatched);
    if (memcmp(dispatched, out, n_len) != 0) {
        (void)fprintf(stderr, "diff mismatch: rsa_vp1_cpu under the bit against the row above\n");
        exit(1);
    }
}

// A random base, and in turn by kind 0, 1, m - 1, m and 2^(64k) - 1: every
// base the call takes, the ones at or above m among them.
static void diff_publics(const uint8_t *n, const rsa_mont64_modulus *mod, int kind) {
    size_t n_len = 8 * mod->words;
    uint8_t base[8 * WORDS_MAX];
    rng_fill(base, n_len);
    diff_public_row(n, mod, base);
    memset(base, 0, n_len);
    switch (kind) {
    case 0:
        break;
    case 1:
        base[n_len - 1] = 1;
        break;
    case 2:
        memcpy(base, n, n_len);
        base[n_len - 1] -= 1; // n is odd
        break;
    case 3:
        memcpy(base, n, n_len);
        break;
    default:
        memset(base, 0xff, n_len);
        break;
    }
    diff_public_row(n, mod, base);
}

// rsa_ifma_public's chain of products for a random base, each product a
// row: the first of the base and digit_r2, sixteen squares and the last of
// the base and the power. Each row reads the digits the product before it
// wrote, and the spec reads the number they hold.
static void diff_chain(const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t base[WORDS_MAX + 1];
    uint64_t base_digits[RSA_IFMA_TEST_LANES];
    uint64_t power[WORDS_MAX + 1];
    uint64_t power_digits[RSA_IFMA_TEST_LANES];
    uint64_t out[RSA_IFMA_TEST_LANES];
    for (size_t i = 0; i < k; i++) {
        base[i] = rng_next();
    }
    base[k] = 0;
    rsa_ifma_model_power_of_two_mod(power, mod->m, k, 104 * rsa_ifma_digit_count(k));
    power[k] = 0;
    rsa_ifma_model_to_digits(base_digits, base, k + 1, k);
    rsa_ifma_model_to_digits(power_digits, power, k + 1, k);
    for (int step = 0; step < 18; step++) {
        if (step == 0 || step == 17) {
            diff_product_row(mod, base, base_digits, power, power_digits, out);
        } else {
            diff_product_row(mod, power, power_digits, power, power_digits, out);
        }
        memcpy(power_digits, out, sizeof out);
        rsa_ifma_model_to_words(power, power_digits, k);
    }
}

// Whether the kernel's register count changes at k, or k is the first or
// the last word count it takes.
static int register_count_edge(size_t k) {
    size_t here = lane_count_of(k);
    return k == RSA_IFMA_WORDS_MIN || k == WORDS_MAX || lane_count_of(k - 1) != here ||
           lane_count_of(k + 1) != here;
}

static void diff_modulus(const uint8_t *n, size_t k, int kind) {
    rsa_mont64_modulus mod;
    rsa_mont64_modulus_load(&mod, n, 8 * k);
    diff_products(&mod);
    diff_powers(&mod);
    if (register_count_edge(k)) {
        diff_publics(n, &mod, kind);
    }
    if (kind == 0 && (k == 32 || k == 48 || k == 64)) {
        diff_chain(&mod);
    }
}

// Lanes that normalize_digits's rare steps act on, as test/rsa_ifma_inputs.h
// draws them: lanes at 2^52 - 1, which pass a carry on, in runs that cross
// a register's edge, lanes just below and just above 2^52, lanes with carry
// bits above 52 and all ones or nearly so below them, and random lanes of
// up to 64 bits.
static uint64_t extreme_lane(void) {
    switch (rng_next() % 7) {
    case 0:
    case 1:
        return DIGIT_MASK;
    case 2:
        return DIGIT_MASK - (rng_next() & 3);
    case 3:
        return (UINT64_C(1) << 52) + (rng_next() & 3);
    case 4:
        return ((rng_next() & 0xfff) << 52) | (DIGIT_MASK - (rng_next() & 1));
    case 5:
        return rng_next() >> (rng_next() % 64);
    default:
        return rng_next();
    }
}

static void diff_normalize(void) {
    static char cmd[COMMAND_SIZE];
    static char want[REPLY_SIZE];
    for (int row = 0; row < NORMALIZE_ROWS; row++) {
        size_t registers = 1 + rng_below(RSA_IFMA_TEST_LANES / 8);
        size_t count = 8 * registers;
        uint64_t lanes[RSA_IFMA_TEST_LANES] = {0};
        for (size_t j = 0; j < count; j++) {
            lanes[j] = extreme_lane();
        }
        size_t len = (size_t)snprintf(cmd, sizeof cmd, "rsa_ifma_normalize ");
        lanes_reply(cmd + len, lanes, count);
        rsa_ifma_model_normalize(lanes, registers);
        lanes_reply(want, lanes, count);
        expect(cmd, want);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff rsa ifma: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    diff_normalize();
    for (size_t k = RSA_IFMA_WORDS_MIN; k <= WORDS_MAX; k++) {
        for (int kind = 0; kind < MODULUS_KINDS; kind++) {
            uint8_t n[8 * WORDS_MAX];
            if (modulus_of_kind(n, k, kind)) {
                diff_modulus(n, k, kind);
            }
        }
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff rsa ifma: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
