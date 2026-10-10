// The AVX2 arm of the differential oracle: rsa_avx2.c's kernel and
// rsa_mont.c's dispatch to it, compiled over the lane model as
// bin/rsa_avx2_model_test compiles them (test/rsa_avx2_model.c), against
// the same Lean spec process test/diff_test.c drives.
// spec/lean/Spec/RsaAvx2.lean models the kernel's arithmetic from the C,
// lane by lane, and proves what it computes: a product below 2m and
// congruent to a b 2^(-Dn) mod m, a square that puts in each lane what the
// multiplication of a by itself puts there, no lane past 2^64, and
// rsa_avx2_public writing base^65537 mod m. These rows are what make those
// proofs about the C: an error in the transcription on either side fails a
// row.
//
// Its own main, as test/diff_rsa_ifma_test.c is: the kernel compiles only
// in a host object, and over the model only in a unit that defines
// CH_RSA_AVX2_MODEL, which no file bin/diff compiles does. The model is
// each instruction in portable C, so these rows run on every machine, and
// bin/rsa_avx2_equiv_test holds the instructions to the model on a CPU
// that has AVX2.
//
// At every word count from RSA_AVX2_WORDS_MIN to RSA_MONT64_WORDS_MAX,
// under the kinds of modulus test/diff_rsa_ifma_test.c draws, every digit
// of the multiplications of pairs of the operands 0, 1, m - 1, 2m - 1 and
// random ones below m and below 2m, and of the squares of 2m - 1 and of
// the random ones. At the word counts where the group count or the digit
// width changes, and at the first and the last, rsa_vp1_cpu's bytes under
// CH_CPU_AVX2, which run power_of_two_mod and rsa_avx2_public, for a
// random base and in turn for 0, 1, m - 1, m and 2^(64k) - 1. At RSA-2048,
// RSA-3072 and RSA-4096, each product of rsa_avx2_public's chain for a
// random base.
#define CH_RSA_AVX2_MODEL 1

#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "cpu_cfg.h"
#include "rsa_avx2.h"
#include "rsa_avx2_test.h"
#include "rsa_mont64.h"

#include "diff_driver.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

_Static_assert(RSA_MONT64_WORDS_MAX == 64,
               "bin/diff_rsa_avx2 builds at the 512-byte bound, where the kernel holds both "
               "digit widths");

#define WORDS_MAX RSA_MONT64_WORDS_MAX
#define HEX_LEN(n) (2 * (n) + 1)
// The zero lanes below a number's digit 0 in rsa_avx2.c's layout.
#define PAD 4
// The most digits a number takes: 152 at RSA-4096.
#define DIGITS_MAX 152

// A command holds an operation, two numbers and three numbers of up to
// WORDS_MAX + 1 words in hex; a reply holds DIGITS_MAX digits of 8 bytes in
// hex.
#define COMMAND_SIZE (64 + 3 * HEX_LEN(8 * (WORDS_MAX + 1)))
#define REPLY_SIZE HEX_LEN(8 * DIGITS_MAX)

// The kinds of modulus test/diff_rsa_ifma_test.c draws: random words with
// the top and bottom bits set, 2^(64k) - 1, 2^(64k - 1) + 1 and at an even
// k (B^(k + 1) + 1) / (B + 1) for B = 2^64. It returns 0 for the last kind
// at an odd k, which has no such modulus.
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

// The reply the spec writes for a number's n digits: each digit as 8
// big-endian bytes in hex, digit 0 first.
static void digits_reply(char *want, const uint64_t *number, size_t digit_count) {
    uint8_t bytes[8 * DIGITS_MAX] = {0};
    for (size_t j = 0; j < digit_count; j++) {
        words_to_bytes(bytes + 8 * j, &number[PAD + j], 1);
    }
    (void)hex_encode(want, bytes, 8 * digit_count);
}

// The record's k0, the low D bits of rsa_mont64.c's -m^-1 mod 2^64.
static uint64_t k0_of(const rsa_mont64_modulus *mod) {
    return mod->m0inv & (((uint64_t)1 << RSA_AVX2_DIGIT_BITS(mod->words)) - 1);
}

// One product: the digits the kernel writes for the numbers a_number and
// b_number, against the spec's product of the numbers a and b, k + 1 words
// each, under the modulus record's m and k0, or with square set the
// square of a. The spec refuses a k0 that is not -m^-1 mod 2^D and
// operands at or above 2m.
static void diff_product_row(const rsa_mont64_modulus *mod, const uint64_t *a,
                             const uint64_t *a_number, const uint64_t *b, const uint64_t *b_number,
                             int square, uint64_t *out) {
    static char cmd[COMMAND_SIZE];
    static char want[REPLY_SIZE];
    size_t k = mod->words;
    memset(out, 0, RSA_AVX2_TEST_LANES * sizeof(uint64_t));
    size_t len;
    if (square) {
        rsa_avx2_model_square(out, a_number, mod);
        len = (size_t)snprintf(cmd, sizeof cmd, "rsa_avx2_square %zu %llu", k,
                               (unsigned long long)k0_of(mod));
        len = append_words(cmd, len, mod->m, k);
        (void)append_words(cmd, len, a, k + 1);
    } else {
        rsa_avx2_model_multiply(out, a_number, b_number, mod);
        len = (size_t)snprintf(cmd, sizeof cmd, "rsa_avx2_multiply %zu %llu", k,
                               (unsigned long long)k0_of(mod));
        len = append_words(cmd, len, mod->m, k);
        len = append_words(cmd, len, a, k + 1);
        (void)append_words(cmd, len, b, k + 1);
    }
    digits_reply(want, out, rsa_avx2_digit_count(k));
    expect(cmd, want);
}

// A multiplication or a square of operands given as k + 1 words, which
// the row converts to numbers with words_to_digits.
static void diff_product(const rsa_mont64_modulus *mod, const uint64_t *a, const uint64_t *b,
                         int square) {
    size_t k = mod->words;
    uint64_t a_number[RSA_AVX2_TEST_LANES];
    uint64_t b_number[RSA_AVX2_TEST_LANES];
    uint64_t out[RSA_AVX2_TEST_LANES];
    rsa_avx2_model_to_digits(a_number, a, k + 1, k);
    rsa_avx2_model_to_digits(b_number, b, k + 1, k);
    diff_product_row(mod, a, a_number, b, b_number, square, out);
}

// o = x + y over count words, for a sum that fits them.
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
        diff_product(mod, a, b, 0);
    }
    static const int SQUARES[] = {OPERAND_TWO_M_LESS_ONE, OPERAND_RANDOM, OPERAND_RANDOM_PLUS_M};
    for (size_t i = 0; i < sizeof SQUARES / sizeof SQUARES[0]; i++) {
        uint64_t a[WORDS_MAX + 1];
        operand(a, mod, SQUARES[i]);
        diff_product(mod, a, a, 1);
    }
}

// rsa_vp1_cpu's n_len bytes under CH_CPU_AVX2 for one base, which runs
// power_of_two_mod and rsa_avx2_public for the moduli these rows draw,
// against the spec's public operation, which computes its power of two
// with its own model of power_of_two_mod. The call must also run the
// kernel once.
static void diff_public_row(const uint8_t *n, size_t k, const uint8_t *base) {
    static char cmd[COMMAND_SIZE];
    static char want[HEX_LEN(8 * WORDS_MAX)];
    size_t n_len = 8 * k;
    uint8_t out[8 * WORDS_MAX];
    rsa_avx2_model_public_calls = 0;
    rsa_avx2_model_vp1_cpu(CH_CPU_PROBED | CH_CPU_AVX2, n, n_len, base, out);
    if (rsa_avx2_model_public_calls != 1) {
        (void)fprintf(stderr, "diff mismatch: rsa_vp1_cpu under the bit ran the kernel %lu times\n",
                      rsa_avx2_model_public_calls);
        exit(1);
    }
    size_t len = (size_t)snprintf(cmd, sizeof cmd, "rsa_avx2_public %zu ", k);
    len += hex_encode(cmd + len, n, n_len);
    cmd[len++] = ' ';
    (void)hex_encode(cmd + len, base, n_len);
    (void)hex_encode(want, out, n_len);
    expect(cmd, want);
}

// A random base, and in turn by kind 0, 1, m - 1, m and 2^(64k) - 1: every
// base the call takes, the ones at or above m among them.
static void diff_publics(const uint8_t *n, size_t k, int kind) {
    size_t n_len = 8 * k;
    uint8_t base[8 * WORDS_MAX];
    rng_fill(base, n_len);
    diff_public_row(n, k, base);
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
    diff_public_row(n, k, base);
}

// rem = 2^(2Dn) mod m by doublings, which share nothing with rsa_mont.c's
// division: the digit_r2 rsa_avx2_public takes.
static void power_by_doublings(uint64_t *rem, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    memset(rem, 0, k * sizeof(uint64_t));
    rem[0] = 1;
    for (size_t e = 0; e < rsa_avx2_r2_exponent(k); e++) {
        rsa_mont64_add(rem, rem, rem, mod);
    }
}

// rsa_avx2_public's chain of products for a random base, each product a
// row: the first of the base and digit_r2, sixteen squares and the last of
// the base and the power. Each row reads the number the product before it
// wrote, and the spec reads the number it holds.
static void diff_chain(const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t base[WORDS_MAX + 1];
    uint64_t base_number[RSA_AVX2_TEST_LANES];
    uint64_t power[WORDS_MAX + 1];
    uint64_t power_number[RSA_AVX2_TEST_LANES];
    uint64_t out[RSA_AVX2_TEST_LANES];
    for (size_t i = 0; i < k; i++) {
        base[i] = rng_next();
    }
    base[k] = 0;
    power_by_doublings(power, mod);
    power[k] = 0;
    rsa_avx2_model_to_digits(base_number, base, k + 1, k);
    rsa_avx2_model_to_digits(power_number, power, k + 1, k);
    for (int step = 0; step < 18; step++) {
        if (step == 0 || step == 17) {
            diff_product_row(mod, base, base_number, power, power_number, 0, out);
        } else {
            diff_product_row(mod, power, power_number, power, power_number, 1, out);
        }
        memcpy(power_number, out, sizeof out);
        rsa_avx2_model_to_words(power, power_number, k);
    }
}

static size_t group_count_of(size_t k) {
    return (rsa_avx2_digit_count(k) + 3) / 4;
}

// Whether the kernel's group count or digit width changes at k, or k is
// the first or the last word count it takes.
static int group_count_edge(size_t k) {
    size_t here = group_count_of(k);
    return k == RSA_AVX2_WORDS_MIN || k == WORDS_MAX || group_count_of(k - 1) != here ||
           group_count_of(k + 1) != here || RSA_AVX2_DIGIT_BITS(k - 1) != RSA_AVX2_DIGIT_BITS(k) ||
           RSA_AVX2_DIGIT_BITS(k + 1) != RSA_AVX2_DIGIT_BITS(k);
}

static void diff_modulus(const uint8_t *n, size_t k, int kind) {
    rsa_mont64_modulus mod;
    rsa_mont64_modulus_load(&mod, n, 8 * k);
    diff_products(&mod);
    if (group_count_edge(k)) {
        diff_publics(n, k, kind);
    }
    if (kind == 0 && (k == 32 || k == 48 || k == 64)) {
        diff_chain(&mod);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff rsa avx2: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    for (size_t k = RSA_AVX2_WORDS_MIN; k <= WORDS_MAX; k++) {
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
    (void)printf("diff rsa avx2: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
