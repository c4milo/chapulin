// rsa_mont64_blocks.c's multiplication and square against rsa_mont64.c's
// loops, word for word (docs/decisions.md 118).
//
// The binary compiles every unit with -DRSA_MONT64_BLOCKS=1, under any
// compiler, so rsa_mont64_mont_mul and rsa_mont64_mont_square run the
// blocks for a word count that is a multiple of 4, as a clang build for
// arm64 runs them. test/rsa_mont64_loops.c compiles rsa_mont64.c once
// more with the blocks off, under second names: the loops, which the
// proofs, bin/rsa_equiv_test_compare and bin/rsa_equiv_test_sum hold to
// rsa_mont.c's 32-bit arithmetic.
//
// At every word count from 1 to the bound, under random odd moduli with
// the top bit set and under moduli whose words sit at an edge, both
// compute from the same operands and the test compares the words they
// write:
//
//   - the modulus record each init writes, whose r2 comes from
//     multiplications;
//   - the multiplication of a from 0, 1, m - 1, the top bit alone, all
//     ones and random values, which may be above m, as the call admits,
//     by b from 0, 1, m - 1, the top bit alone and random values below m,
//     with o apart from both, o on a and o on b;
//   - for each a below m, the multiplication of a by itself, apart from o
//     and in place, and the square, apart from o and in place;
//   - at a multiple of 4, rsa_mont64_blocks_square against
//     rsa_mont64_blocks_mul(o, a, a, mod), both before the last
//     subtraction, since rsa_mont64_mont_square runs the square only above
//     RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX words.
//
// A word count that is not a multiple of 4 runs the loops on both sides,
// which shows that the calls pick the blocks for no other count.
//
// The random values come from the seeded generator below, so an ordinary
// run replays exactly.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "rsa_mont64.h"
#include "rsa_mont64_blocks.h"

#if !RSA_MONT64_BLOCKS
#error "bin/rsa_blocks_equiv_test compiles with -DRSA_MONT64_BLOCKS=1"
#endif

// rsa_mont64.c's loops under second names (test/rsa_mont64_loops.c).
void rsa_mont64_loops_modulus_init(rsa_mont64_modulus *mod, const uint8_t *m, size_t m_len,
                                   size_t bits);
void rsa_mont64_loops_mont_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                               const rsa_mont64_modulus *mod);
void rsa_mont64_loops_mont_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod);

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define WORDS_MAX RSA_MONT64_WORDS_MAX

// xorshift64, as test/rsa_equiv_test.c writes it and for its reasons: a
// fixed default seed, so a mismatch reproduces bit for bit, and an
// environment variable to vary it. Never time().
#define RSA_BLOCKS_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = RSA_BLOCKS_DEFAULT_SEED;

// Reads CH_RSA_EQUIV_SEED, if set, as the seed, and returns the seed in
// use. A value that is not a number, or zero, keeps the default:
// xorshift64 is all zeroes forever from zero.
static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_RSA_EQUIV_SEED");
    if (text != NULL) {
        char *end = NULL;
        unsigned long long value = strtoull(text, &end, 0);
        if (end != text && *end == 0 && value != 0) {
            rng_state = (uint64_t)value;
        }
    }
    return rng_state;
}

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static int failures = 0;
static unsigned long multiplied = 0;
static unsigned long squared = 0;

// 1 when the k words of a are below those of m.
static int below(const uint64_t *a, const uint64_t *m, size_t k) {
    for (size_t i = k; i-- > 0;) {
        if (a[i] != m[i]) {
            return a[i] < m[i];
        }
    }
    return 0;
}

// A random value below m, by drawing k random words until they are: m's
// top bit is set, so a draw is below m about half the time or more.
static void random_below(uint64_t *a, const uint64_t *m, size_t k) {
    do {
        for (size_t i = 0; i < k; i++) {
            a[i] = rng_next();
        }
    } while (!below(a, m, k));
}

// The words the blocks wrote against the words the loops wrote, for one
// case. The first word that differs is printed.
static void compare(const char *case_name, const char *shape, size_t k, const uint64_t *blocks,
                    const uint64_t *loops) {
    for (size_t i = 0; i < k; i++) {
        if (blocks[i] != loops[i]) {
            failures++;
            (void)fprintf(stderr,
                          "FAIL %s, %s, at %zu words: word %zu is %016llx from the blocks and "
                          "%016llx from the loops\n",
                          case_name, shape, k, i, (unsigned long long)blocks[i],
                          (unsigned long long)loops[i]);
            return;
        }
    }
}

// a * b / R through both, in the three shapes: o apart from both, o on a
// and o on b. Each output starts from bytes the other does not, so a call
// that wrote nothing cannot agree with the other by chance.
static void compare_product(const char *case_name, const uint64_t *a, const uint64_t *b,
                            const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t loops[WORDS_MAX];
    uint64_t blocks[WORDS_MAX];
    memset(loops, 0x55, sizeof loops);
    rsa_mont64_loops_mont_mul(loops, a, b, mod);

    memset(blocks, 0xaa, sizeof blocks);
    rsa_mont64_mont_mul(blocks, a, b, mod);
    compare(case_name, "o apart", k, blocks, loops);

    memcpy(blocks, a, k * sizeof(uint64_t));
    rsa_mont64_mont_mul(blocks, blocks, b, mod);
    compare(case_name, "o on a", k, blocks, loops);

    memcpy(blocks, b, k * sizeof(uint64_t));
    rsa_mont64_mont_mul(blocks, a, blocks, mod);
    compare(case_name, "o on b", k, blocks, loops);
    multiplied += 3;
}

// The blocks' square against their multiplication of a by itself, both
// before the last subtraction. Each computes (a^2 + U m) / R for the one U
// below R that makes the sum a multiple of R, so the words and the top
// word are the same.
static void compare_block_square(const char *case_name, const uint64_t *a,
                                 const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t square_words[WORDS_MAX + 1];
    uint64_t product_words[WORDS_MAX + 1];
    memset(square_words, 0xaa, sizeof square_words);
    memset(product_words, 0x55, sizeof product_words);
    square_words[k] = rsa_mont64_blocks_square(square_words, a, mod);
    product_words[k] = rsa_mont64_blocks_mul(product_words, a, a, mod);
    compare(case_name, "the blocks' square and product before the subtraction", k + 1, square_words,
            product_words);
    squared++;
}

// a * a / R through both, for a below m: the multiplication with a and b
// one array, apart from o and in place, and the square in the same two
// shapes, all against the loops' square, which bin/rsa_equiv_test_compare
// and bin/rsa_equiv_test_sum hold to the loops' multiplication.
static void compare_square(const char *case_name, const uint64_t *a,
                           const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t loops[WORDS_MAX];
    uint64_t x[WORDS_MAX];
    uint64_t blocks[WORDS_MAX];
    memset(loops, 0x55, sizeof loops);
    rsa_mont64_loops_mont_square(loops, a, mod);

    memcpy(x, a, k * sizeof(uint64_t));
    memset(blocks, 0xaa, sizeof blocks);
    rsa_mont64_mont_mul(blocks, x, x, mod);
    compare(case_name, "a on b", k, blocks, loops);

    rsa_mont64_mont_mul(x, x, x, mod);
    compare(case_name, "o, a and b on one array", k, x, loops);

    memset(blocks, 0xaa, sizeof blocks);
    rsa_mont64_mont_square(blocks, a, mod);
    compare(case_name, "square, o apart", k, blocks, loops);

    memcpy(x, a, k * sizeof(uint64_t));
    rsa_mont64_mont_square(x, x, mod);
    compare(case_name, "square, o on a", k, x, loops);
    multiplied += 2;
    squared += 2;
    if (k % 4 == 0) {
        compare_block_square(case_name, a, mod);
    }
}

// Every case under one modulus of k words, given as len = 8k big-endian
// bytes with the top bit set.
static void run_modulus(const char *modulus_name, const uint8_t *n, size_t k) {
    size_t len = 8 * k;
    rsa_mont64_modulus mod;
    rsa_mont64_modulus loops_mod;
    rsa_mont64_modulus_init(&mod, n, len, 8 * len);
    rsa_mont64_loops_modulus_init(&loops_mod, n, len, 8 * len);
    compare(modulus_name, "the modulus words", k, mod.m, loops_mod.m);
    compare(modulus_name, "r2", k, mod.r2, loops_mod.r2);
    compare(modulus_name, "m0inv", 1, &mod.m0inv, &loops_mod.m0inv);

    // a: 0, 1, m - 1, the top bit alone, all ones, a random value below m
    // and a random value of k words. Rows 0, 1, 2, 3 and 5 are below m;
    // rows 4 and 6 may not be, which the multiplication admits for a.
    enum { A_ROWS = 7, B_ROWS = 6 };
    uint64_t a[A_ROWS][WORDS_MAX] = {{0}};
    a[1][0] = 1;
    memcpy(a[2], mod.m, k * sizeof(uint64_t));
    a[2][0] -= 1;
    a[3][k - 1] = UINT64_C(1) << 63;
    memset(a[4], 0xff, k * sizeof(uint64_t));
    random_below(a[5], mod.m, k);
    for (size_t i = 0; i < k; i++) {
        a[6][i] = rng_next();
    }
    // b, all below m: 0, 1, m - 1, the top bit alone and two random values.
    uint64_t b[B_ROWS][WORDS_MAX] = {{0}};
    b[1][0] = 1;
    memcpy(b[2], a[2], k * sizeof(uint64_t));
    b[3][k - 1] = UINT64_C(1) << 63;
    random_below(b[4], mod.m, k);
    random_below(b[5], mod.m, k);

    for (int i = 0; i < A_ROWS; i++) {
        for (int j = 0; j < B_ROWS; j++) {
            compare_product(modulus_name, a[i], b[j], &mod);
        }
    }
    static const int below_m[] = {0, 1, 2, 3, 5};
    for (size_t i = 0; i < sizeof below_m / sizeof below_m[0]; i++) {
        compare_square(modulus_name, a[below_m[i]], &mod);
    }
    for (int j = 4; j < B_ROWS; j++) {
        compare_square(modulus_name, b[j], &mod);
    }
}

// The big-endian bytes of the k words in words, top word first.
static void to_bytes(uint8_t *n, const uint64_t *words, size_t k) {
    for (size_t i = 0; i < k; i++) {
        uint64_t word = words[k - 1 - i];
        for (size_t j = 0; j < 8; j++) {
            n[8 * i + j] = (uint8_t)(word >> (56 - 8 * j));
        }
    }
}

// The moduli at k words: two random ones, and the moduli whose words sit
// at an edge, as test/rsa_equiv_test.c names them: all ones, the top and
// bottom bits alone, a low word of 1 and a low word of all ones under
// random words, and zero words between a random top word and a random low
// word. Each is odd with its top bit set.
static void run_word_count(size_t k) {
    uint64_t m[WORDS_MAX];
    uint8_t n[8 * WORDS_MAX];
    for (int r = 0; r < 2; r++) {
        for (size_t i = 0; i < k; i++) {
            m[i] = rng_next();
        }
        m[0] |= 1;
        m[k - 1] |= UINT64_C(1) << 63;
        to_bytes(n, m, k);
        run_modulus("a random modulus", n, k);
    }

    memset(m, 0xff, k * sizeof(uint64_t));
    to_bytes(n, m, k);
    run_modulus("all ones", n, k);

    memset(m, 0, k * sizeof(uint64_t));
    m[0] = 1;
    m[k - 1] |= UINT64_C(1) << 63;
    to_bytes(n, m, k);
    run_modulus("the top and bottom bits", n, k);

    for (size_t i = 0; i < k; i++) {
        m[i] = rng_next();
    }
    m[0] = 1;
    m[k - 1] |= UINT64_C(1) << 63;
    to_bytes(n, m, k);
    run_modulus("a low word of 1", n, k);

    m[0] = UINT64_MAX;
    to_bytes(n, m, k);
    run_modulus("a low word of all ones", n, k);

    memset(m, 0, k * sizeof(uint64_t));
    m[0] = rng_next() | 1;
    m[k - 1] = rng_next() | (UINT64_C(1) << 63);
    to_bytes(n, m, k);
    run_modulus("zero middle words", n, k);
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    for (size_t k = 1; k <= WORDS_MAX; k++) {
        run_word_count(k);
    }
    if (failures != 0) {
        (void)fprintf(stderr, "rsa_blocks_equiv_test: %d failure(s), seed 0x%llx\n", failures,
                      (unsigned long long)seed);
        return 1;
    }
    (void)printf(
        "rsa_blocks_equiv_test: %lu multiplications and %lu squares at 1 to %d words, seed "
        "0x%llx, all equal\n",
        multiplied, squared, (int)WORDS_MAX, (unsigned long long)seed);
    return 0;
}
