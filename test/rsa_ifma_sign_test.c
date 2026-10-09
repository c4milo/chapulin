// bin/rsa_ifma_sign_model_test and bin/rsa_ifma_sign_equiv_test:
// rsa_ifma_sign.c's two exponentiations against rsa_sign64.c's window,
// word for word, and rsa_sign64_sp1 under a ch_cfg.cpu value that names
// AVX-512 IFMA against the same call under one that does not, byte for
// byte (docs/decisions.md 120). The window is the reference:
// bin/rsa_sign_equiv_test holds it to rsa_sign.c's ladder.
//
// Two builds of this file, each with a twin at the 384-byte bound, whose
// kernel has copies of the product for three and four registers and no
// fifth. bin/rsa_ifma_sign_model_test compiles every unit under
// CH_RSA_IFMA_MODEL with -Itest, so rsa_ifma_sign.c, rsa_ifma.c's public
// operation and the dispatch to both run over test/rsa_ifma_model_lanes.h
// on any host, which runs the kernel's own text on every machine.
// bin/rsa_ifma_sign_equiv_test compiles them on the instructions. On
// another architecture it says so and passes, and on an x86-64 CPU
// without AVX-512 IFMA it skips, unless CH_REQUIRE_AVX512_IFMA is 1
// (test/x86_kernels_cpu.h): Intel's emulator, SDE, runs it under that
// variable in the nightly.
//
// What it compares:
//
//   - rsa_ifma_sign_power_pair against two calls of rsa_sign64_power, at
//     every prime word count from 16 to RSA_IFMA_SIGN_WORDS_MAX on the
//     instructions, and over the model at the first and the last word
//     count each register count takes. Each runs under moduli of four
//     shapes: random with the top bit set, all ones, the top bit and 1,
//     and a top word half full, the primes of RSA-2112. The bases are 0,
//     1, m - 1 and random ones, in the domain; the exponents are zero,
//     all ones, 1, every digit value in turn, the top bit alone and random
//     ones, of eight bytes, and one random exponent as long as the prime.
//     Each output is compared once on a base of its own and once written
//     over its base.
//   - rsa_sign64_sp1 under the two values, for the four keys of
//     test/rsa_sign_vectors.h this build's bound takes, the messages 0, 1,
//     n - 1 and random ones, and a key with one bit of dp changed, which
//     both refuse with sig untouched. Each call under the IFMA value must
//     run the kernel once and wipe the stack below it twice, after the
//     exponentiations and after the check, and each call under the other
//     value must do neither, nor a call whose value names IFMA without the
//     multiply bit.
//   - state_finish, the end of each exponentiation, at the top word: a
//     power at or above 2^(64k) and below 2m, which only the word above
//     the k words holds, must come out reduced below m. A modulus with
//     its top word all ones takes such a power from m + 1 up.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "x86_kernels_cpu.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#if !defined(__x86_64__) && !defined(CH_RSA_IFMA_MODEL)

int main(void) {
    (void)printf("SKIP rsa_ifma_sign equivalence: the AVX-512 IFMA kernel is x86-64 only "
                 "(rsa_ifma_sign.h)\n");
    return 0;
}

#else

#include "cpu_cfg.h"
#include "rsa_ifma.h"
#include "rsa_ifma_sign.h"
#include "rsa_ifma_sign_test.h"
#include "rsa_mont64.h"
#include "rsa_sign.h"
#include "rsa_sign64.h"
#include "rsa_sign_key.h"

#define WINDOW_CPU (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY)
#define IFMA_CPU (WINDOW_CPU | CH_CPU_AVX512_IFMA)

#ifdef CH_RSA_IFMA_MODEL
#define WHERE "model"
#else
#define WHERE "instructions"
#endif

#define PRIME_WORDS RSA_IFMA_SIGN_WORDS_MAX
#define PRIME_BYTES (8 * PRIME_WORDS)
#define SHORT_EXPONENT 8

static int failures = 0;
static unsigned long compared = 0;

// xorshift64, as test/rsa_equiv_test.c writes it and for its reasons.
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static void rng_fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(rng_next() >> 56);
    }
}

static void check_words(const char *what, size_t k, const uint64_t *want, const uint64_t *got) {
    if (memcmp(want, got, k * sizeof(uint64_t)) == 0) {
        compared++;
        return;
    }
    failures++;
    (void)fprintf(stderr, "FAIL %s at %zu words\n", what, k);
    for (size_t i = k; i-- > 0;) {
        if (want[i] != got[i]) {
            (void)fprintf(stderr, "  word %zu: want %016llx got %016llx\n", i,
                          (unsigned long long)want[i], (unsigned long long)got[i]);
            break;
        }
    }
}

static void check(int ok, const char *what, size_t size) {
    if (ok) {
        compared++;
        return;
    }
    failures++;
    (void)fprintf(stderr, "FAIL %s, at %zu\n", what, size);
}

// A modulus of k words in the shape kind names, odd, in bytes. Returns its
// bit length.
#define MODULUS_KINDS 4
static size_t modulus_of_kind(uint8_t *bytes, size_t k, int kind) {
    size_t len = 8 * k;
    size_t bits = 8 * len;
    rng_fill(bytes, len);
    switch (kind) {
    case 0:
        bytes[0] |= 0x80;
        break;
    case 1:
        memset(bytes, 0xff, len);
        break;
    case 2:
        memset(bytes, 0, len);
        bytes[0] = 0x80;
        break;
    default:
        // The top word half full: 32 bits below a whole number of words.
        memset(bytes, 0, 4);
        bytes[4] |= 0x80;
        bits -= 32;
        break;
    }
    bytes[len - 1] |= 1;
    return bits;
}

// A base below m in the domain of mod, in the shape kind names: 0, 1,
// m - 1 or random, each multiplied by R^2 / R.
#define BASE_KINDS 4
static void base_of_kind(uint64_t *base, const rsa_mont64_modulus *mod, int kind) {
    size_t k = mod->words;
    uint64_t plain[PRIME_WORDS] = {0};
    if (kind == 1) {
        plain[0] = 1;
    } else if (kind == 2) {
        memcpy(plain, mod->m, k * sizeof(uint64_t));
        plain[0] -= 1; // m is odd
    } else if (kind == 3) {
        for (size_t i = 0; i < k; i++) {
            plain[i] = rng_next();
        }
    }
    rsa_mont64_mont_mul(base, plain, mod->r2, mod);
}

// An exponent of len bytes in the shape kind names.
#define EXPONENT_KINDS 6
static void exponent_of_kind(uint8_t *e, size_t len, int kind) {
    memset(e, 0, len);
    switch (kind) {
    case 0:
        break;
    case 1:
        memset(e, 0xff, len);
        break;
    case 2:
        e[len - 1] = 1;
        break;
    case 3:
        // Every digit value in turn, from the most significant.
        for (size_t i = 0; i < len; i++) {
            e[i] = (uint8_t)((((2 * i) & 15) << 4) | ((2 * i + 1) & 15));
        }
        break;
    case 4:
        e[0] = 0x80;
        break;
    default:
        rng_fill(e, len);
        break;
    }
}

// The pair against the window under one pair of moduli, bases and
// exponents, each output on an array of its own and then over its base.
static void compare_powers(const rsa_mont64_modulus *mod_p, const rsa_mont64_modulus *mod_q,
                           const uint64_t *base_p, const uint64_t *base_q, const uint8_t *e_p,
                           const uint8_t *e_q, size_t e_len) {
    size_t k = mod_p->words;
    uint64_t want_p[PRIME_WORDS];
    uint64_t want_q[PRIME_WORDS];
    uint64_t got_p[PRIME_WORDS];
    uint64_t got_q[PRIME_WORDS];
    rsa_sign64_power(want_p, base_p, e_p, e_len, mod_p);
    rsa_sign64_power(want_q, base_q, e_q, e_len, mod_q);

    memset(got_p, 0x5a, sizeof got_p);
    memset(got_q, 0xa5, sizeof got_q);
    rsa_ifma_sign_power_pair(got_p, base_p, e_p, mod_p, got_q, base_q, e_q, mod_q, e_len);
    check_words("rsa_ifma_sign_power_pair, first prime", k, want_p, got_p);
    check_words("rsa_ifma_sign_power_pair, second prime", k, want_q, got_q);

    memcpy(got_p, base_p, k * sizeof(uint64_t));
    memcpy(got_q, base_q, k * sizeof(uint64_t));
    rsa_ifma_sign_power_pair(got_p, got_p, e_p, mod_p, got_q, got_q, e_q, mod_q, e_len);
    check_words("rsa_ifma_sign_power_pair over its bases, first prime", k, want_p, got_p);
    check_words("rsa_ifma_sign_power_pair over its bases, second prime", k, want_q, got_q);
}

// Every shape of modulus, base and exponent at k words.
static void run_word_count(size_t k) {
    uint8_t bytes_p[PRIME_BYTES];
    uint8_t bytes_q[PRIME_BYTES];
    rsa_mont64_modulus mod_p;
    rsa_mont64_modulus mod_q;
    uint64_t base_p[PRIME_WORDS];
    uint64_t base_q[PRIME_WORDS];
    uint8_t e_p[PRIME_BYTES];
    uint8_t e_q[PRIME_BYTES];
    size_t len = 8 * k;
    for (int kind = 0; kind < MODULUS_KINDS; kind++) {
        size_t bits_p = modulus_of_kind(bytes_p, k, kind);
        size_t bits_q = modulus_of_kind(bytes_q, k, (kind + 1) % MODULUS_KINDS);
        rsa_mont64_modulus_init(&mod_p, bytes_p, len, bits_p);
        rsa_mont64_modulus_init(&mod_q, bytes_q, len, bits_q);
        for (int base_kind = 0; base_kind < BASE_KINDS; base_kind++) {
            base_of_kind(base_p, &mod_p, base_kind);
            base_of_kind(base_q, &mod_q, BASE_KINDS - 1 - base_kind);
            for (int e_kind = 0; e_kind < EXPONENT_KINDS; e_kind++) {
                exponent_of_kind(e_p, SHORT_EXPONENT, e_kind);
                exponent_of_kind(e_q, SHORT_EXPONENT, (e_kind + 3) % EXPONENT_KINDS);
                compare_powers(&mod_p, &mod_q, base_p, base_q, e_p, e_q, SHORT_EXPONENT);
            }
        }
        // Random bases under random exponents as long as the primes, the
        // length a signature's exponents take.
        base_of_kind(base_p, &mod_p, 3);
        base_of_kind(base_q, &mod_q, 3);
        rng_fill(e_p, len);
        rng_fill(e_q, len);
        compare_powers(&mod_p, &mod_q, base_p, base_q, e_p, e_q, len);
    }
}

// The word counts the pair runs at: every one on the instructions, and
// over the model, whose products take far longer, the first and the last
// each register count takes up to this build's bound: 16 and 19 in three
// registers, 20 and 25 in four, or 24 at the 384-byte bound, and 26 and
// 32 in five.
static void run_word_counts(void) {
#ifdef CH_RSA_IFMA_MODEL
    static const size_t counts[] = {16, 19, 20, 24, 25, 26, 32};
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        if (counts[i] <= PRIME_WORDS) {
            run_word_count(counts[i]);
        }
    }
#else
    for (size_t k = RSA_IFMA_SIGN_WORDS_MIN; k <= PRIME_WORDS; k++) {
        run_word_count(k);
    }
#endif
}

static ch_rsa_priv key;

// One message under key, signed under the two values: the same verdict,
// the same bytes, and on the IFMA value one kernel call and two wipes. A
// value that names IFMA without the multiply bit runs the window.
static void compare_sign(const char *name, const uint8_t *em, int want_signed) {
    uint8_t want[CH_RSA_MODULUS_MAX];
    uint8_t got[CH_RSA_MODULUS_MAX];
    memset(want, 0x11, sizeof want);
    memset(got, 0x11, sizeof got);
    rsa_ifma_sign_pair_calls = 0;
    rsa_ifma_sign_wipe_calls = 0;
    int want_rc = rsa_sign64_sp1(WINDOW_CPU, &key, em, want);
    check(rsa_ifma_sign_pair_calls == 0 && rsa_ifma_sign_wipe_calls == 0,
          "rsa_sign64_sp1 ran the kernel under a value without CH_CPU_AVX512_IFMA", key.n_len);
    int ifma_without_multiply = rsa_sign64_sp1(CH_CPU_PROBED | CH_CPU_AVX512_IFMA, &key, em, got);
    check(rsa_ifma_sign_pair_calls == 0 && rsa_ifma_sign_wipe_calls == 0,
          "rsa_sign64_sp1 ran the kernel under a value without the multiply bit", key.n_len);
    check(ifma_without_multiply == want_rc && memcmp(got, want, key.n_len) == 0,
          "rsa_sign64_sp1 without the multiply bit", key.n_len);
    memset(got, 0x11, sizeof got);
    int rc = rsa_sign64_sp1(IFMA_CPU, &key, em, got);
    check(rsa_ifma_sign_pair_calls == 1 && rsa_ifma_sign_wipe_calls == 2,
          "rsa_sign64_sp1 under CH_CPU_AVX512_IFMA ran the kernel once and wiped twice", key.n_len);
    if (want_rc != want_signed || rc != want_rc || memcmp(got, want, key.n_len) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s at %zu bytes: the window returned %d, IFMA %d, %s bytes\n",
                      name, key.n_len, want_rc, rc,
                      memcmp(got, want, key.n_len) == 0 ? "the same" : "other");
        return;
    }
    compared++;
}

static void run_key(const test_rsa_sign_key *from, int messages) {
    if (from->n_len > CH_RSA_MODULUS_MAX) {
        return;
    }
    test_rsa_sign_key_load(&key, from);
    uint8_t em[CH_RSA_MODULUS_MAX];
    memset(em, 0, sizeof em);
    compare_sign("message 0", em, 1);
    em[key.n_len - 1] = 1;
    compare_sign("message 1", em, 1);
    // n - 1: n is odd, so clearing its low bit subtracts one.
    memcpy(em, key.n, key.n_len);
    em[key.n_len - 1] &= 0xfe;
    compare_sign("message n - 1", em, 1);
    for (int i = 0; i < messages; i++) {
        rng_fill(em, key.n_len);
        em[0] &= 0x7f;
        compare_sign("random message", em, 1);
    }
    // One bit of dp changed: the check refuses both signers' candidates,
    // and sig keeps its bytes.
    key.dp[key.n_len / 2 - 1] ^= 0x04;
    rng_fill(em, key.n_len);
    em[0] &= 0x7f;
    compare_sign("refused, dp changed", em, 0);
}

// words[0..count) as n digits of 52 bits.
static void to_digits(uint64_t *digits, size_t n, const uint64_t *words, size_t count) {
    for (size_t j = 0; j < n; j++) {
        size_t bit = 52 * j;
        size_t index = bit / 64;
        unsigned offset = (unsigned)(bit % 64);
        uint64_t low = index < count ? words[index] >> offset : 0;
        uint64_t high = index + 1 < count ? words[index + 1] << (63 - offset) << 1 : 0;
        digits[j] = (low | high) & ((UINT64_C(1) << 52) - 1);
    }
}

// a + b over k words into k + 1.
static void add_words(uint64_t *o, const uint64_t *a, const uint64_t *b, size_t k) {
    uint64_t carry = 0;
    for (size_t i = 0; i < k; i++) {
        ct_u128 sum = (ct_u128)a[i] + b[i] + carry;
        o[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    o[k] = carry;
}

// state_finish of m + x, which must give x, for an x below m.
static void finish_one(const char *what, const rsa_mont64_modulus *mod, const uint64_t *x) {
    size_t k = mod->words;
    uint64_t value[PRIME_WORDS + 1];
    uint64_t digits[8 * ((RSA_IFMA_DIGIT_COUNT(PRIME_WORDS) + 7) / 8)];
    uint64_t got[PRIME_WORDS];
    add_words(value, mod->m, x, k);
    to_digits(digits, RSA_IFMA_DIGIT_COUNT(k), value, k + 1);
    rsa_ifma_sign_test_finish(got, digits, mod);
    check_words(what, k, x, got);
}

// The end of an exponentiation at the top word, at k words: under a
// modulus whose top word is all ones, m + x for x = 1, 3, 2^(64k) - m and
// m - 1, each at or above 2^(64k) but the first, and m itself, which must
// give 0; and under the modulus with the top bit and 1, 2m - 1, whose top
// word is 1 too.
static void run_finish(size_t k) {
    uint8_t bytes[PRIME_BYTES];
    rsa_mont64_modulus mod;
    uint64_t x[PRIME_WORDS] = {0};
    size_t len = 8 * k;
    memset(bytes, 0xff, len);
    bytes[len - 1] = 0xfd; // m = 2^(64k) - 3
    rsa_mont64_modulus_init(&mod, bytes, len, 8 * len);
    finish_one("state_finish of m", &mod, x);
    x[0] = 1;
    finish_one("state_finish of m + 1", &mod, x);
    x[0] = 3;
    finish_one("state_finish of 2^(64k)", &mod, x);
    x[0] = 7;
    finish_one("state_finish of 2^(64k) + 4", &mod, x);
    memcpy(x, mod.m, k * sizeof(uint64_t));
    x[0] -= 1;
    finish_one("state_finish of 2m - 1", &mod, x);

    memset(bytes, 0, len);
    bytes[0] = 0x80;
    bytes[len - 1] = 1; // m = 2^(64k - 1) + 1
    rsa_mont64_modulus_init(&mod, bytes, len, 8 * len);
    memcpy(x, mod.m, k * sizeof(uint64_t));
    x[0] -= 1;
    finish_one("state_finish of 2m - 1 under the top bit and 1", &mod, x);
}

int main(void) {
#ifndef CH_RSA_IFMA_MODEL
    if (!x86_cpu_has_avx512_ifma()) {
        if (x86_ifma_required()) {
            (void)fprintf(stderr, "rsa_ifma_sign equivalence: this CPU lacks AVX-512 IFMA, and "
                                  "CH_REQUIRE_AVX512_IFMA is 1\n");
            return 1;
        }
        (void)printf("SKIP the IFMA signer: this CPU lacks AVX-512 IFMA\n");
        return 0;
    }
#endif
    for (size_t k = RSA_IFMA_SIGN_WORDS_MIN; k <= PRIME_WORDS; k++) {
        run_finish(k);
    }
    run_word_counts();
    static const test_rsa_sign_key keys[] = {TEST_RSA_SIGN_KEY(2048), TEST_RSA_SIGN_KEY(2112),
                                             TEST_RSA_SIGN_KEY(3072), TEST_RSA_SIGN_KEY(4096)};
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        run_key(&keys[i], 2);
    }
    if (failures != 0) {
        (void)fprintf(stderr, "rsa_ifma_sign (%s): %d failures, %lu comparisons passed\n", WHERE,
                      failures, compared);
        return 1;
    }
    (void)printf("rsa_ifma_sign (%s): %lu comparisons pass, words %d to %d, bound %d\n", WHERE,
                 compared, RSA_IFMA_SIGN_WORDS_MIN, (int)PRIME_WORDS, (int)CH_RSA_MODULUS_MAX);
    return 0;
}

#endif // __x86_64__ || CH_RSA_IFMA_MODEL
