// bin/rsa_ifma_sign_residue_test: what rsa_ifma_sign.c's exponentiations
// and the signer's check on rsa_ifma.c leave on the stack and in the
// vector registers, on the AVX-512 IFMA instructions (docs/decisions.md
// 120). A signature's kernel calls hold the primes, the bases' powers and
// the candidate signature in digits of 52 bits, in arrays the calls wipe,
// in stack slots the compiler picks and in 512-bit registers. rsa_sign64.c
// runs rsa_ifma_sign_wipe_below and avx512_wipe_registers after each such
// call, from the function that made it; this binary holds those two to
// what they must clear.
//
//   - Depth: how far below its caller rsa_ifma_sign_power_pair, and
//     rsa_vp1_cpu on the kernel, write, which must stay inside the
//     RSA_IFMA_SIGN_BELOW_LEN bytes rsa_ifma_sign_wipe_below clears.
//   - Residue: the stack below the caller and the 32 vector registers
//     after each call and the two wipes, searched for two words side by
//     side of each value the call held: each prime in digits, the sixteen
//     table entries of each in digits, reduced and plus the prime, since a
//     product leaves either, R mod p and base * R' mod p in words, and for
//     the check the candidate in digits. A finding fails. The same search
//     without the wipes prints what it finds and counts nothing: it says
//     what the wipes are there for.
//   - Differential: the exponentiations under two pairs of exponents, and
//     of two bases, each followed by the wipes, must leave the stack the
//     same in every byte, which holds a value too short to look for.
//
// It runs where rsa_ifma_sign.c has a body, on x86-64, and skips on a CPU
// without AVX-512 IFMA unless CH_REQUIRE_AVX512_IFMA is 1, and in a build
// whose stack holds no claim (test/stack_residue.c).
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

#ifndef __x86_64__

int main(void) {
    (void)printf("SKIP rsa_ifma_sign residue: the AVX-512 IFMA kernel is x86-64 only "
                 "(rsa_ifma_sign.h)\n");
    return 0;
}

#else

#include "avx512_wipe.h"
#include "cpu_cfg.h"
#include "rsa.h"
#include "rsa_ifma.h"
#include "rsa_ifma_sign.h"
#include "rsa_mont64.h"
#include "rsa_sign.h"
#include "rsa_sign_key.h"

#define IFMA_CPU (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY | CH_CPU_AVX512_IFMA)
#define PRIME_WORDS RSA_IFMA_SIGN_WORDS_MAX
#define DIGITS_MAX (8 * ((RSA_IFMA_DIGIT_COUNT(RSA_MONT64_WORDS_MAX) + 7) / 8))
#define RESIDUE_BYTES 40960
#define RESIDUE_PAINT 0xa5

_Static_assert(RESIDUE_BYTES > RSA_IFMA_SIGN_BELOW_LEN, "the copy reaches past the wipe");

static int failures = 0;
static unsigned long passed = 0;

static uint64_t rng_state = UINT64_C(0x2545f4914f6cdd1d);

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
void stack_residue_fill(volatile uint8_t *below, size_t n, uint8_t value);
const char *stack_residue_unsearched(void);

static uint8_t residue_copy[RESIDUE_BYTES];

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

static __attribute__((noinline)) void residue_paint(void) {
    volatile uint8_t below[RESIDUE_BYTES + 512];
    stack_residue_fill(below, sizeof below, RESIDUE_PAINT);
}

// The 32 vector registers as they are: VMOVDQU64 of each to memory.
#define VECTOR_REGISTERS 32
#define STORE_ONE(n) "vmovdqu64 %%zmm" #n ", " #n "*64(%0)\n\t"
static __attribute__((target("avx512f"), noinline)) void store_registers(uint64_t (*out)[8]) {
    __asm__ volatile(STORE_ONE(0) STORE_ONE(1) STORE_ONE(2) STORE_ONE(3) STORE_ONE(4) STORE_ONE(5)
                         STORE_ONE(6) STORE_ONE(7) STORE_ONE(8) STORE_ONE(9) STORE_ONE(10)
                             STORE_ONE(11) STORE_ONE(12) STORE_ONE(13) STORE_ONE(14) STORE_ONE(15)
                                 STORE_ONE(16) STORE_ONE(17) STORE_ONE(18) STORE_ONE(19)
                                     STORE_ONE(20) STORE_ONE(21) STORE_ONE(22) STORE_ONE(23)
                                         STORE_ONE(24) STORE_ONE(25) STORE_ONE(26) STORE_ONE(27)
                                             STORE_ONE(28) STORE_ONE(29) STORE_ONE(30) STORE_ONE(31)
                     :
                     : "r"(out)
                     : "memory");
}
static uint64_t registers_after[VECTOR_REGISTERS][8];

// The inputs of the call under test, static so that every call runs from
// one address with the same registers saved.
static ch_rsa_priv key;
static rsa_mont64_modulus mod_p;
static rsa_mont64_modulus mod_q;
static uint64_t base_p[PRIME_WORDS];
static uint64_t base_q[PRIME_WORDS];
static uint8_t e_p[8 * PRIME_WORDS];
static uint8_t e_q[8 * PRIME_WORDS];
static size_t e_len;
static uint64_t out_p[PRIME_WORDS];
static uint64_t out_q[PRIME_WORDS];
static uint8_t candidate[CH_RSA_MODULUS_MAX];
static uint8_t power[CH_RSA_MODULUS_MAX];
static int with_wipes;
static int calling_check;

// The kernel call, and the two wipes rsa_sign64.c runs after it, from one
// frame, as rsa_sign64.c's both_powers and check_power make them.
static __attribute__((noinline)) void call_under_test(void) {
    if (calling_check) {
        rsa_vp1_cpu(IFMA_CPU, key.n, key.n_len, candidate, power);
    } else {
        rsa_ifma_sign_power_pair(out_p, base_p, e_p, &mod_p, out_q, base_q, e_q, &mod_q, e_len);
    }
    if (with_wipes) {
        rsa_ifma_sign_wipe_below();
        avx512_wipe_registers();
    }
    store_registers(registers_after);
}

// The values a call holds, each as words, to look for two side by side.
#define VALUES_MAX 72
static struct {
    char name[48];
    uint64_t words[DIGITS_MAX + 1];
    size_t count;
} values[VALUES_MAX];
static size_t value_count;

static void add_value(const char *name, const uint64_t *words, size_t count) {
    CH_ASSERT(value_count < VALUES_MAX && count <= DIGITS_MAX + 1);
    (void)snprintf(values[value_count].name, sizeof values[value_count].name, "%s", name);
    memcpy(values[value_count].words, words, count * sizeof(uint64_t));
    values[value_count].count = count;
    value_count++;
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

// Every value one prime's exponentiation holds: the prime in digits, R mod
// m and base * R' in words, and base^i * R' mod m in digits, reduced and
// plus m, for i from 0 to 15.
static void add_prime_values(const char *which, const rsa_mont64_modulus *mod,
                             const uint64_t *base) {
    size_t k = mod->words;
    size_t n = RSA_IFMA_DIGIT_COUNT(k);
    size_t spare = 52 * n - 64 * k;
    char name[48];
    uint64_t digits[DIGITS_MAX];
    uint64_t one[PRIME_WORDS] = {1};
    uint64_t r_mod[PRIME_WORDS];
    uint64_t running[PRIME_WORDS];
    uint64_t scaled[PRIME_WORDS];
    uint64_t plus_m[PRIME_WORDS + 1];

    to_digits(digits, n, mod->m, k);
    (void)snprintf(name, sizeof name, "%s in digits", which);
    add_value(name, digits, n);
    rsa_mont64_mont_mul(r_mod, one, mod->r2, mod);
    (void)snprintf(name, sizeof name, "R mod %s in words", which);
    add_value(name, r_mod, k);
    // running = base^i * R mod m, scaled = that times 2^spare: base^i * R'.
    memcpy(running, r_mod, sizeof running);
    for (int i = 0; i < 16; i++) {
        memcpy(scaled, running, k * sizeof(uint64_t));
        for (size_t s = 0; s < spare; s++) {
            rsa_mont64_add(scaled, scaled, scaled, mod);
        }
        if (i == 1) {
            (void)snprintf(name, sizeof name, "base * R' mod %s in words", which);
            add_value(name, scaled, k);
        }
        to_digits(digits, n, scaled, k);
        (void)snprintf(name, sizeof name, "entry %d of %s, reduced", i, which);
        add_value(name, digits, n);
        add_words(plus_m, scaled, mod->m, k);
        to_digits(digits, n, plus_m, k + 1);
        (void)snprintf(name, sizeof name, "entry %d of %s, plus m", i, which);
        add_value(name, digits, n);
        rsa_mont64_mont_mul(running, running, base, mod);
    }
}

// Whether len bytes hold two words of a value side by side at any offset.
// Reports each value found, as a failure where counted, and as what the
// wipes are there for where not.
static int bytes_hold(const char *where, const uint8_t *bytes, size_t len, int counted) {
    int found = 0;
    for (size_t v = 0; v < value_count; v++) {
        int this_value = 0;
        for (size_t i = 0; i + 2 <= values[v].count && !this_value; i++) {
            if (values[v].words[i] <= 1) {
                continue;
            }
            for (size_t at = 0; at + 16 <= len && !this_value; at++) {
                if (memcmp(&bytes[at], &values[v].words[i], 16) == 0) {
                    (void)fprintf(counted ? stderr : stdout,
                                  "%s %s holds two words of %s from word %zu, %zu bytes from "
                                  "the end\n",
                                  counted ? "FAIL" : "INFO", where, values[v].name, i, len - at);
                    this_value = 1;
                }
            }
        }
        found |= this_value;
    }
    return found;
}

// One key's inputs: its primes' records, random bases in their domains,
// dp and dq, and a random candidate below n, with every value a call
// holds.
static void set_inputs(const test_rsa_sign_key *from) {
    test_rsa_sign_key_load(&key, from);
    size_t half_len = key.n_len / 2;
    rsa_mont64_modulus_init(&mod_p, key.p, half_len, 8 * half_len);
    rsa_mont64_modulus_init(&mod_q, key.q, half_len, 8 * half_len);
    uint64_t plain[PRIME_WORDS] = {0};
    for (size_t i = 0; i < mod_p.words; i++) {
        plain[i] = rng_next();
    }
    rsa_mont64_mont_mul(base_p, plain, mod_p.r2, &mod_p);
    for (size_t i = 0; i < mod_q.words; i++) {
        plain[i] = rng_next();
    }
    rsa_mont64_mont_mul(base_q, plain, mod_q.r2, &mod_q);
    memcpy(e_p, key.dp, half_len);
    memcpy(e_q, key.dq, half_len);
    e_len = half_len;
    for (size_t i = 0; i < key.n_len; i++) {
        candidate[i] = (uint8_t)(rng_next() >> 56);
    }
    candidate[0] &= 0x7f;
    value_count = 0;
    add_prime_values("p", &mod_p, base_p);
    add_prime_values("q", &mod_q, base_q);
    uint64_t words[RSA_MONT64_WORDS_MAX];
    uint64_t digits[DIGITS_MAX];
    size_t k = key.n_len / 8;
    rsa_mont64_from_bytes(words, k, candidate, key.n_len);
    to_digits(digits, RSA_IFMA_DIGIT_COUNT(k), words, k);
    add_value("the candidate in digits", digits, RSA_IFMA_DIGIT_COUNT(k));
}

// The depth of each call and its residue, with and without the wipes.
static void run_depth_and_residue(const char *key_name) {
    static const char *const callee[2] = {"rsa_ifma_sign_power_pair", "the check's rsa_vp1_cpu"};
    char where[128];
    for (int check = 0; check < 2; check++) {
        for (int wipes = 0; wipes < 2; wipes++) {
            calling_check = check;
            with_wipes = wipes;
            residue_paint();
            call_under_test();
            residue_snapshot();
            if (!wipes) {
                size_t depth = 0;
                for (size_t i = 0; i < RESIDUE_BYTES && depth == 0; i++) {
                    if (residue_copy[i] != RESIDUE_PAINT) {
                        depth = RESIDUE_BYTES - i;
                    }
                }
                (void)printf("%s %s: writes %zu bytes below its caller, and the wipe clears %d\n",
                             key_name, callee[check], depth, RSA_IFMA_SIGN_BELOW_LEN);
                if (depth == 0 || depth > RSA_IFMA_SIGN_BELOW_LEN) {
                    failures++;
                    (void)fprintf(stderr, "FAIL depth: %s %s writes %zu bytes below its caller\n",
                                  key_name, callee[check], depth);
                } else {
                    passed++;
                }
            }
            const char *after = wipes ? "and the two wipes" : "with no wipe";
            (void)snprintf(where, sizeof where, "%s: the stack after %s %s", key_name,
                           callee[check], after);
            int stack_held = bytes_hold(where, residue_copy, RESIDUE_BYTES, wipes);
            (void)snprintf(where, sizeof where, "%s: zmm0 to zmm31 after %s %s", key_name,
                           callee[check], after);
            int registers_held =
                bytes_hold(where, (const uint8_t *)registers_after, sizeof registers_after, wipes);
            if (wipes) {
                failures += stack_held + registers_held;
                passed += (unsigned long)(2 - stack_held - registers_held);
            }
        }
    }
}

// The differential: the exponentiations under two secrets, with the
// wipes, and the two stacks equal in every byte. Of three calls the first
// does not count: it leaves what the calls before it left.
static uint8_t differential_copies[2][RESIDUE_BYTES];
static volatile size_t differential_turn;
static void (*differential_set)(void);
static uint8_t saved_e_p[8 * PRIME_WORDS];
static uint8_t saved_e_q[8 * PRIME_WORDS];
static uint64_t saved_base_p[PRIME_WORDS];
static uint64_t other_base_p[PRIME_WORDS];

static void set_exponents(void) {
    memcpy(e_p, differential_turn == 2 ? saved_e_q : saved_e_p, sizeof e_p);
    memcpy(e_q, differential_turn == 2 ? saved_e_p : saved_e_q, sizeof e_q);
}

static void set_bases(void) {
    memcpy(base_p, differential_turn == 2 ? other_base_p : saved_base_p, sizeof base_p);
}

static __attribute__((noinline)) void differential_keep(void) {
    size_t turn = differential_turn;
    memcpy(differential_copies[turn / 2], residue_copy, RESIDUE_BYTES);
    differential_turn = turn + 1;
}

static __attribute__((noinline)) void differential_step(void) {
    differential_set();
    residue_snapshot();
    call_under_test();
    residue_snapshot();
    differential_keep();
}

static void differential_pair(const char *what, void (*set)(void)) {
    differential_set = set;
    differential_turn = 0;
    differential_step();
    differential_step();
    differential_step();
    size_t differing = 0;
    size_t deepest = 0;
    for (size_t at = 0; at < RESIDUE_BYTES; at++) {
        if (differential_copies[0][at] != differential_copies[1][at]) {
            if (differing == 0) {
                deepest = at;
            }
            differing++;
        }
    }
    if (differing != 0) {
        failures++;
        (void)fprintf(stderr,
                      "FAIL differential: %s leave stacks that differ in %zu bytes, the deepest "
                      "%zu bytes from the end\n",
                      what, differing, RESIDUE_BYTES - deepest);
        return;
    }
    passed++;
}

static void run_differential(const char *key_name) {
    char what[96];
    memcpy(saved_e_p, e_p, sizeof e_p);
    memcpy(saved_e_q, e_q, sizeof e_q);
    memcpy(saved_base_p, base_p, sizeof base_p);
    uint64_t plain[PRIME_WORDS] = {0};
    for (size_t i = 0; i < mod_p.words; i++) {
        plain[i] = rng_next();
    }
    rsa_mont64_mont_mul(other_base_p, plain, mod_p.r2, &mod_p);
    with_wipes = 1;
    calling_check = 0;
    (void)snprintf(what, sizeof what, "%s: two pairs of exponents", key_name);
    differential_pair(what, set_exponents);
    (void)snprintf(what, sizeof what, "%s: two bases", key_name);
    differential_pair(what, set_bases);
    memcpy(e_p, saved_e_p, sizeof e_p);
    memcpy(e_q, saved_e_q, sizeof e_q);
    memcpy(base_p, saved_base_p, sizeof base_p);
}

int main(void) {
    if (!x86_cpu_has_avx512_ifma()) {
        if (x86_ifma_required()) {
            (void)fprintf(stderr, "rsa_ifma_sign residue: this CPU lacks AVX-512 IFMA, and "
                                  "CH_REQUIRE_AVX512_IFMA is 1\n");
            return 1;
        }
        (void)printf("SKIP rsa_ifma_sign residue: this CPU lacks AVX-512 IFMA\n");
        return 0;
    }
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        (void)printf("SKIP rsa_ifma_sign residue: %s\n", unsearched);
        return 0;
    }
    static const test_rsa_sign_key keys[] = {TEST_RSA_SIGN_KEY(2048), TEST_RSA_SIGN_KEY(3072),
                                             TEST_RSA_SIGN_KEY(4096)};
    static const char *const names[] = {"RSA-2048", "RSA-3072", "RSA-4096"};
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        if (keys[i].n_len > CH_RSA_MODULUS_MAX) {
            continue;
        }
        set_inputs(&keys[i]);
        run_depth_and_residue(names[i]);
        run_differential(names[i]);
    }
    if (failures != 0) {
        (void)fprintf(stderr, "rsa_ifma_sign residue: %d failures, %lu checks passed\n", failures,
                      passed);
        return 1;
    }
    (void)printf("rsa_ifma_sign residue: %lu checks pass, bound %d\n", passed,
                 (int)CH_RSA_MODULUS_MAX);
    return 0;
}

#endif // __x86_64__
