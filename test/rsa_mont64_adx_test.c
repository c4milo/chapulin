// rsa_mont64_adx.c against rsa_mont64.c, the reference it replaces in the
// signer's window (docs/decisions.md 183).
//
// On every host, the model build (test/rsa_mont64_adx_model.c) against
// rsa_mont64_mont_mul and rsa_mont64_mont_square, word for word. On an
// x86-64 CPU with BMI2 and ADX, the assembly build against the model too.
// Each runs at every word count from 2 to RSA_MONT64_WORDS_MAX, over:
//
//   - moduli of all ones, of a top bit and a low bit alone, and with a low
//     word of 1 and of all ones, the two ends of m0inv, beside random odd
//     moduli with the top bit set;
//   - operands 0, 1, m - 1, m - 2, the top bit alone and random values below
//     m, so the rows run with every carry they can make and the final
//     subtraction takes both of its choices.
//
// On an x86-64 CPU without BMI2 or ADX the assembly part prints SKIP, unless
// CH_REQUIRE_BMI2_ADX is 1: a CI job that runs it on such a CPU on purpose
// sets it, so a runner that lacks the instructions fails.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "rsa_mont64.h"
#include "rsa_mont64_adx.h"
#include "x86_kernels_cpu.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

void rsa_mont64_adx_model_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                              const rsa_mont64_modulus *mod);
void rsa_mont64_adx_model_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod);

// xorshift64 from a fixed seed, so a run replays the same cases.
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static int failures = 0;
static unsigned long compared = 0;

static void check(int same, const char *what, size_t k) {
    compared++;
    if (!same) {
        failures++;
        (void)fprintf(stderr, "rsa_mont64_adx: %s differs at %zu words\n", what, k);
    }
}

// The operations under test: the model's, and on x86-64 the assembly's.
typedef struct {
    void (*mul)(uint64_t *, const uint64_t *, const uint64_t *, const rsa_mont64_modulus *);
    void (*square)(uint64_t *, const uint64_t *, const rsa_mont64_modulus *);
    const char *name;
} adx_build;

// The modulus of k words in shape s: 0 to 4 are the edge shapes above, and
// any other is random. Every one is odd with its top bit set.
static void make_modulus(uint8_t *m, size_t k, unsigned s) {
    size_t len = 8 * k;
    for (size_t i = 0; i < len; i++) {
        m[i] = (uint8_t)rng_next();
    }
    if (s <= 1) {
        memset(m, s == 0 ? 0xff : 0, len); // all ones, or the two bits set below alone
    }
    if (s == 2) {
        memset(m + len - 8, 0, 8); // low word 1
    }
    if (s == 3) {
        memset(m + len - 8, 0xff, 8); // low word all ones
    }
    m[0] |= 0x80;
    m[len - 1] |= 1;
}

// Operand x of shape s below mod: 0 to 4 are 0, 1, m - 1, m - 2 and the top
// bit alone, and any other is random below m.
static void make_operand(uint64_t *x, const rsa_mont64_modulus *mod, unsigned s) {
    size_t k = mod->words;
    memset(x, 0, k * sizeof(uint64_t));
    if (s == 1) {
        x[0] = 1;
    } else if (s == 2 || s == 3) {
        memcpy(x, mod->m, k * sizeof(uint64_t));
        x[0] -= s == 2 ? 1 : 2; // m is odd, so its low word is 1 or more
    } else if (s == 4) {
        x[k - 1] = UINT64_C(1) << 62;
    } else if (s >= 5) {
        for (size_t i = 0; i < k; i++) {
            x[i] = rng_next();
        }
        x[k - 1] &= mod->m[k - 1] >> 1; // below m, whose top bit is set
    }
}

static void compare_build(const adx_build *b, const rsa_mont64_modulus *mod, const uint64_t *x,
                          const uint64_t *y) {
    size_t k = mod->words;
    uint64_t want[RSA_MONT64_WORDS_MAX];
    uint64_t got[RSA_MONT64_WORDS_MAX];
    rsa_mont64_mont_mul(want, x, y, mod);
    b->mul(got, x, y, mod);
    check(memcmp(want, got, k * sizeof(uint64_t)) == 0, b->name, k);
    rsa_mont64_mont_square(want, x, mod);
    b->square(got, x, mod);
    check(memcmp(want, got, k * sizeof(uint64_t)) == 0, b->name, k);
    // In place, as the window runs them.
    memcpy(got, x, k * sizeof(uint64_t));
    b->square(got, got, mod);
    check(memcmp(want, got, k * sizeof(uint64_t)) == 0, b->name, k);
}

static void run_build(const adx_build *b) {
    static rsa_mont64_modulus mod;
    uint8_t m[CH_RSA_MODULUS_MAX];
    uint64_t x[RSA_MONT64_WORDS_MAX];
    uint64_t y[RSA_MONT64_WORDS_MAX];
    for (size_t k = 2; k <= RSA_MONT64_WORDS_MAX; k++) {
        for (unsigned ms = 0; ms < 8; ms++) {
            make_modulus(m, k, ms);
            rsa_mont64_modulus_init(&mod, m, 8 * k, 64 * k);
            for (unsigned xs = 0; xs < 9; xs++) {
                for (unsigned ys = 0; ys < 9; ys++) {
                    make_operand(x, &mod, xs);
                    make_operand(y, &mod, ys);
                    compare_build(b, &mod, x, y);
                }
            }
        }
    }
}

int main(void) {
    const adx_build model = {rsa_mont64_adx_model_mul, rsa_mont64_adx_model_square, "the model"};
    run_build(&model);
#ifdef __x86_64__
    if (x86_cpu_has_bmi2_adx()) {
        const adx_build asm_build = {rsa_mont64_adx_mul, rsa_mont64_adx_square, "the assembly"};
        run_build(&asm_build);
    } else if (x86_bmi2_adx_required()) {
        (void)fprintf(stderr, "rsa_mont64_adx: this CPU lacks BMI2 or ADX, and "
                              "CH_REQUIRE_BMI2_ADX is 1\n");
        return 1;
    } else {
        (void)printf("SKIP rsa_mont64_adx, the assembly: this CPU lacks BMI2 or ADX\n");
    }
#endif
    if (failures != 0) {
        (void)fprintf(stderr, "rsa_mont64_adx: %d of %lu comparisons differ\n", failures, compared);
        return 1;
    }
    (void)printf("rsa_mont64_adx: %lu products and squares match rsa_mont64.c word for word\n",
                 compared);
    return 0;
}
