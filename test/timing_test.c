// Constant-time checker, dudect-style: for each primitive, time two
// randomly interleaved input classes and run Welch's t-test on the
// per-class latency distributions after cropping the top decile
// (scheduler noise). |t| >= 10 means this host can see a class-dependent
// timing difference. Load-sensitive by nature, so it runs from `make
// timing`, not `make check`.
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ch_assert.h"
#include "chacha20.h"
#include "ct.h"
#include "poly1305.h"
#include "rand.h"
#include "test_random.h"
#include "x25519.h"

// Per-class sample counts. Inner repeat loops amplify a one-byte early
// exit far past the threshold at these sizes.
#define FAST_N 200000
#define X25519_N 2000
// bin/timing_x25519_wide builds this file as a host object's test with
// -DTEST_X25519_WIDE, and the x25519 row then calls the wide field's
// entry. That field is about twelve times faster, so it takes ten times the
// samples in less time and names its row apart.
#ifdef TEST_X25519_WIDE
#include "x25519_wide.h"
#undef X25519_N
#define X25519_N 20000
#define X25519_ROW "x25519_wide"
#define X25519_BASE x25519_wide_base
#else
#define X25519_ROW "x25519"
#define X25519_BASE x25519_base
#endif
// bin/timing_p256_wide builds this file with -DTEST_P256_WIDE over a host
// object's P-256 sources alone, and runs the P-256 rows below in place of
// the four above them.
#ifdef TEST_P256_WIDE
#include "p256_ecdh.h"
#include "p256_sign.h"
#include "p256_wide_table.h"
#include "widemul.h"
#define P256_KEYGEN_N 20000
#define P256_ECDH_N 10000
#define P256_SIGN_N 10000
#endif
// bin/timing_rsa_sign64 builds this file as a host object's test with
// -DTEST_RSA_SIGN64 and runs two more rows after the four: the 64-bit
// Montgomery multiplication and the windowed exponentiation a host object
// signs RSA with (rsa_sign64.h).
#ifdef TEST_RSA_SIGN64
#include "rsa_mont64.h"
#include "rsa_sign64.h"
#define RSA_POWER_N 20000
#define RSA_MUL_REPS 64
#endif
#define WARMUP 4096
#define T_MAX 10.0

#define EQ_REPS 256
#define POLY_REPS 16
#define CHACHA_REPS 16

static int failures = 0;
static volatile uint32_t sink; // keeps timed bodies from being elided

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static uint64_t now_ns(void) {
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000U + (uint64_t)ts.tv_nsec;
}

// xorshift64*, seeded once from ch_rand_bytes; drives only the class
// schedule, never key material.
static uint64_t rng_state;

static uint64_t rng64(void) {
    uint64_t x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;
    return x * 0x2545f4914f6cdd1dU;
}

// Exactly n samples per class in random order, so slow drift (thermal,
// frequency scaling) lands on both classes equally.
static uint8_t schedule[2 * FAST_N];

static void shuffle_schedule(size_t n) {
    for (size_t i = 0; i < 2 * n; i++) {
        schedule[i] = (uint8_t)(i < n ? 0 : 1);
    }
    for (size_t i = 2 * n - 1; i > 0; i--) {
        size_t j = (size_t)(rng64() % (i + 1));
        uint8_t tmp = schedule[i];
        schedule[i] = schedule[j];
        schedule[j] = tmp;
    }
}

static uint64_t latency[2][FAST_N];

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

// Mean and variance over the lowest 90% of a class; the top decile is
// preemption and interrupts, not the operation.
static void cropped_stats(uint64_t *v, size_t n, double *mean, double *var, size_t *kept) {
    qsort(v, n, sizeof *v, cmp_u64);
    size_t k = n - n / 10;
    double m = 0.0;
    for (size_t i = 0; i < k; i++) {
        m += (double)v[i];
    }
    m /= (double)k;
    double s = 0.0;
    for (size_t i = 0; i < k; i++) {
        double d = (double)v[i] - m;
        s += d * d;
    }
    *mean = m;
    *var = s / (double)(k - 1);
    *kept = k;
}

static double welch_t(uint64_t *a, size_t n_a, uint64_t *b, size_t n_b) {
    double mean_a;
    double var_a;
    double mean_b;
    double var_b;
    size_t kept_a;
    size_t kept_b;
    cropped_stats(a, n_a, &mean_a, &var_a, &kept_a);
    cropped_stats(b, n_b, &mean_b, &var_b, &kept_b);
    return (mean_a - mean_b) / sqrt(var_a / (double)kept_a + var_b / (double)kept_b);
}

typedef void (*prep_fn)(int class_id);
typedef void (*run_fn)(void);

static double measure(prep_fn prep, run_fn run, size_t n, size_t warm) {
    shuffle_schedule(n);
    for (size_t i = 0; i < warm; i++) {
        prep((int)(i & 1));
        run();
    }
    size_t count[2] = {0, 0};
    for (size_t i = 0; i < 2 * n; i++) {
        int class_id = schedule[i];
        prep(class_id);
        uint64_t t0 = now_ns();
        run();
        uint64_t t1 = now_ns();
        latency[class_id][count[class_id]++] = t1 - t0;
    }
    return welch_t(latency[0], n, latency[1], n);
}

#ifndef TEST_P256_WIDE
// ct_memeq: equal buffers vs a difference at byte 0. An early-exit
// compare finishes after one byte for class 1 and drives t positive.
static uint8_t eq_a[64];
static uint8_t eq_b[64];

static void eq_prep(int class_id) {
    ch_rand_bytes(eq_a, sizeof eq_a);
    memcpy(eq_b, eq_a, sizeof eq_b);
    eq_b[0] ^= (uint8_t)class_id;
}

static void eq_run(void) {
    uint32_t acc = 0;
    for (int r = 0; r < EQ_REPS; r++) {
        acc ^= ct_memeq(eq_a, eq_b, sizeof eq_a);
    }
    sink ^= acc;
}

// poly1305: fixed message, fixed key vs fresh random keys. Catches
// key-dependent behavior in clamping, the word products, or the final
// reduction.
static uint8_t poly_key_fixed[POLY1305_KEY];
static uint8_t poly_key[POLY1305_KEY];
static uint8_t poly_msg[256];

static void poly_prep(int class_id) {
    ch_rand_bytes(poly_key, sizeof poly_key);
    if (class_id == 0) {
        memcpy(poly_key, poly_key_fixed, sizeof poly_key);
    }
}

static void poly_run(void) {
    uint8_t tag[POLY1305_TAG];
    for (int r = 0; r < POLY_REPS; r++) {
        poly1305 p;
        poly1305_init(&p, poly_key);
        poly1305_update(&p, poly_msg, sizeof poly_msg);
        poly1305_final(&p, tag);
    }
    sink ^= tag[0];
}

// chacha20_xor: 256-byte buffer, fixed key vs fresh random keys.
static uint8_t chacha_key_fixed[CHACHA20_KEY];
static uint8_t chacha_key[CHACHA20_KEY];
static uint8_t chacha_buf[256];

static void chacha_prep(int class_id) {
    ch_rand_bytes(chacha_key, sizeof chacha_key);
    if (class_id == 0) {
        memcpy(chacha_key, chacha_key_fixed, sizeof chacha_key);
    }
}

static void chacha_run(void) {
    static const uint8_t nonce[CHACHA20_NONCE] = {0};
    for (int r = 0; r < CHACHA_REPS; r++) {
        chacha20_xor(chacha_key, nonce, 1, chacha_buf, chacha_buf, sizeof chacha_buf);
    }
    sink ^= chacha_buf[0];
}

// x25519: fixed scalar vs fresh random scalars on the base point. A
// ladder that branches on scalar bits or skips work per word shows here.
static uint8_t x_scalar_fixed[X25519_LEN];
static uint8_t x_scalar[X25519_LEN];

static void x_prep(int class_id) {
    ch_rand_bytes(x_scalar, sizeof x_scalar);
    if (class_id == 0) {
        memcpy(x_scalar, x_scalar_fixed, sizeof x_scalar);
    }
}

static void x_run(void) {
    uint8_t out[X25519_LEN];
    X25519_BASE(out, x_scalar);
    sink ^= out[0];
}
#else
// The wide P-256 files, through the entries a session calls, under the
// constant-time answer (widemul.h, docs/decisions.md 94): one fixed scalar
// against fresh random ones. A multiplication whose time moves with a
// window's digit shows here: a scan that passes over the entries the digit
// does not name took the key generation's rows past the threshold when it
// was tried (docs/decisions.md 94). main sets p256_fixed to a random
// scalar, then for the key generation to the one whose six-bit windows are
// all 0x20 and for the key exchange to the one whose four-bit windows are
// all 8, so that every window but the top one names the same entry of its
// row.
static uint8_t p256_fixed[P256_SCALAR_LEN];
static uint8_t p256_now[P256_SCALAR_LEN];
static uint8_t p256_peer[P256_POINT_LEN];
static uint8_t p256_hash[32];

// A scalar below n: n is above 2^255, and the top bit is clear. It is zero
// with a probability no run meets.
static void p256_random_scalar(uint8_t out[P256_SCALAR_LEN]) {
    ch_rand_bytes(out, P256_SCALAR_LEN);
    out[0] &= 0x7f;
}

static void p256_prep(int class_id) {
    p256_random_scalar(p256_now);
    if (class_id == 0) {
        memcpy(p256_now, p256_fixed, sizeof p256_now);
    }
}

// k*G from the table: a key generation.
static void p256_keygen_run(void) {
    uint8_t priv[P256_SCALAR_LEN];
    uint8_t pub[P256_POINT_LEN];
    sink ^= (uint32_t)p256_ecdh_keygen(WIDEMUL_CONSTANT_TIME, p256_now, priv, pub);
    sink ^= pub[P256_POINT_LEN - 1];
}

// k*P over eight multiples of the peer's point: a key exchange.
static void p256_ecdh_run(void) {
    uint8_t shared[P256_SECRET_LEN];
    sink ^= (uint32_t)p256_ecdh(WIDEMUL_CONSTANT_TIME, p256_now, p256_peer, shared);
    sink ^= shared[0];
}

// A signature under the scalar as the private key. RFC 6979 derives the
// nonce from the key and the hash, so the fixed class signs under one
// nonce and the random class under fresh ones.
static void p256_sign_run(void) {
    uint8_t sig[P256_SIG_MAX];
    size_t sig_len = 0;
    sink ^=
        (uint32_t)p256_sign(WIDEMUL_CONSTANT_TIME, p256_now, p256_hash, sig, sizeof sig, &sig_len);
    sink ^= sig[0];
}
#endif

#ifdef TEST_RSA_SIGN64
// Both rows run under a modulus drawn once: random bytes with the top bit
// and the low bit set, which is all Montgomery arithmetic needs of one.
// The multiplication's is 128 bytes, 16 words, the size one half of an
// RSA-2048 signature runs at. The exponentiation's is 16 bytes, two words,
// so that the read of the table is a large share of a step and a
// difference in it is not lost among the multiplications.
#define RSA_MODULUS_LEN 128
#define RSA_SMALL_LEN 16
static rsa_mont64_modulus rsa_mod;
static rsa_mont64_modulus rsa_small;
static uint64_t rsa_a[RSA_MONT64_WORDS_MAX];
static uint64_t rsa_b[RSA_MONT64_WORDS_MAX];
static uint8_t rsa_exponent[RSA_MODULUS_LEN];

// mod = the record of a fresh random odd modulus of len bytes with its top
// bit set.
static void rsa_random_modulus(rsa_mont64_modulus *mod, size_t len) {
    uint8_t bytes[RSA_MODULUS_LEN];
    ch_rand_bytes(bytes, len);
    bytes[0] |= 0x80;
    bytes[len - 1] |= 1;
    rsa_mont64_modulus_init(mod, bytes, len, 8 * len);
}

// o = fresh random words below mod's modulus: random bytes with the top
// bit clear, under a modulus whose top bit is set.
static void rsa_random_below(uint64_t *o, const rsa_mont64_modulus *mod) {
    uint8_t bytes[RSA_MODULUS_LEN];
    size_t len = 8 * mod->words;
    ch_rand_bytes(bytes, len);
    bytes[0] &= 0x7f;
    rsa_mont64_from_bytes(o, mod->words, bytes, len);
}

// rsa_mont64_mont_mul: one fixed pair of operands vs fresh random pairs.
// The fixed pair needs the subtraction that ends a multiplication every
// time or never, and a random pair some of the time, so a subtraction
// behind a branch shows here. Both classes draw a fresh pair and both
// copy a pair into the operands, the fixed one or the fresh one, so the
// classes differ in the operands' values and not in how they were
// written: a row that wrote one class with rsa_mont64_from_bytes and the
// other with memcpy measured the writes, at |t| of 10 to 16.
static uint64_t rsa_a_fixed[RSA_MONT64_WORDS_MAX];
static uint64_t rsa_b_fixed[RSA_MONT64_WORDS_MAX];
static uint64_t rsa_a_fresh[RSA_MONT64_WORDS_MAX];
static uint64_t rsa_b_fresh[RSA_MONT64_WORDS_MAX];

static void rsa_mul_prep(int class_id) {
    rsa_random_below(rsa_a_fresh, &rsa_mod);
    rsa_random_below(rsa_b_fresh, &rsa_mod);
    memcpy(rsa_a, class_id == 0 ? rsa_a_fixed : rsa_a_fresh, sizeof rsa_a);
    memcpy(rsa_b, class_id == 0 ? rsa_b_fixed : rsa_b_fresh, sizeof rsa_b);
}

static void rsa_mul_run(void) {
    uint64_t out[RSA_MONT64_WORDS_MAX];
    for (int r = 0; r < RSA_MUL_REPS; r++) {
        rsa_mont64_mont_mul(out, rsa_a, rsa_b, &rsa_mod);
    }
    sink ^= (uint32_t)out[0];
}

// rsa_mont64_mont_square: n - 1 vs fresh random operands below 2^(64k - 1).
// The top bit of n - 1 is set and that of every fresh operand is clear, so
// the classes differ in the bit the square adds under a mask at each row's
// top, and n - 1 needs the subtraction that ends a square every time or
// never: a branch on either shows here. Both classes copy an operand in,
// for the reason the multiplication's row gives.
static uint64_t rsa_square_fixed[RSA_MONT64_WORDS_MAX];

static void rsa_square_prep(int class_id) {
    rsa_random_below(rsa_a_fresh, &rsa_mod);
    memcpy(rsa_a, class_id == 0 ? rsa_square_fixed : rsa_a_fresh, sizeof rsa_a);
}

static void rsa_square_run(void) {
    uint64_t out[RSA_MONT64_WORDS_MAX];
    for (int r = 0; r < RSA_MUL_REPS; r++) {
        rsa_mont64_mont_square(out, rsa_a, &rsa_mod);
    }
    sink ^= (uint32_t)out[0];
}

// rsa_sign64_power: an exponent of zero bytes vs fresh random exponents,
// over one random base. Every digit of the first names the table's first
// entry, so a read that stops at its entry, a branch on a digit or a step
// that skips a zero digit shows here.
static uint64_t rsa_small_base[RSA_MONT64_WORDS_MAX];

static void rsa_power_prep(int class_id) {
    ch_rand_bytes(rsa_exponent, sizeof rsa_exponent);
    if (class_id == 0) {
        memset(rsa_exponent, 0, sizeof rsa_exponent);
    }
}

static void rsa_power_run(void) {
    uint64_t out[RSA_MONT64_WORDS_MAX];
    rsa_sign64_power(out, rsa_small_base, rsa_exponent, sizeof rsa_exponent, &rsa_small);
    sink ^= (uint32_t)out[0];
}
#endif

static void report(const char *name, double t) {
    int ok = fabs(t) < T_MAX;
    (void)printf("%-12s |t| = %6.2f  %s\n", name, fabs(t), ok ? "ok" : "LEAK");
    if (!ok) {
        failures++;
    }
}

#ifdef TEST_P256_WIDE
int main(void) {
    uint8_t draw[P256_SCALAR_LEN];
    uint8_t peer_priv[P256_SCALAR_LEN];
    ch_rand_bytes((uint8_t *)&rng_state, sizeof rng_state);
    rng_state |= 1;
    p256_random_scalar(draw);
    if (!p256_ecdh_keygen(WIDEMUL_CONSTANT_TIME, draw, peer_priv, p256_peer)) {
        (void)fprintf(stderr, "timing: no peer key\n");
        return 1;
    }
    ch_rand_bytes(p256_hash, sizeof p256_hash);

    p256_random_scalar(p256_fixed);
    report("keygen", measure(p256_prep, p256_keygen_run, P256_KEYGEN_N, 64));
    report("ecdh", measure(p256_prep, p256_ecdh_run, P256_ECDH_N, 64));
    report("sign", measure(p256_prep, p256_sign_run, P256_SIGN_N, 64));
    memset(p256_fixed, 0, sizeof p256_fixed);
    for (size_t bit = P256_WIDE_TABLE_WINDOW_BITS - 1; bit < 256;
         bit += P256_WIDE_TABLE_WINDOW_BITS) {
        p256_fixed[P256_SCALAR_LEN - 1 - bit / 8] |= (uint8_t)(1U << (bit % 8));
    }
    report("keygen same", measure(p256_prep, p256_keygen_run, P256_KEYGEN_N, 64));
    memset(p256_fixed, 0x88, sizeof p256_fixed);
    p256_fixed[0] = 0x08;
    report("ecdh same", measure(p256_prep, p256_ecdh_run, P256_ECDH_N, 64));
    return failures ? 1 : 0;
}
#else
int main(void) {
    ch_rand_bytes((uint8_t *)&rng_state, sizeof rng_state);
    rng_state |= 1;
    ch_rand_bytes(poly_key_fixed, sizeof poly_key_fixed);
    ch_rand_bytes(chacha_key_fixed, sizeof chacha_key_fixed);
    ch_rand_bytes(x_scalar_fixed, sizeof x_scalar_fixed);
    ch_rand_bytes(poly_msg, sizeof poly_msg);
    ch_rand_bytes(chacha_buf, sizeof chacha_buf);

    report("ct_memeq", measure(eq_prep, eq_run, FAST_N, WARMUP));
    report("poly1305", measure(poly_prep, poly_run, FAST_N, WARMUP));
    report("chacha20_xor", measure(chacha_prep, chacha_run, FAST_N, WARMUP));
    report(X25519_ROW, measure(x_prep, x_run, X25519_N, 32));
#ifdef TEST_RSA_SIGN64
    rsa_random_modulus(&rsa_mod, RSA_MODULUS_LEN);
    rsa_random_below(rsa_a_fixed, &rsa_mod);
    rsa_random_below(rsa_b_fixed, &rsa_mod);
    report("rsa64_mul", measure(rsa_mul_prep, rsa_mul_run, FAST_N, WARMUP));
    memcpy(rsa_square_fixed, rsa_mod.m, sizeof rsa_square_fixed);
    rsa_square_fixed[0] -= 1;
    report("rsa64_square", measure(rsa_square_prep, rsa_square_run, FAST_N, WARMUP));
    // The exponentiation's base: one random value below its modulus, moved
    // into the modulus's domain, the same for both classes.
    rsa_random_modulus(&rsa_small, RSA_SMALL_LEN);
    rsa_random_below(rsa_small_base, &rsa_small);
    rsa_mont64_mont_mul(rsa_small_base, rsa_small_base, rsa_small.r2, &rsa_small);
    report("rsa64_power", measure(rsa_power_prep, rsa_power_run, RSA_POWER_N, 32));
#endif
    return failures ? 1 : 0;
}
#endif
