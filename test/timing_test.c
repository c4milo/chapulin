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
// key-dependent behavior in clamping, the limb products, or the final
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
// ladder that branches on scalar bits or skips work per limb shows here.
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
    x25519_base(out, x_scalar);
    sink ^= out[0];
}

static void report(const char *name, double t) {
    int ok = fabs(t) < T_MAX;
    (void)printf("%-12s |t| = %6.2f  %s\n", name, fabs(t), ok ? "ok" : "LEAK");
    if (!ok) {
        failures++;
    }
}

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
    report("x25519", measure(x_prep, x_run, X25519_N, 32));
    return failures ? 1 : 0;
}
