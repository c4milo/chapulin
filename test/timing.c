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

#include "chacha20.h"
#include "ct.h"
#include "ms_assert.h"
#include "poly1305.h"
#include "rand.h"
#include "testrand.h"
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

noreturn void ms_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static uint64_t now_ns(void) {
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000U + (uint64_t)ts.tv_nsec;
}

// xorshift64*, seeded once from ms_rand_bytes; drives only the class
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
static uint8_t sched[2 * FAST_N];

static void shuffle_sched(size_t n) {
    for (size_t i = 0; i < 2 * n; i++) {
        sched[i] = (uint8_t)(i < n ? 0 : 1);
    }
    for (size_t i = 2 * n - 1; i > 0; i--) {
        size_t j = (size_t)(rng64() % (i + 1));
        uint8_t tmp = sched[i];
        sched[i] = sched[j];
        sched[j] = tmp;
    }
}

static uint64_t lat[2][FAST_N];

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

static double welch_t(uint64_t *a, size_t na, uint64_t *b, size_t nb) {
    double ma;
    double va;
    double mb;
    double vb;
    size_t ka;
    size_t kb;
    cropped_stats(a, na, &ma, &va, &ka);
    cropped_stats(b, nb, &mb, &vb, &kb);
    return (ma - mb) / sqrt(va / (double)ka + vb / (double)kb);
}

typedef void (*prep_fn)(int cls);
typedef void (*run_fn)(void);

static double measure(prep_fn prep, run_fn run, size_t n, size_t warm) {
    shuffle_sched(n);
    for (size_t i = 0; i < warm; i++) {
        prep((int)(i & 1));
        run();
    }
    size_t count[2] = {0, 0};
    for (size_t i = 0; i < 2 * n; i++) {
        int cls = sched[i];
        prep(cls);
        uint64_t t0 = now_ns();
        run();
        uint64_t t1 = now_ns();
        lat[cls][count[cls]++] = t1 - t0;
    }
    return welch_t(lat[0], n, lat[1], n);
}

// ct_memeq: equal buffers vs a difference at byte 0. An early-exit
// compare finishes after one byte for class 1 and drives t positive.
static uint8_t eq_a[64];
static uint8_t eq_b[64];

static void eq_prep(int cls) {
    ms_rand_bytes(eq_a, sizeof eq_a);
    memcpy(eq_b, eq_a, sizeof eq_b);
    eq_b[0] ^= (uint8_t)cls;
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

static void poly_prep(int cls) {
    ms_rand_bytes(poly_key, sizeof poly_key);
    if (cls == 0) {
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
static uint8_t cc_key_fixed[CHACHA20_KEY];
static uint8_t cc_key[CHACHA20_KEY];
static uint8_t cc_buf[256];

static void cc_prep(int cls) {
    ms_rand_bytes(cc_key, sizeof cc_key);
    if (cls == 0) {
        memcpy(cc_key, cc_key_fixed, sizeof cc_key);
    }
}

static void cc_run(void) {
    static const uint8_t nonce[CHACHA20_NONCE] = {0};
    for (int r = 0; r < CHACHA_REPS; r++) {
        chacha20_xor(cc_key, nonce, 1, cc_buf, cc_buf, sizeof cc_buf);
    }
    sink ^= cc_buf[0];
}

// x25519: fixed scalar vs fresh random scalars on the base point. A
// ladder that branches on scalar bits or skips work per limb shows here.
static uint8_t x_scalar_fixed[X25519_LEN];
static uint8_t x_scalar[X25519_LEN];

static void x_prep(int cls) {
    ms_rand_bytes(x_scalar, sizeof x_scalar);
    if (cls == 0) {
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
    ms_rand_bytes((uint8_t *)&rng_state, sizeof rng_state);
    rng_state |= 1;
    ms_rand_bytes(poly_key_fixed, sizeof poly_key_fixed);
    ms_rand_bytes(cc_key_fixed, sizeof cc_key_fixed);
    ms_rand_bytes(x_scalar_fixed, sizeof x_scalar_fixed);
    ms_rand_bytes(poly_msg, sizeof poly_msg);
    ms_rand_bytes(cc_buf, sizeof cc_buf);

    report("ct_memeq", measure(eq_prep, eq_run, FAST_N, WARMUP));
    report("poly1305", measure(poly_prep, poly_run, FAST_N, WARMUP));
    report("chacha20_xor", measure(cc_prep, cc_run, FAST_N, WARMUP));
    report("x25519", measure(x_prep, x_run, X25519_N, 32));
    return failures ? 1 : 0;
}
