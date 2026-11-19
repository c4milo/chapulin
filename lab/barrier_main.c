// Lab only: chacha20_sve2_xor against the pinned variant: equal bytes, and the time of each.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "chacha20.h"
#include "chacha20_sve2.h"
#include "chacha20_vector.h"

void chacha20_sve2_barrier_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                               const uint8_t *in, uint8_t *out, size_t n);

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

enum { N = 16384 };
static uint8_t key[32], nonce[12], in[N], a[N], b[N];
typedef void (*xor_fn)(const uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint8_t *,
                       size_t);

static double best(xor_fn f, size_t len) {
    double m = 1e30;
    int reps = len >= 4096 ? 50 : 2000;
    for (int s = 0; s < 31; s++) {
        double t0 = now_ns();
        for (int r = 0; r < reps; r++) f(key, nonce, 1, in, a, len);
        double per = (now_ns() - t0) / reps;
        if (per < m) m = per;
    }
    return m;
}

int main(void) {
    for (int i = 0; i < N; i++) in[i] = (uint8_t)(i * 31 + 5);
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (size_t len = 0; len <= 2400; len++) {
        chacha20_xor(key, nonce, 7, in, a, len);
        chacha20_sve2_barrier_xor(key, nonce, 7, in, b, len);
        if (memcmp(a, b, len) != 0) { printf("MISMATCH %zu\n", len); return 1; }
    }
    size_t lens[3] = {256, 1024, 16384};
    for (int i = 0; i < 3; i++) {
        double neon = best(chacha20_vector_xor, lens[i]);
        double ship = best(chacha20_sve2_xor, lens[i]);
        double pin = best(chacha20_sve2_barrier_xor, lens[i]);
        printf("len %5zu  neon %7.0f  sve2 %7.0f (%.3f)  pinned %7.0f (%.3f)\n", lens[i], neon,
               ship, ship / neon, pin, pin / neon);
    }
    return 0;
}
