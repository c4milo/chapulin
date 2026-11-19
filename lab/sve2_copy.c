// Lab only (branch lab/n2-sve2-chacha, never merged): checks chacha20_sve2.c's copy against
// chacha20_xor and times it beside the NEON path, through chacha20_xor_cpu.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "chacha20.h"
#include "chacha20_sve2.h"
#include "chacha20_vector.h"
#include "cpu_cfg.h"

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

enum { N = 16384 };
static uint8_t key[32], nonce[12], in[N], ref[N], got[N];

static double best_ns(uint32_t cpu, size_t len) {
    double best = 1e30;
    int reps = len >= 4096 ? 50 : 2000;
    for (int s = 0; s < 31; s++) {
        double t0 = now_ns();
        for (int r = 0; r < reps; r++) {
            chacha20_xor_cpu(cpu, key, nonce, 1, in, got, len);
        }
        double per = (now_ns() - t0) / reps;
        if (per < best) best = per;
    }
    return best;
}

int main(void) {
#ifndef CH_CHACHA20_SVE2
    printf("this compiler builds no SVE2 copy\n");
    return 0;
#else
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i * 13 + 3);
    for (int i = 0; i < N; i++) in[i] = (uint8_t)(i * 31 + 5);
    uint32_t counters[3] = {1, 0xfffffff0U, 0xffffffffU};
    for (int c = 0; c < 3; c++) {
        chacha20_xor(key, nonce, counters[c], in, ref, N);
        for (size_t len = 0; len <= 2400; len++) {
            memset(got, 0, sizeof got);
            chacha20_sve2_xor(key, nonce, counters[c], in, got, len);
            if (memcmp(got, ref, len) != 0 || (len < N && got[len] != 0)) {
                printf("MISMATCH counter %x length %zu\n", (unsigned)counters[c], len);
                return 1;
            }
        }
        memcpy(got, in, N);
        chacha20_sve2_xor(key, nonce, counters[c], got, got, N);
        if (memcmp(got, ref, N) != 0) {
            printf("MISMATCH in place counter %x\n", (unsigned)counters[c]);
            return 1;
        }
    }
    printf("equal at lengths 0..2400, three counters, and in place over 16 KiB\n");
    size_t lens[4] = {64, 256, 1024, 16384};
    for (int i = 0; i < 4; i++) {
        double neon = best_ns(CH_CPU_PROBED, lens[i]);
        double sve2 = best_ns(CH_CPU_PROBED | CH_CPU_SVE2, lens[i]);
        printf("len %5zu  neon %8.0f ns  sve2 %8.0f ns  ratio %.3f  sve2 %.2f GB/s\n", lens[i], neon,
               sve2, sve2 / neon, lens[i] / sve2);
    }
    return 0;
#endif
}
