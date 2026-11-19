// Lab only (branch lab/n2-sve2-chacha, never merged): a ChaCha20 keystream XOR on SVE2, checked
// against chacha20_xor and timed beside it. Words are sliced across lanes: lane i holds block i.
// SVE2's XAR does a XOR and a rotation in one instruction, which NEON lacks. Fixed to 4 lanes,
// the vector length of a Neoverse N2.
#include <arm_sve.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "chacha20.h"

// Fixed-length SVE types (-msve-vector-bits=128), so arrays of them are allowed.
typedef svuint32_t v32 __attribute__((arm_sve_vector_bits(128)));
typedef svuint64_t v64 __attribute__((arm_sve_vector_bits(128)));

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

#define QR(a, b, c, d)                                                                             \
    a = svadd_u32_x(pg, a, b);                                                                     \
    d = svxar_n_u32(d, a, 16);                                                                     \
    c = svadd_u32_x(pg, c, d);                                                                     \
    b = svxar_n_u32(b, c, 20);                                                                     \
    a = svadd_u32_x(pg, a, b);                                                                     \
    d = svxar_n_u32(d, a, 24);                                                                     \
    c = svadd_u32_x(pg, c, d);                                                                     \
    b = svxar_n_u32(b, c, 25);

#define ROUNDS(x)                                                                                  \
    for (int r = 0; r < 10; r++) {                                                                 \
        QR(x[0], x[4], x[8], x[12]) QR(x[1], x[5], x[9], x[13]) QR(x[2], x[6], x[10], x[14])     \
        QR(x[3], x[7], x[11], x[15]) QR(x[0], x[5], x[10], x[15]) QR(x[1], x[6], x[11], x[12])   \
        QR(x[2], x[7], x[8], x[13]) QR(x[3], x[4], x[9], x[14])                                  \
    }

// Writes four blocks (256 bytes) of in XOR keystream to out, from the state's 16 words.
static void store4(const v32 *x, const uint8_t *in, uint8_t *out) {
    svbool_t p8 = svptrue_b8();
    for (int g = 0; g < 4; g++) {
        svuint32_t t0 = svzip1_u32(x[4 * g], x[4 * g + 1]);
        svuint32_t t1 = svzip2_u32(x[4 * g], x[4 * g + 1]);
        svuint32_t t2 = svzip1_u32(x[4 * g + 2], x[4 * g + 3]);
        svuint32_t t3 = svzip2_u32(x[4 * g + 2], x[4 * g + 3]);
        v64 r[4] = {svzip1_u64(svreinterpret_u64_u32(t0), svreinterpret_u64_u32(t2)),
                           svzip2_u64(svreinterpret_u64_u32(t0), svreinterpret_u64_u32(t2)),
                           svzip1_u64(svreinterpret_u64_u32(t1), svreinterpret_u64_u32(t3)),
                           svzip2_u64(svreinterpret_u64_u32(t1), svreinterpret_u64_u32(t3))};
        for (int b = 0; b < 4; b++) {
            size_t at = (size_t)b * 64 + (size_t)g * 16;
            svuint8_t k = svreinterpret_u8_u64(r[b]);
            svst1_u8(p8, out + at, sveor_u8_x(p8, svld1_u8(p8, in + at), k));
        }
    }
}

// Variant 1: four blocks a pass. Variant 2: eight blocks a pass, two independent states.
static void sve2_xor(int variant, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                     const uint8_t *in, uint8_t *out, size_t n) {
    svbool_t pg = svptrue_b32();
    uint32_t s[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (int i = 0; i < 8; i++) {
        s[4 + i] = load32(key + 4 * i);
    }
    for (int i = 0; i < 3; i++) {
        s[13 + i] = load32(nonce + 4 * i);
    }
    size_t step = variant == 2 ? 512 : 256;
    while (n >= step) {
        v32 a[16], b[16], ia[16], ib[16];
        for (int i = 0; i < 16; i++) {
            ia[i] = svdup_n_u32(i == 12 ? 0 : s[i]);
            ib[i] = ia[i];
        }
        ia[12] = svindex_u32(counter, 1);
        ib[12] = svindex_u32(counter + 4, 1);
        for (int i = 0; i < 16; i++) {
            a[i] = ia[i];
            b[i] = ib[i];
        }
        if (variant == 2) {
            for (int r = 0; r < 10; r++) {
                QR(a[0], a[4], a[8], a[12]) QR(b[0], b[4], b[8], b[12])
                QR(a[1], a[5], a[9], a[13]) QR(b[1], b[5], b[9], b[13])
                QR(a[2], a[6], a[10], a[14]) QR(b[2], b[6], b[10], b[14])
                QR(a[3], a[7], a[11], a[15]) QR(b[3], b[7], b[11], b[15])
                QR(a[0], a[5], a[10], a[15]) QR(b[0], b[5], b[10], b[15])
                QR(a[1], a[6], a[11], a[12]) QR(b[1], b[6], b[11], b[12])
                QR(a[2], a[7], a[8], a[13]) QR(b[2], b[7], b[8], b[13])
                QR(a[3], a[4], a[9], a[14]) QR(b[3], b[4], b[9], b[14])
            }
        } else {
            ROUNDS(a)
        }
        for (int i = 0; i < 16; i++) {
            a[i] = svadd_u32_x(pg, a[i], ia[i]);
            b[i] = svadd_u32_x(pg, b[i], ib[i]);
        }
        store4(a, in, out);
        if (variant == 2) {
            store4(b, in + 256, out + 256);
        }
        counter += (uint32_t)(step / 64);
        in += step;
        out += step;
        n -= step;
    }
    if (n > 0) {
        chacha20_xor(key, nonce, counter, in, out, n);
    }
}

int main(void) {
    if (svcntw() != 4) {
        printf("vector length %u words, not 4: this lab assumes an N2\n", (unsigned)svcntw());
        return 1;
    }
    enum { N = 16384 };
    static uint8_t key[32], nonce[12], in[N], ref[N], got[N];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i * 13 + 3);
    for (int i = 0; i < N; i++) in[i] = (uint8_t)(i * 31 + 5);
    chacha20_xor(key, nonce, 1, in, ref, N);
    for (int v = 1; v <= 2; v++) {
        for (size_t len = 0; len <= 1100; len += 37) {
            memset(got, 0, sizeof got);
            sve2_xor(v, key, nonce, 1, in, got, len);
            if (memcmp(got, ref, len) != 0) {
                printf("MISMATCH variant %d at length %zu\n", v, len);
                return 1;
            }
        }
        sve2_xor(v, key, nonce, 1, in, got, N);
        if (memcmp(got, ref, N) != 0) {
            printf("MISMATCH variant %d at 16 KiB\n", v);
            return 1;
        }
    }
    const char *names[3] = {"neon_chacha20_xor", "sve2_4_blocks", "sve2_8_blocks"};
    for (int m = 0; m < 3; m++) {
        double best = 1e30;
        for (int s = 0; s < 31; s++) {
            double t0 = now_ns();
            for (int rep = 0; rep < 50; rep++) {
                if (m == 0) {
                    chacha20_xor(key, nonce, 1, in, got, N);
                } else {
                    sve2_xor(m, key, nonce, 1, in, got, N);
                }
            }
            double per = (now_ns() - t0) / 50;
            if (per < best) best = per;
        }
        printf("%s,16384,%.0f ns,%.3f GB/s\n", names[m], best, N / best);
    }
    return 0;
}
