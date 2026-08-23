// x25519 differential section: the scalar multiplication of a random
// point and of the base point. Both rows run the C module and the Lean
// spec on the same scalar and compare the 32 output bytes.
// Included by test/diff.c after diffdrv.h (single translation unit).
#ifndef CH_DIFFX25519_H
#define CH_DIFFX25519_H

#include "x25519.h"

static void diff_x25519(void) {
    for (int i = 0; i < 100; i++) {
        uint8_t scalar[X25519_LEN];
        rng_fill(scalar, sizeof scalar);
        uint8_t point[X25519_LEN];
        rng_fill(point, sizeof point);
        uint8_t out[X25519_LEN];
        (void)x25519(out, scalar, point); // 0 = all-zero out; still comparable
        char key_hex[65];
        (void)hex_encode(key_hex, scalar, sizeof scalar);
        char point_hex[65];
        (void)hex_encode(point_hex, point, sizeof point);
        char want[65];
        (void)hex_encode(want, out, sizeof out);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "x25519 %s %s", key_hex, point_hex);
        expect(cmd, want);
    }
}

static void diff_x25519_base(void) {
    for (int i = 0; i < 50; i++) {
        uint8_t scalar[X25519_LEN];
        rng_fill(scalar, sizeof scalar);
        uint8_t out[X25519_LEN];
        x25519_base(out, scalar);
        char key_hex[65];
        (void)hex_encode(key_hex, scalar, sizeof scalar);
        char want[65];
        (void)hex_encode(want, out, sizeof out);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "x25519_base %s", key_hex);
        expect(cmd, want);
    }
}

#endif
