// The halving's rows of bin/diff_p256_wide (test/diff_p256_wide_test.c, which includes this file
// after the driver's helpers): p256_wide_fe_half on one element below p against the spec's
// product of it and the inverse of 2, the step the doubling of spec/lean/Spec/P256WidePoint.lean
// reads (docs/decisions.md 196).
#ifndef CH_TEST_DIFF_P256_WIDE_HALF_H
#define CH_TEST_DIFF_P256_WIDE_HALF_H

#include "p256_wide_field.h"

// The halving is the same map on the Montgomery domain and off it, so this side halves the
// element's words as they are.
static void diff_half_row(const uint8_t element[P256_FE_LEN]) {
    p256_wide_fe value;
    uint8_t bytes[P256_FE_LEN];
    char cmd[32 + HEX_LEN(P256_FE_LEN)];
    char want[HEX_LEN(P256_FE_LEN)];
    size_t cmd_len = (size_t)snprintf(cmd, sizeof cmd, "p256_half ");
    (void)hex_encode(cmd + cmd_len, element, P256_FE_LEN);
    p256_wide_fe_from_bytes(&value, element);
    p256_wide_fe_half(&value, &value);
    p256_wide_fe_to_bytes(bytes, &value);
    (void)hex_encode(want, bytes, sizeof bytes);
    expect(cmd, want);
}

// The edges of the words first: 0, 1 and 2, then p - 1, the largest element, and p - 2, the
// largest odd element, whose sum with p carries out of the four words. Then random elements.
static void diff_half(void) {
    // p - 1, big-endian.
    static const uint8_t P_LESS_ONE[P256_FE_LEN] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    };
    uint8_t element[P256_FE_LEN];
    for (uint8_t low = 0; low <= 2; low++) {
        memset(element, 0, sizeof element);
        element[P256_FE_LEN - 1] = low;
        diff_half_row(element);
    }
    memcpy(element, P_LESS_ONE, sizeof element);
    diff_half_row(element);
    element[P256_FE_LEN - 1] = 0xfd;
    diff_half_row(element);
    for (int round = 0; round < ROUNDS; round++) {
        draw_element(element);
        diff_half_row(element);
    }
}

#endif
