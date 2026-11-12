// The mixed Jacobian addition's rows of bin/diff_p256_wide (test/diff_p256_wide_test.c, which
// includes this file after the driver's helpers): p256_wide_point_add_jacobian_affine_incomplete
// on a Jacobian point and an affine one against spec/lean/Spec/P256WidePoint.lean's
// addJacobianAffineIncomplete, coordinate for coordinate (docs/decisions.md 224).
#ifndef CH_TEST_DIFF_P256_WIDE_MIXED_H
#define CH_TEST_DIFF_P256_WIDE_MIXED_H

#include "p256_wide_point.h"

static void run_add_jacobian_affine_incomplete(p256_wide_fe out[COORDINATES],
                                               const p256_wide_fe in[]) {
    p256_wide_jacobian a = {in[0], in[1], in[2]};
    p256_wide_affine b = {in[3], in[4]};
    p256_wide_point_add_jacobian_affine_incomplete(&a, &a, &b);
    out[0] = a.x;
    out[1] = a.y;
    out[2] = a.z;
}

// Random coordinates, on the curve or not, and then two inputs outside the addition's
// condition: Z1 = 0, and Z1 = 1 with x2 = X1, two points with the same x. On both the result's
// Z is zero, and the two sides must still agree on every coordinate.
static void diff_add_jacobian_affine_incomplete(void) {
    uint8_t coordinate[5][P256_FE_LEN];
    for (size_t i = 0; i < 5; i++) {
        draw_element(coordinate[i]);
    }
    diff_point_row("p256_add_jacobian_affine_incomplete", coordinate, 5,
                   run_add_jacobian_affine_incomplete);
    memset(coordinate[2], 0, P256_FE_LEN);
    diff_point_row("p256_add_jacobian_affine_incomplete", coordinate, 5,
                   run_add_jacobian_affine_incomplete);
    coordinate[2][P256_FE_LEN - 1] = 1;
    memcpy(coordinate[3], coordinate[0], P256_FE_LEN);
    diff_point_row("p256_add_jacobian_affine_incomplete", coordinate, 5,
                   run_add_jacobian_affine_incomplete);
}

#endif
