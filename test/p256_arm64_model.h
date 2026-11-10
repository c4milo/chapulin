// A model of p256_arm64_field.c's two assembly routines in portable C.
// p256_arm64_field_inline.h includes it in their place under
// CH_P256_ARM64_MODEL, with -Itest: the CBMC harnesses, the model test and
// the differential build it that way, and no library object does.
// bin/p256_arm64_equiv_test includes it beside the assembly build and
// compares the two word for word.
//
// Each step writes the words the assembly writes. The product is four rows
// of p256_wide_word.h's p256_wide_mul_row, row i at word i for a[i], and the
// square is p256_wide_sqr_product's eight words: the assembly runs the same
// two carry chains a row and the same ten products. The rounds and the final
// subtraction are test/p256_adx_model.h's model_reduce: u << 32, u >> 32 and
// the two words of u * p3, the high one plus the carry the round before
// left, added at words k + 1 to k + 4, then the subtraction of p and the
// choice by the borrow. spec/lean/Spec/P256Adx.lean models those rounds and
// proves what they compute.
#ifndef CH_TEST_P256_ARM64_MODEL_H
#define CH_TEST_P256_ARM64_MODEL_H

#include <stdint.h>

#include "p256_adx_model.h"
#include "p256_wide_word.h"

// o = a * b / 2^256 mod p. o may be a or b.
static inline void p256_arm64_mul_mont(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t t[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    t[4] = p256_wide_mul_row(&t[0], &t[1], &t[2], &t[3], a[0], b[0], b[1], b[2], b[3]);
    t[5] = p256_wide_mul_row(&t[1], &t[2], &t[3], &t[4], a[1], b[0], b[1], b[2], b[3]);
    t[6] = p256_wide_mul_row(&t[2], &t[3], &t[4], &t[5], a[2], b[0], b[1], b[2], b[3]);
    t[7] = p256_wide_mul_row(&t[3], &t[4], &t[5], &t[6], a[3], b[0], b[1], b[2], b[3]);
    model_reduce(o, t);
}

// o = a * a / 2^256 mod p. o may be a.
static inline void p256_arm64_sqr_mont(uint64_t o[4], const uint64_t a[4]) {
    uint64_t t[8];
    p256_wide_sqr_product(&t[0], &t[1], &t[2], &t[3], &t[4], &t[5], &t[6], &t[7], a[0], a[1], a[2],
                          a[3]);
    model_reduce(o, t);
}

#endif
