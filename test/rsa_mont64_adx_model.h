// A model of rsa_mont64_adx.c's five assembly operations in portable C, on
// ct.h's ct_u128. rsa_mont64_adx.c includes it in their place under
// CH_RSA_MONT64_ADX_MODEL, with -Itest: the CBMC harnesses, the model test
// and the equivalence test build it that way, and no library object does.
//
// Each function writes the exact sum its assembly's comment states, so the
// words are the assembly's own and bin/rsa_mont64_adx_equiv_test compares
// them word for word. Each loop runs over the public word count alone.
#ifndef CH_TEST_RSA_MONT64_ADX_MODEL_H
#define CH_TEST_RSA_MONT64_ADX_MODEL_H

#include <stddef.h>
#include <stdint.h>

#include "ct.h"

// t[0..n] = y * v[0..n-1].
static void adx_row_first(uint64_t *t, uint64_t y, const uint64_t *v, size_t n) {
    uint64_t carry = 0;
    for (size_t j = 0; j < n; j++) {
        ct_u128 sum = ct_mul128(y, v[j]) + carry;
        t[j] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    t[n] = carry;
}

// t[0..n-1] += y * v[0..n-1], and t[n] = the top word of that sum.
static void adx_row_store_top(uint64_t *t, uint64_t y, const uint64_t *v, size_t n) {
    uint64_t carry = 0;
    for (size_t j = 0; j < n; j++) {
        ct_u128 sum = ct_mul128(y, v[j]) + t[j] + carry;
        t[j] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    t[n] = carry;
}

// t[0..n] += y * v[0..n-1] + cin * 2^(64n). Returns the carry out of t[n].
static uint64_t adx_row_carry(uint64_t *t, uint64_t y, const uint64_t *v, size_t n, uint64_t cin) {
    uint64_t carry = 0;
    for (size_t j = 0; j < n; j++) {
        ct_u128 sum = ct_mul128(y, v[j]) + t[j] + carry;
        t[j] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    ct_u128 top = (ct_u128)t[n] + carry + cin;
    t[n] = (uint64_t)top;
    return (uint64_t)(top >> 64);
}

// t[0..2k-1] = 2 * t + the sum of a[i]^2 * 2^(128 i).
static void adx_double_add_diagonal(uint64_t *t, const uint64_t *a, size_t k) {
    uint64_t carry = 0;
    for (size_t i = 0; i < k; i++) {
        ct_u128 sq = ct_mul128(a[i], a[i]);
        ct_u128 low = ((ct_u128)t[2 * i] << 1) + (uint64_t)sq + carry;
        t[2 * i] = (uint64_t)low;
        ct_u128 high = ((ct_u128)t[2 * i + 1] << 1) + (uint64_t)(sq >> 64) + (uint64_t)(low >> 64);
        t[2 * i + 1] = (uint64_t)high;
        carry = (uint64_t)(high >> 64);
    }
}

// All ones when bit is 1 and all zeros when it is 0, in rsa_mont64.c's
// form, which wraps no unsigned value.
static uint64_t model_mask(uint64_t bit) {
    return (uint64_t)((int64_t)(bit << 63) >> 63);
}

// o = top:t - m when top:t is m or more, and top:t otherwise. Each word of
// t - m is t + ~m + the carry, where the carry is 1 less the borrow, so no
// sum wraps. The choice is a mask, as the assembly's is a CMOVC.
static void adx_final_sub(uint64_t *o, const uint64_t *t, uint64_t top, const uint64_t *m,
                          size_t k) {
    uint64_t carry = 1;
    for (size_t j = 0; j < k; j++) {
        ct_u128 sum = (ct_u128)t[j] + ~m[j] + carry;
        o[j] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    // top:t is below m exactly when top is 0 and the subtraction borrowed:
    // the borrow out of top less the borrow. top is 0 or 1.
    uint64_t keep = model_mask((carry ^ 1) & (top ^ 1));
    for (size_t j = 0; j < k; j++) {
        o[j] = (o[j] & ~keep) | (t[j] & keep);
    }
}

#endif
