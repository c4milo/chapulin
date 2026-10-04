// The reference arithmetic p256_wide_field_harness.c and
// p256_wide_scalar_harness.c hold the masked code to: four 64-bit limbs added
// and subtracted through 128-bit sums that cannot wrap, with the carry or the
// borrow read from bit 64. The shipped code takes its carries from
// __builtin_add_overflow and its choices from masks, so a reference written
// with neither is what makes "the same value" a claim and not a restatement.
#ifndef CH_PROOF_P256_WIDE_REFERENCE_H
#define CH_PROOF_P256_WIDE_REFERENCE_H

#include <stddef.h>
#include <stdint.h>

#include "ct.h"

#define REF_LIMBS 4

uint64_t nondet_u64(void);

static int limbs_same(const uint64_t a[REF_LIMBS], const uint64_t b[REF_LIMBS]) {
    for (size_t i = 0; i < REF_LIMBS; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

// o = a + b. Returns the carry out, 0 or 1.
static uint64_t ref_add(uint64_t o[REF_LIMBS], const uint64_t a[REF_LIMBS],
                        const uint64_t b[REF_LIMBS]) {
    uint64_t carry = 0;
    for (size_t i = 0; i < REF_LIMBS; i++) {
        ct_u128 sum = (ct_u128)a[i] + b[i] + carry;
        o[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    return carry;
}

// o = a - b. Returns the borrow out, 0 or 1. Each limb is lent 2^64, so no
// difference goes below zero.
static uint64_t ref_sub(uint64_t o[REF_LIMBS], const uint64_t a[REF_LIMBS],
                        const uint64_t b[REF_LIMBS]) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < REF_LIMBS; i++) {
        ct_u128 difference = ((ct_u128)1 << 64) + a[i] - b[i] - borrow;
        o[i] = (uint64_t)difference;
        borrow = 1 - (uint64_t)(difference >> 64);
    }
    return borrow;
}

// 1 when a is below the modulus m, 0 otherwise.
static int ref_below(const uint64_t a[REF_LIMBS], const uint64_t m[REF_LIMBS]) {
    uint64_t discard[REF_LIMBS];
    return ref_sub(discard, a, m) == 1;
}

#endif
