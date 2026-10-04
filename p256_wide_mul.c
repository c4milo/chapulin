// The two P-256 scalar multiplications over the wide field (see p256_wide_mul.h for the
// contracts).
//
// p256_wide_base_mul writes the scalar as 64 signed odd digits, one for each four-bit window,
// and adds one entry of the table of multiples of G (p256_wide_table.h) for each digit. It
// never doubles. p256_wide_mul is p256_point.c's ladder on the wide field: 256 rounds, each
// one masked exchange, one addition, one doubling by the same addition, and the exchange
// back.
//
// The digits. The base multiplication computes K times G for K = k | 1, which is odd, and
// takes G away again when k was even. Write b_j for bit j of K, so b_0 is 1. Then
//
//     K = 2^255 + sum over j from 0 to 254 of s_j 2^j,  with s_j = 2 b_(j+1) - 1,
//
// because the sum is (K - 1) - (2^255 - 1). Each s_j is +1 or -1: +1 when the bit above
// position j is set. Four of them make the digit of window i,
//
//     d_i = s_(4i) + 2 s_(4i+1) + 4 s_(4i+2) + 8 s_(4i+3),
//
// with the 2^255 term standing in for s_255, so K is the sum of d_i 16^i. A digit is odd and
// lies between -15 and 15, and none is zero, so every window adds exactly one entry and the
// sequence of operations is the same for every scalar. A digit's sign is the sign of its top
// term: bit 4i + 4 of k, and positive for the top window. With v the three bits 4i + 1 to
// 4i + 3 of k, a positive digit is 2v + 1 and a negative one is -(2 (7 - v) + 1). Bit 0 of k
// is read once, for the correction at the end: K's bit 0 is 1 whatever k's is.
// proof/p256_wide_digit_harness.c proves that the digits add up to k | 1 for every k.
#include "p256_wide_mul.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>

#include "ct.h"
#include "p256_wide_field.h"
#include "p256_wide_limb.h"
#include "p256_wide_point.h"
#include "p256_wide_table.h"

#define WINDOW_BITS 4
#define WINDOWS P256_WIDE_TABLE_WINDOWS
#define ENTRIES P256_WIDE_TABLE_ENTRIES

static const p256_wide_fe FE_ZERO = {
    {0, 0, 0, 0}
};

// Bit i of k, for i below 256.
static inline uint64_t scalar_bit(const p256_scalar *k, size_t i) {
    return (k->limb[i >> 5] >> (i & 31)) & 1U;
}

// All ones when a and b are the same value and zero otherwise. a ^ b is zero exactly when the
// two are equal, and adding 2^64 - 1 to it, 128 bits wide so that nothing wraps, carries into
// bit 64 exactly when it is not zero.
static inline uint64_t equal_mask(uint64_t a, uint64_t b) {
    uint64_t differ = (uint64_t)(((ct_u128)(a ^ b) + UINT64_MAX) >> 64);
    return p256_wide_mask(differ ^ 1U);
}

// One digit of k | 1.
typedef struct {
    uint64_t index;    // where its size sits among the odd multiples: 0 for 1, 7 for 15
    uint64_t negative; // all ones for a negative digit, zero for a positive one
} digit;

// The digit of one window of k | 1, for window below WINDOWS. Its index is below ENTRIES.
static digit window_digit(const p256_scalar *k, size_t window) {
    size_t low = WINDOW_BITS * window;
    uint64_t size =
        scalar_bit(k, low + 1) | (scalar_bit(k, low + 2) << 1) | (scalar_bit(k, low + 3) << 2);
    // The top window's sign is the 2^255 term's. The test reads the window, a loop counter,
    // and never the scalar.
    uint64_t positive = 1;
    if (window + 1 < WINDOWS) {
        positive = scalar_bit(k, low + WINDOW_BITS);
    }
    digit d;
    d.negative = p256_wide_mask(positive ^ 1U);
    d.index = size ^ (d.negative & (ENTRIES - 1));
    return d;
}

// o |= a where mask is all ones, and o unchanged where it is zero.
static inline void fe_keep(p256_wide_fe *o, const p256_wide_fe *a, uint64_t mask) {
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        o->limb[i] |= a->limb[i] & mask;
    }
}

// o = row[index], for index below ENTRIES. It reads every entry of the row, in the same order
// whatever index holds, and keeps one by mask: no address read and no branch depends on
// index.
static void table_select(p256_wide_affine *o, const p256_wide_affine row[ENTRIES], uint64_t index) {
    o->x = FE_ZERO;
    o->y = FE_ZERO;
    for (uint64_t j = 0; j < ENTRIES; j++) {
        uint64_t mask = equal_mask(j, index);
        fe_keep(&o->x, &row[j].x, mask);
        fe_keep(&o->y, &row[j].y, mask);
    }
}

// o = a where mask is all ones, o unchanged where it is zero.
static void point_cmov(p256_wide_point *o, const p256_wide_point *a, uint64_t mask) {
    p256_wide_fe_cmov(&o->x, &a->x, mask);
    p256_wide_fe_cmov(&o->y, &a->y, mask);
    p256_wide_fe_cmov(&o->z, &a->z, mask);
}

// What the digit of one window adds, from the table of multiples of G: the entry of that
// window's row at the digit's size, with Y negated for a negative digit. *negated is the
// caller's, so that one wipe at the end of the multiplication covers it.
static void digit_entry(p256_wide_affine *o, p256_wide_fe *negated, const p256_scalar *k,
                        size_t window) {
    digit d = window_digit(k, window);
    table_select(o, p256_wide_table[window], d.index);
    p256_wide_fe_neg(negated, &o->y);
    p256_wide_fe_cmov(&o->y, negated, d.negative);
}

void p256_wide_base_mul(p256_point *o, const p256_scalar *k) {
    p256_wide_point sum;
    p256_wide_point corrected;
    p256_wide_affine entry;
    p256_wide_fe negated;

    // Window 0 starts the sum. Its entry is a finite point, so Z is 1.
    digit_entry(&entry, &negated, k, 0);
    sum.x = entry.x;
    sum.y = entry.y;
    sum.z = p256_wide_fe_one_mont;
    for (size_t window = 1; window < WINDOWS; window++) {
        digit_entry(&entry, &negated, k, window);
        p256_wide_point_add_affine(&sum, &sum, &entry);
    }
    // The digits are those of k | 1, so an even k takes G away again: the sum plus -G is
    // computed for every k and kept by mask.
    entry = p256_wide_table[0][0];
    p256_wide_fe_neg(&entry.y, &entry.y);
    p256_wide_point_add_affine(&corrected, &sum, &entry);
    point_cmov(&sum, &corrected, p256_wide_mask(scalar_bit(k, 0) ^ 1U));
    p256_wide_point_to_portable(o, &sum);

    ct_wipe(&sum, sizeof sum);
    ct_wipe(&corrected, sizeof corrected);
    ct_wipe(&entry, sizeof entry);
    ct_wipe(&negated, sizeof negated);
}

// Exchanges a and b when mask is all ones, leaves both when it is zero.
static void point_cswap(p256_wide_point *a, p256_wide_point *b, uint64_t mask) {
    p256_wide_fe_cswap(&a->x, &b->x, mask);
    p256_wide_fe_cswap(&a->y, &b->y, mask);
    p256_wide_fe_cswap(&a->z, &b->z, mask);
}

// One round of the Montgomery ladder, for bit i of k: p256_point.c's ladder_round on the wide
// field. The bit becomes a mask through p256_wide_mask and decides nothing else.
static void ladder_round(p256_wide_point *r0, p256_wide_point *r1, p256_wide_point *sum,
                         const p256_scalar *k, int i) {
    uint64_t bit = (k->limb[i >> 5] >> (i & 31)) & 1U;
    uint64_t mask = p256_wide_mask(bit);
    point_cswap(r0, r1, mask);
    p256_wide_point_add(sum, r0, r1);
    p256_wide_point_add(r0, r0, r0);
    *r1 = *sum;
    point_cswap(r0, r1, mask);
}

void p256_wide_mul(p256_point *o, const p256_scalar *k, const p256_point *p) {
    p256_wide_point r0;
    p256_wide_point r1;
    p256_wide_point sum;

    p256_wide_point_from_portable(&r0, &p256_point_infinity);
    p256_wide_point_from_portable(&r1, p);
    // Most significant bit first: 256 rounds, each the same work whatever the bit holds.
    for (int i = P256_SCALAR_LIMBS * 32 - 1; i >= 0; i--) {
        ladder_round(&r0, &r1, &sum, k, i);
    }
    p256_wide_point_to_portable(o, &r0);

    ct_wipe(&r0, sizeof r0);
    ct_wipe(&r1, sizeof r1);
    ct_wipe(&sum, sizeof sum);
}

#endif // CH_CPU_RUNTIME
