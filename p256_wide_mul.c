// The two P-256 scalar multiplications over the wide field (see p256_wide_mul.h for the
// contracts). The ladder is p256_point.c's: 256 rounds, each one masked exchange, one addition,
// one doubling by the same addition, and the exchange back.
#include "p256_wide_mul.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>

#include "ct.h"
#include "p256_wide_field.h"
#include "p256_wide_limb.h"
#include "p256_wide_point.h"

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

void p256_wide_base_mul(p256_point *o, const p256_scalar *k) {
    p256_wide_mul(o, k, &p256_point_generator);
}

#endif // CH_CPU_RUNTIME
