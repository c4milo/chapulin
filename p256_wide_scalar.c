// The wide P-256 scalar arithmetic (see p256_wide_scalar.h for the contracts). A scalar is four
// little-endian uint64 limbs inside a call. Multiplication is the 512-bit product, four rows
// of p256_wide_limb.h's p256_wide_mul_row, and then four rounds of Montgomery reduction, each
// one more row. A square is p256_wide_sqr_product's ten products and the same rounds. The
// inverse is a Fermat power over a table of the first fifteen powers, and its squarings are
// those squares.
//
// The layout follows p256_wide_field.c's, as p256_scalar.c follows p256_field.c's. The two
// differ in the modulus, its Montgomery constants and the reduction round: the field prime's
// round is shifts, and the group order's is a product.
#include "p256_wide_scalar.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>

#include "ct.h"
#include "p256_wide_limb.h"

#define LIMBS 4

typedef struct {
    uint64_t limb[LIMBS];
} wide_scalar;

// SEC 2 secp256r1's group order, least significant limb first, and the constants derived
// from it, R = 2^256. The same order is p256_scalar.c's N, in limbs half as wide.
// tools/p256_wide.py recomputes each one and stops if a limb differs.
#define N0 UINT64_C(0xf3b9cac2fc632551)
#define N1 UINT64_C(0xbce6faada7179e84)
#define N2 UINT64_C(0xffffffffffffffff)
#define N3 UINT64_C(0xffffffff00000000)
// -n^-1 mod 2^64.
#define N0_INV UINT64_C(0xccd1c8aaee00bc4f)

// 2^512 mod n: multiplying by it enters the Montgomery domain.
static const wide_scalar RR = {
    {UINT64_C(0x83244c95be79eea2), UINT64_C(0x4699799c49bd6fa6), UINT64_C(0x2845b2392b6bec59),
     UINT64_C(0x66e12d94f3d95620)}
};
// R mod n, the Montgomery form of 1.
static const wide_scalar ONE_MONT = {
    {UINT64_C(0x0c46353d039cdaaf), UINT64_C(0x4319055258e8617b), UINT64_C(0x0000000000000000),
     UINT64_C(0x00000000ffffffff)}
};
static const wide_scalar ONE = {
    {1, 0, 0, 0}
};

// n - 2, the Fermat exponent, is
//   ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc63254f.
// Its top two limbs are 32 ones, 32 zeros and 64 ones, which p256_wide_scalar_inverse writes
// as runs of ones. These are its low two limbs, least significant first, which that routine
// reads four bits at a time.
static const uint64_t EXPONENT_LOW[2] = {UINT64_C(0xf3b9cac2fc63254f),
                                         UINT64_C(0xbce6faada7179e84)};
#define EXPONENT_LOW_NIBBLES 32

// Four bits of EXPONENT_LOW: nibble `at`, 0 the least significant, for at below
// EXPONENT_LOW_NIBBLES. Shifts and masks stand in for / and % (INV-23). The result is below 16,
// and it indexes the table of powers in p256_wide_scalar_inverse.
static inline uint64_t exponent_low_nibble(size_t at) {
    return (EXPONENT_LOW[at >> 4] >> (4 * (at & 15))) & 15U;
}

// o = (high : t3 : t2 : t1 : t0) - n when that 257-bit value is at or above n, o = t otherwise.
// high is 0 or 1: it is the carry out of mont_mul's last round.
static inline void reduce_once(uint64_t o[LIMBS], uint64_t t0, uint64_t t1, uint64_t t2,
                               uint64_t t3, uint64_t high) {
    uint64_t borrow = 0;
    uint64_t r0 = p256_wide_sub_borrow(&borrow, t0, N0);
    uint64_t r1 = p256_wide_sub_borrow(&borrow, t1, N1);
    uint64_t r2 = p256_wide_sub_borrow(&borrow, t2, N2);
    uint64_t r3 = p256_wide_sub_borrow(&borrow, t3, N3);
    // high : t is below n exactly when high is 0 and the subtraction borrowed out.
    uint64_t keep = p256_wide_mask(borrow & (high ^ 1U));
    o[0] = (t0 & keep) | (r0 & ~keep);
    o[1] = (t1 & keep) | (r1 & ~keep);
    o[2] = (t2 & keep) | (r2 & ~keep);
    o[3] = (t3 & keep) | (r3 & ~keep);
}

// One round of Montgomery reduction on the five limbs (*t4 : *t3 : *t2 : *t1 : *t0). It adds
// u * n for the u that makes the low limb zero, and returns the carry out of *t4, 0 or 1. The
// caller drops *t0. top is the carry the round before returned, which belongs in *t4.
static inline uint64_t reduce_round(uint64_t *t0, uint64_t *t1, uint64_t *t2, uint64_t *t3,
                                    uint64_t *t4, uint64_t top) {
    // The low 64 bits of the product: the cast drops the high half on purpose.
    uint64_t u = (uint64_t)ct_mul128(*t0, N0_INV);
    uint64_t above = p256_wide_mul_row(t0, t1, t2, t3, u, N0, N1, N2, N3);
    uint64_t carry = top;
    *t4 = p256_wide_add_carry(&carry, *t4, above);
    return carry;
}

// o = a*b/R mod n. The four rounds leave a value below 2^256 + n in (high : t7 : t6 : t5 :
// t4), so one conditional subtraction lands it below 2^256, and below n when a and b are.
// Every limb of a and b is read before o is written, so o may be a or b.
static void mont_mul(wide_scalar *o, const wide_scalar *a, const wide_scalar *b) {
    uint64_t b0 = b->limb[0];
    uint64_t b1 = b->limb[1];
    uint64_t b2 = b->limb[2];
    uint64_t b3 = b->limb[3];
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t t3 = 0;
    uint64_t t4 = p256_wide_mul_row(&t0, &t1, &t2, &t3, a->limb[0], b0, b1, b2, b3);
    uint64_t t5 = p256_wide_mul_row(&t1, &t2, &t3, &t4, a->limb[1], b0, b1, b2, b3);
    uint64_t t6 = p256_wide_mul_row(&t2, &t3, &t4, &t5, a->limb[2], b0, b1, b2, b3);
    uint64_t t7 = p256_wide_mul_row(&t3, &t4, &t5, &t6, a->limb[3], b0, b1, b2, b3);
    uint64_t high = reduce_round(&t0, &t1, &t2, &t3, &t4, 0);
    high = reduce_round(&t1, &t2, &t3, &t4, &t5, high);
    high = reduce_round(&t2, &t3, &t4, &t5, &t6, high);
    high = reduce_round(&t3, &t4, &t5, &t6, &t7, high);
    reduce_once(o->limb, t4, t5, t6, t7, high);
}

// The same scalar in 64-bit limbs: limb i here is limbs 2i and 2i + 1 there.
static void from_portable(wide_scalar *o, const p256_scalar *a) {
    for (size_t i = 0; i < LIMBS; i++) {
        o->limb[i] = (uint64_t)a->limb[2 * i] | ((uint64_t)a->limb[2 * i + 1] << 32);
    }
}

static void to_portable(p256_scalar *o, const wide_scalar *a) {
    for (size_t i = 0; i < LIMBS; i++) {
        o->limb[2 * i] = (uint32_t)a->limb[i];
        o->limb[2 * i + 1] = (uint32_t)(a->limb[i] >> 32);
    }
}

void p256_wide_scalar_mul(p256_scalar *o, const p256_scalar *a, const p256_scalar *b) {
    wide_scalar x;
    wide_scalar y;
    from_portable(&x, a);
    from_portable(&y, b);
    // Two Montgomery products make one plain product: the first leaves a*b/R, and the second
    // multiplies by R^2/R.
    mont_mul(&x, &x, &y);
    mont_mul(&x, &x, &RR);
    to_portable(o, &x);
    ct_wipe(&x, sizeof x);
    ct_wipe(&y, sizeof y);
}

// o = a^(2^n): n squarings in a row. n is a constant at every call.
// o = a*a/R mod n: mont_mul's rounds on the square's eight limbs.
static void mont_sqr(wide_scalar *o, const wide_scalar *a) {
    uint64_t t0;
    uint64_t t1;
    uint64_t t2;
    uint64_t t3;
    uint64_t t4;
    uint64_t t5;
    uint64_t t6;
    uint64_t t7;
    p256_wide_sqr_product(&t0, &t1, &t2, &t3, &t4, &t5, &t6, &t7, a->limb[0], a->limb[1],
                          a->limb[2], a->limb[3]);
    uint64_t high = reduce_round(&t0, &t1, &t2, &t3, &t4, 0);
    high = reduce_round(&t1, &t2, &t3, &t4, &t5, high);
    high = reduce_round(&t2, &t3, &t4, &t5, &t6, high);
    high = reduce_round(&t3, &t4, &t5, &t6, &t7, high);
    reduce_once(o->limb, t4, t5, t6, t7, high);
}

static void sqr_times(wide_scalar *o, const wide_scalar *a, int n) {
    mont_sqr(o, a);
    for (int i = 1; i < n; i++) {
        mont_sqr(o, o);
    }
}

void p256_wide_scalar_inverse(p256_scalar *o, const p256_scalar *a) {
    // power[i] = a^i in the Montgomery domain.
    wide_scalar power[16];
    wide_scalar ones_8;
    wide_scalar ones_16;
    wide_scalar ones_32;
    wide_scalar t;
    from_portable(&t, a);
    power[0] = ONE_MONT;
    mont_mul(&power[1], &t, &RR);
    for (size_t i = 2; i < 16; i++) {
        mont_mul(&power[i], &power[i - 1], &power[1]);
    }
    // ones_n = a^(2^n - 1), whose exponent is n one bits. power[15] is ones_4.
    sqr_times(&t, &power[15], 4);
    mont_mul(&ones_8, &t, &power[15]);
    sqr_times(&t, &ones_8, 8);
    mont_mul(&ones_16, &t, &ones_8);
    sqr_times(&t, &ones_16, 16);
    mont_mul(&ones_32, &t, &ones_16);
    // The exponent's top two limbs: 32 ones, 32 zeros and 32 ones, then 32 more ones.
    sqr_times(&t, &ones_32, 64);
    mont_mul(&t, &t, &ones_32);
    sqr_times(&t, &t, 32);
    mont_mul(&t, &t, &ones_32);
    // Its low two limbs, four bits at a time, most significant first. The four bits index the
    // table of powers, and they are bits of a build constant, so the index reads the constant
    // and never a.
    for (size_t i = EXPONENT_LOW_NIBBLES; i > 0; i--) {
        sqr_times(&t, &t, 4);
        mont_mul(&t, &t, &power[exponent_low_nibble(i - 1)]);
    }
    mont_mul(&t, &t, &ONE);
    to_portable(o, &t);
    ct_wipe(power, sizeof power);
    ct_wipe(&ones_8, sizeof ones_8);
    ct_wipe(&ones_16, sizeof ones_16);
    ct_wipe(&ones_32, sizeof ones_32);
    ct_wipe(&t, sizeof t);
}

#endif // CH_CPU_RUNTIME
