// The wide P-256 scalar arithmetic (see p256_wide_scalar.h for the contracts). A scalar is four
// little-endian uint64 words inside a call. Multiplication is the 512-bit product, four rows
// of p256_wide_word.h's p256_wide_mul_row, and then four rounds of Montgomery reduction, each
// one more row. The inverse is p256_wide_inverse.c's binary GCD.
//
// The layout follows p256_wide_field.c's, as p256_scalar.c follows p256_field.c's. The two
// differ in the modulus, its Montgomery constants and the reduction round: the field prime's
// round is shifts, and the group order's is a product.
#include "p256_wide_scalar.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>

#include "ct.h"
#include "p256_wide_inverse.h"
#include "p256_wide_word.h"

#define WORDS 4

typedef struct {
    uint64_t word[WORDS];
} wide_scalar;

// SEC 2 secp256r1's group order, least significant word first, and the constants derived
// from it, R = 2^256. The same order is p256_scalar.c's N, in words half as wide.
// tools/p256_wide.py recomputes each one and stops if a word differs.
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
// The order as p256_wide_inverse takes it.
static const p256_wide_modulus ORDER = {
    {N0, N1, N2, N3},
    N0_INV
};

// o = (high : t3 : t2 : t1 : t0) - n when that 257-bit value is at or above n, o = t otherwise.
// high is 0 or 1: it is the carry out of mont_mul's last round.
static inline void reduce_once(uint64_t o[WORDS], uint64_t t0, uint64_t t1, uint64_t t2,
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

// One round of Montgomery reduction on the five words (*t4 : *t3 : *t2 : *t1 : *t0). It adds
// u * n for the u that makes the low word zero, and returns the carry out of *t4, 0 or 1. The
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
// Every word of a and b is read before o is written, so o may be a or b.
static void mont_mul(wide_scalar *o, const wide_scalar *a, const wide_scalar *b) {
    uint64_t b0 = b->word[0];
    uint64_t b1 = b->word[1];
    uint64_t b2 = b->word[2];
    uint64_t b3 = b->word[3];
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t t3 = 0;
    uint64_t t4 = p256_wide_mul_row(&t0, &t1, &t2, &t3, a->word[0], b0, b1, b2, b3);
    uint64_t t5 = p256_wide_mul_row(&t1, &t2, &t3, &t4, a->word[1], b0, b1, b2, b3);
    uint64_t t6 = p256_wide_mul_row(&t2, &t3, &t4, &t5, a->word[2], b0, b1, b2, b3);
    uint64_t t7 = p256_wide_mul_row(&t3, &t4, &t5, &t6, a->word[3], b0, b1, b2, b3);
    uint64_t high = reduce_round(&t0, &t1, &t2, &t3, &t4, 0);
    high = reduce_round(&t1, &t2, &t3, &t4, &t5, high);
    high = reduce_round(&t2, &t3, &t4, &t5, &t6, high);
    high = reduce_round(&t3, &t4, &t5, &t6, &t7, high);
    reduce_once(o->word, t4, t5, t6, t7, high);
}

// The same scalar in 64-bit words: word i here is words 2i and 2i + 1 there.
static void from_portable(wide_scalar *o, const p256_scalar *a) {
    for (size_t i = 0; i < WORDS; i++) {
        o->word[i] = (uint64_t)a->word[2 * i] | ((uint64_t)a->word[2 * i + 1] << 32);
    }
}

static void to_portable(p256_scalar *o, const wide_scalar *a) {
    for (size_t i = 0; i < WORDS; i++) {
        o->word[2 * i] = (uint32_t)a->word[i];
        o->word[2 * i + 1] = (uint32_t)(a->word[i] >> 32);
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

void p256_wide_scalar_inverse(p256_scalar *o, const p256_scalar *a) {
    wide_scalar t;
    from_portable(&t, a);
    p256_wide_inverse(t.word, t.word, &ORDER);
    to_portable(o, &t);
    ct_wipe(&t, sizeof t);
}

// a is public, so the copy holds nothing to wipe.
void p256_wide_scalar_inverse_public(p256_scalar *o, const p256_scalar *a) {
    wide_scalar t;
    from_portable(&t, a);
    p256_wide_inverse_public(t.word, t.word, &ORDER);
    to_portable(o, &t);
}

#endif // CH_CPU_RUNTIME
