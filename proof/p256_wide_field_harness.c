// Proves, for p256_wide_field.c, CONCRETE (real bodies, no stub), every
// routine but the multiply and the three built on it:
//
//   memory safety and absence of UB over fully nondet limbs, a superset of
//   the "below p" contract, in the distinct and aliased shapes a point
//   formula calls them in, and no unsigned wrap anywhere
//   (--unsigned-overflow-check on the launch line): every carry and borrow
//   here goes through p256_wide_limb.h's two steps, which wrap nothing;
//
//   functional equivalence of every masked choice to a reference that writes
//   the same choice as a branch: reduce_once against `if (value >= p)
//   subtract`, p256_wide_fe_add and p256_wide_fe_sub against a reference
//   that carries and borrows in 128-bit sums, p256_wide_fe_cmov against
//   `if (mask)`, and the three predicates against `==` and `<`. An inverted
//   mask fails these;
//
//   the field contract on the linear routines: given elements below p,
//   p256_wide_fe_add, p256_wide_fe_sub and p256_wide_fe_neg leave an element
//   below p, and zero negates to zero;
//
//   a reduction round's carry out is 0 or 1 when the carry it is handed
//   is, which is the limb above the four that reduce_once takes;
//
//   the bound of the Montgomery reduction: reduce() takes any eight limbs
//   whose high four are below p, which is every product of two elements,
//   to four limbs below p, and wraps nothing on the way for any eight limbs
//   at all. Its four rounds are shifts and adds, with no product, so the
//   bound is a formula of adders;
//
//   the byte marshalling round trip over any 32 bytes, and the two copies to
//   and from p256_field.h's element: each takes the limbs two at a time, and
//   the round trip gives back what went in.
//
// Not proven here. The product's value: p256_wide_field_mul_harness.c proves
// the multiply safe over a contract for its rows, and what the product is
// rests on bin/p256_equiv_test and the vectors.
#include "harness.h"

#include "p256_wide_reference.h"

#include "p256_wide_field.c"

#define LIMBS P256_WIDE_FE_LIMBS

static const uint64_t PRIME[LIMBS] = {P0, P1, P2, P3};

static void fe_nondet(p256_wide_fe *f) {
    for (size_t i = 0; i < LIMBS; i++) {
        f->limb[i] = nondet_u64();
    }
}

static int ref_below_p(const uint64_t a[LIMBS]) {
    return ref_below(a, PRIME);
}

static void prove_reduce_once(void) {
    uint64_t t[LIMBS];
    uint64_t got[LIMBS];
    uint64_t want[LIMBS];
    for (size_t i = 0; i < LIMBS; i++) {
        t[i] = nondet_u64();
    }
    uint64_t high = nondet_u64();
    __CPROVER_assume(high <= 1); // the carry out of an add, or of reduce()'s last round

    uint64_t borrow = ref_sub(want, t, PRIME);
    reduce_once(got, t[0], t[1], t[2], t[3], high);
    int at_or_above = high == 1 || borrow == 0;
    __CPROVER_assert(limbs_same(got, at_or_above ? want : t),
                     "reduce_once: subtracts p exactly when the value is at or above it");
}

// One round of the reduction returns a carry that is 0 or 1 when the carry
// it is handed is. reduce() hands the first round 0 and each later round
// what the round before returned, so the limb above the four it gives
// reduce_once is 0 or 1, which is what prove_reduce_once assumes.
static void prove_reduce_round(void) {
    uint64_t t1 = nondet_u64();
    uint64_t t2 = nondet_u64();
    uint64_t t3 = nondet_u64();
    uint64_t t4 = nondet_u64();
    uint64_t top = nondet_u64();
    __CPROVER_assume(top <= 1);
    uint64_t carry = reduce_round(nondet_u64(), &t1, &t2, &t3, &t4, top);
    __CPROVER_assert(carry <= 1, "reduce_round: the carry it returns is 0 or 1");
}

// add and sub against the reference, over any limbs, and the field contract
// over elements.
static void prove_linear(void) {
    p256_wide_fe a;
    p256_wide_fe b;
    p256_wide_fe o;
    uint64_t sum[LIMBS];
    uint64_t reduced[LIMBS];
    fe_nondet(&a);
    fe_nondet(&b);
    int elements = ref_below_p(a.limb) && ref_below_p(b.limb);

    uint64_t carry = ref_add(sum, a.limb, b.limb);
    uint64_t borrow = ref_sub(reduced, sum, PRIME);
    p256_wide_fe_add(&o, &a, &b);
    __CPROVER_assert(limbs_same(o.limb, (carry == 1 || borrow == 0) ? reduced : sum),
                     "p256_wide_fe_add: the sum, less p when it is at or above p");
    __CPROVER_assert(!elements || ref_below_p(o.limb), "p256_wide_fe_add: the sum is an element");

    borrow = ref_sub(sum, a.limb, b.limb);
    (void)ref_add(reduced, sum, PRIME);
    p256_wide_fe_sub(&o, &a, &b);
    __CPROVER_assert(limbs_same(o.limb, borrow == 1 ? reduced : sum),
                     "p256_wide_fe_sub: the difference, plus p when it borrowed");
    __CPROVER_assert(!elements || ref_below_p(o.limb),
                     "p256_wide_fe_sub: the difference is an element");

    // p - a for an element that is not zero. The routine computes it as ~a - ~p, and the
    // reference subtracts the limbs as they are.
    (void)ref_sub(reduced, PRIME, a.limb);
    p256_wide_fe_neg(&o, &a);
    __CPROVER_assert(!elements || ref_below_p(o.limb),
                     "p256_wide_fe_neg: the negative is an element");
    __CPROVER_assert(!elements || p256_wide_fe_zero_mask(&a) == UINT64_MAX ||
                         limbs_same(o.limb, reduced),
                     "p256_wide_fe_neg: p less an element that is not zero");
    __CPROVER_assert(p256_wide_fe_zero_mask(&a) != UINT64_MAX ||
                         p256_wide_fe_zero_mask(&o) == UINT64_MAX,
                     "p256_wide_fe_neg: zero negates to zero, not to p");

    // The shapes a point formula writes: the output over either input, and
    // both inputs one object.
    fe_nondet(&a);
    fe_nondet(&b);
    p256_wide_fe_add(&a, &a, &b);
    p256_wide_fe_add(&b, &a, &b);
    p256_wide_fe_add(&a, &a, &a);
    p256_wide_fe_sub(&a, &a, &b);
    p256_wide_fe_sub(&b, &a, &b);
    p256_wide_fe_neg(&a, &a);
}

static void prove_masked(void) {
    p256_wide_fe x;
    p256_wide_fe y;
    fe_nondet(&x);
    fe_nondet(&y);
    p256_wide_fe before_x = x;
    p256_wide_fe before_y = y;
    uint64_t mask = nondet_u64();
    __CPROVER_assume(mask == 0 || mask == UINT64_MAX);

    p256_wide_fe_cmov(&x, &y, mask);
    __CPROVER_assert(limbs_same(x.limb, mask ? y.limb : before_x.limb),
                     "p256_wide_fe_cmov: moves under the mask and only then");

    int zero = 1;
    int same = 1;
    for (size_t i = 0; i < LIMBS; i++) {
        zero &= before_x.limb[i] == 0;
        same &= before_x.limb[i] == before_y.limb[i];
    }
    __CPROVER_assert(p256_wide_fe_zero_mask(&before_x) == (zero ? UINT64_MAX : 0),
                     "p256_wide_fe_zero_mask: all ones for zero and nothing else");
    __CPROVER_assert(p256_wide_fe_equal_mask(&before_x, &before_y) == (same ? UINT64_MAX : 0),
                     "p256_wide_fe_equal_mask: all ones for equal limbs and nothing else");
    __CPROVER_assert(p256_wide_fe_reduced_mask(&before_x) ==
                         (ref_below_p(before_x.limb) ? UINT64_MAX : 0),
                     "p256_wide_fe_reduced_mask: all ones below p and nothing else");
}

// The Montgomery reduction: any eight limbs wrap nothing, and a value below
// p * 2^256, whose high four limbs are below p, lands below p.
static void prove_reduce(void) {
    uint64_t t[2 * LIMBS];
    uint64_t o[LIMBS];
    for (size_t i = 0; i < 2 * LIMBS; i++) {
        t[i] = nondet_u64();
    }
    reduce(o, t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]);
    __CPROVER_assert(!ref_below_p(t + LIMBS) || ref_below_p(o),
                     "reduce: a value below p * 2^256 lands below p");
}

static void prove_marshalling(void) {
    uint8_t in[P256_FE_LEN];
    uint8_t out[P256_FE_LEN];
    p256_wide_fe wide;
    fill_nondet(in, sizeof in);
    p256_wide_fe_from_bytes(&wide, in);
    p256_wide_fe_to_bytes(out, &wide);
    for (size_t i = 0; i < sizeof in; i++) {
        __CPROVER_assert(out[i] == in[i], "the byte marshalling round trips");
    }

    p256_fe portable;
    p256_fe back;
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        portable.limb[i] = nondet_u32();
    }
    p256_wide_fe_from_portable(&wide, &portable);
    for (size_t i = 0; i < LIMBS; i++) {
        __CPROVER_assert((uint32_t)wide.limb[i] == portable.limb[2 * i] &&
                             (uint32_t)(wide.limb[i] >> 32) == portable.limb[2 * i + 1],
                         "p256_wide_fe_from_portable: limb i is limbs 2i and 2i + 1");
    }
    p256_wide_fe_to_portable(&back, &wide);
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        __CPROVER_assert(back.limb[i] == portable.limb[i], "the two copies round trip");
    }
}

int main(void) {
    prove_reduce_once();
    prove_reduce_round();
    prove_linear();
    prove_masked();
    prove_reduce();
    prove_marshalling();
    return 0;
}
