// Proves, for p256_field.c, CONCRETE (real bodies, no stub):
//
//   memory safety and absence of UB in every public routine, over fully
//   nondet limbs — a superset of the "below p" contract — in the
//   distinct and aliased shapes a point routine calls them in;
//
//   functional equivalence of every masked choice to a reference that
//   writes the same choice as a branch: add_limbs and sub_limbs against
//   a reference that carries and borrows through comparisons rather
//   than through 64-bit high words, reduce_once against `if (value >=
//   p) subtract`, select_limbs, p256_fe_cmov and p256_fe_cswap against
//   `if (mask)`, and the three predicates against `==`. An inverted
//   mask is the one mistake that would leave every routine here
//   plausible and wrong, and it fails these;
//
//   the field contract on the linear routines: given elements below p,
//   p256_fe_add, p256_fe_sub and p256_fe_neg leave an element below p;
//
//   the byte marshalling round trip, over any 32 bytes.
//
// Not proven here. mont_mul's value: equality of two multipliers is the
// classic hard SAT instance (docs/proofs.md, and ctwidemul converges
// only at 8-bit operands), so the Montgomery product is proven
// memory-safe and UB-free over full-range limbs, and its value rests on
// test/p256_field_test.c's vectors. Its uint64 carry chain — that the
// accumulation cannot wrap and that t's ninth word holds at most one
// bit, for any uint32 operands — is proof/p256_mul_harness.c's lemma,
// which is the same eight-limb CIOS shape.
//
// Not unrolled: p256_fe_inv's 256 rounds, thousands of Montgomery
// multiplies that never leave symex, the same split p256_harness.c and
// p384_harness.c make for their loop drivers. Its round body is
// mont_mul, proven above, and its only iteration-dependent memory
// access is the exponent bit walk, proven in bounds for every i in
// [0,255] below.
#include "harness.h"

#include "p256_field.c"

uint32_t nondet_u32(void);
int nondet_int(void);

// Fully nondet limbs, stored through the object's own type
// (docs/proofs.md). No index in p256_field.c depends on a limb value, so
// safety must hold for every one of them.
static void fe_nondet(p256_fe *f) {
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        f->limb[i] = nondet_u32();
    }
}

static void limbs_nondet(uint32_t v[P256_FE_LIMBS]) {
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        v[i] = nondet_u32();
    }
}

static int limbs_same(const uint32_t a[P256_FE_LIMBS], const uint32_t b[P256_FE_LIMBS]) {
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

// The reference arithmetic: the same three operations written with
// comparisons and branches instead of high words and masks. Nothing here
// multiplies, so the equivalence costs the solver almost nothing.
static uint32_t ref_add(uint32_t o[P256_FE_LIMBS], const uint32_t a[P256_FE_LIMBS],
                        const uint32_t b[P256_FE_LIMBS]) {
    uint32_t carry = 0;
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        uint32_t sum = a[i] + b[i];
        uint32_t out = (sum < a[i]) ? 1U : 0U;
        sum += carry;
        if (sum < carry) {
            out = 1U;
        }
        o[i] = sum;
        carry = out;
    }
    return carry;
}

static uint32_t ref_sub(uint32_t o[P256_FE_LIMBS], const uint32_t a[P256_FE_LIMBS],
                        const uint32_t b[P256_FE_LIMBS]) {
    uint32_t borrow = 0;
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        uint32_t diff = a[i] - b[i];
        uint32_t out = (a[i] < b[i]) ? 1U : 0U;
        if (diff < borrow) {
            out = 1U;
        }
        o[i] = diff - borrow;
        borrow = out;
    }
    return borrow;
}

// 1 when the limbs are below p, which is ref_sub's borrow.
static uint32_t ref_below_p(const uint32_t a[P256_FE_LIMBS]) {
    uint32_t discard[P256_FE_LIMBS];
    return ref_sub(discard, a, P);
}

static void prove_limb_arithmetic(void) {
    uint32_t a[P256_FE_LIMBS];
    uint32_t b[P256_FE_LIMBS];
    uint32_t got[P256_FE_LIMBS];
    uint32_t want[P256_FE_LIMBS];

    limbs_nondet(a);
    limbs_nondet(b);
    uint32_t carry = add_limbs(got, a, b);
    uint32_t ref_carry = ref_add(want, a, b);
    __CPROVER_assert(limbs_same(got, want), "add_limbs: limbs match the reference");
    __CPROVER_assert(carry == ref_carry, "add_limbs: carry matches the reference");

    limbs_nondet(a);
    limbs_nondet(b);
    uint32_t borrow_mask = sub_limbs(got, a, b);
    uint32_t ref_borrow = ref_sub(want, a, b);
    __CPROVER_assert(limbs_same(got, want), "sub_limbs: limbs match the reference");
    __CPROVER_assert(borrow_mask == (ref_borrow ? UINT32_MAX : 0),
                     "sub_limbs: the borrow comes back as a whole mask");

    // The select and the two masked movers, under both masks and under
    // nothing else: a mask is 0 or all ones by contract.
    limbs_nondet(a);
    limbs_nondet(b);
    uint32_t mask = nondet_u32();
    __CPROVER_assume(mask == 0 || mask == UINT32_MAX);
    select_limbs(got, a, b, mask);
    __CPROVER_assert(limbs_same(got, mask ? a : b), "select_limbs: takes the masked side");

    p256_fe x;
    p256_fe y;
    p256_fe before_x;
    p256_fe before_y;
    fe_nondet(&x);
    fe_nondet(&y);
    before_x = x;
    p256_fe_cmov(&x, &y, mask);
    __CPROVER_assert(limbs_same(x.limb, mask ? y.limb : before_x.limb),
                     "p256_fe_cmov: moves under the mask and only then");

    fe_nondet(&x);
    fe_nondet(&y);
    before_x = x;
    before_y = y;
    p256_fe_cswap(&x, &y, mask);
    __CPROVER_assert(limbs_same(x.limb, mask ? before_y.limb : before_x.limb),
                     "p256_fe_cswap: first operand");
    __CPROVER_assert(limbs_same(y.limb, mask ? before_x.limb : before_y.limb),
                     "p256_fe_cswap: second operand");
}

static void prove_reduce_once(void) {
    uint32_t t[P256_FE_LIMBS];
    uint32_t got[P256_FE_LIMBS];
    uint32_t want[P256_FE_LIMBS];
    limbs_nondet(t);
    uint32_t high = nondet_u32();
    __CPROVER_assume(high <= 1); // the carry out of an add, or CIOS's ninth word

    uint32_t borrow = ref_sub(want, t, P);
    reduce_once(got, t, high);
    // high:t is at or above p unless the low subtraction borrowed out
    // with no high bit to cover it.
    int at_or_above = (high == 1) || !borrow;
    __CPROVER_assert(limbs_same(got, at_or_above ? want : t),
                     "reduce_once: subtracts p exactly when the value is at or above it");
    __CPROVER_assert(!at_or_above || high == 1 || ref_below_p(got),
                     "reduce_once: a reduced value below 2p lands below p");
}

static void prove_predicates(void) {
    p256_fe a;
    p256_fe b;
    fe_nondet(&a);
    fe_nondet(&b);

    int zero = 1;
    int same = 1;
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        if (a.limb[i] != 0) {
            zero = 0;
        }
        if (a.limb[i] != b.limb[i]) {
            same = 0;
        }
    }
    __CPROVER_assert(p256_fe_zero_mask(&a) == (zero ? UINT32_MAX : 0),
                     "p256_fe_zero_mask: all ones for zero and nothing else");
    __CPROVER_assert(p256_fe_equal_mask(&a, &b) == (same ? UINT32_MAX : 0),
                     "p256_fe_equal_mask: all ones for equal limbs and nothing else");
    __CPROVER_assert(p256_fe_reduced_mask(&a) == (ref_below_p(a.limb) ? UINT32_MAX : 0),
                     "p256_fe_reduced_mask: all ones below p and nothing else");
}

// The linear routines keep the field's contract: elements in, an element
// out. p256_fe_mul cannot join them — that claim rests on the CIOS
// invariant, which the header comment says is tested rather than proven.
static void prove_field_contract(void) {
    p256_fe a;
    p256_fe b;
    p256_fe o;
    fe_nondet(&a);
    fe_nondet(&b);
    __CPROVER_assume(ref_below_p(a.limb));
    __CPROVER_assume(ref_below_p(b.limb));

    p256_fe_add(&o, &a, &b);
    __CPROVER_assert(ref_below_p(o.limb), "p256_fe_add: the sum is an element");
    p256_fe_sub(&o, &a, &b);
    __CPROVER_assert(ref_below_p(o.limb), "p256_fe_sub: the difference is an element");
    p256_fe_neg(&o, &a);
    __CPROVER_assert(ref_below_p(o.limb), "p256_fe_neg: the negative is an element");
    __CPROVER_assert(p256_fe_zero_mask(&a) != UINT32_MAX || p256_fe_zero_mask(&o) == UINT32_MAX,
                     "p256_fe_neg: zero negates to zero, not to p");
}

// Every routine again over unconstrained limbs, in the aliasing shapes a
// point routine uses. No assertion on the values: this is the memory
// safety and UB leg, and it must hold for limbs no contract allows.
static void prove_safety(void) {
    p256_fe a;
    p256_fe b;
    p256_fe o;

    fe_nondet(&a);
    fe_nondet(&b);
    p256_fe_add(&o, &a, &b);
    p256_fe_add(&a, &a, &b); // o == a
    fe_nondet(&a);
    p256_fe_add(&a, &a, &a); // o == a == b, a doubling
    fe_nondet(&a);
    fe_nondet(&b);
    p256_fe_sub(&o, &a, &b);
    p256_fe_sub(&b, &a, &b); // o == b
    fe_nondet(&a);
    p256_fe_neg(&a, &a);

    fe_nondet(&a);
    fe_nondet(&b);
    p256_fe_mul(&o, &a, &b);
    fe_nondet(&a);
    fe_nondet(&b);
    p256_fe_mul(&a, &a, &b); // o == a
    fe_nondet(&a);
    fe_nondet(&b);
    p256_fe_mul(&b, &a, &b); // o == b
    fe_nondet(&a);
    p256_fe_sqr(&a, &a); // o == a == b, the shape p256_fe_inv squares in
    fe_nondet(&a);
    p256_fe_to_mont(&o, &a);
    fe_nondet(&a);
    p256_fe_from_mont(&a, &a);
}

int main(void) {
    prove_limb_arithmetic();
    prove_reduce_once();
    prove_predicates();
    prove_field_contract();
    prove_safety();

    // Marshalling over any 32 bytes, and the round trip back out.
    uint8_t in[P256_FE_LEN];
    uint8_t out[P256_FE_LEN];
    p256_fe a;
    fill_nondet(in, sizeof in);
    p256_fe_from_bytes(&a, in);
    p256_fe_to_bytes(out, &a);
    for (size_t i = 0; i < sizeof in; i++) {
        __CPROVER_assert(out[i] == in[i], "the byte marshalling round trips");
    }

    // p256_fe_inv's only iteration-dependent memory access, for every
    // round the loop can run.
    int i = nondet_int();
    __CPROVER_assume(i >= 0 && i <= 255);
    uint32_t bit = (P_MINUS_2[i >> 5] >> (i & 31)) & 1U;
    (void)bit;
    return 0;
}
