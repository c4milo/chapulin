// Proves, for p256_scalar.c, CONCRETE (real bodies, no stub):
//
//   memory safety and absence of UB in every public routine, over fully
//   nondet limbs — a superset of the "below n" contract — in the
//   distinct and aliased shapes p256_sign.c calls them in;
//
//   functional equivalence of every masked choice to a reference that
//   writes the same choice as a branch: add_limbs and sub_limbs against
//   a reference that carries and borrows through comparisons rather
//   than through 64-bit high words, reduce_once against `if (value >=
//   n) subtract`, select_limbs and p256_scalar_cmov against
//   `if (mask)`, and both predicates against `==`. An inverted mask
//   would leave every routine here plausible and wrong, and it fails
//   these;
//
//   the contract p256_sign.c rests on: p256_scalar_reduce turns ANY
//   256-bit value into one below n with a single subtraction, which is
//   what makes the message hash a valid z and the x coordinate a valid
//   r, and p256_scalar_add leaves a scalar below n;
//
//   the byte marshalling round trip, over any 32 bytes;
//
//   the bounds of the index expressions p256_scalar_inverse walks its
//   exponent with, restated in the harness because calling the real
//   routine drags 512 Montgomery multiplies into the formula.
//
// Not proven here. mont_mul's value: equality of two multipliers is the
// classic hard SAT instance (docs/proofs.md, and ctwidemul converges
// only at 8-bit operands), so the Montgomery product is proven
// memory-safe and UB-free over full-range limbs, and its value rests on
// test/p256_sign_test.c's vectors against Python's integers. The uint64
// carry chain it shares with p256_field.c's CIOS loop is that file's
// p256_mul lemma; the two loops are the same eight-limb shape over a
// different modulus.
//
// Not unrolled: p256_scalar_inverse's 256 rounds, thousands of
// Montgomery multiplies that never leave symex, the same split
// p256_harness.c and p384_harness.c make for their loop drivers. Its
// round body is mont_mul, whose safety is proven above, and its only
// iteration-dependent memory access is the exponent bit walk, whose
// index expressions are proven in bounds for every i in [0,255] below.
#include "harness.h"

#include "p256_scalar.c"

uint32_t nondet_u32(void);

#define LIMB_COUNT P256_SCALAR_LIMBS

// Fully nondet limbs, stored through the object's own type
// (docs/proofs.md). No index in p256_scalar.c depends on a limb value,
// so safety must hold for every one of them.
static void scalar_nondet(p256_scalar *s) {
    for (size_t i = 0; i < LIMB_COUNT; i++) {
        s->limb[i] = nondet_u32();
    }
}

static void limbs_nondet(uint32_t v[LIMB_COUNT]) {
    for (size_t i = 0; i < LIMB_COUNT; i++) {
        v[i] = nondet_u32();
    }
}

static int limbs_same(const uint32_t a[LIMB_COUNT], const uint32_t b[LIMB_COUNT]) {
    for (size_t i = 0; i < LIMB_COUNT; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

// The reference arithmetic: the same two operations written with
// comparisons and branches instead of high words and masks. Nothing here
// multiplies, so the equivalence costs the solver almost nothing.
static uint32_t ref_add(uint32_t o[LIMB_COUNT], const uint32_t a[LIMB_COUNT],
                        const uint32_t b[LIMB_COUNT]) {
    uint32_t carry = 0;
    for (size_t i = 0; i < LIMB_COUNT; i++) {
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

static uint32_t ref_sub(uint32_t o[LIMB_COUNT], const uint32_t a[LIMB_COUNT],
                        const uint32_t b[LIMB_COUNT]) {
    uint32_t borrow = 0;
    for (size_t i = 0; i < LIMB_COUNT; i++) {
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

// 1 when the limbs are below n, which is ref_sub's borrow.
static uint32_t ref_below_order(const uint32_t a[LIMB_COUNT]) {
    uint32_t discard[LIMB_COUNT];
    return ref_sub(discard, a, N);
}

static void prove_limb_arithmetic(void) {
    uint32_t a[LIMB_COUNT];
    uint32_t b[LIMB_COUNT];
    uint32_t got[LIMB_COUNT];
    uint32_t want[LIMB_COUNT];

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

    // The select and the masked mover, under both masks and under
    // nothing else: a mask is 0 or all ones by contract.
    limbs_nondet(a);
    limbs_nondet(b);
    uint32_t mask = nondet_u32();
    __CPROVER_assume(mask == 0 || mask == UINT32_MAX);
    select_limbs(got, a, b, mask);
    __CPROVER_assert(limbs_same(got, mask ? a : b), "select_limbs: takes the masked side");

    p256_scalar x;
    p256_scalar y;
    p256_scalar before_x;
    scalar_nondet(&x);
    scalar_nondet(&y);
    before_x = x;
    p256_scalar_cmov(&x, &y, mask);
    __CPROVER_assert(limbs_same(x.limb, mask ? y.limb : before_x.limb),
                     "p256_scalar_cmov: moves under the mask and only then");
}

static void prove_reduce_once(void) {
    uint32_t t[LIMB_COUNT];
    uint32_t got[LIMB_COUNT];
    uint32_t want[LIMB_COUNT];
    limbs_nondet(t);
    uint32_t high = nondet_u32();
    __CPROVER_assume(high <= 1); // the carry out of an add, or CIOS's ninth word

    uint32_t borrow = ref_sub(want, t, N);
    reduce_once(got, t, high);
    // high:t is at or above n unless the low subtraction borrowed out
    // with no high bit to cover it.
    int at_or_above = (high == 1) || !borrow;
    __CPROVER_assert(limbs_same(got, at_or_above ? want : t),
                     "reduce_once: subtracts n exactly when the value is at or above it");
    __CPROVER_assert(!at_or_above || high == 1 || ref_below_order(got),
                     "reduce_once: a reduced value below 2n lands below n");
}

static void prove_predicates(void) {
    p256_scalar a;
    scalar_nondet(&a);

    int zero = 1;
    for (size_t i = 0; i < LIMB_COUNT; i++) {
        if (a.limb[i] != 0) {
            zero = 0;
        }
    }
    __CPROVER_assert(p256_scalar_zero_mask(&a) == (zero ? UINT32_MAX : 0),
                     "p256_scalar_zero_mask: all ones for zero and nothing else");
    __CPROVER_assert(p256_scalar_reduced_mask(&a) == (ref_below_order(a.limb) ? UINT32_MAX : 0),
                     "p256_scalar_reduced_mask: all ones below n and nothing else");
}

// The two contracts p256_sign.c rests on. The reduce one is the load
// bearing claim: z comes from a 32-byte hash and r from a coordinate
// below the field prime, neither of them constrained below n, and both
// must come out of p256_scalar_reduce as scalars.
static void prove_scalar_contract(void) {
    p256_scalar a;
    p256_scalar b;
    p256_scalar o;

    scalar_nondet(&a);
    p256_scalar_reduce(&o, &a);
    __CPROVER_assert(ref_below_order(o.limb),
                     "p256_scalar_reduce: any 256-bit value lands below n");

    scalar_nondet(&a);
    scalar_nondet(&b);
    __CPROVER_assume(ref_below_order(a.limb));
    __CPROVER_assume(ref_below_order(b.limb));
    p256_scalar_add(&o, &a, &b);
    __CPROVER_assert(ref_below_order(o.limb), "p256_scalar_add: the sum is a scalar");
}

static void prove_marshalling(void) {
    uint8_t in[P256_SCALAR_LEN];
    uint8_t out[P256_SCALAR_LEN];
    p256_scalar s;

    fill_nondet(in, sizeof in);
    p256_scalar_from_bytes(&s, in);
    p256_scalar_to_bytes(out, &s);
    for (size_t i = 0; i < P256_SCALAR_LEN; i++) {
        __CPROVER_assert(out[i] == in[i], "the byte round trip returns the same bytes");
    }
}

// Every routine again over unconstrained limbs, in the aliasing shapes
// p256_sign.c uses. No assertion on the values: this is the memory
// safety and UB leg, and it must hold for limbs no contract allows.
static void prove_safety(void) {
    p256_scalar a;
    p256_scalar b;
    p256_scalar o;

    scalar_nondet(&a);
    scalar_nondet(&b);
    p256_scalar_add(&o, &a, &b);
    p256_scalar_add(&a, &a, &b); // o == a
    p256_scalar_add(&b, &a, &b); // o == b, the shape signature_scalar uses
    scalar_nondet(&a);
    p256_scalar_add(&a, &a, &a); // o == a == b
    scalar_nondet(&a);
    p256_scalar_reduce(&a, &a); // o == a, the shape p256_sign uses

    scalar_nondet(&a);
    scalar_nondet(&b);
    p256_scalar_mul(&o, &a, &b);
    scalar_nondet(&a);
    scalar_nondet(&b);
    p256_scalar_mul(&a, &a, &b); // o == a
    scalar_nondet(&a);
    scalar_nondet(&b);
    p256_scalar_mul(&b, &a, &b); // o == b
    scalar_nondet(&a);
    p256_scalar_mul(&a, &a, &a); // o == a == b
}

// The index expressions p256_scalar_inverse walks the exponent with,
// restated here and proven in bounds for every round, plus the
// signed-overflow freedom of its counter.
//
// What this is and is not. It is the same two expressions over the same
// range, not a call into p256_scalar_inverse, because calling that
// function drags 512 Montgomery multiplies into the formula and the
// solver returns no verdict. So it catches a limb count and a shift
// width that stop agreeing with each other, and it does not prove the
// real loop. The real loop's body is mont_mul, whose memory safety
// prove_safety covers over full-range limbs, and its values rest on
// test/p256_sign_test.c's inverse vectors.
static void prove_exponent_index_bounds(void) {
    uint32_t seen = 0;
    for (int i = 256 - 1; i >= 0; i--) {
        __CPROVER_assert((i >> 5) < LIMB_COUNT, "the exponent index stays inside the limb array");
        __CPROVER_assert((i & 31) < 32, "the exponent shift stays below the limb width");
        seen |= (N_MINUS_2[i >> 5] >> (i & 31)) & 1U;
    }
    __CPROVER_assert(seen == 1, "the exponent has at least one set bit");
}

int main(void) {
    prove_limb_arithmetic();
    prove_reduce_once();
    prove_predicates();
    prove_scalar_contract();
    prove_marshalling();
    prove_safety();
    prove_exponent_index_bounds();
    return 0;
}
