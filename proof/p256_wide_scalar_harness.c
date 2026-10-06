// Proves, for p256_wide_scalar.c:
//
//   reduce_once against a reference that branches: for any four limbs and a
//   limb above them that is 0 or 1, it subtracts n exactly when the 257-bit
//   value is at or above n. An inverted mask fails this;
//
//   reduce_round returns 0 or 1 for any five limbs when the carry it is
//   handed is 0 or 1. mont_mul hands the first round 0 and every later round
//   what the round before returned, so the limb above the four it gives
//   reduce_once is 0 or 1, which is what the claim above assumes;
//
//   mont_mul, mont_sqr through sqr_times, and p256_wide_scalar_mul are
//   memory-safe and UB-free over fully nondet limbs and wrap no unsigned
//   value (--unsigned-overflow-check on the launch line), in every aliasing
//   shape p256_sign.c and the inverse use: the output distinct from both
//   inputs, over the first, over the second, and both inputs one object.
//   p256_wide_scalar_mul wipes the two copies it makes through ct_wipe,
//   whose stub proves each wipe inside its object;
//
//   exponent_low_nibble, the one read in p256_wide_scalar_inverse that moves
//   with a loop counter: for every position the loop passes, 0 to 31, the
//   read of EXPONENT_LOW is in bounds, its shift is below the limb's width,
//   and the result is below 16, the length of the table of powers it
//   indexes. Every operand of the index is the build constant or the
//   counter, never the scalar;
//
//   the two copies to and from p256_scalar.h's scalar: each takes the limbs
//   two at a time, and the round trip gives back what went in.
//
// The rows of every product are the contract in proof/p256_wide_stubs.h,
// which p256_wide_row_harness.c discharges on the real multiply, and so is
// the square of four limbs mont_sqr starts from, which
// p256_wide_sqr_harness.c discharges. The one product outside a row and the
// square, the multiplier each reduction round makes from its low limb and
// N0_INV, runs on the real multiply here.
//
// p256_wide_scalar_inverse is not run whole, for the reason
// proof/p256_wide_field_mul_harness.c gives for the field's: its 305
// products in one formula cost symbolic execution more than this tier
// admits. Its chain is mont_mul and sqr_times, whose squares are mont_sqr's,
// in the shapes proven here, on its own locals and its table, at counts that
// are literals and at the index proven here.
//
// Not proven here: the product's value, and so the bound that mont_mul
// leaves a scalar below n. The reduction's rounds are products, not shifts
// as the field prime's are, so the bound is a claim about multipliers, the
// SAT instance docs/proofs.md says does not converge. bin/p256_equiv_test
// holds both entries to p256_scalar.c's on random and edge scalars, and
// bin/p256_sign_test_host runs RFC 6979's vectors through them.
// tools/p256_wide.py checks that EXPONENT_LOW is the low half of n - 2 and
// that the high half is the runs of ones the chain writes.
#include "p256_wide_stubs.h"

#include "p256_wide_reference.h"

#include "p256_wide_scalar.c"

static const uint64_t ORDER[LIMBS] = {N0, N1, N2, N3};

static void wide_nondet(wide_scalar *s) {
    for (size_t i = 0; i < LIMBS; i++) {
        s->limb[i] = nondet_u64();
    }
}

static void scalar_nondet(p256_scalar *s) {
    for (size_t i = 0; i < P256_SCALAR_LIMBS; i++) {
        s->limb[i] = nondet_u32();
    }
}

static void prove_reduce_once(void) {
    uint64_t t[LIMBS];
    uint64_t got[LIMBS];
    uint64_t want[LIMBS];
    for (size_t i = 0; i < LIMBS; i++) {
        t[i] = nondet_u64();
    }
    uint64_t high = nondet_u64();
    __CPROVER_assume(high <= 1); // what prove_reduce_round shows of mont_mul's rounds

    uint64_t borrow = ref_sub(want, t, ORDER);
    reduce_once(got, t[0], t[1], t[2], t[3], high);
    int at_or_above = high == 1 || borrow == 0;
    __CPROVER_assert(limbs_same(got, at_or_above ? want : t),
                     "reduce_once: subtracts n exactly when the value is at or above it");
}

static void prove_reduce_round(void) {
    uint64_t t0 = nondet_u64();
    uint64_t t1 = nondet_u64();
    uint64_t t2 = nondet_u64();
    uint64_t t3 = nondet_u64();
    uint64_t t4 = nondet_u64();
    uint64_t top = nondet_u64();
    __CPROVER_assume(top <= 1);
    uint64_t carry = reduce_round(&t0, &t1, &t2, &t3, &t4, top);
    __CPROVER_assert(carry <= 1, "reduce_round: the carry it returns is 0 or 1");
}

static void prove_mont_mul(void) {
    wide_scalar a;
    wide_scalar b;
    wide_scalar o;

    wide_nondet(&a);
    wide_nondet(&b);
    mont_mul(&o, &a, &b);
    wide_nondet(&a);
    wide_nondet(&b);
    mont_mul(&a, &a, &b); // o == a
    wide_nondet(&a);
    wide_nondet(&b);
    mont_mul(&b, &a, &b); // o == b
    wide_nondet(&a);
    mont_mul(&a, &a, &a); // all three one object
}

static void prove_sqr_times(void) {
    wide_scalar a;
    wide_scalar o;
    wide_nondet(&a);
    sqr_times(&o, &a, 4); // the inverse's first use: a power into t
    wide_nondet(&a);
    sqr_times(&a, &a, 4); // and its later ones: t over itself
}

static void prove_exponent_nibble(void) {
    size_t at = nondet_size_t();
    __CPROVER_assume(at < EXPONENT_LOW_NIBBLES);
    uint64_t nibble = exponent_low_nibble(at);
    __CPROVER_assert(nibble < 16, "exponent_low_nibble: the result indexes sixteen powers");
}

static void prove_scalar_mul(void) {
    p256_scalar a;
    p256_scalar b;
    p256_scalar o;

    scalar_nondet(&a);
    scalar_nondet(&b);
    p256_wide_scalar_mul(&o, &a, &b);
    scalar_nondet(&a);
    scalar_nondet(&b);
    p256_wide_scalar_mul(&a, &a, &b); // o == a
    scalar_nondet(&a);
    scalar_nondet(&b);
    p256_wide_scalar_mul(&b, &a, &b); // o == b
    scalar_nondet(&a);
    p256_wide_scalar_mul(&a, &a, &a); // all three one object
}

static void prove_portable(void) {
    p256_scalar portable;
    p256_scalar back;
    wide_scalar wide;
    scalar_nondet(&portable);
    from_portable(&wide, &portable);
    for (size_t i = 0; i < LIMBS; i++) {
        __CPROVER_assert((uint32_t)wide.limb[i] == portable.limb[2 * i] &&
                             (uint32_t)(wide.limb[i] >> 32) == portable.limb[2 * i + 1],
                         "from_portable: limb i is limbs 2i and 2i + 1");
    }
    to_portable(&back, &wide);
    for (size_t i = 0; i < P256_SCALAR_LIMBS; i++) {
        __CPROVER_assert(back.limb[i] == portable.limb[i], "the two copies round trip");
    }
}

int main(void) {
    prove_reduce_once();
    prove_reduce_round();
    prove_mont_mul();
    prove_sqr_times();
    prove_exponent_nibble();
    prove_scalar_mul();
    prove_portable();
    return 0;
}
