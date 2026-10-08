// Proves, for p256_wide_scalar.c:
//
//   reduce_once against a reference that branches: for any four words and a
//   word above them that is 0 or 1, it subtracts n exactly when the 257-bit
//   value is at or above n. An inverted mask fails this;
//
//   reduce_round returns 0 or 1 for any five words when the carry it is
//   handed is 0 or 1. mont_mul hands the first round 0 and every later round
//   what the round before returned, so the word above the four it gives
//   reduce_once is 0 or 1, which is what the claim above assumes;
//
//   mont_mul and p256_wide_scalar_mul are memory-safe and UB-free over fully
//   nondet words and wrap no unsigned value (--unsigned-overflow-check on
//   the launch line), in every aliasing shape p256_sign.c uses: the output
//   distinct from both inputs, over the first, over the second, and both
//   inputs one object. p256_wide_scalar_mul wipes the two copies it makes
//   through ct_wipe, whose stub proves each wipe inside its object;
//
//   p256_wide_scalar_inverse and p256_wide_scalar_inverse_public, whole, in
//   both shapes, over contracts of p256_wide_inverse and
//   p256_wide_inverse_public below, which read y and the modulus and write
//   any four words: their copies to and from 64-bit words and the first's
//   wipe;
//
//   the two copies to and from p256_scalar.h's scalar: each takes the words
//   two at a time, and the round trip gives back what went in.
//
// The rows of every product are the contract in proof/p256_wide_stubs.h,
// which p256_wide_row_harness.c discharges on the real multiply. The one
// product outside a row, the multiplier each reduction round makes from its
// low word and N0_INV, runs on the real multiply here. The four
// p256_wide_inverse harnesses prove the inverse's own accesses and steps.
//
// Not proven here: the product's value, and so the bound that mont_mul
// leaves a scalar below n. The reduction's rounds are products, not shifts
// as the field prime's are, so the bound is a claim about multipliers, the
// SAT instance docs/proofs.md says does not converge. bin/p256_equiv_test
// holds both entries to p256_scalar.c's on random and edge scalars, and
// bin/p256_sign_test_host runs RFC 6979's vectors through them.
#include "p256_wide_stubs.h"

#include "p256_wide_reference.h"

#include "p256_wide_scalar.c"

// p256_wide_inverse and p256_wide_inverse_public read y and the modulus and write any four words.
static void inverse_contract(uint64_t o[P256_WIDE_INVERSE_WORDS],
                             const uint64_t y[P256_WIDE_INVERSE_WORDS],
                             const p256_wide_modulus *m) {
    __CPROVER_assert(__CPROVER_r_ok(y, sizeof(uint64_t) * P256_WIDE_INVERSE_WORDS) &&
                         __CPROVER_r_ok(m, sizeof *m) &&
                         __CPROVER_w_ok(o, sizeof(uint64_t) * P256_WIDE_INVERSE_WORDS),
                     "the inverse: y and the modulus readable, the four words writable");
    for (size_t i = 0; i < P256_WIDE_INVERSE_WORDS; i++) {
        o[i] = nondet_u64();
    }
}

void p256_wide_inverse(uint64_t o[P256_WIDE_INVERSE_WORDS],
                       const uint64_t y[P256_WIDE_INVERSE_WORDS], const p256_wide_modulus *m) {
    inverse_contract(o, y, m);
}

void p256_wide_inverse_public(uint64_t o[P256_WIDE_INVERSE_WORDS],
                              const uint64_t y[P256_WIDE_INVERSE_WORDS],
                              const p256_wide_modulus *m) {
    inverse_contract(o, y, m);
}

static const uint64_t ORDER_WORDS[WORDS] = {N0, N1, N2, N3};

static void wide_nondet(wide_scalar *s) {
    for (size_t i = 0; i < WORDS; i++) {
        s->word[i] = nondet_u64();
    }
}

static void scalar_nondet(p256_scalar *s) {
    for (size_t i = 0; i < P256_SCALAR_WORDS; i++) {
        s->word[i] = nondet_u32();
    }
}

static void prove_reduce_once(void) {
    uint64_t t[WORDS];
    uint64_t got[WORDS];
    uint64_t want[WORDS];
    for (size_t i = 0; i < WORDS; i++) {
        t[i] = nondet_u64();
    }
    uint64_t high = nondet_u64();
    __CPROVER_assume(high <= 1); // what prove_reduce_round shows of mont_mul's rounds

    uint64_t borrow = ref_sub(want, t, ORDER_WORDS);
    reduce_once(got, t[0], t[1], t[2], t[3], high);
    int at_or_above = high == 1 || borrow == 0;
    __CPROVER_assert(words_same(got, at_or_above ? want : t),
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

static void prove_scalar_inverse(void) {
    p256_scalar a;
    p256_scalar o;
    scalar_nondet(&a);
    p256_wide_scalar_inverse(&o, &a);
    scalar_nondet(&a);
    p256_wide_scalar_inverse(&a, &a); // o == a
    scalar_nondet(&a);
    p256_wide_scalar_inverse_public(&o, &a);
    scalar_nondet(&a);
    p256_wide_scalar_inverse_public(&a, &a); // o == a
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
    for (size_t i = 0; i < WORDS; i++) {
        __CPROVER_assert((uint32_t)wide.word[i] == portable.word[2 * i] &&
                             (uint32_t)(wide.word[i] >> 32) == portable.word[2 * i + 1],
                         "from_portable: word i is words 2i and 2i + 1");
    }
    to_portable(&back, &wide);
    for (size_t i = 0; i < P256_SCALAR_WORDS; i++) {
        __CPROVER_assert(back.word[i] == portable.word[i], "the two copies round trip");
    }
}

int main(void) {
    prove_reduce_once();
    prove_reduce_round();
    prove_mont_mul();
    prove_scalar_inverse();
    prove_scalar_mul();
    prove_portable();
    return 0;
}
