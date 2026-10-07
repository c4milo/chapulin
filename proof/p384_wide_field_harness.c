// Proves, for p384_wide_field.c: every routine but the Fermat loop is
// memory-safe and UB-free, and no sum in it wraps, for any words, any
// modulus record and any m0inv.
//
//   p384_wide_from_bytes               : any 48 bytes
//   p384_wide_is_zero, p384_wide_compare
//   p384_wide_add_raw, p384_wide_sub_raw,
//   p384_wide_mod_add, p384_wide_mod_sub : in every shape of their
//                                          arguments a caller uses
//   p384_wide_mont_mul                 : the same, and with the right
//                                          operand inside the modulus
//                                          record, as r2 is
//   p384_wide_mod_mul                  : into a third array and over its
//                                          left operand
//
// The no-wrap half is --unsigned-overflow-check on the launch line, which
// makes every unsigned +, - and * a property: each sum of a product, a
// word of the running sum and a carry; the two top steps of a round; and
// every word of a subtraction, which adds a complement where a borrow
// would wrap.
//
// The products are a contract: ct_mul128 returns any value at or below
// (2^64 - 1)^2, which proof/rsa_mont64_mul128_harness.c proves of the real
// multiply for every pair of operands. Under it the bound is the one
// p384_wide_field.c's header states: a product and two words are at most
// 2^128 - 1. What the contract gives up is the value: nothing here says a
// result is the Montgomery product, or is below the modulus.
// bin/p384_equiv_test holds each routine to p384_field.c's result.
//
// Not unrolled: p384_wide_mod_inverse's 384 rounds, the counterpart of
// the loop proof/p384_harness.c leaves to its proven bodies. Its body is
// the Montgomery product run here, its first statement is a
// p384_wide_sub_raw, and its one iteration-dependent access, the bit walk
// e[i / 64] >> (i % 64), is proven in bounds for every i in [0, 383]
// below.
#include "harness.h"

#include "ct.h"
// From here on the multiply p384_wide_field.c calls is the contract below.
#define ct_mul128 stub_mul128

// (2^64 - 1)^2.
#define MUL128_MAX ((((ct_u128)(UINT64_MAX - 1)) << 64) | 1)

ct_u128 nondet_u128(void);
uint64_t nondet_u64(void);
int nondet_int(void);

static ct_u128 stub_mul128(uint64_t a, uint64_t b) {
    (void)a;
    (void)b;
    ct_u128 product = nondet_u128();
    __CPROVER_assume(product <= MUL128_MAX);
    return product;
}

#include "p384_wide_field.c"

static void havoc_words(uint64_t a[P384_WIDE_WORDS]) {
    for (size_t i = 0; i < P384_WIDE_WORDS; i++) {
        a[i] = nondet_u64();
    }
}

// A modulus record with every word unconstrained: the memory accesses and
// the sums hold for any modulus, odd or not, and for any m0inv.
static void havoc_modulus(p384_wide_modulus *mod) {
    havoc_words(mod->m);
    havoc_words(mod->r2);
    mod->m0inv = nondet_u64();
}

typedef void routine(uint64_t *o, const uint64_t *a, const uint64_t *b,
                     const p384_wide_modulus *mod);

// One routine in the five shapes of its arguments: a third array for the
// result, the result over the left operand, over the right one, one array
// as all three, and the right operand inside the modulus record.
static void shapes(routine *run) {
    p384_wide_modulus mod;
    uint64_t a[P384_WIDE_WORDS];
    uint64_t b[P384_WIDE_WORDS];
    uint64_t o[P384_WIDE_WORDS];

    havoc_modulus(&mod);
    havoc_words(a);
    havoc_words(b);
    run(o, a, b, &mod);

    havoc_modulus(&mod);
    havoc_words(a);
    havoc_words(b);
    run(a, a, b, &mod);

    havoc_modulus(&mod);
    havoc_words(a);
    havoc_words(b);
    run(b, a, b, &mod);

    havoc_modulus(&mod);
    havoc_words(a);
    run(a, a, a, &mod);

    havoc_modulus(&mod);
    havoc_words(a);
    run(o, a, mod.r2, &mod);
}

int main(void) {
    uint8_t bytes[P384_LEN];
    uint64_t a[P384_WIDE_WORDS];
    uint64_t b[P384_WIDE_WORDS];
    uint64_t o[P384_WIDE_WORDS];

    fill_nondet(bytes, sizeof bytes);
    p384_wide_from_bytes(a, bytes);

    havoc_words(a);
    havoc_words(b);
    (void)p384_wide_is_zero(a);
    (void)p384_wide_compare(a, b);

    // The plain sum and difference, into a third array and over the left
    // operand, as p384_wide_mod_add, p384_wide_mod_sub and the verifier's
    // reduction of the hash call them.
    (void)p384_wide_add_raw(o, a, b);
    (void)p384_wide_sub_raw(o, a, b);
    (void)p384_wide_add_raw(a, a, b);
    havoc_words(a);
    (void)p384_wide_sub_raw(a, a, b);

    shapes(p384_wide_mod_add);
    shapes(p384_wide_mod_sub);
    shapes(p384_wide_mont_mul);

    // p384_wide_mod_mul is two of those products through an array of its
    // own, so the two shapes its callers use are enough: a third array for
    // the result, and the result over the left operand.
    p384_wide_modulus mod;
    havoc_modulus(&mod);
    havoc_words(a);
    havoc_words(b);
    p384_wide_mod_mul(o, a, b, &mod);
    havoc_modulus(&mod);
    havoc_words(a);
    havoc_words(b);
    p384_wide_mod_mul(a, a, b, &mod);

    // p384_wide_mod_inverse's only iteration-dependent access, for every i
    // its loop produces.
    int i = nondet_int();
    __CPROVER_assume(i >= 0 && i < 384);
    havoc_words(a);
    uint64_t bit = (a[i / 64] >> (i % 64)) & 1;
    (void)bit;
    return 0;
}
