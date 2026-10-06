// The contract p256_wide_field_mul, p256_wide_field_inv, p256_wide_scalar and
// p256_wide_scalar_inverse replace p256_wide_limb.h's product row with, the
// way proof/x25519_wide_stubs.h serves the wide X25519 field.
//
// Why this exists: one field multiply runs 16 products, each a 64x64
// multiplier widened to 128 bits, and the field inversion runs 267
// multiplies. One scalar multiply runs 36 products, and the scalar inverse
// runs 305 of them. A formula over the real products at
// that count is the shape docs/proofs.md says does not converge. So the one
// routine every product goes through, p256_wide_mul_row, is the contract
// below. The harness reads p256_wide_limb.h first under its own name, the
// #define renames every later use, and the header's include guard keeps the
// wide files' own #include from reading the real definition again.
//
// WHAT THE STUB MODELS: p256_wide_mul_row writes any four limbs and returns
// any limb. A limb here has no bound to keep: the four limbs are 64 bits
// each and so is the limb above them, so every value the real row can
// return is one the stub returns.
//
// WHAT DISCHARGES THE CONTRACT: p256_wide_row_harness.c proves the real row
// wraps no unsigned value for any operands. That is the one property of the
// row a harness over the stub cannot state, because the stub adds nothing.
// Nothing in the four harnesses reads a row's value. Every property they
// state is a bound, a carry that is 0 or 1 or a memory access, and the stub
// returns every five limbs the real row can, so a proof over the stub covers
// the real rows.
//
// What the contract gives up: the value. The harnesses over it prove
// nothing about what a product is, which bin/p256_equiv_test and the
// vectors hold.
#ifndef CH_PROOF_P256_WIDE_STUBS_H
#define CH_PROOF_P256_WIDE_STUBS_H

#include "harness.h"

// The two carry steps as clang compiles them. p256_wide_row_harness.c holds
// this form and the 128-bit sums to one reference, so what a harness over
// this header proves holds on both.
#define P256_WIDE_CARRY P256_WIDE_CARRY_BUILTIN
#include "p256_wide_limb.h"
// From here on the row and the square the wide files call are the contracts below.
#define p256_wide_mul_row stub_mul_row
#define p256_wide_sqr_product stub_sqr_product

uint64_t nondet_u64(void);

static uint64_t stub_mul_row(uint64_t *t0, uint64_t *t1, uint64_t *t2, uint64_t *t3, uint64_t x,
                             uint64_t b0, uint64_t b1, uint64_t b2, uint64_t b3) {
    (void)x;
    (void)b0;
    (void)b1;
    (void)b2;
    (void)b3;
    __CPROVER_assert(__CPROVER_w_ok(t0, sizeof *t0) && __CPROVER_w_ok(t1, sizeof *t1) &&
                         __CPROVER_w_ok(t2, sizeof *t2) && __CPROVER_w_ok(t3, sizeof *t3),
                     "p256_wide_mul_row: the four limbs are writable");
    *t0 = nondet_u64();
    *t1 = nondet_u64();
    *t2 = nondet_u64();
    *t3 = nondet_u64();
    return nondet_u64();
}

// p256_wide_sqr_product writes any eight limbs. proof/p256_wide_sqr_harness.c proves the real
// square wraps no unsigned value for any four limbs, the one property a harness over this
// stub cannot state, and nothing in the harnesses reads the square's value.
static void stub_sqr_product(uint64_t *t0, uint64_t *t1, uint64_t *t2, uint64_t *t3, uint64_t *t4,
                             uint64_t *t5, uint64_t *t6, uint64_t *t7, uint64_t a0, uint64_t a1,
                             uint64_t a2, uint64_t a3) {
    (void)a0;
    (void)a1;
    (void)a2;
    (void)a3;
    __CPROVER_assert(__CPROVER_w_ok(t0, sizeof *t0) && __CPROVER_w_ok(t1, sizeof *t1) &&
                         __CPROVER_w_ok(t2, sizeof *t2) && __CPROVER_w_ok(t3, sizeof *t3) &&
                         __CPROVER_w_ok(t4, sizeof *t4) && __CPROVER_w_ok(t5, sizeof *t5) &&
                         __CPROVER_w_ok(t6, sizeof *t6) && __CPROVER_w_ok(t7, sizeof *t7),
                     "p256_wide_sqr_product: the eight limbs are writable");
    *t0 = nondet_u64();
    *t1 = nondet_u64();
    *t2 = nondet_u64();
    *t3 = nondet_u64();
    *t4 = nondet_u64();
    *t5 = nondet_u64();
    *t6 = nondet_u64();
    *t7 = nondet_u64();
}

#endif
