// The contract the rsa_mont64 harnesses replace the 64x64->128 multiply
// with, the way proof/x25519_wide_stubs.h serves the wide X25519 field.
//
// Why this exists: one Montgomery multiplication at RSA-3072 runs 4,656
// products, and docs/proofs.md says SAT cost follows the multiply count.
// So the one multiply rsa_mont64.c calls, ct_mul128, is the contract
// below. The harness reads ct.h first under its own name, the #define
// renames every later use, and ct.h's include guard keeps rsa_mont64.c's
// own #include from reading the real definition again.
//
// WHAT THE STUB MODELS: ct_mul128 takes any two operands and returns any
// value at or below (2^64 - 1)^2, the largest product two words have.
// That is 2^128 - 2^65 + 1: a high word of 2^64 - 2 and a low word of 1.
//
// WHAT DISCHARGES THE CONTRACT: rsa_mont64_mul128_harness.c proves the
// real ct_mul128 returns a product at or below that value for every pair
// of operands. Every property the harnesses over this stub hold is a
// bound or a memory access, and none reads a product's value beyond that
// bound, so a proof over every value under it covers the real products.
//
// What the contract gives up: the value. No harness over it says the
// result of a multiplication is the Montgomery product, or below the
// modulus. bin/rsa_equiv_test, the published vectors and the Wycheproof
// suites hold those.
//
// rsa_mont64.h's step, rsa_mont64_mul_add_add, is the second function
// replaced here: x * y + a + b as one 128-bit sum, which wraps nothing
// under the product contract, in place of either form of the step, the
// compare form whose two 64-bit adds wrap on purpose or the sum form
// (docs/decisions.md 117). The header is read first under its own name, as
// ct.h is, and the #define renames every later call.
// rsa_mont64_step_harness.c and rsa_mont64_step_sum_harness.c prove that
// each form returns this sum's two words for every input and every product
// the contract admits.
#ifndef CH_RSA_MONT64_STUBS_H
#define CH_RSA_MONT64_STUBS_H

// The harnesses over this file run rsa_mont64.c's own loops, whatever compiler preprocesses
// them. rsa_mont64_blocks.c's blocks, which a clang build for arm64 runs, have harnesses of
// their own, which set RSA_MONT64_BLOCKS to 1 before they read this file and include
// rsa_mont64_blocks.c after it, under the same product contract (docs/decisions.md 118).
#ifndef RSA_MONT64_BLOCKS
#define RSA_MONT64_BLOCKS 0
#endif

#include "harness.h"

#include "ct.h"
// From here on the multiply rsa_mont64.c calls is the contract below.
#define ct_mul128 stub_mul128

// (2^64 - 1)^2.
#define MUL128_MAX ((((ct_u128)(UINT64_MAX - 1)) << 64) | 1)

ct_u128 nondet_u128(void);
uint64_t nondet_u64(void);

static ct_u128 stub_mul128(uint64_t a, uint64_t b) {
    (void)a;
    (void)b;
    ct_u128 product = nondet_u128();
    __CPROVER_assume(product <= MUL128_MAX);
    return product;
}

#include "rsa_mont64.h"
// From here on the step rsa_mont64.c calls is the sum below, written in
// place: a function that returned it took rsa_mont64_mul from 36 s and
// 773 MB to 51 s and 1.7 GB.
static ct_u128 stub_step_value;
#define rsa_mont64_mul_add_add(x, y, a, b)                                                         \
    (stub_step_value = ct_mul128((x), (y)) + (a) + (b),                                            \
     (rsa_mont64_sum){(uint64_t)stub_step_value, (uint64_t)(stub_step_value >> 64)})

#include "rsa_mont64.c"

static void havoc_words(uint64_t *a, size_t k) {
    for (size_t i = 0; i < k; i++) {
        a[i] = nondet_u64();
    }
}

// A modulus record of k words, every word unconstrained: the
// multiplication's memory accesses and its sums hold for any modulus,
// odd or not, and for any m0inv.
static void havoc_modulus(rsa_mont64_modulus *mod, size_t k) {
    havoc_words(mod->m, k);
    havoc_words(mod->r2, k);
    mod->m0inv = nondet_u64();
    mod->words = k;
}

#endif
