// Proves the carry lemma behind mont_mul: in both CIOS passes the uint64
// accumulation v = x*y + t + c cannot wrap and its carry-out fits back in
// one 32-bit limb — for ANY uint32 operands, re-establishing c <= 2^32-1
// step by step — and each pass's tail fold t[N] + c carries out at most
// one bit, so the overflow word t[LIMBS+1] only ever holds 0 or 1.
// mont_mul's memory safety (concrete index walk) is p256_harness.c. The
// final single conditional subtract (t < 2m at loop exit) is a functional
// CIOS invariant resting on the RFC 6979 vectors in test/unit_test.c — same
// standing as x25519's open limb-growth invariant.
#include "harness.h"

#include <stdint.h>

uint32_t nondet_u32(void);

// One CIOS pass, x nondet per step: a superset of both real passes
// (multiply holds x = a[i] fixed, reduction runs 7 steps with x = u).
static uint64_t mac_pass(uint64_t c) {
    for (int j = 0; j < 8; j++) {
        uint64_t x = nondet_u32();
        uint64_t y = nondet_u32();
        uint64_t t = nondet_u32();
        uint64_t p = x * y; // <= (2^32-1)^2, no uint64 wrap possible
        __CPROVER_assert(p <= UINT64_MAX - t - c, "accumulate cannot wrap");
        c = (p + t + c) >> 32;
        __CPROVER_assert(c <= UINT32_MAX, "carry fits one limb");
    }
    return c;
}

int main(void) {
    // Multiply pass, then its tail: v = t[N] + c spills at most one bit
    // into t[N+1].
    uint64_t c = mac_pass(0);
    uint64_t v = (uint64_t)nondet_u32() + c;
    __CPROVER_assert((v >> 32) <= 1, "multiply tail spills one bit at most");

    // Reduction pass: the first step folds u*m[0] + t[0] with no carry-in
    // and feeds the rest of the pass.
    uint64_t u = nondet_u32();
    uint64_t m0 = nondet_u32();
    uint64_t t0 = nondet_u32();
    __CPROVER_assert(u * m0 <= UINT64_MAX - t0, "first fold cannot wrap");
    c = mac_pass((u * m0 + t0) >> 32);
    v = (uint64_t)nondet_u32() + c;
    __CPROVER_assert((v >> 32) <= 1, "reduction tail spills one bit at most");
    return 0;
}
