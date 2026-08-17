// Proves the two pieces of rsa_mont.c that rsa_harness's rsa_vp1 stub
// leaves uncovered, with full checks:
//
// Marshalling. from_bytes and to_bytes — the byte<->limb conversions
// RSAVP1 runs over the attacker's n and sig, both directions — driven
// concretely at k = 96 (RSA-3072, the LIMBS_MAX bound rsa_pss_verify's
// n_len gate enforces before rsa_vp1 runs) over nondet bytes and limbs.
// The maximal k is the binding case for every index; smaller k only
// shrinks the loop counts.
//
// Carry lemma. Behind mont_mul (CIOS): in both passes the uint64
// accumulation v = x*y + t + c cannot wrap and its carry-out fits back
// in one 32-bit limb — for ANY uint32 operands, re-establishing
// c <= 2^32-1 step by step — and each pass's tail fold spills at most
// one bit, so the carry word t[k] the next round reads only ever holds
// 0..2. The bound is inductive, so a fixed step count stands in for the
// real k-limb passes; the count never enters the argument. mont_mul
// itself is undriven in both harnesses (its symbolic modexp never
// leaves symex): every index walks a fixed LIMBS_MAX-sized array under
// the k <= 96 bound. The final conditional subtract (t < 2m at loop
// exit) is a functional CIOS invariant resting on the vectors in
// test/rsa_test.c — same standing as x25519's open limb-growth
// invariant.
#include "harness.h"

#include <stdint.h>

uint32_t nondet_u32(void);

#include "rsa_mont.c"

// One CIOS pass, x nondet each step: a superset of both real passes (the
// multiply pass holds x = a[i] fixed, the reduction pass runs with x = u).
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
    // Marshalling at the k = 96 bound: 384 nondet bytes into limbs, 96
    // nondet limbs back out to bytes.
    uint8_t b[4 * LIMBS_MAX];
    uint32_t limbs[LIMBS_MAX];
    fill_nondet(b, sizeof b);
    from_bytes(limbs, b, LIMBS_MAX);
    for (size_t i = 0; i < LIMBS_MAX; i++) {
        limbs[i] = nondet_u32();
    }
    to_bytes(b, limbs, LIMBS_MAX);

    // Multiply pass, then its tail: v = t[k] + c spills at most one bit
    // into t[k+1].
    uint64_t c = mac_pass(0);
    uint64_t v = (uint64_t)nondet_u32() + c;
    uint32_t t_k1 = (uint32_t)(v >> 32); // t[k+1] after the multiply tail
    __CPROVER_assert(t_k1 <= 1, "multiply tail spills one bit at most");

    // Reduction pass: the first step folds u*m[0] + t[0] with no carry-in
    // and feeds the rest of the pass.
    uint64_t u = nondet_u32();
    uint64_t m0 = nondet_u32();
    uint64_t t0 = nondet_u32();
    __CPROVER_assert(u * m0 <= UINT64_MAX - t0, "first fold cannot wrap");
    c = mac_pass((u * m0 + t0) >> 32);
    v = (uint64_t)nondet_u32() + c;
    uint32_t spill = (uint32_t)(v >> 32);
    __CPROVER_assert(spill <= 1, "reduction tail spills one bit at most");

    // The reduction tail folds t[k] = t[k+1] + spill; both are 0 or 1, so
    // the carry word the next round reads stays inside one limb.
    uint64_t t_k = (uint64_t)t_k1 + spill;
    __CPROVER_assert(t_k <= UINT32_MAX, "carry word fold stays in one limb");
    return 0;
}
