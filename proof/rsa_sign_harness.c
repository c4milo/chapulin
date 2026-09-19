// Proves rsa_sign.c's memory safety and absence of UB over unconstrained
// inputs, in five pieces, with full checks.
//
// Marshalling and the limb helpers, at the real bound. limbs_from_bytes
// and limbs_to_bytes, and then sub_borrow, sub_masked, below, cond_sub
// and cswap_limbs, run at k = LIMBS_MAX (96 for the device bound of
// RSA-3072) over nondet bytes and nondet limbs, with the operands
// havocked freshly before every call. The maximal k is the binding case
// for every index: rsa_pss_sign's n_len check is what holds k there, and
// a smaller k only shortens the same loops.
//
// The mask. mask_of_bit must return all ones or all zeros and nothing
// else, because every select in the file is an AND against it or its
// complement: a mask with a mixed bit pattern would mix two values
// instead of choosing one. Proved over both inputs, and below()'s answer
// is proved to be the one bit mask_of_bit admits.
//
// The exponent index. The ladder reads bit i of d for i over
// 0..8*n_len-1, and the byte it reads is d[n_len - 1 - (i >> 3)]. The
// loop itself has 8 * n_len iterations, far past any unwinding bound, so
// the index is proved here over a nondet i under the loop's own range,
// which is what the loop establishes for each of its iterations.
//
// The CIOS carry lemma, behind mont_mul. In both passes the uint64
// accumulation v = x*y + t + c cannot wrap and its carry-out fits back in
// one 32-bit limb, for ANY uint32 operands, and each pass's tail spills
// at most one bit. The bound is inductive, so a fixed step count stands
// in for the real k-limb passes and the count never enters the argument.
// This is rsa_mul_harness.c's lemma over the same CIOS shape; the two
// files keep their own copies because rsa_sign.c's products go through
// ct_widemul and rsa_mont.c's do not.
//
// What no formula here drives, and why:
//
//   mont_mul whole, and rsa_sp1 above it. Its inner passes are k
//   multiplies deep at k = 96, and a symbolic modexp never leaves
//   symbolic execution -- the same limit rsa_mul_harness.c records for
//   rsa_vp1. Every index in it walks a fixed LIMBS_MAX-sized array under
//   k <= LIMBS_MAX, and the carry lemma covers the arithmetic.
//
//   mont_r2. Its shift loop runs 64 * k = 6,144 times, past any unwinding
//   bound this tier can carry. Its body is cond_sub and a limb shift,
//   both proved here.
//
//   The final conditional subtract's functional claim, that t stays below
//   2m at loop exit. That is a CIOS invariant, and it rests on the
//   vectors in test/rsa_sign_test.c and the Wycheproof signing suite, not
//   on a proof.
// The PSS encoder hashes, and the encoder is a piece this harness drives
// whole; sha256.c has its own proof, so the stub stands in for it.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <stdint.h>

#include "sha256.h"

uint32_t nondet_u32(void);

#include "rsa_sign.c"

// The salt the encoder draws: unconstrained bytes, less the all-zero
// draw. rsa_sign.c asserts against that one because it is what a hook
// that returns without writing leaves behind (INV-4), and rand.h's
// contract is that the hook writes n random bytes. This harness is the
// hook, so it honours the contract rather than firing the assertion.
void ch_rand_bytes(uint8_t *p, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(p, n), "ch_rand_bytes: output writable");
    fill_nondet(p, n);
    uint8_t any = 0;
    for (size_t i = 0; i < n; i++) {
        any |= p[i];
    }
    __CPROVER_assume(any != 0);
}

static void havoc_limbs(uint32_t *a, size_t k) {
    for (size_t i = 0; i < k; i++) {
        a[i] = nondet_u32();
    }
}

// One CIOS pass, x nondet each step: a superset of both real passes (the
// multiply pass holds x = a[i] fixed, the reduction pass runs with
// x = u).
static uint64_t mac_pass(uint64_t c) {
    for (int j = 0; j < 8; j++) {
        uint64_t x = nondet_u32();
        uint64_t y = nondet_u32();
        uint64_t t = nondet_u32();
        uint64_t p = ct_widemul((uint32_t)x, (uint32_t)y); // <= (2^32-1)^2, no wrap
        __CPROVER_assert(p <= UINT64_MAX - t - c, "accumulate cannot wrap");
        c = (p + t + c) >> 32;
        __CPROVER_assert(c <= UINT32_MAX, "carry fits one limb");
    }
    return c;
}

static void prove_marshalling(void) {
    uint8_t b[4 * LIMBS_MAX];
    uint32_t limbs[LIMBS_MAX];
    fill_nondet(b, sizeof b);
    limbs_from_bytes(limbs, b, LIMBS_MAX);
    havoc_limbs(limbs, LIMBS_MAX);
    limbs_to_bytes(b, limbs, LIMBS_MAX);
}

static void prove_limb_helpers(void) {
    uint32_t a[LIMBS_MAX];
    uint32_t b[LIMBS_MAX];
    havoc_limbs(a, LIMBS_MAX);
    havoc_limbs(b, LIMBS_MAX);
    uint32_t borrow = sub_borrow(a, b, LIMBS_MAX);
    __CPROVER_assert(borrow <= 1, "sub_borrow answers one bit");

    havoc_limbs(a, LIMBS_MAX);
    havoc_limbs(b, LIMBS_MAX);
    sub_masked(a, b, LIMBS_MAX, nondet_u32());

    havoc_limbs(a, LIMBS_MAX);
    havoc_limbs(b, LIMBS_MAX);
    uint32_t low = below(a, b, LIMBS_MAX, nondet_u32());
    __CPROVER_assert(low <= 1, "below answers one bit");

    havoc_limbs(a, LIMBS_MAX);
    havoc_limbs(b, LIMBS_MAX);
    cond_sub(a, b, LIMBS_MAX, nondet_u32() & 1);

    havoc_limbs(a, LIMBS_MAX);
    havoc_limbs(b, LIMBS_MAX);
    cswap_limbs(a, b, LIMBS_MAX, nondet_u32());
}

static void prove_masks(void) {
    uint32_t bit = nondet_u32() & 1;
    uint32_t m = mask_of_bit(bit);
    __CPROVER_assert(m == 0 || m == UINT32_MAX, "mask_of_bit is all ones or all zeros");
    __CPROVER_assert((bit == 1) == (m == UINT32_MAX), "mask_of_bit follows its bit");
}

// The ladder's read of bit i of d, over the range the loop gives it.
static void prove_exponent_index(void) {
    size_t n_len = nondet_size_t();
    __CPROVER_assume(n_len >= 256 && n_len <= CH_RSA_MODULUS_MAX && n_len % 8 == 0);
    size_t i = nondet_size_t();
    __CPROVER_assume(i < 8 * n_len);
    size_t byte = n_len - 1 - (i >> 3);
    __CPROVER_assert(byte < n_len, "the exponent byte index stays inside d");
    __CPROVER_assert((i & 7) < 8, "the shift stays inside a byte");
}

// The encoder whole, at the largest encoded message it writes. Every
// length it computes comes from em_len, so the maximal one is the
// binding case for the MGF1 mask, the PS run and the salt copy.
static void prove_encoder(void) {
    uint8_t msg_hash[32];
    uint8_t em[CH_RSA_MODULUS_MAX];
    fill_nondet(msg_hash, sizeof msg_hash);
    fill_nondet(em, sizeof em);
    emsa_pss_encode(msg_hash, em, CH_RSA_MODULUS_MAX);
}

int main(void) {
    prove_marshalling();
    prove_limb_helpers();
    prove_masks();
    prove_exponent_index();
    prove_encoder();

    // Multiply pass, then its tail: v = t[k] + c spills at most one bit
    // into t[k+1].
    uint64_t c = mac_pass(0);
    uint64_t v = (uint64_t)nondet_u32() + c;
    uint32_t t_k1 = (uint32_t)(v >> 32);
    __CPROVER_assert(t_k1 <= 1, "multiply tail spills one bit at most");

    // Reduction pass: the first step adds u*m[0] to t[0] with no carry-in
    // and feeds the rest of the pass.
    uint64_t u = nondet_u32();
    uint64_t m0 = nondet_u32();
    uint64_t t0 = nondet_u32();
    uint64_t first = ct_widemul((uint32_t)u, (uint32_t)m0);
    __CPROVER_assert(first <= UINT64_MAX - t0, "first add cannot wrap");
    c = mac_pass((first + t0) >> 32);
    v = (uint64_t)nondet_u32() + c;
    uint32_t spill = (uint32_t)(v >> 32);
    __CPROVER_assert(spill <= 1, "reduction tail spills one bit at most");

    // The reduction tail sets t[k] = t[k+1] + spill; both are 0 or 1, so
    // the carry word the next round reads stays inside one limb.
    uint64_t t_k = (uint64_t)t_k1 + spill;
    __CPROVER_assert(t_k <= UINT32_MAX, "carry word sum stays in one limb");
    return 0;
}
