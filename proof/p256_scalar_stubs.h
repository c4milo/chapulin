// The p256_scalar.h stubs every harness above the scalar arithmetic
// shares: proof/p256_sign_harness.c and proof/p256_ecdh_harness.c. Each
// stub asserts the contract p256_scalar.h states for its arguments and
// havocs its output, so nothing a caller computes depends on a scalar
// value. The real bodies are proven in proof/p256_scalar_harness.c.
//
// The two predicates return an unconstrained mask rather than a chosen
// answer. That is what makes a proof cover every acceptance pattern its
// caller can see -- every pattern of usable and unusable RFC 6979
// candidates for the signer, and both verdicts on a private key for the
// key exchange.
//
// Every output is stored through the scalar's own type, never a byte
// fill of one, which is what docs/proofs.md asks for.
#ifndef CH_PROOF_P256_SCALAR_STUBS_H
#define CH_PROOF_P256_SCALAR_STUBS_H

#include "harness.h"

#include "p256_scalar.h"

const p256_scalar p256_scalar_zero = {
    {0, 0, 0, 0, 0, 0, 0, 0}
};

static void havoc_scalar(p256_scalar *o) {
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "scalar output writable");
    for (size_t i = 0; i < P256_SCALAR_LIMBS; i++) {
        o->limb[i] = nondet_u32();
    }
}

void p256_scalar_from_bytes(p256_scalar *o, const uint8_t in[P256_SCALAR_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(in, P256_SCALAR_LEN), "from_bytes: input readable");
    havoc_scalar(o);
}

void p256_scalar_to_bytes(uint8_t out[P256_SCALAR_LEN], const p256_scalar *a) {
    __CPROVER_assert(__CPROVER_w_ok(out, P256_SCALAR_LEN), "to_bytes: output writable");
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "to_bytes: input readable");
    fill_nondet(out, P256_SCALAR_LEN);
}

uint32_t p256_scalar_reduced_mask(const p256_scalar *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "reduced_mask: input readable");
    return nondet_mask();
}

uint32_t p256_scalar_zero_mask(const p256_scalar *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "zero_mask: input readable");
    return nondet_mask();
}

void p256_scalar_cmov(p256_scalar *o, const p256_scalar *a, uint32_t mask) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "cmov: input readable");
    __CPROVER_assert(mask == 0 || mask == UINT32_MAX, "cmov: the mask is 0 or all ones");
    havoc_scalar(o);
}

void p256_scalar_reduce(p256_scalar *o, const p256_scalar *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "reduce: input readable");
    havoc_scalar(o);
}

void p256_scalar_add(p256_scalar *o, const p256_scalar *a, const p256_scalar *b) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "add: first input readable");
    __CPROVER_assert(__CPROVER_r_ok(b, sizeof *b), "add: second input readable");
    havoc_scalar(o);
}

void p256_scalar_mul(p256_scalar *o, const p256_scalar *a, const p256_scalar *b) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "mul: first input readable");
    __CPROVER_assert(__CPROVER_r_ok(b, sizeof *b), "mul: second input readable");
    havoc_scalar(o);
}

void p256_scalar_inverse(p256_scalar *o, const p256_scalar *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "inverse: input readable");
    havoc_scalar(o);
}

#endif
