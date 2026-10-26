// Proves: every exported function in mldsa_poly.c but the two transforms
// is memory-safe and UB-free with the signed-overflow check on: the
// products in the NTT domain and the difference, over coefficients from
// all of int32_t; the unpacking of t1 and z and the hints, over every
// byte string; and both samplers, over every SHAKE stream. mldsa_ntt
// proves the transforms.
//
// The coefficient functions are replaced with their contracts
// (proof/mldsa_stubs.h), and mldsa_coefficient proves the real ones. The
// SHAKE sponge is stubbed to its pointer contract with arbitrary output,
// as in mlkem_poly_harness.c, and sha3_harness.c proves the real one. So
// the rejection samplers are proved over every stream, and their bounds,
// MLD_SAMPLE_BLOCKS and MLD_BALL_BYTES, are what make their loops end.
//
// mld_poly_use_hint gets a list of up to omega positions in any order, a
// superset of what mldsa.c passes after its HintBitUnpack checks. Every
// call gets freshly havocked operands. mldsa.c calls the three products
// with the output aliased to an input, pointwise(e, c, e),
// pointwise_acc(s, e, z) and sub(s, s, e), so the harness calls those
// shapes too.
#include "harness.h"
#include "mldsa_poly.h"
#include "mldsa_stubs.h"

#include "mldsa_poly.c"

int32_t nondet_i32(void);

static void havoc_poly(mld_poly *p) {
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = nondet_i32();
    }
}

void shake128_init(shake *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake128_init: ctx writable");
    fill_nondet((uint8_t *)s, sizeof *s);
}

void shake256_init(shake *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake256_init: ctx writable");
    fill_nondet((uint8_t *)s, sizeof *s);
}

void shake_absorb(shake *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake_absorb: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "shake_absorb: input readable");
}

void shake_squeeze(shake *s, uint8_t *out, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake_squeeze: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(out, n), "shake_squeeze: output writable");
    fill_nondet(out, n);
}

int main(void) {
    mld_poly a;
    mld_poly b;
    mld_poly r;
    uint8_t bytes[MLD_Z_BYTES];
    uint8_t w1[MLD_W1_BYTES];
    uint8_t hints[MLD_OMEGA];
    uint8_t rho[MLD_RHO_BYTES];
    uint8_t c_tilde[64];

    havoc_poly(&a);
    havoc_poly(&b);
    mld_poly_pointwise(&r, &a, &b);
    havoc_poly(&a);
    havoc_poly(&b);
    mld_poly_pointwise(&b, &a, &b);
    havoc_poly(&a);
    havoc_poly(&b);
    havoc_poly(&r);
    mld_poly_pointwise_acc(&r, &a, &b);
    havoc_poly(&a);
    havoc_poly(&b);
    mld_poly_pointwise_acc(&a, &b, &a);
    havoc_poly(&a);
    havoc_poly(&b);
    mld_poly_sub(&r, &a, &b);
    havoc_poly(&a);
    havoc_poly(&b);
    mld_poly_sub(&a, &a, &b);

    fill_nondet(bytes, MLD_T1_BYTES);
    mld_poly_unpack_t1_shifted(&r, bytes);
    fill_nondet(bytes, MLD_Z_BYTES);
    (void)mld_poly_unpack_z(&r, bytes);

    size_t hint_count = nondet_size_t();
    __CPROVER_assume(hint_count <= MLD_OMEGA);
    fill_nondet(hints, sizeof hints);
    havoc_poly(&a);
    mld_poly_use_hint(w1, &a, hints, hint_count);

    fill_nondet(rho, sizeof rho);
    (void)mld_sample_ntt(&r, rho, nondet_u8(), nondet_u8());
    fill_nondet(c_tilde, sizeof c_tilde);
    (void)mld_sample_in_ball(&r, c_tilde);
    return 0;
}
