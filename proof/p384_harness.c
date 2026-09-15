// Proves: everything attacker bytes reach in p384_ecdsa_verify is
// memory-safe and UB-free, CONCRETE (real bodies, real rbuf via buf.c),
// the way p256_harness.c proves p256_ecdsa_verify at eight limbs:
//
//   der_parse/der_scalar      : any input up to 112 bytes (a valid sig is
//                               <= 104: two 49-byte INTEGERs and framing)
//   p384_from_bytes           : the byte->limb marshalling of r/s/pub/hash
//   p384_compare/p384_is_zero/p384_add_raw/p384_sub_raw,
//   p384_mod_add/p384_mod_sub : including the aliased shapes
//   p384_mont_mul/p384_mod_mul: both moduli, o aliasing a as mod_inverse does
//   on_curve, point_double, point_add : fully nondet points, including the
//                               o == a aliasing point_mul and verify use
//
// Not unrolled: the two 384-iteration loop drivers, point_mul and
// p384_mod_inverse — tens of thousands of Montgomery multiplies never
// leave symex, the p384 counterpart of p256's and x25519's mul-vs-SAT
// split. Their loop bodies are exactly the routines proven above, and
// their only iteration-dependent memory access — the k[i/32] / e[i/32]
// bit walk — is proven in bounds for every i in [0,383] below. The
// top-level p384_ecdsa_verify body is therefore not called whole; every
// statement it executes is one of the proven pieces. The uint64
// carry-chain lemma behind p384_mont_mul is p384_mul_harness.c.
#include "harness.h"

#include "p384_field.c"

#include "p384.c"

uint32_t nondet_u32(void);
int nondet_int(void);

// Fully nondet limbs — a superset of the "below m" contract; no index in
// p384.c or p384_field.c depends on limb values, so safety must hold
// regardless.
static void fe_nondet(uint32_t f[P384_LIMBS]) {
    for (size_t i = 0; i < P384_LIMBS; i++) {
        f[i] = nondet_u32();
    }
}

static void point_nondet(point *p) {
    fe_nondet(p->x);
    fe_nondet(p->y);
    fe_nondet(p->z);
}

int main(void) {
    // The wire surface: strict DER over any bytes, any length up to 112.
    uint8_t sig[112];
    fill_nondet(sig, sizeof sig);
    size_t sig_len = nondet_size_t();
    __CPROVER_assume(sig_len <= sizeof sig);
    uint8_t r_be[P384_LEN];
    uint8_t s_be[P384_LEN];
    (void)der_parse(sig, sig_len, r_be, s_be);

    // Marshalling and range checks, as verify's prologue runs them.
    uint8_t pub[P384_PUB_LEN];
    uint8_t hash[P384_LEN];
    fill_nondet(pub, sizeof pub);
    fill_nondet(hash, sizeof hash);
    uint32_t a[P384_LIMBS];
    uint32_t b[P384_LIMBS];
    uint32_t o[P384_LIMBS];
    p384_from_bytes(a, pub);
    p384_from_bytes(b, pub + P384_LEN);
    p384_from_bytes(o, hash);
    if (p384_compare(o, p384_modn.m) >= 0) {
        (void)p384_sub_raw(o, o, p384_modn.m);
    }
    (void)p384_is_zero(o);

    // Field/group layer, one call per shape the loop drivers use.
    fe_nondet(a);
    fe_nondet(b);
    (void)p384_add_raw(o, a, b);
    (void)p384_sub_raw(o, a, b);
    p384_mod_add(o, a, b, &p384_modp);
    p384_mod_add(a, a, a, &p384_modp); // o == a == b, point_double's 3*alpha shape
    p384_mod_sub(o, a, b, &p384_modn);
    fe_nondet(a);
    fe_nondet(b);
    p384_mont_mul(o, a, b, &p384_modp);
    fe_nondet(a);
    fe_nondet(b);
    p384_mont_mul(a, a, b, &p384_modn); // o aliasing a
    fe_nondet(a);
    p384_mont_mul(a, a, a, &p384_modn); // o == a == b, mod_inverse's square step
    fe_nondet(a);
    fe_nondet(b);
    p384_mod_mul(o, a, b, &p384_modp);
    fe_nondet(a);
    fe_nondet(b);
    p384_mod_mul(a, a, b, &p384_modn);
    fe_nondet(a);
    p384_mod_mul(a, a, a, &p384_modp); // point_double's mod_mul(r.z, r.z, r.z)
    fe_nondet(a);
    fe_nondet(b);
    (void)on_curve(a, b);

    point pa;
    point pb;
    point_nondet(&pa);
    point_nondet(&pb);
    point_double(&pa, &pa); // aliased, as point_mul doubles acc in place
    point_add(&pa, &pa, &pb);

    // The loop drivers' only iteration-dependent access: both bit-walk
    // index expressions, for every i either loop can produce.
    int i = nondet_int();
    __CPROVER_assume(i >= 0 && i < SCALAR_BITS);
    fe_nondet(a);
    uint32_t bit = (a[(size_t)i / 32] >> ((size_t)i % 32)) & 1; // point_mul
    bit |= (a[i / 32] >> (i % 32)) & 1;                         // mod_inverse
    (void)bit;
    return 0;
}
