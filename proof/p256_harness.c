// Proves: everything attacker bytes reach in p256_ecdsa_verify is
// memory-safe and UB-free, CONCRETE (real bodies, real rbuf via buf.c):
//
//   der_parse/der_scalar  : any input up to 80 bytes (a valid sig is <= 72)
//   fe_from_bytes         : the byte->limb marshalling of r/s/pub/hash
//   fe_cmp/fe_is_zero/fe_add_raw/fe_sub_raw, mod_add/mod_sub (aliased too)
//   mont_mul/mod_mul      : both moduli, o aliasing a as mod_inv does
//   on_curve, point_double, point_add : fully nondet points, including the
//                           o == a aliasing point_mul and verify use
//
// Not unrolled: the two 256-iteration loop drivers, point_mul and
// mod_inv — 25k+ Montgomery multiplies never leave symex, the p256
// counterpart of x25519's mul-vs-SAT split. Their loop bodies are exactly
// the routines proven above, and their only iteration-dependent memory
// access — the k[i/32] / e[i/32] bit walk — is proven in bounds for every
// i in [0,255] below. mod_inv's prologue (e = m, e[0] -= 2) is uint32
// arithmetic on constants, no memory shape of its own. The top-level
// p256_ecdsa_verify body is therefore not called whole; every statement
// it executes is one of the proven pieces. The uint64 carry-chain lemma
// behind mont_mul is p256_mul_harness.c.
#include "harness.h"

#include "p256.c"

uint32_t nondet_u32(void);
int nondet_int(void);

// Fully nondet limbs — a superset of the "below m" contract; no index in
// p256.c depends on limb values, so safety must hold regardless.
static void fe_nondet(uint32_t f[NLIMBS]) {
    for (size_t i = 0; i < NLIMBS; i++) {
        f[i] = nondet_u32();
    }
}

static void point_nondet(point *p) {
    fe_nondet(p->x);
    fe_nondet(p->y);
    fe_nondet(p->z);
}

int main(void) {
    // The wire surface: strict DER over any bytes, any length up to 80.
    uint8_t sig[80];
    fill_nondet(sig, sizeof sig);
    size_t sig_len = nondet_size_t();
    __CPROVER_assume(sig_len <= sizeof sig);
    uint8_t r_be[32];
    uint8_t s_be[32];
    (void)der_parse(sig, sig_len, r_be, s_be);

    // Marshalling and range checks, as verify's prologue runs them.
    uint8_t pub[64];
    uint8_t hash[32];
    fill_nondet(pub, sizeof pub);
    fill_nondet(hash, sizeof hash);
    uint32_t a[NLIMBS];
    uint32_t b[NLIMBS];
    uint32_t o[NLIMBS];
    fe_from_bytes(a, pub);
    fe_from_bytes(b, pub + 32);
    fe_from_bytes(o, hash);
    if (fe_cmp(o, MODN.m) >= 0) {
        (void)fe_sub_raw(o, o, MODN.m);
    }
    (void)fe_is_zero(o);

    // Field/group layer, one call per shape the loop drivers use.
    fe_nondet(a);
    fe_nondet(b);
    (void)fe_add_raw(o, a, b);
    (void)fe_sub_raw(o, a, b);
    mod_add(o, a, b, &MODP);
    mod_add(a, a, a, &MODP); // o == a == b, point_double's 3*alpha shape
    mod_sub(o, a, b, &MODN);
    fe_nondet(a);
    fe_nondet(b);
    mont_mul(o, a, b, &MODP);
    mont_mul(a, a, b, &MODN); // o aliasing a, as mod_inv squares
    mod_mul(o, a, b, &MODP);
    mod_mul(a, a, b, &MODN);
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
    __CPROVER_assume(i >= 0 && i <= 255);
    fe_nondet(a);
    uint32_t bit = (a[(size_t)i / 32] >> ((size_t)i % 32)) & 1; // point_mul
    bit |= (a[i / 32] >> (i % 32)) & 1;                         // mod_inv
    (void)bit;
    return 0;
}
