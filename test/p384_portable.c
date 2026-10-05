// p384_field.c and the 32-bit arm of p384.c, the reference, in a host test
// binary. bin/p384_equiv_test compiles every unit under -DCH_CPU_RUNTIME,
// as a host object is compiled, so p384_field.c beside this unit has no
// body and p384.c is the arm that calls p384_wide_verify.c. This unit
// takes the define away and compiles what a device object holds: the
// field under its own names, which nothing else in the binary defines,
// and the verifier under a second one.
//
// The #define rewrites both the definition in p384.c and the declaration
// it reads from p384.h, because it is in effect before that header is
// read. test/p256_verify_portable.c is the same construction for P-256.
//
// After the two files comes what bin/p384_equiv_test builds its keys and
// signatures with. It sits here because the 32-bit arm's points and its
// scalar multiplication are static to p384.c.
#undef CH_CPU_RUNTIME
#define p384_ecdsa_verify p384_ecdsa_verify_portable

#include "p384_field.c"

#include "p384.c"

#include "p384_portable.h"

void p384_portable_to_bytes(uint8_t b[P384_LEN], const uint32_t a[P384_LIMBS]) {
    for (int i = 0; i < P384_LIMBS; i++) {
        for (int j = 0; j < 4; j++) {
            b[P384_LEN - 1 - 4 * i - j] = (uint8_t)(a[i] >> (8 * j));
        }
    }
}

static void affine_point(point *o, const uint32_t x[P384_LIMBS], const uint32_t y[P384_LIMBS]) {
    memcpy(o->x, x, sizeof o->x);
    memcpy(o->y, y, sizeof o->y);
    memset(o->z, 0, sizeof o->z);
    o->z[0] = 1;
}

int p384_portable_double_mul(uint8_t out[P384_PUB_LEN], const uint8_t k1[P384_LEN],
                             const uint8_t k2[P384_LEN], const uint8_t q[P384_PUB_LEN]) {
    uint32_t scalar[P384_LIMBS];
    uint32_t x[P384_LIMBS];
    uint32_t y[P384_LIMBS];
    point term;
    point sum;
    affine_point(&term, GX, GY);
    p384_from_bytes(scalar, k1);
    point_mul(&sum, scalar, &term);
    if (q != NULL) {
        p384_from_bytes(x, q);
        p384_from_bytes(y, q + P384_LEN);
        affine_point(&term, x, y);
        p384_from_bytes(scalar, k2);
        point_mul(&term, scalar, &term);
        point_add(&sum, &sum, &term);
    }
    if (p384_is_zero(sum.z)) {
        return 0;
    }
    // The affine point: x = X / Z^2 and y = Y / Z^3.
    uint32_t z_inverse[P384_LIMBS];
    uint32_t power[P384_LIMBS];
    p384_mod_inverse(z_inverse, sum.z, &p384_modp);
    p384_mod_mul(power, z_inverse, z_inverse, &p384_modp);
    p384_mod_mul(x, sum.x, power, &p384_modp);
    p384_mod_mul(power, power, z_inverse, &p384_modp);
    p384_mod_mul(y, sum.y, power, &p384_modp);
    p384_portable_to_bytes(out, x);
    p384_portable_to_bytes(out + P384_LEN, y);
    return 1;
}
