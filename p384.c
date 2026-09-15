// NIST P-384 ECDSA verification. Variable time on purpose — every input
// is public (see p384.h). The field and scalar arithmetic is in
// p384_field.c; this file holds the curve: Jacobian points (Z == 0 is
// infinity), the group law, and the verify equation over strict-DER
// signatures. It is p256.c line for line at 12 limbs. Clarity over
// speed: this runs once per connection.
#include "p384.h"

#include <string.h>

#include "buf.h"
#include "p384_field.h"

#define SCALAR_BITS 384

// SEC 2 curve constants, printed by test/gen_p384_constants.py after it
// checks them against openssl. a = p - 3, so the a = -3 doubling
// formula applies unchanged.
static const uint32_t B[P384_LIMBS] = {0xd3ec2aef, 0x2a85c8ed, 0x8a2ed19d, 0xc656398d,
                                       0x5013875a, 0x0314088f, 0xfe814112, 0x181d9c6e,
                                       0xe3f82d19, 0x988e056b, 0xe23ee7e4, 0xb3312fa7};

static const uint32_t GX[P384_LIMBS] = {0x72760ab7, 0x3a545e38, 0xbf55296c, 0x5502f25d,
                                        0x82542a38, 0x59f741e0, 0x8ba79b98, 0x6e1d3b62,
                                        0xf320ad74, 0x8eb1c71e, 0xbe8b0537, 0xaa87ca22};

static const uint32_t GY[P384_LIMBS] = {0x90ea0e5f, 0x7a431d7c, 0x1d7e819d, 0x0a60b1ce,
                                        0xb5f0b8c0, 0xe9da3113, 0x289a147c, 0xf8f41dbd,
                                        0x9292dc29, 0x5d9e98bf, 0x96262c6f, 0x3617de4a};

typedef struct {
    uint32_t x[P384_LIMBS];
    uint32_t y[P384_LIMBS];
    uint32_t z[P384_LIMBS]; // Jacobian: affine (x/z^2, y/z^3); z == 0 is infinity
} point;

// Doubling, a = -3 (EFD dbl-2001-b). Maps infinity to infinity: z == 0
// forces z3 == 0.
static void point_double(point *o, const point *a) {
    uint32_t delta[P384_LIMBS];
    uint32_t gamma[P384_LIMBS];
    uint32_t beta[P384_LIMBS];
    uint32_t alpha[P384_LIMBS];
    uint32_t t[P384_LIMBS];
    uint32_t t2[P384_LIMBS];
    point r;
    p384_mod_mul(delta, a->z, a->z, &p384_modp); // delta = Z^2
    p384_mod_mul(gamma, a->y, a->y, &p384_modp); // gamma = Y^2
    p384_mod_mul(beta, a->x, gamma, &p384_modp); // beta = X*gamma
    p384_mod_sub(t, a->x, delta, &p384_modp);
    p384_mod_add(t2, a->x, delta, &p384_modp);
    p384_mod_mul(alpha, t, t2, &p384_modp); // alpha = 3*(X-delta)*(X+delta)
    p384_mod_add(t, alpha, alpha, &p384_modp);
    p384_mod_add(alpha, t, alpha, &p384_modp);
    p384_mod_mul(r.x, alpha, alpha, &p384_modp); // X3 = alpha^2 - 8*beta
    p384_mod_add(t, beta, beta, &p384_modp);
    p384_mod_add(t, t, t, &p384_modp); // t = 4*beta
    p384_mod_add(t2, t, t, &p384_modp);
    p384_mod_sub(r.x, r.x, t2, &p384_modp);
    p384_mod_add(r.z, a->y, a->z, &p384_modp); // Z3 = (Y+Z)^2 - gamma - delta
    p384_mod_mul(r.z, r.z, r.z, &p384_modp);
    p384_mod_sub(r.z, r.z, gamma, &p384_modp);
    p384_mod_sub(r.z, r.z, delta, &p384_modp);
    p384_mod_sub(t, t, r.x, &p384_modp); // Y3 = alpha*(4*beta - X3) - 8*gamma^2
    p384_mod_mul(r.y, alpha, t, &p384_modp);
    p384_mod_mul(t, gamma, gamma, &p384_modp);
    p384_mod_add(t, t, t, &p384_modp);
    p384_mod_add(t, t, t, &p384_modp);
    p384_mod_add(t, t, t, &p384_modp);
    p384_mod_sub(r.y, r.y, t, &p384_modp);
    *o = r;
}

// General Jacobian addition (EFD add-2007-bl shape) with the exceptional
// cases spelled out: either operand at infinity, P == Q (double), and
// P == -Q (infinity). o may alias a.
static void point_add(point *o, const point *a, const point *b) {
    if (p384_is_zero(a->z)) {
        *o = *b;
        return;
    }
    if (p384_is_zero(b->z)) {
        *o = *a;
        return;
    }
    uint32_t z1z1[P384_LIMBS];
    uint32_t z2z2[P384_LIMBS];
    uint32_t u1[P384_LIMBS];
    uint32_t u2[P384_LIMBS];
    uint32_t s1[P384_LIMBS];
    uint32_t s2[P384_LIMBS];
    uint32_t h[P384_LIMBS];
    uint32_t rr[P384_LIMBS];
    p384_mod_mul(z1z1, a->z, a->z, &p384_modp);
    p384_mod_mul(z2z2, b->z, b->z, &p384_modp);
    p384_mod_mul(u1, a->x, z2z2, &p384_modp);
    p384_mod_mul(u2, b->x, z1z1, &p384_modp);
    p384_mod_mul(s1, a->y, b->z, &p384_modp);
    p384_mod_mul(s1, s1, z2z2, &p384_modp);
    p384_mod_mul(s2, b->y, a->z, &p384_modp);
    p384_mod_mul(s2, s2, z1z1, &p384_modp);
    p384_mod_sub(h, u2, u1, &p384_modp);
    p384_mod_sub(rr, s2, s1, &p384_modp);
    if (p384_is_zero(h)) {
        if (p384_is_zero(rr)) {
            point_double(o, a);
        } else {
            memset(o, 0, sizeof *o);
        }
        return;
    }
    uint32_t hh[P384_LIMBS];
    uint32_t hhh[P384_LIMBS];
    uint32_t v[P384_LIMBS];
    uint32_t t[P384_LIMBS];
    point r;
    p384_mod_mul(hh, h, h, &p384_modp);
    p384_mod_mul(hhh, hh, h, &p384_modp);
    p384_mod_mul(v, u1, hh, &p384_modp);
    p384_mod_mul(r.x, rr, rr, &p384_modp); // X3 = r^2 - h^3 - 2*u1*h^2
    p384_mod_sub(r.x, r.x, hhh, &p384_modp);
    p384_mod_sub(r.x, r.x, v, &p384_modp);
    p384_mod_sub(r.x, r.x, v, &p384_modp);
    p384_mod_sub(t, v, r.x, &p384_modp); // Y3 = r*(u1*h^2 - X3) - s1*h^3
    p384_mod_mul(r.y, rr, t, &p384_modp);
    p384_mod_mul(t, s1, hhh, &p384_modp);
    p384_mod_sub(r.y, r.y, t, &p384_modp);
    p384_mod_mul(r.z, a->z, b->z, &p384_modp); // Z3 = Z1*Z2*h
    p384_mod_mul(r.z, r.z, h, &p384_modp);
    *o = r;
}

// o = k*p, plain left-to-right double-and-add; k and p are public.
static void point_mul(point *o, const uint32_t k[P384_LIMBS], const point *p) {
    point acc;
    memset(&acc, 0, sizeof acc); // infinity
    for (int i = SCALAR_BITS - 1; i >= 0; i--) {
        point_double(&acc, &acc);
        if ((k[(size_t)i / 32] >> ((size_t)i % 32)) & 1) {
            point_add(&acc, &acc, p);
        }
    }
    *o = acc;
}

// y^2 == x^3 - 3x + b mod p; inputs already below p.
static int on_curve(const uint32_t x[P384_LIMBS], const uint32_t y[P384_LIMBS]) {
    uint32_t lhs[P384_LIMBS];
    uint32_t rhs[P384_LIMBS];
    uint32_t t[P384_LIMBS];
    p384_mod_mul(lhs, y, y, &p384_modp);
    p384_mod_mul(t, x, x, &p384_modp);
    p384_mod_mul(rhs, t, x, &p384_modp);
    p384_mod_sub(rhs, rhs, x, &p384_modp);
    p384_mod_sub(rhs, rhs, x, &p384_modp);
    p384_mod_sub(rhs, rhs, x, &p384_modp);
    p384_mod_add(rhs, rhs, B, &p384_modp);
    return p384_compare(lhs, rhs) == 0;
}

// One strict-DER INTEGER carrying an ECDSA scalar: minimal length, no
// negatives, at most one leading zero and only when the next byte's high
// bit needs it. A scalar below n fits 48 bytes, so the content is at
// most 49 bytes: 48 plus the one leading zero. Writes the value
// big-endian into v[48].
static int der_scalar(rbuf *r, uint8_t v[P384_LEN]) {
    if (rb_u8(r) != 0x02) {
        return 0;
    }
    size_t len = rb_u8(r);
    if (r->err || len < 1 || len > P384_LEN + 1) {
        return 0;
    }
    const uint8_t *c = rb_bytes(r, len);
    if (c == NULL || (c[0] & 0x80)) {
        return 0; // short input, or a negative value
    }
    if (len > 1 && c[0] == 0 && !(c[1] & 0x80)) {
        return 0; // non-minimal leading zero
    }
    if (len == P384_LEN + 1 && c[0] != 0) {
        return 0; // 49 content bytes only ever pad a high bit
    }
    size_t skip = c[0] == 0 ? 1 : 0; // covers INTEGER 0 too: range check kills it
    memset(v, 0, P384_LEN);
    memcpy(v + (P384_LEN - (len - skip)), c + skip, len - skip);
    return 1;
}

// ECDSA-Sig-Value: SEQUENCE of exactly two INTEGERs filling sig_len.
// Each INTEGER is at most 2 + 49 bytes, so the SEQUENCE content is at
// most 2*(2+49) = 102 bytes, under 128: any long-form length is
// non-minimal and rejected by the < 0x80 check here (der_scalar's len
// cap covers the inner ones).
static int der_parse(const uint8_t *sig, size_t sig_len, uint8_t r_be[P384_LEN],
                     uint8_t s_be[P384_LEN]) {
    rbuf rb;
    rb_init(&rb, sig, sig_len);
    if (rb_u8(&rb) != 0x30) {
        return 0;
    }
    size_t len = rb_u8(&rb);
    if (rb.err || len >= 0x80 || len != rb_left(&rb)) {
        return 0;
    }
    if (!der_scalar(&rb, r_be) || !der_scalar(&rb, s_be)) {
        return 0;
    }
    return rb_left(&rb) == 0 && !rb.err;
}

int p384_ecdsa_verify(const uint8_t pub[P384_PUB_LEN], const uint8_t msg_hash[P384_LEN],
                      const uint8_t *sig_der, size_t sig_len) {
    uint8_t r_be[P384_LEN];
    uint8_t s_be[P384_LEN];
    if (!der_parse(sig_der, sig_len, r_be, s_be)) {
        return 0;
    }
    uint32_t r[P384_LIMBS];
    uint32_t s[P384_LIMBS];
    p384_from_bytes(r, r_be);
    p384_from_bytes(s, s_be);
    if (p384_is_zero(r) || p384_is_zero(s) || p384_compare(r, p384_modn.m) >= 0 ||
        p384_compare(s, p384_modn.m) >= 0) {
        return 0;
    }

    point q;
    p384_from_bytes(q.x, pub);
    p384_from_bytes(q.y, pub + P384_LEN);
    memset(q.z, 0, sizeof q.z);
    q.z[0] = 1;
    if (p384_compare(q.x, p384_modp.m) >= 0 || p384_compare(q.y, p384_modp.m) >= 0 ||
        !on_curve(q.x, q.y)) {
        return 0; // infinity has no X||Y encoding, so on-curve suffices
    }

    // e = the hash as a big-endian integer mod n; one subtract is enough
    // because n > 2^383, so 2n > 2^384.
    uint32_t e[P384_LIMBS];
    p384_from_bytes(e, msg_hash);
    if (p384_compare(e, p384_modn.m) >= 0) {
        (void)p384_sub_raw(e, e, p384_modn.m);
    }

    uint32_t w[P384_LIMBS];
    uint32_t u1[P384_LIMBS];
    uint32_t u2[P384_LIMBS];
    p384_mod_inverse(w, s, &p384_modn); // w = s^-1
    p384_mod_mul(u1, e, w, &p384_modn);
    p384_mod_mul(u2, r, w, &p384_modn);

    // R = u1*G + u2*Q; two plain scalar multiplies beat Shamir on clarity.
    point g;
    memcpy(g.x, GX, sizeof g.x);
    memcpy(g.y, GY, sizeof g.y);
    memset(g.z, 0, sizeof g.z);
    g.z[0] = 1;
    point p1;
    point p2;
    point_mul(&p1, u1, &g);
    point_mul(&p2, u2, &q);
    point_add(&p1, &p1, &p2);
    if (p384_is_zero(p1.z)) {
        return 0;
    }

    // v = (R.X / R.Z^2 mod p) mod n; p < 2n so one subtract reduces.
    uint32_t z_inv[P384_LIMBS];
    uint32_t x1[P384_LIMBS];
    p384_mod_inverse(z_inv, p1.z, &p384_modp);
    p384_mod_mul(z_inv, z_inv, z_inv, &p384_modp);
    p384_mod_mul(x1, p1.x, z_inv, &p384_modp);
    if (p384_compare(x1, p384_modn.m) >= 0) {
        (void)p384_sub_raw(x1, x1, p384_modn.m);
    }
    return p384_compare(x1, r) == 0;
}
