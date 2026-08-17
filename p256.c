// NIST P-256 ECDSA verification. Variable time on purpose — every input
// is public (see p256.h). Field elements and scalars are 8 little-endian
// uint32 limbs; products and carries live in uint64. Multiplication
// reduces word-by-word Montgomery-style (CIOS), with one constant set
// per modulus so the field prime p and the group order n share every
// routine; inverses are Fermat powers. Points are Jacobian (Z == 0 is
// infinity). Clarity over speed: this runs once per connection.
#include "p256.h"

#include <string.h>

#include "buf.h"

#define LIMBS 8 // limb: one 32-bit word of a big number; P-256 = 8 limbs

typedef struct {
    uint32_t m[LIMBS];  // the modulus
    uint32_t r2[LIMBS]; // 2^512 mod m, entry ticket to the Montgomery domain
    uint32_t m0inv;     // -m^-1 mod 2^32
} modulus;

// SEC 2 curve constants; r2/m0inv derived from them (2^512 mod m and
// -m^-1 mod 2^32).
static const modulus MODP = {
    {0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
     0xffffffff},
    {0x00000003, 0x00000000, 0xffffffff, 0xfffffffb, 0xfffffffe, 0xffffffff, 0xfffffffd,
     0x00000004},
    1,
};

static const modulus MODN = {
    {0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000,
     0xffffffff},
    {0xbe79eea2, 0x83244c95, 0x49bd6fa6, 0x4699799c, 0x2b6bec59, 0x2845b239, 0xf3d95620,
     0x66e12d94},
    0xee00bc4f,
};

static const uint32_t B[LIMBS] = {0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0,
                                  0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8};

static const uint32_t GX[LIMBS] = {0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
                                   0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2};

static const uint32_t GY[LIMBS] = {0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
                                   0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2};

static int fe_is_zero(const uint32_t a[LIMBS]) {
    uint32_t v = 0;
    for (int i = 0; i < LIMBS; i++) {
        v |= a[i];
    }
    return v == 0;
}

static int fe_cmp(const uint32_t a[LIMBS], const uint32_t b[LIMBS]) {
    for (int i = LIMBS - 1; i >= 0; i--) {
        if (a[i] != b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

// 32 big-endian bytes -> 8 little-endian limbs, byte by byte.
static void fe_from_bytes(uint32_t o[LIMBS], const uint8_t b[32]) {
    for (int i = 0; i < LIMBS; i++) {
        o[i] = (uint32_t)b[31 - 4 * i] | ((uint32_t)b[30 - 4 * i] << 8) |
               ((uint32_t)b[29 - 4 * i] << 16) | ((uint32_t)b[28 - 4 * i] << 24);
    }
}

static uint32_t fe_add_raw(uint32_t o[LIMBS], const uint32_t a[LIMBS], const uint32_t b[LIMBS]) {
    uint64_t c = 0;
    for (int i = 0; i < LIMBS; i++) {
        c += (uint64_t)a[i] + b[i];
        o[i] = (uint32_t)c;
        c >>= 32;
    }
    return (uint32_t)c;
}

static uint32_t fe_sub_raw(uint32_t o[LIMBS], const uint32_t a[LIMBS], const uint32_t b[LIMBS]) {
    uint64_t borrow = 0;
    for (int i = 0; i < LIMBS; i++) {
        uint64_t v = (uint64_t)a[i] - b[i] - borrow;
        o[i] = (uint32_t)v;
        borrow = (v >> 32) & 1;
    }
    return (uint32_t)borrow;
}

// Inputs below m; one conditional subtract covers the sum (< 2m).
static void mod_add(uint32_t o[LIMBS], const uint32_t a[LIMBS], const uint32_t b[LIMBS],
                    const modulus *mod) {
    uint32_t c = fe_add_raw(o, a, b);
    if (c || fe_cmp(o, mod->m) >= 0) {
        (void)fe_sub_raw(o, o, mod->m);
    }
}

static void mod_sub(uint32_t o[LIMBS], const uint32_t a[LIMBS], const uint32_t b[LIMBS],
                    const modulus *mod) {
    if (fe_sub_raw(o, a, b)) {
        (void)fe_add_raw(o, o, mod->m);
    }
}

// Montgomery product o = a*b / 2^256 mod m (CIOS, Koç et al.). Inputs
// below m, result below m; o may alias a or b. Each round adds one limb
// of a into t, then folds a multiple of m in to zero t's low limb and
// shifts down one limb.
static void mont_mul(uint32_t o[LIMBS], const uint32_t a[LIMBS], const uint32_t b[LIMBS],
                     const modulus *mod) {
    uint32_t t[LIMBS + 2] = {0};
    for (int i = 0; i < LIMBS; i++) {
        uint64_t c = 0;
        for (int j = 0; j < LIMBS; j++) {
            uint64_t v = (uint64_t)a[i] * b[j] + t[j] + c;
            t[j] = (uint32_t)v;
            c = v >> 32;
        }
        uint64_t v = (uint64_t)t[LIMBS] + c;
        t[LIMBS] = (uint32_t)v;
        t[LIMBS + 1] = (uint32_t)(v >> 32);

        uint32_t u = t[0] * mod->m0inv;
        c = ((uint64_t)u * mod->m[0] + t[0]) >> 32;
        for (int j = 1; j < LIMBS; j++) {
            v = (uint64_t)u * mod->m[j] + t[j] + c;
            t[j - 1] = (uint32_t)v;
            c = v >> 32;
        }
        v = (uint64_t)t[LIMBS] + c;
        t[LIMBS - 1] = (uint32_t)v;
        t[LIMBS] = t[LIMBS + 1] + (uint32_t)(v >> 32);
        t[LIMBS + 1] = 0;
    }
    // t < 2m with at most one bit in t[LIMBS]; the subtraction's borrow
    // cancels that bit exactly, so the low limbs are the answer.
    if (t[LIMBS] || fe_cmp(t, mod->m) >= 0) {
        (void)fe_sub_raw(o, t, mod->m);
    } else {
        memcpy(o, t, LIMBS * sizeof(uint32_t));
    }
}

// Plain product mod m: into the Montgomery domain and back in one extra
// multiply (a*b/R, then *R^2/R).
static void mod_mul(uint32_t o[LIMBS], const uint32_t a[LIMBS], const uint32_t b[LIMBS],
                    const modulus *mod) {
    uint32_t t[LIMBS];
    mont_mul(t, a, b, mod);
    mont_mul(o, t, mod->r2, mod);
}

// o = a^(m-2) mod m: Fermat inverse, square-and-multiply in the
// Montgomery domain. The exponent is a public constant, so the
// bit-dependent multiply leaks nothing.
static void mod_inv(uint32_t o[LIMBS], const uint32_t a[LIMBS], const modulus *mod) {
    static const uint32_t one[LIMBS] = {1};
    uint32_t e[LIMBS];
    uint32_t a_mont[LIMBS];
    uint32_t acc[LIMBS];
    memcpy(e, mod->m, sizeof e);
    e[0] -= 2;                         // both moduli end well above 2: no borrow
    mont_mul(a_mont, a, mod->r2, mod); // a*R
    mont_mul(acc, one, mod->r2, mod);  // 1*R
    for (int i = 255; i >= 0; i--) {
        mont_mul(acc, acc, acc, mod);
        if ((e[i / 32] >> (i % 32)) & 1) {
            mont_mul(acc, acc, a_mont, mod);
        }
    }
    mont_mul(o, acc, one, mod); // strip the R factor
}

typedef struct {
    uint32_t x[LIMBS];
    uint32_t y[LIMBS];
    uint32_t z[LIMBS]; // Jacobian: affine (x/z^2, y/z^3); z == 0 is infinity
} point;

// Doubling, a = -3 (EFD dbl-2001-b). Maps infinity to infinity: z == 0
// forces z3 == 0.
static void point_double(point *o, const point *a) {
    uint32_t delta[LIMBS];
    uint32_t gamma[LIMBS];
    uint32_t beta[LIMBS];
    uint32_t alpha[LIMBS];
    uint32_t t[LIMBS];
    uint32_t t2[LIMBS];
    point r;
    mod_mul(delta, a->z, a->z, &MODP); // delta = Z^2
    mod_mul(gamma, a->y, a->y, &MODP); // gamma = Y^2
    mod_mul(beta, a->x, gamma, &MODP); // beta = X*gamma
    mod_sub(t, a->x, delta, &MODP);
    mod_add(t2, a->x, delta, &MODP);
    mod_mul(alpha, t, t2, &MODP); // alpha = 3*(X-delta)*(X+delta)
    mod_add(t, alpha, alpha, &MODP);
    mod_add(alpha, t, alpha, &MODP);
    mod_mul(r.x, alpha, alpha, &MODP); // X3 = alpha^2 - 8*beta
    mod_add(t, beta, beta, &MODP);
    mod_add(t, t, t, &MODP); // t = 4*beta
    mod_add(t2, t, t, &MODP);
    mod_sub(r.x, r.x, t2, &MODP);
    mod_add(r.z, a->y, a->z, &MODP); // Z3 = (Y+Z)^2 - gamma - delta
    mod_mul(r.z, r.z, r.z, &MODP);
    mod_sub(r.z, r.z, gamma, &MODP);
    mod_sub(r.z, r.z, delta, &MODP);
    mod_sub(t, t, r.x, &MODP); // Y3 = alpha*(4*beta - X3) - 8*gamma^2
    mod_mul(r.y, alpha, t, &MODP);
    mod_mul(t, gamma, gamma, &MODP);
    mod_add(t, t, t, &MODP);
    mod_add(t, t, t, &MODP);
    mod_add(t, t, t, &MODP);
    mod_sub(r.y, r.y, t, &MODP);
    *o = r;
}

// General Jacobian addition (EFD add-2007-bl shape) with the exceptional
// cases spelled out: either operand at infinity, P == Q (double), and
// P == -Q (infinity). o may alias a.
static void point_add(point *o, const point *a, const point *b) {
    if (fe_is_zero(a->z)) {
        *o = *b;
        return;
    }
    if (fe_is_zero(b->z)) {
        *o = *a;
        return;
    }
    uint32_t z1z1[LIMBS];
    uint32_t z2z2[LIMBS];
    uint32_t u1[LIMBS];
    uint32_t u2[LIMBS];
    uint32_t s1[LIMBS];
    uint32_t s2[LIMBS];
    uint32_t h[LIMBS];
    uint32_t rr[LIMBS];
    mod_mul(z1z1, a->z, a->z, &MODP);
    mod_mul(z2z2, b->z, b->z, &MODP);
    mod_mul(u1, a->x, z2z2, &MODP);
    mod_mul(u2, b->x, z1z1, &MODP);
    mod_mul(s1, a->y, b->z, &MODP);
    mod_mul(s1, s1, z2z2, &MODP);
    mod_mul(s2, b->y, a->z, &MODP);
    mod_mul(s2, s2, z1z1, &MODP);
    mod_sub(h, u2, u1, &MODP);
    mod_sub(rr, s2, s1, &MODP);
    if (fe_is_zero(h)) {
        if (fe_is_zero(rr)) {
            point_double(o, a);
        } else {
            memset(o, 0, sizeof *o);
        }
        return;
    }
    uint32_t hh[LIMBS];
    uint32_t hhh[LIMBS];
    uint32_t v[LIMBS];
    uint32_t t[LIMBS];
    point r;
    mod_mul(hh, h, h, &MODP);
    mod_mul(hhh, hh, h, &MODP);
    mod_mul(v, u1, hh, &MODP);
    mod_mul(r.x, rr, rr, &MODP); // X3 = r^2 - h^3 - 2*u1*h^2
    mod_sub(r.x, r.x, hhh, &MODP);
    mod_sub(r.x, r.x, v, &MODP);
    mod_sub(r.x, r.x, v, &MODP);
    mod_sub(t, v, r.x, &MODP); // Y3 = r*(u1*h^2 - X3) - s1*h^3
    mod_mul(r.y, rr, t, &MODP);
    mod_mul(t, s1, hhh, &MODP);
    mod_sub(r.y, r.y, t, &MODP);
    mod_mul(r.z, a->z, b->z, &MODP); // Z3 = Z1*Z2*h
    mod_mul(r.z, r.z, h, &MODP);
    *o = r;
}

// o = k*p, plain left-to-right double-and-add; k and p are public.
static void point_mul(point *o, const uint32_t k[LIMBS], const point *p) {
    point acc;
    memset(&acc, 0, sizeof acc); // infinity
    for (int i = 255; i >= 0; i--) {
        point_double(&acc, &acc);
        if ((k[(size_t)i / 32] >> ((size_t)i % 32)) & 1) {
            point_add(&acc, &acc, p);
        }
    }
    *o = acc;
}

// y^2 == x^3 - 3x + b mod p; inputs already below p.
static int on_curve(const uint32_t x[LIMBS], const uint32_t y[LIMBS]) {
    uint32_t lhs[LIMBS];
    uint32_t rhs[LIMBS];
    uint32_t t[LIMBS];
    mod_mul(lhs, y, y, &MODP);
    mod_mul(t, x, x, &MODP);
    mod_mul(rhs, t, x, &MODP);
    mod_sub(rhs, rhs, x, &MODP);
    mod_sub(rhs, rhs, x, &MODP);
    mod_sub(rhs, rhs, x, &MODP);
    mod_add(rhs, rhs, B, &MODP);
    return fe_cmp(lhs, rhs) == 0;
}

// One strict-DER INTEGER carrying an ECDSA scalar: minimal length, no
// negatives, at most one leading zero and only when the next byte's high
// bit needs it. Writes the value big-endian into v[32].
static int der_scalar(rbuf *r, uint8_t v[32]) {
    if (rb_u8(r) != 0x02) {
        return 0;
    }
    size_t len = rb_u8(r);
    if (r->err || len < 1 || len > 33) {
        return 0;
    }
    const uint8_t *c = rb_bytes(r, len);
    if (c == NULL || (c[0] & 0x80)) {
        return 0; // short input, or a negative value
    }
    if (len > 1 && c[0] == 0 && !(c[1] & 0x80)) {
        return 0; // non-minimal leading zero
    }
    if (len == 33 && c[0] != 0) {
        return 0; // 33 content bytes only ever pad a high bit
    }
    size_t skip = c[0] == 0 ? 1 : 0; // covers INTEGER 0 too: range check kills it
    memset(v, 0, 32);
    memcpy(v + (32 - (len - skip)), c + skip, len - skip);
    return 1;
}

// ECDSA-Sig-Value: SEQUENCE of exactly two INTEGERs filling sig_len.
// Everything here is under 128 bytes, so any long-form length is
// non-minimal and rejected by the < 0x80 checks (der_scalar's len cap
// covers the inner ones).
static int der_parse(const uint8_t *sig, size_t sig_len, uint8_t r_be[32], uint8_t s_be[32]) {
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

int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    uint8_t r_be[32];
    uint8_t s_be[32];
    if (!der_parse(sig_der, sig_len, r_be, s_be)) {
        return 0;
    }
    uint32_t r[LIMBS];
    uint32_t s[LIMBS];
    fe_from_bytes(r, r_be);
    fe_from_bytes(s, s_be);
    if (fe_is_zero(r) || fe_is_zero(s) || fe_cmp(r, MODN.m) >= 0 || fe_cmp(s, MODN.m) >= 0) {
        return 0;
    }

    point q;
    fe_from_bytes(q.x, pub);
    fe_from_bytes(q.y, pub + 32);
    memset(q.z, 0, sizeof q.z);
    q.z[0] = 1;
    if (fe_cmp(q.x, MODP.m) >= 0 || fe_cmp(q.y, MODP.m) >= 0 || !on_curve(q.x, q.y)) {
        return 0; // infinity has no X||Y encoding, so on-curve suffices
    }

    // e = the hash as a big-endian integer mod n; one subtract is enough
    // because 2n > 2^256.
    uint32_t e[LIMBS];
    fe_from_bytes(e, msg_hash);
    if (fe_cmp(e, MODN.m) >= 0) {
        (void)fe_sub_raw(e, e, MODN.m);
    }

    uint32_t w[LIMBS];
    uint32_t u1[LIMBS];
    uint32_t u2[LIMBS];
    mod_inv(w, s, &MODN); // w = s^-1
    mod_mul(u1, e, w, &MODN);
    mod_mul(u2, r, w, &MODN);

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
    if (fe_is_zero(p1.z)) {
        return 0;
    }

    // v = (R.X / R.Z^2 mod p) mod n; p < 2n so one subtract reduces.
    uint32_t z_inv[LIMBS];
    uint32_t x1[LIMBS];
    mod_inv(z_inv, p1.z, &MODP);
    mod_mul(z_inv, z_inv, z_inv, &MODP);
    mod_mul(x1, p1.x, z_inv, &MODP);
    if (fe_cmp(x1, MODN.m) >= 0) {
        (void)fe_sub_raw(x1, x1, MODN.m);
    }
    return fe_cmp(x1, r) == 0;
}
