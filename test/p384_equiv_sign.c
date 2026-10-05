// The keys and signatures bin/p384_equiv_test's cases are built from, and
// the arithmetic modulo n they take: all of it on 48 big-endian bytes,
// through p384_field.c and the 32-bit arm's points (test/p384_portable.c).
// That is the reference's arithmetic, so a case's signature is right when
// the reference is, and a case that knows its verdict states it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p384_equiv.h"
#include "p384_field.h"
#include "p384_portable.h"

// Two points test/gen_p384_constants.py prints, as X||Y. LARGE has the
// smallest x above n, which is n + 2, so its x modulo n is 2. SMALL has
// the smallest x there is, 0, so x + p still fits 48 bytes.
static const char *const LARGE_HEX = "ffffffffffffffffffffffffffffffffffffffffffffffff"
                                     "c7634d81f4372ddf581a0db248b0a77aecec196accc52975"
                                     "98b248e2aa2e6b74c382b3a9db8b52ec8b9a069fa4383983"
                                     "4605494060c35d0f782a95716dfa9755d908150fc118f5ba";
static const char *const SMALL_HEX = "000000000000000000000000000000000000000000000000"
                                     "000000000000000000000000000000000000000000000000"
                                     "3cf99ef04f51a5ea630ba3f9f960dd593a14c9be39fd2bd2"
                                     "15d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e521e";

const uint8_t ZERO[P384_LEN] = {0};
uint8_t ORDER[P384_LEN];
uint8_t PRIME[P384_LEN];
uint8_t GENERATOR[P384_PUB_LEN];
uint8_t LARGE[P384_PUB_LEN];
uint8_t SMALL[P384_PUB_LEN];

static uint8_t nibble(char c) {
    return (uint8_t)(c <= '9' ? c - '0' : c - 'a' + 10);
}

static void unhex(uint8_t *out, const char *hex, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
}

void sign_setup(void) {
    uint8_t one[P384_LEN];
    p384_portable_to_bytes(ORDER, p384_modn.m);
    p384_portable_to_bytes(PRIME, p384_modp.m);
    unhex(LARGE, LARGE_HEX, sizeof LARGE);
    unhex(SMALL, SMALL_HEX, sizeof SMALL);
    scalar_small(one, 1);
    key_of(GENERATOR, one);
}

// One minimal DER INTEGER of the 48 big-endian bytes at v, written at out.
// Returns its length.
size_t der_integer(uint8_t *out, const uint8_t v[P384_LEN]) {
    size_t skip = 0;
    while (skip < P384_LEN - 1 && v[skip] == 0) {
        skip++;
    }
    size_t pad = (v[skip] & 0x80) != 0 ? 1 : 0;
    size_t len = P384_LEN - skip + pad;
    out[0] = 0x02;
    out[1] = (uint8_t)len;
    out[2] = 0;
    memcpy(out + 2 + pad, v + skip, P384_LEN - skip);
    return 2 + len;
}

// The DER ECDSA-Sig-Value of (r, s). Returns its length, SIG_MAX at most.
size_t der_signature(uint8_t out[SIG_MAX], const uint8_t r[P384_LEN], const uint8_t s[P384_LEN]) {
    size_t n = der_integer(out + 2, r);
    n += der_integer(out + 2 + n, s);
    out[0] = 0x30;
    out[1] = (uint8_t)n;
    return 2 + n;
}

// A step of a case's own arithmetic that cannot fail unless the case is
// wrong.
void must(int ok, const char *what) {
    if (!ok) {
        (void)fprintf(stderr, "p384_equiv: %s\n", what);
        exit(2);
    }
}

// Arithmetic modulo n on 48 big-endian bytes, through the 32-bit field.
typedef void field_op(uint32_t *o, const uint32_t *a, const uint32_t *b, const p384_modulus *mod);

static void scalar_op(field_op *op, uint8_t o[P384_LEN], const uint8_t a[P384_LEN],
                      const uint8_t b[P384_LEN]) {
    uint32_t x[P384_LIMBS];
    uint32_t y[P384_LIMBS];
    p384_from_bytes(x, a);
    p384_from_bytes(y, b);
    op(x, x, y, &p384_modn);
    p384_portable_to_bytes(o, x);
}

void scalar_mul(uint8_t o[P384_LEN], const uint8_t a[P384_LEN], const uint8_t b[P384_LEN]) {
    scalar_op(p384_mod_mul, o, a, b);
}

void scalar_add(uint8_t o[P384_LEN], const uint8_t a[P384_LEN], const uint8_t b[P384_LEN]) {
    scalar_op(p384_mod_add, o, a, b);
}

void scalar_sub(uint8_t o[P384_LEN], const uint8_t a[P384_LEN], const uint8_t b[P384_LEN]) {
    scalar_op(p384_mod_sub, o, a, b);
}

void scalar_inverse(uint8_t o[P384_LEN], const uint8_t a[P384_LEN]) {
    uint32_t x[P384_LIMBS];
    p384_from_bytes(x, a);
    p384_mod_inverse(x, x, &p384_modn);
    p384_portable_to_bytes(o, x);
}

// v mod n for any 48 bytes: one subtraction, because 2n is above 2^384.
void scalar_reduce(uint8_t v[P384_LEN]) {
    uint32_t x[P384_LIMBS];
    p384_from_bytes(x, v);
    if (p384_compare(x, p384_modn.m) >= 0) {
        (void)p384_sub_raw(x, x, p384_modn.m);
    }
    p384_portable_to_bytes(v, x);
}

// A scalar in 1..n-1.
void scalar_random(uint8_t v[P384_LEN]) {
    do {
        p384_equiv_rng_bytes(v, P384_LEN);
        scalar_reduce(v);
    } while (memcmp(v, ZERO, P384_LEN) == 0);
}

void scalar_small(uint8_t v[P384_LEN], uint8_t value) {
    memset(v, 0, P384_LEN);
    v[P384_LEN - 1] = value;
}

// o = a + b as 384-bit numbers, the carry out dropped.
void plain_add(uint8_t o[P384_LEN], const uint8_t a[P384_LEN], const uint8_t b[P384_LEN]) {
    uint32_t x[P384_LIMBS];
    uint32_t y[P384_LIMBS];
    p384_from_bytes(x, a);
    p384_from_bytes(y, b);
    (void)p384_add_raw(x, x, y);
    p384_portable_to_bytes(o, x);
}

// o = a - b as 384-bit numbers, the borrow out dropped.
void plain_sub(uint8_t o[P384_LEN], const uint8_t a[P384_LEN], const uint8_t b[P384_LEN]) {
    uint32_t x[P384_LIMBS];
    uint32_t y[P384_LIMBS];
    p384_from_bytes(x, a);
    p384_from_bytes(y, b);
    (void)p384_sub_raw(x, x, y);
    p384_portable_to_bytes(o, x);
}

int in_range(const uint8_t v[P384_LEN]) {
    return memcmp(v, ZERO, P384_LEN) != 0 && memcmp(v, ORDER, P384_LEN) < 0;
}

void key_of(uint8_t pub[P384_PUB_LEN], const uint8_t d[P384_LEN]) {
    must(p384_portable_double_mul(pub, d, ZERO, NULL), "a private key gave no public key");
}

// The signature under key for which the verifier computes exactly
// u1*G + u2*key, with no private key: r is that point's x modulo n,
// s = r / u2 and the hash is u1 * s. u2 is not zero. Returns 0 when the
// point is the point at infinity, where there is no such signature.
int from_scalars(signed_hash *m, const uint8_t u1[P384_LEN], const uint8_t u2[P384_LEN],
                 const uint8_t key[P384_PUB_LEN]) {
    uint8_t point[P384_PUB_LEN];
    uint8_t u2_inverse[P384_LEN];
    if (!p384_portable_double_mul(point, u1, u2, key)) {
        return 0;
    }
    memcpy(m->pub, key, sizeof m->pub);
    memcpy(m->r, point, P384_LEN);
    scalar_reduce(m->r);
    scalar_inverse(u2_inverse, u2);
    scalar_mul(m->s, m->r, u2_inverse);
    scalar_mul(m->hash, u1, m->s);
    return 1;
}

// The signature of hash under the key d*G with the nonce k: r is k*G's x
// modulo n, and s = (e + r*d) / k for e = hash mod n.
void sign(signed_hash *m, const uint8_t d[P384_LEN], const uint8_t k[P384_LEN],
          const uint8_t hash[P384_LEN]) {
    uint8_t point[P384_PUB_LEN];
    uint8_t e[P384_LEN];
    uint8_t k_inverse[P384_LEN];
    key_of(m->pub, d);
    key_of(point, k);
    memcpy(m->hash, hash, P384_LEN);
    memcpy(e, hash, P384_LEN);
    scalar_reduce(e);
    memcpy(m->r, point, P384_LEN);
    scalar_reduce(m->r);
    scalar_mul(m->s, m->r, d);
    scalar_add(m->s, m->s, e);
    scalar_inverse(k_inverse, k);
    scalar_mul(m->s, m->s, k_inverse);
}

// A key and a signature for which the verifier's sum u1*G + u2*Q is the
// point at xy, and whose r is the caller's, in 1..n-1: s and the hash e
// are random, and Q = (s*R - e*G) / r. The verdict then turns on r alone.
void from_point(signed_hash *m, const uint8_t xy[P384_PUB_LEN], const uint8_t r[P384_LEN]) {
    uint8_t r_inverse[P384_LEN];
    uint8_t k1[P384_LEN];
    uint8_t k2[P384_LEN];
    memcpy(m->r, r, P384_LEN);
    scalar_random(m->s);
    scalar_random(m->hash);
    scalar_inverse(r_inverse, r);
    scalar_mul(k1, m->hash, r_inverse);
    scalar_sub(k1, ZERO, k1);
    scalar_mul(k2, m->s, r_inverse);
    must(p384_portable_double_mul(m->pub, k1, k2, xy), "a key for a chosen point is infinity");
}
