// A host object's ECDSA P-256 verifier against the portable one, which
// stays the reference (docs/decisions.md 96): the same key, hash and
// signature into both, the same verdict out.
//
// A host object checks a signature on the wide files' four 64-bit limbs
// (p256_wide_verify.c) and a device object on p256.c's eight 32-bit
// limbs. This binary holds both: p256_ecdsa_verify is the host arm, and
// p256_ecdsa_verify_portable is the device arm, which
// test/p256_verify_portable.c compiles under that name. The 32-bit arm
// carries the CBMC harness, the Lean differential and the vectors of
// bin/unit; this binary is what carries the 64-bit arm to the same
// verdict on every input it tries:
//
//   - signatures p256_sign.c writes, under both of its answers, each with
//     one bit changed in the hash, in the key and in the signature;
//   - signatures this file computes from a key and a nonce on
//     p256_scalar.c and p256_point.c, a third arithmetic that is neither
//     verifier's, so that the case decides the scalars: s of 1, 2 and 3,
//     and then s + n, which is the same number modulo n and no signature;
//     a hash at or above n; a hash of zero, where u1 is zero; u2 of one,
//     where R is the key itself; the case where u1*G equals u2*Q and the
//     last addition is a doubling; and the case where they are negatives
//     and R is the point at infinity;
//   - five cases over four keys whose multiples meet the sum inside the
//     host arm's pass over the digits, so that an addition there has two
//     equal operands or two negatives (test/p256_verify_equiv_joint.h);
//   - r and s at 0, n - 1, n and 2^256 - 1;
//   - a key with a coordinate at p or above it, a key off the curve and
//     a key of zeros;
//   - a signature whose DER is cut short, runs long, has another tag or
//     pads an INTEGER it need not.
//
// Each case names the verdict it wants where it knows one, so the two
// arms are not held only to each other.
//
// The random values come from the seeded generator below, so an ordinary
// run replays exactly and the nightly can vary CH_P256_VERIFY_EQUIV_SEED.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "p256.h"
#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_sign.h"
#include "widemul.h"

// The device arm of p256.c (test/p256_verify_portable.c).
int p256_ecdsa_verify_portable(const uint8_t pub[64], const uint8_t msg_hash[32],
                               const uint8_t *sig_der, size_t sig_len);

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// xorshift64, as test/x25519_equiv_test.c writes it and for its reasons:
// a fixed default seed, so a mismatch reproduces bit for bit, and an
// environment variable the nightly sets to vary it. Never time().
#define P256_VERIFY_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = P256_VERIFY_EQUIV_DEFAULT_SEED;

// Reads CH_P256_VERIFY_EQUIV_SEED, if set, as the seed, and returns the
// seed in use. A value that is not a number, or zero, keeps the default:
// xorshift64 is all zeroes forever from zero.
static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_P256_VERIFY_EQUIV_SEED");
    if (text != NULL) {
        char *end = NULL;
        unsigned long long value = strtoull(text, &end, 0);
        if (end != text && *end == 0 && value != 0) {
            rng_state = (uint64_t)value;
        }
    }
    return rng_state;
}

static uint64_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void rng_bytes(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(rng_next() >> 32);
    }
}

// SEC 2's group order n and field prime p, big-endian.
static const uint8_t ORDER[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
                                  0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
static const uint8_t PRIME[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static unsigned long comparisons = 0;
static int failures = 0;

// Runs both verifiers on one input. They must agree, and both must give
// the verdict the case wants.
static void both(const char *what, const uint8_t pub[64], const uint8_t hash[32],
                 const uint8_t *sig, size_t sig_len, int want) {
    int wide = p256_ecdsa_verify(pub, hash, sig, sig_len);
    int portable = p256_ecdsa_verify_portable(pub, hash, sig, sig_len);
    comparisons++;
    if (wide != want || portable != want) {
        failures++;
        (void)fprintf(stderr,
                      "p256_verify_equiv: %s: the wide verifier says %d and the 32-bit one %d, "
                      "and the case wants %d\n",
                      what, wide, portable, want);
    }
}

// One minimal DER INTEGER of the 32 big-endian bytes at v, written at out.
// Returns its length.
static size_t der_integer(uint8_t *out, const uint8_t v[32]) {
    size_t skip = 0;
    while (skip < 31 && v[skip] == 0) {
        skip++;
    }
    size_t pad = (v[skip] & 0x80) != 0 ? 1 : 0;
    size_t len = 32 - skip + pad;
    out[0] = 0x02;
    out[1] = (uint8_t)len;
    out[2] = 0;
    memcpy(out + 2 + pad, v + skip, 32 - skip);
    return 2 + len;
}

// The DER ECDSA-Sig-Value of (r, s). Returns its length, 72 at most.
static size_t der_signature(uint8_t out[P256_SIG_MAX], const uint8_t r[32], const uint8_t s[32]) {
    size_t n = der_integer(out + 2, r);
    n += der_integer(out + 2 + n, s);
    out[0] = 0x30;
    out[1] = (uint8_t)n;
    return 2 + n;
}

// Both verifiers on (r, s), each 32 big-endian bytes.
static void both_rs(const char *what, const uint8_t pub[64], const uint8_t hash[32],
                    const uint8_t r[32], const uint8_t s[32], int want) {
    uint8_t sig[P256_SIG_MAX];
    size_t sig_len = der_signature(sig, r, s);
    both(what, pub, hash, sig, sig_len, want);
}

// A scalar in 1..n-1.
static void scalar_random(p256_scalar *o) {
    uint8_t bytes[32];
    do {
        rng_bytes(bytes, sizeof bytes);
        p256_scalar_from_bytes(o, bytes);
        p256_scalar_reduce(o, o);
    } while (p256_scalar_zero_mask(o) != 0);
}

static void scalar_small(p256_scalar *o, uint8_t value) {
    uint8_t bytes[32] = {0};
    bytes[31] = value;
    p256_scalar_from_bytes(o, bytes);
}

// o = -a mod n: the product by n - 1.
static void scalar_negate(p256_scalar *o, const p256_scalar *a) {
    uint8_t bytes[32];
    p256_scalar minus_one;
    memcpy(bytes, ORDER, sizeof bytes);
    bytes[31] -= 1;
    p256_scalar_from_bytes(&minus_one, bytes);
    p256_scalar_mul(o, a, &minus_one);
}

// o = the affine X of k*G, reduced modulo n: the r of a signature whose
// nonce is k. xy takes the point's X||Y when it is not NULL.
static void base_point(p256_scalar *o, uint8_t xy[64], const p256_scalar *k) {
    p256_point point;
    uint8_t x[32];
    uint8_t y[32];
    p256_point_base_mul(&point, k);
    CH_ASSERT(p256_point_affine(x, y, &point) != 0);
    p256_scalar_from_bytes(o, x);
    p256_scalar_reduce(o, o);
    if (xy != NULL) {
        memcpy(xy, x, 32);
        memcpy(xy + 32, y, 32);
    }
}

// The signature of e under the key d with the nonce k: r is k*G's X, and
// s = (e + r*d) / k.
static void sign_with(p256_scalar *r, p256_scalar *s, const p256_scalar *d, const p256_scalar *k,
                      const p256_scalar *e) {
    p256_scalar k_inverse;
    base_point(r, NULL, k);
    p256_scalar_mul(s, r, d);
    p256_scalar_add(s, s, e);
    p256_scalar_inverse(&k_inverse, k);
    p256_scalar_mul(s, s, &k_inverse);
}

// One key and one nonce, and the bytes a case reads them as.
typedef struct {
    p256_scalar d;
    p256_scalar k;
    uint8_t pub[64];
} fixture;

static void fixture_random(fixture *f) {
    p256_scalar ignored;
    scalar_random(&f->d);
    scalar_random(&f->k);
    base_point(&ignored, f->pub, &f->d);
}

// Signatures p256_sign.c writes, under both of its answers, and each with
// one bit changed in the hash, in the key and in the signature.
static void signer_case(void) {
    fixture f;
    uint8_t priv[32];
    uint8_t hash[32];
    fixture_random(&f);
    p256_scalar_to_bytes(priv, &f.d);
    rng_bytes(hash, sizeof hash);
    static const uint8_t answers[2] = {WIDEMUL_NOT_STATED, WIDEMUL_CONSTANT_TIME};
    for (size_t i = 0; i < 2; i++) {
        uint8_t sig[P256_SIG_MAX];
        size_t sig_len = 0;
        CH_ASSERT(p256_sign(answers[i], priv, hash, sig, sizeof sig, &sig_len) == 1);
        both("a signature p256_sign wrote", f.pub, hash, sig, sig_len, 1);

        uint8_t changed[P256_SIG_MAX];
        size_t bit = (size_t)(rng_next() % 256);
        memcpy(changed, hash, 32);
        changed[bit / 8] ^= (uint8_t)(1U << (bit % 8));
        both("one bit of the hash changed", f.pub, changed, sig, sig_len, 0);

        uint8_t other_key[64];
        bit = (size_t)(rng_next() % 512);
        memcpy(other_key, f.pub, 64);
        other_key[bit / 8] ^= (uint8_t)(1U << (bit % 8));
        both("one bit of the key changed", other_key, hash, sig, sig_len, 0);

        bit = (size_t)(rng_next() % (8 * sig_len));
        memcpy(changed, sig, sig_len);
        changed[bit / 8] ^= (uint8_t)(1U << (bit % 8));
        both("one bit of the signature changed", f.pub, hash, changed, sig_len, 0);
    }
}

// s of 1, 2 and 3: the hash that makes each a signature is s*k - r*d.
// Then s + n, which fits 32 bytes for a small s, is the same number
// modulo n, and is outside 1..n-1.
static void small_s_case(const fixture *f) {
    for (uint8_t value = 1; value <= 3; value++) {
        p256_scalar r;
        p256_scalar s;
        p256_scalar e;
        p256_scalar product;
        uint8_t hash[32];
        uint8_t r_be[32];
        uint8_t s_be[32];
        scalar_small(&s, value);
        base_point(&r, NULL, &f->k);
        p256_scalar_mul(&e, &s, &f->k);
        p256_scalar_mul(&product, &r, &f->d);
        scalar_negate(&product, &product);
        p256_scalar_add(&e, &e, &product);
        p256_scalar_to_bytes(hash, &e);
        p256_scalar_to_bytes(r_be, &r);
        p256_scalar_to_bytes(s_be, &s);
        both_rs("a small s", f->pub, hash, r_be, s_be, 1);
        memcpy(s_be, ORDER, 32);
        s_be[31] = (uint8_t)(s_be[31] + value);
        both_rs("a small s with n added", f->pub, hash, r_be, s_be, 0);
    }
}

// A hash at or above n is reduced: n + t signs as t does, and so does a
// hash of all ones. A hash of zero and a hash of n both make u1 zero.
static void hash_case(const fixture *f) {
    static const uint8_t offsets[3] = {0, 1, 0x7f};
    for (size_t i = 0; i < 3; i++) {
        p256_scalar r;
        p256_scalar s;
        p256_scalar e;
        uint8_t hash[32];
        uint8_t r_be[32];
        uint8_t s_be[32];
        scalar_small(&e, offsets[i]);
        sign_with(&r, &s, &f->d, &f->k, &e);
        p256_scalar_to_bytes(r_be, &r);
        p256_scalar_to_bytes(s_be, &s);
        p256_scalar_to_bytes(hash, &e);
        both_rs("a small hash", f->pub, hash, r_be, s_be, 1);
        memcpy(hash, ORDER, 32);
        hash[31] = (uint8_t)(hash[31] + offsets[i]);
        both_rs("that hash with n added", f->pub, hash, r_be, s_be, 1);
    }
    p256_scalar r;
    p256_scalar s;
    p256_scalar e;
    uint8_t hash[32];
    uint8_t r_be[32];
    uint8_t s_be[32];
    memset(hash, 0xff, sizeof hash);
    p256_scalar_from_bytes(&e, hash);
    p256_scalar_reduce(&e, &e);
    sign_with(&r, &s, &f->d, &f->k, &e);
    p256_scalar_to_bytes(r_be, &r);
    p256_scalar_to_bytes(s_be, &s);
    both_rs("a hash of all ones", f->pub, hash, r_be, s_be, 1);
}

// Three cases the sum u1*G + u2*Q can be. With a hash of -r*d the two
// parts are negatives, R is the point at infinity, and no (r, s) is a
// signature. With a hash of d*r and s = 2*d*r/k the two parts are equal,
// the last addition is a doubling, and (r, s) is a signature. With a hash
// of zero and s = r, u1 is zero and u2 is one, so R is the key, and
// (r, s) is a signature when r is the key's X.
static void sum_case(const fixture *f) {
    p256_scalar r;
    p256_scalar s;
    p256_scalar e;
    uint8_t hash[32];
    uint8_t r_be[32];
    uint8_t s_be[32];

    scalar_random(&r);
    scalar_random(&s);
    p256_scalar_mul(&e, &r, &f->d);
    scalar_negate(&e, &e);
    p256_scalar_to_bytes(hash, &e);
    p256_scalar_to_bytes(r_be, &r);
    p256_scalar_to_bytes(s_be, &s);
    both_rs("R at infinity", f->pub, hash, r_be, s_be, 0);

    p256_scalar k_inverse;
    p256_scalar two;
    base_point(&r, NULL, &f->k);
    p256_scalar_mul(&e, &f->d, &r);
    scalar_small(&two, 2);
    p256_scalar_inverse(&k_inverse, &f->k);
    p256_scalar_mul(&s, &e, &two);
    p256_scalar_mul(&s, &s, &k_inverse);
    p256_scalar_to_bytes(hash, &e);
    p256_scalar_to_bytes(r_be, &r);
    p256_scalar_to_bytes(s_be, &s);
    both_rs("u1*G equal to u2*Q", f->pub, hash, r_be, s_be, 1);

    memset(hash, 0, sizeof hash);
    p256_scalar_from_bytes(&r, f->pub);
    p256_scalar_reduce(&r, &r);
    p256_scalar_to_bytes(r_be, &r);
    both_rs("R equal to the key", f->pub, hash, r_be, r_be, 1);
}

#include "p256_verify_equiv_joint.h"

// r and s at the ends of their range and past them, a key no curve point
// encodes, and a signature no DER reader takes, each beside one valid
// signature under the same key.
static void refusal_case(const fixture *f) {
    p256_scalar r;
    p256_scalar s;
    p256_scalar e;
    uint8_t hash[32];
    uint8_t r_be[32];
    uint8_t s_be[32];
    uint8_t edge[32];
    scalar_random(&e);
    sign_with(&r, &s, &f->d, &f->k, &e);
    p256_scalar_to_bytes(hash, &e);
    p256_scalar_to_bytes(r_be, &r);
    p256_scalar_to_bytes(s_be, &s);
    both_rs("a signature this file computed", f->pub, hash, r_be, s_be, 1);

    memset(edge, 0, sizeof edge);
    both_rs("r of zero", f->pub, hash, edge, s_be, 0);
    both_rs("s of zero", f->pub, hash, r_be, edge, 0);
    memcpy(edge, ORDER, sizeof edge);
    both_rs("r of n", f->pub, hash, edge, s_be, 0);
    both_rs("s of n", f->pub, hash, r_be, edge, 0);
    edge[31] -= 1;
    both_rs("r of n - 1", f->pub, hash, edge, s_be, 0);
    both_rs("s of n - 1", f->pub, hash, r_be, edge, 0);
    memset(edge, 0xff, sizeof edge);
    both_rs("r of all ones", f->pub, hash, edge, s_be, 0);
    both_rs("s of all ones", f->pub, hash, r_be, edge, 0);

    uint8_t key[64];
    memcpy(key, f->pub, sizeof key);
    memcpy(key, PRIME, 32);
    both_rs("a key whose X is p", key, hash, r_be, s_be, 0);
    memcpy(key, f->pub, sizeof key);
    memcpy(key + 32, PRIME, 32);
    both_rs("a key whose Y is p", key, hash, r_be, s_be, 0);
    memset(key, 0xff, 32);
    both_rs("a key whose X is all ones", key, hash, r_be, s_be, 0);
    memcpy(key, f->pub, sizeof key);
    key[63] ^= 1;
    both_rs("a key off the curve", key, hash, r_be, s_be, 0);
    memset(key, 0, sizeof key);
    both_rs("a key of zeros", key, hash, r_be, s_be, 0);

    uint8_t sig[P256_SIG_MAX + 2];
    size_t sig_len = der_signature(sig, r_be, s_be);
    both("a signature cut short", f->pub, hash, sig, sig_len - 1, 0);
    sig[sig_len] = 0;
    both("a signature with a byte after it", f->pub, hash, sig, sig_len + 1, 0);
    sig[0] = 0x31;
    both("a signature under another tag", f->pub, hash, sig, sig_len, 0);
    // r as an INTEGER with a zero byte it does not need, in a SEQUENCE
    // whose length counts it. A DER reader refuses the padding.
    if ((r_be[0] & 0x80) == 0 && r_be[0] != 0) {
        uint8_t padded[P256_SIG_MAX + 2];
        size_t s_len = der_integer(padded + 2 + 35, s_be);
        padded[0] = 0x30;
        padded[1] = (uint8_t)(35 + s_len);
        padded[2] = 0x02;
        padded[3] = 33;
        padded[4] = 0;
        memcpy(padded + 5, r_be, 32);
        both("r padded with a zero byte", f->pub, hash, padded, 2 + 35 + s_len, 0);
    }
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    for (int round = 0; round < 24; round++) {
        fixture f;
        signer_case();
        fixture_random(&f);
        small_s_case(&f);
        hash_case(&f);
        sum_case(&f);
        joint_case();
        refusal_case(&f);
    }
    if (failures != 0) {
        (void)fprintf(stderr, "p256_verify_equiv: %d failures (seed 0x%llx)\n", failures,
                      (unsigned long long)seed);
        return 1;
    }
    printf("p256_verify_equiv: %lu verdicts, the wide verifier == the 32-bit verifier (seed "
           "0x%llx)\n",
           comparisons, (unsigned long long)seed);
    return 0;
}
