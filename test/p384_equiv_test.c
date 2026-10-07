// A host object's ECDSA P-384 verifier against the portable one, which
// stays the reference (docs/decisions.md 97): the same key, hash and
// signature into both, the same verdict out.
//
// A host object checks a signature on six 64-bit words
// (p384_wide_verify.c over p384_wide_field.c) and a device object on
// p384.c's twelve 32-bit words. This binary holds both: p384_ecdsa_verify
// is the host arm, and p384_ecdsa_verify_portable is the device arm, which
// test/p384_portable.c compiles under that name. The 32-bit arm carries
// the RFC 6979 vectors, the Wycheproof suite and the Lean differential;
// this binary is what carries the 64-bit arm to the same verdict on every
// input it tries. test/p384_equiv_field.c compares the two fields routine
// by routine first, and then this file compares verdicts:
//
//   - signatures of random keys and scalars, each with one bit changed in
//     the hash, in the key, in r and in s, and with s negated, which is a
//     signature too;
//   - signatures in which the verifier's two scalars are chosen: zero and
//     one, the values either side of a window of the signed digits, the
//     values just under n, and the ones whose top digits carry;
//   - keys of G, -G and their doubles, where u1*G is u2*Q, or its
//     negative, or either one but for a small multiple of G, so that an
//     addition inside the scalar multiplication meets its own operand;
//   - a hash at or above n, and s at 1, 2 and 3 and then s + n;
//   - a point whose x is above n, where r is x - n, and the three values
//     of r that are that near to a point's x and are not its x modulo n;
//   - r and s at 0, n and 2^384 - 1;
//   - a key with a coordinate at p or above it, the negative of the key,
//     a key of zeros, and a key off the curve beside the signature that
//     verifies if nothing checks the key;
//   - a signature whose DER is cut short, runs long, has another tag or
//     pads an INTEGER it need not.
//
// Each case names the verdict it wants, so the two arms are not held only
// to each other. Every key and signature is computed on the 32-bit arm's
// field and points, by test/p384_equiv_sign.c through test/p384_portable.c.
//
// The random values come from the seeded generator below, so an ordinary
// run replays exactly and the nightly can vary CH_P384_EQUIV_SEED.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p384.h"
#include "p384_equiv.h"
#include "p384_field.h"
#include "p384_portable.h"

// xorshift64, as test/x25519_equiv_test.c writes it and for its reasons:
// a fixed default seed, so a mismatch reproduces bit for bit, and an
// environment variable the nightly sets to vary it. Never time().
#define P384_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = P384_EQUIV_DEFAULT_SEED;

// Reads CH_P384_EQUIV_SEED, if set, as the seed, and returns the seed in
// use. A value that is not a number, or zero, keeps the default:
// xorshift64 is all zeroes forever from zero.
static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_P384_EQUIV_SEED");
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

void p384_equiv_rng_bytes(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(rng_next() >> 32);
    }
}

static unsigned long comparisons = 0;
static int failures = 0;

// Runs both verifiers on one input. They must agree, and both must give
// the verdict the case wants.
static void both(const char *what, const uint8_t pub[P384_PUB_LEN], const uint8_t hash[P384_LEN],
                 const uint8_t *sig, size_t sig_len, int want) {
    int wide = p384_ecdsa_verify(pub, hash, sig, sig_len);
    int portable = p384_ecdsa_verify_portable(pub, hash, sig, sig_len);
    comparisons++;
    if (wide != want || portable != want) {
        failures++;
        (void)fprintf(stderr,
                      "p384_equiv: %s: the 64-bit verifier says %d and the 32-bit one %d, and the "
                      "case wants %d\n",
                      what, wide, portable, want);
    }
}

static void both_signed(const char *what, const signed_hash *m, int want) {
    uint8_t sig[SIG_MAX];
    size_t sig_len = der_signature(sig, m->r, m->s);
    both(what, m->pub, m->hash, sig, sig_len, want);
}

static void flip_bit(uint8_t *bytes, size_t n) {
    uint64_t bit = rng_next() % (8 * n);
    bytes[bit / 8] ^= (uint8_t)(1U << (bit % 8));
}

// A random key and random scalars, and the ways one bit breaks them.
static void random_case(void) {
    uint8_t d[P384_LEN];
    uint8_t u1[P384_LEN];
    uint8_t u2[P384_LEN];
    uint8_t key[P384_PUB_LEN];
    signed_hash m;
    scalar_random(d);
    scalar_random(u1);
    scalar_random(u2);
    key_of(key, d);
    must(from_scalars(&m, u1, u2, key), "a random signature is infinity");
    both_signed("a signature", &m, 1);

    signed_hash changed = m;
    scalar_sub(changed.s, ZERO, m.s);
    both_signed("a signature with s negated", &changed, 1);
    changed = m;
    flip_bit(changed.hash, P384_LEN);
    both_signed("one bit of the hash changed", &changed, 0);
    changed = m;
    flip_bit(changed.pub, sizeof changed.pub);
    both_signed("one bit of the key changed", &changed, 0);
    changed = m;
    flip_bit(changed.r, P384_LEN);
    both_signed("one bit of r changed", &changed, 0);
    changed = m;
    flip_bit(changed.s, P384_LEN);
    both_signed("one bit of s changed", &changed, 0);
}

// The scalars either side of a signed digit's window, the ones just under
// n, and the ones whose top bits are all set, where the digits carry out
// of bit 383. value[i] is in 0..n-1.
#define CHOSEN 18
static void chosen_scalars(uint8_t value[CHOSEN][P384_LEN]) {
    static const uint8_t SMALL_VALUES[10] = {0, 1, 2, 3, 15, 16, 17, 31, 32, 33};
    for (int i = 0; i < 10; i++) {
        scalar_small(value[i], SMALL_VALUES[i]);
    }
    for (int i = 10; i < 15; i++) { // n - 1, n - 2, n - 15, n - 16, n - 17
        static const uint8_t BELOW[5] = {1, 2, 15, 16, 17};
        uint8_t small[P384_LEN];
        scalar_small(small, BELOW[i - 10]);
        scalar_sub(value[i], ZERO, small);
    }
    memset(value[15], 0, P384_LEN); // 2^383
    value[15][0] = 0x80;
    memset(value[16], 0, P384_LEN); // 31 * 2^379: the top five bits
    value[16][0] = 0xf8;
    memset(value[17], 0xff, P384_LEN); // 2^384 - 1 modulo n
    scalar_reduce(value[17]);
}

// Each chosen value as u1 beside a random u2, and as u2 beside a random
// u1. u2 is never zero.
static void scalar_cases(void) {
    uint8_t value[CHOSEN][P384_LEN];
    uint8_t d[P384_LEN];
    uint8_t other[P384_LEN];
    uint8_t key[P384_PUB_LEN];
    signed_hash m;
    chosen_scalars(value);
    scalar_random(d);
    key_of(key, d);
    for (int i = 0; i < CHOSEN; i++) {
        scalar_random(other);
        must(from_scalars(&m, value[i], other, key), "a chosen u1 gave infinity");
        both_signed("a chosen u1", &m, 1);
        if (i != 0) {
            must(from_scalars(&m, other, value[i], key), "a chosen u2 gave infinity");
            both_signed("a chosen u2", &m, 1);
        }
    }
}

// The key d*G, and scalars for which u1*G and u2*Q are one point, are
// negatives, or are either but for five times G.
static void relation_case(const uint8_t d[P384_LEN]) {
    uint8_t key[P384_PUB_LEN];
    uint8_t u2[P384_LEN];
    uint8_t u1[P384_LEN];
    uint8_t five[P384_LEN];
    signed_hash m;
    key_of(key, d);
    scalar_random(u2);
    scalar_small(five, 5);

    scalar_mul(u1, u2, d);
    must(from_scalars(&m, u1, u2, key), "equal parts gave infinity");
    both_signed("u1*G equal to u2*Q", &m, 1);
    scalar_add(u1, u1, five);
    must(from_scalars(&m, u1, u2, key), "nearly equal parts gave infinity");
    both_signed("u1*G five times G past u2*Q", &m, 1);

    scalar_mul(u1, u2, d);
    scalar_sub(u1, ZERO, u1);
    must(!from_scalars(&m, u1, u2, key), "opposite parts did not give infinity");
    // No signature has that sum, so take any r: s = r / u2 and the hash
    // u1 * s make the verifier compute it.
    uint8_t u2_inverse[P384_LEN];
    memcpy(m.pub, key, sizeof m.pub);
    scalar_random(m.r);
    scalar_inverse(u2_inverse, u2);
    scalar_mul(m.s, m.r, u2_inverse);
    scalar_mul(m.hash, u1, m.s);
    both_signed("u1*G the negative of u2*Q", &m, 0);
    scalar_add(u1, u1, five);
    must(from_scalars(&m, u1, u2, key), "nearly opposite parts gave infinity");
    both_signed("u1*G five times G past the negative of u2*Q", &m, 1);
}

static void relation_cases(void) {
    uint8_t d[P384_LEN];
    uint8_t small[P384_LEN];
    for (uint8_t value = 1; value <= 2; value++) {
        scalar_small(d, value); // Q is G, then 2G
        relation_case(d);
        scalar_small(small, value);
        scalar_sub(d, ZERO, small); // Q is -G, then -2G
        relation_case(d);
    }
    scalar_random(d);
    relation_case(d);
}

// Hashes at and around n, which the verifier reduces, and chosen s.
static void hash_and_s_cases(void) {
    uint8_t d[P384_LEN];
    uint8_t k[P384_LEN];
    uint8_t hash[6][P384_LEN];
    signed_hash m;
    memset(hash, 0, sizeof hash); // 0
    hash[1][P384_LEN - 1] = 1;    // 1
    scalar_small(hash[2], 1);     // n - 1
    plain_sub(hash[2], ORDER, hash[2]);
    memcpy(hash[3], ORDER, P384_LEN); // n
    scalar_small(hash[4], 1);         // n + 1
    plain_add(hash[4], ORDER, hash[4]);
    memset(hash[5], 0xff, P384_LEN); // 2^384 - 1
    for (int i = 0; i < 6; i++) {
        scalar_random(d);
        scalar_random(k);
        sign(&m, d, k, hash[i]);
        both_signed("a hash at the edge of n", &m, 1);
    }
    // s of 1, 2 and 3: with r from the nonce, the hash that makes s the
    // signature is e = s*k - r*d. Then s + n, which is the same number
    // modulo n and is no signature.
    for (uint8_t value = 1; value <= 3; value++) {
        uint8_t s[P384_LEN];
        uint8_t t[P384_LEN];
        scalar_random(d);
        scalar_random(k);
        sign(&m, d, k, ZERO);
        scalar_small(s, value);
        scalar_mul(m.hash, s, k);
        scalar_mul(t, m.r, d);
        scalar_sub(m.hash, m.hash, t);
        memcpy(m.s, s, P384_LEN);
        both_signed("a small s", &m, 1);
        plain_add(m.s, s, ORDER);
        both_signed("a small s plus n", &m, 0);
    }
}

// r and s outside 1..n-1, in a signature that verifies until then.
static void range_cases(void) {
    uint8_t d[P384_LEN];
    uint8_t k[P384_LEN];
    uint8_t hash[P384_LEN];
    uint8_t outside[3][P384_LEN];
    signed_hash m;
    scalar_random(d);
    scalar_random(k);
    p384_equiv_rng_bytes(hash, sizeof hash);
    sign(&m, d, k, hash);
    both_signed("a signature before its scalars leave the range", &m, 1);
    memset(outside[0], 0, P384_LEN);
    memcpy(outside[1], ORDER, P384_LEN);
    memset(outside[2], 0xff, P384_LEN);
    for (int i = 0; i < 3; i++) {
        signed_hash changed = m;
        memcpy(changed.r, outside[i], P384_LEN);
        both_signed("r outside 1..n-1", &changed, 0);
        changed = m;
        memcpy(changed.s, outside[i], P384_LEN);
        both_signed("s outside 1..n-1", &changed, 0);
    }
}

// x modulo n is r for x = r, and for x = r + n when that is below p. These
// are a point on each side of that rule.
static void x_cases(void) {
    uint8_t r[P384_LEN];
    uint8_t k[P384_LEN];
    uint8_t point[P384_PUB_LEN];
    signed_hash m;

    // x = n + 2, so r = 2 and the signature verifies through r + n.
    plain_sub(r, LARGE, ORDER);
    from_point(&m, LARGE, r);
    both_signed("a point whose x is above n", &m, 1);

    // x = 0 and r = p - n. r + n is p, which is no x: a verifier that
    // took r + n modulo p would find 0 and accept.
    plain_sub(r, PRIME, ORDER);
    from_point(&m, SMALL, r);
    both_signed("r + n equal to p, at a point whose x is 0", &m, 0);

    // A random point, with r its x modulo n, and then with r = x - n
    // modulo 2^384, which is x + 2^384 - n: r + n is x again, but only
    // after it wraps 384 bits.
    scalar_random(k);
    key_of(point, k);
    memcpy(r, point, P384_LEN);
    scalar_reduce(r);
    from_point(&m, point, r);
    both_signed("a random point and its x", &m, 1);
    plain_sub(r, point, ORDER);
    must(in_range(r), "x + 2^384 - n is outside 1..n-1");
    from_point(&m, point, r);
    both_signed("r + n equal to x after it wraps", &m, 0);
}

// m under the key (x, y) in place of its own.
static void with_key(const char *what, const signed_hash *m, const uint8_t x[P384_LEN],
                     const uint8_t y[P384_LEN], int want) {
    signed_hash changed = *m;
    memcpy(changed.pub, x, P384_LEN);
    memcpy(changed.pub + P384_LEN, y, P384_LEN);
    both_signed(what, &changed, want);
}

// Keys a verifier must refuse, each beside a signature that verifies
// under the key it stands in for: the point whose x is 0.
static void key_cases(void) {
    uint8_t u1[P384_LEN];
    uint8_t u2[P384_LEN];
    uint8_t negated[P384_LEN];
    uint8_t ones[P384_LEN];
    signed_hash m;
    scalar_random(u1);
    scalar_random(u2);
    must(from_scalars(&m, u1, u2, SMALL), "a signature under the point at x = 0 is infinity");
    const uint8_t *x = m.pub;
    const uint8_t *y = m.pub + P384_LEN;
    both_signed("the key whose x is 0", &m, 1);
    // x = 0 + p is the same point, and no encoding of it.
    with_key("a key whose x is p", &m, PRIME, y, 0);
    plain_sub(negated, PRIME, y); // (x, p - y) is -Q
    with_key("the negative of the key", &m, x, negated, 0);
    with_key("a key whose y is p", &m, x, PRIME, 0);
    memset(ones, 0xff, sizeof ones);
    with_key("a key whose x is 2^384 - 1", &m, ones, y, 0);
    with_key("a key of zeros", &m, ZERO, ZERO, 0);

    // A key off the curve, under the one signature that would verify if
    // nothing checked the key. The point formulas never read b, so u2
    // times that key is a point of whichever curve the key lies on, and
    // with a hash of zero, where u1 is zero, it is the whole sum.
    uint8_t off[P384_PUB_LEN];
    signed_hash under_off;
    memcpy(off, m.pub, sizeof off);
    off[sizeof off - 1] ^= 1;
    must(from_scalars(&under_off, ZERO, u2, off), "a multiple of a key off the curve is infinity");
    both_signed("a key off the curve, and the signature its multiple makes", &under_off, 0);
}

// Signatures the DER reader refuses before either arm sees r and s.
static void der_cases(void) {
    uint8_t u1[P384_LEN];
    uint8_t u2[P384_LEN];
    uint8_t sig[SIG_MAX + 2];
    signed_hash m;
    scalar_random(u1);
    scalar_random(u2);
    must(from_scalars(&m, u1, u2, GENERATOR), "a signature under G is infinity");
    size_t sig_len = der_signature(sig, m.r, m.s);
    both("a signature under the key G", m.pub, m.hash, sig, sig_len, 1);
    both("a signature cut one byte short", m.pub, m.hash, sig, sig_len - 1, 0);
    sig[sig_len] = 0;
    both("a signature with a byte after it", m.pub, m.hash, sig, sig_len + 1, 0);
    sig[0] = 0x31;
    both("a signature under another tag", m.pub, m.hash, sig, sig_len, 0);
    // r as an INTEGER with a zero byte it does not need, in a SEQUENCE
    // whose length counts it. A DER reader refuses the padding.
    m.r[0] &= 0x7f;
    m.r[0] |= 0x01;
    size_t s_len = der_integer(sig + 2 + 3 + P384_LEN, m.s);
    sig[0] = 0x30;
    sig[1] = (uint8_t)(3 + P384_LEN + s_len);
    sig[2] = 0x02;
    sig[3] = P384_LEN + 1;
    sig[4] = 0;
    memcpy(sig + 5, m.r, P384_LEN);
    both("r padded with a zero byte", m.pub, m.hash, sig, 2 + 3 + P384_LEN + s_len, 0);
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    sign_setup();

    unsigned long field_comparisons = p384_equiv_field(&failures);
    for (int round = 0; round < 16; round++) {
        random_case();
    }
    scalar_cases();
    relation_cases();
    hash_and_s_cases();
    range_cases();
    x_cases();
    key_cases();
    der_cases();
    if (failures != 0) {
        (void)fprintf(stderr, "p384_equiv: %d failures (seed 0x%llx)\n", failures,
                      (unsigned long long)seed);
        return 1;
    }
    printf("p384_equiv: %lu field results and %lu verdicts, the 64-bit words == the 32-bit words "
           "(seed 0x%llx)\n",
           field_comparisons, comparisons, (unsigned long long)seed);
    return 0;
}
