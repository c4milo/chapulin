// Ed25519 signing on the wide field (ed25519_sign.h states the contract),
// included by x25519_wide.c alone, after x25519_wide_ed25519.h, whose
// group order, word loads and verifier it reuses, and after
// x25519_wide_edwards.h, whose table scan and point additions it reuses.
//
// The scalars r and a are secret. So the arithmetic modulo L here is not
// the verifier's, which branches on its public values: each step below
// subtracts L always and keeps one of the two results by mask.
#ifndef CH_X25519_WIDE_ED25519_SIGN_H
#define CH_X25519_WIDE_ED25519_SIGN_H

#ifdef CH_JWS

#include "ed25519_sign.h"
#include "sha512.h"

// All ones for a bit of 1 and zero for a bit of 0. The bit goes through a
// volatile object before the mask is built, so no compiler can turn a
// select under the mask into a jump on the bit (docs/decisions.md 125).
static uint64_t bit_mask(uint64_t bit) {
    volatile uint64_t held = bit;
    uint64_t read = held;
    return (uint64_t)((int64_t)(read << 63) >> 63);
}

// o = o less L when o is at or above L, and o as it is when it is below,
// for an o below 2 L. The subtraction runs always, and its last borrow,
// which is 1 exactly when o is below L, picks the result by mask.
static void scalar_settle(uint64_t o[4]) {
    uint64_t less[4];
    uint64_t borrow = 0;
    for (size_t i = 0; i < 4; i++) {
        ct_u128 difference = (ct_u128)o[i] - ED25519_L[i] - borrow;
        less[i] = (uint64_t)difference;
        borrow = (uint64_t)(difference >> 64) & 1;
    }
    uint64_t keep = bit_mask(borrow);
    for (size_t i = 0; i < 4; i++) {
        o[i] = (o[i] & keep) | (less[i] & ~keep);
    }
    ct_wipe(less, sizeof less);
}

// o = 2 o + bit modulo L, for an o below L and a bit of 0 or 1. The
// doubled value is below 2 L, which is below 2^254, so no word wraps.
static void scalar_double(uint64_t o[4], uint64_t bit) {
    o[3] = (o[3] << 1) | (o[2] >> 63);
    o[2] = (o[2] << 1) | (o[1] >> 63);
    o[1] = (o[1] << 1) | (o[0] >> 63);
    o[0] = (o[0] << 1) | bit;
    scalar_settle(o);
}

// o = o + a modulo L, for o and a below L. The sum is below 2 L.
static void scalar_add(uint64_t o[4], const uint64_t a[4]) {
    uint64_t carry = 0;
    for (size_t i = 0; i < 4; i++) {
        ct_u128 sum = (ct_u128)o[i] + a[i] + carry;
        o[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    scalar_settle(o);
}

// o = the 512-bit little-endian h modulo L, a bit at a time from the top:
// reduce_mod_l's division, with scalar_double's step in place of the
// verifier's.
static void scalar_reduce(uint64_t o[4], const uint8_t h[64]) {
    o[0] = o[1] = o[2] = o[3] = 0;
    for (size_t bit = 512; bit-- > 0;) {
        scalar_double(o, (uint64_t)((h[bit >> 3] >> (bit & 7)) & 1));
    }
}

// o = r + k a modulo L, for r and k below L and a, 32 little-endian bytes,
// of any value: S of RFC 8032 section 5.1.6, step 5. It reads a's bits
// from the top. Each step doubles the sum and adds k under the bit's
// mask, so the sum is k times the bits read so far, below L after every
// step.
static void scalar_muladd(uint64_t o[4], const uint64_t r[4], const uint64_t k[4],
                          const uint8_t a[X25519_LEN]) {
    uint64_t sum[4] = {0, 0, 0, 0};
    uint64_t term[4];
    for (size_t bit = 8 * X25519_LEN; bit-- > 0;) {
        uint64_t mask = bit_mask((uint64_t)((a[bit >> 3] >> (bit & 7)) & 1));
        scalar_double(sum, 0);
        for (size_t i = 0; i < 4; i++) {
            term[i] = k[i] & mask;
        }
        scalar_add(sum, term);
    }
    scalar_add(sum, r);
    for (size_t i = 0; i < 4; i++) {
        o[i] = sum[i];
    }
    ct_wipe(sum, sizeof sum);
    ct_wipe(term, sizeof term);
}

// sum = scalar times the base point B, for a scalar below 2^255, whose
// top nibble recode() takes. These are x25519_wide_base_mul's loops. That
// function ends in to_u and gives the Montgomery u alone; this one keeps
// the point, whose x a signature's encoding needs.
static void base_point(edwards_point *sum, const uint8_t scalar[X25519_LEN]) {
    int64_t e[DIGITS];
    edwards_sum partial;
    edwards_entry entry;
    recode(e, scalar);

    // The identity: x = 0 and y = 1.
    for (size_t w = 0; w < 5; w++) {
        sum->x[w] = 0;
        sum->y[w] = 0;
        sum->z[w] = 0;
        sum->t[w] = 0;
    }
    sum->y[0] = 1;
    sum->z[0] = 1;

    for (size_t row = 0; row < X25519_WIDE_TABLE_ROWS; row++) {
        add_digit(sum, &entry, &partial, row, e[2 * row + 1]);
    }
    for (size_t i = 0; i < 4; i++) {
        double_point(&partial, sum);
        to_extended(sum, &partial);
    }
    for (size_t row = 0; row < X25519_WIDE_TABLE_ROWS; row++) {
        add_digit(sum, &entry, &partial, row, e[2 * row]);
    }
    ct_wipe(e, sizeof e);
    ct_wipe(&partial, sizeof partial);
    ct_wipe(&entry, sizeof entry);
}

// out = the encoding of p (RFC 8032 section 5.1.2): y = Y / Z in 255
// bits, and the low bit of x = X / Z in bit 255. Two carry passes take Z's
// words under 2^51, the form invert() takes, as to_u does. Z is not zero:
// every point of the curve has one.
static void encode_point(uint8_t out[X25519_LEN], const edwards_point *p) {
    fe z_inverse;
    fe x;
    fe y;
    uint8_t x_bytes[X25519_LEN];
    for (size_t w = 0; w < 5; w++) {
        z_inverse[w] = p->z[w];
    }
    carry_words(z_inverse);
    carry_words(z_inverse);
    invert(z_inverse, z_inverse);
    mul(x, p->x, z_inverse);
    mul(y, p->y, z_inverse);
    pack(out, y);
    pack(x_bytes, x);
    out[X25519_LEN - 1] |= (uint8_t)((x_bytes[0] & 1) << 7);
    ct_wipe(z_inverse, sizeof z_inverse);
    ct_wipe(x, sizeof x);
    ct_wipe(y, sizeof y);
    ct_wipe(x_bytes, sizeof x_bytes);
}

// SHA-512 of up to three parts, in order. An empty part adds no bytes.
static void hash_parts(uint8_t out[SHA512_LEN], const uint8_t *first, size_t first_len,
                       const uint8_t *second, size_t second_len, const uint8_t *third,
                       size_t third_len) {
    sha512 s;
    sha512_init(&s);
    sha512_update(&s, first, first_len);
    if (second_len != 0) {
        sha512_update(&s, second, second_len);
    }
    if (third_len != 0) {
        sha512_update(&s, third, third_len);
    }
    sha512_final(&s, out);
    ct_wipe(&s, sizeof s);
}

int ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t msg_len, uint8_t sig[64]) {
    // RFC 8032 section 5.1.5: the seed's hash gives the scalar a, with
    // three bits cleared and one set, and the prefix.
    uint8_t h[SHA512_LEN];
    uint8_t a[X25519_LEN];
    hash_parts(h, seed, 32, NULL, 0, NULL, 0);
    for (size_t i = 0; i < X25519_LEN; i++) {
        a[i] = h[i];
    }
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;

    // The public key A = a B, encoded.
    edwards_point point;
    uint8_t key[X25519_LEN];
    base_point(&point, a);
    encode_point(key, &point);

    // Section 5.1.6: r = SHA-512(prefix, M) modulo L, and R = r B.
    uint8_t digest[SHA512_LEN];
    uint64_t r[4];
    uint8_t r_bytes[X25519_LEN];
    uint8_t candidate[64];
    hash_parts(digest, h + X25519_LEN, X25519_LEN, msg, msg_len, NULL, 0);
    scalar_reduce(r, digest);
    for (size_t i = 0; i < 4; i++) {
        store_le64(r_bytes + 8 * i, r[i]);
    }
    base_point(&point, r_bytes);
    encode_point(candidate, &point);

    // k = SHA-512(R, A, M) modulo L, over public bytes, so the verifier's
    // reduction serves. Then S = r + k a modulo L. A is the public key and
    // R is the signature's first half, so both are marked public here, as
    // the check below marks S (docs/decisions.md 223).
    CT_DECLASSIFY(key, sizeof key);
    CT_DECLASSIFY(candidate, X25519_LEN);
    uint8_t hram[SHA512_LEN];
    uint64_t k[4];
    uint64_t s[4];
    hash_parts(hram, candidate, X25519_LEN, key, X25519_LEN, msg, msg_len);
    reduce_mod_l(k, hram);
    scalar_muladd(s, r, k, a);
    for (size_t i = 0; i < 4; i++) {
        store_le64(candidate + X25519_LEN + 8 * i, s[i]);
    }

    // The signature leaves only when the verifier a peer runs accepts it.
    // A fault in the two multiplications or in S fails here. The verifier
    // is variable time, so the public key, the candidate and their hash
    // are marked public first: the call publishes all three when no fault
    // changed them. A candidate that a fault changed is never written, but
    // the time its check takes is observable (docs/decisions.md 223).
    CT_DECLASSIFY(key, sizeof key);
    CT_DECLASSIFY(candidate, sizeof candidate);
    CT_DECLASSIFY(hram, sizeof hram);
    int ok = ed25519_verify_hram(key, hram, candidate);
    for (size_t i = 0; i < 64; i++) {
        sig[i] = ok ? candidate[i] : 0;
    }
    ct_wipe(h, sizeof h);
    ct_wipe(a, sizeof a);
    ct_wipe(&point, sizeof point);
    ct_wipe(digest, sizeof digest);
    ct_wipe(r, sizeof r);
    ct_wipe(r_bytes, sizeof r_bytes);
    ct_wipe(s, sizeof s);
    ct_wipe(candidate, sizeof candidate);
    return ok;
}

#endif // CH_JWS

#endif
