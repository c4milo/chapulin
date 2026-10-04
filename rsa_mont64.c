// RSA's Montgomery arithmetic on 64-bit limbs, which a host object holds
// (rsa_mont64.h): the multiplication, the constant R^2 mod m that moves a
// number into the Montgomery domain, and the public operation,
// base^65537 mod m.
//
// Every sum here is written so that it cannot wrap. A product is one
// ct_mul128, at most (2^64 - 1)^2, and two more limbs fit above it in 128
// bits: (2^64 - 1)^2 + 2 * (2^64 - 1) = 2^128 - 1. A subtraction adds the
// complement of the subtrahend and one, and reads the carry where a
// borrow would be. proof/rsa_mont64_sums_harness.c and
// proof/rsa_mont64_ops_harness.c run with --unsigned-overflow-check on,
// the first over a contract of ct_mul128, so each of those sums is a
// property CBMC checks. neg_inverse is the one function whose arithmetic
// wraps on purpose, modulo 2^64, and proof/rsa_mont64_init_harness.c
// runs it with that check off.
//
// Constant time: no branch and no memory index depends on a limb. The
// branches the file compiles to are loops over limb and byte counts, the
// doublings rsa_mont64_modulus_init counts from its bits argument, the
// sixteen squarings of the public exponent, and the two CH_ASSERTs on
// public lengths.
#include "rsa_mont64.h"

#ifdef CH_CPU_RUNTIME

#include <string.h>

#include "ch_assert.h"
#include "ct.h"

// All ones when bit is 1, all zeros when bit is 0. The mask comes from
// moving the bit to the top and spreading it down with an arithmetic
// shift, the form rsa_sign.c's mask_of_bit takes for the reason its
// comment gives: gcc rewrites `x & -bit` as a multiply by the bit.
static uint64_t mask_of_bit(uint64_t bit) {
    return (uint64_t)((int64_t)(bit << 63) >> 63);
}

void rsa_mont64_from_bytes(uint64_t *limbs, size_t count, const uint8_t *bytes, size_t len) {
    memset(limbs, 0, count * sizeof(uint64_t));
    // Byte i from the end has weight 2^(8i): limb i / 8, shifted up
    // 8 * (i % 8) bits.
    for (size_t i = 0; i < len; i++) {
        limbs[i >> 3] |= (uint64_t)bytes[len - 1 - i] << (8 * (i & 7));
    }
}

void rsa_mont64_to_bytes(uint8_t *bytes, size_t len, const uint64_t *limbs) {
    for (size_t i = 0; i < len; i++) {
        bytes[len - 1 - i] = (uint8_t)(limbs[i >> 3] >> (8 * (i & 7)));
    }
}

// 1 when the k + 1 limb value top:a is at or above m, and 0 when it is
// below. It adds the complement of m and one, limb by limb, which is
// a - m with no step that wraps, and the carry out of the top limb is the
// answer: a subtraction that does not borrow carries here. m has no limb
// above k, so the top limb adds the complement of zero.
static uint64_t at_or_above(const uint64_t *a, uint64_t top, const uint64_t *m, size_t k) {
    uint64_t carry = 1;
    for (size_t i = 0; i < k; i++) {
        ct_u128 v = (ct_u128)a[i] + ~m[i] + carry;
        carry = (uint64_t)(v >> 64);
    }
    return (uint64_t)(((ct_u128)top + UINT64_MAX + carry) >> 64);
}

// o = a - (m & mask) over k limbs, by the same sum. mask is all ones or
// all zeros, so this is the whole subtraction or a subtraction of zero,
// and both take the same time and write the same limbs. o may be a.
static void sub_masked(uint64_t *o, const uint64_t *a, const uint64_t *m, size_t k, uint64_t mask) {
    uint64_t carry = 1;
    for (size_t i = 0; i < k; i++) {
        ct_u128 v = (ct_u128)a[i] + ~(m[i] & mask) + carry;
        o[i] = (uint64_t)v;
        carry = (uint64_t)(v >> 64);
    }
}

// o = top:a - m when top:a is at or above m, and a when it is below: one
// subtraction of m, chosen by a mask. For top:a below 2m the result is
// top:a mod m. o may be a.
static void reduce_once(uint64_t *o, const uint64_t *a, uint64_t top, const uint64_t *m, size_t k) {
    sub_masked(o, a, m, k, mask_of_bit(at_or_above(a, top, m, k)));
}

// x = 2x mod m, for x below m: a shift up by one bit, the bit that leaves
// the top limb kept as the limb above, and one subtraction.
static void double_mod(uint64_t *x, const uint64_t *m, size_t k) {
    uint64_t moved = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t next = x[i] >> 63;
        x[i] = (x[i] << 1) | moved;
        moved = next;
    }
    reduce_once(x, x, moved, m, k);
}

// x = 2^bit over k limbs, for a bit below 64 * k.
static void power_of_two(uint64_t *x, size_t k, size_t bit) {
    memset(x, 0, k * sizeof(uint64_t));
    x[bit >> 6] = (uint64_t)1 << (bit & 63);
}

// -m0^-1 mod 2^64, by Newton's iteration. m0 is odd, so x = 1 is the
// inverse to one bit, and each step doubles the bits that are right: six
// steps make 64. This arithmetic is modulo 2^64, so it wraps on purpose.
static uint64_t neg_inverse(uint64_t m0) {
    uint64_t x = 1;
    for (int i = 0; i < 6; i++) {
        x *= 2U - m0 * x;
    }
    return 0U - x;
}

void rsa_mont64_mont_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                         const rsa_mont64_modulus *mod) {
    size_t k = mod->limbs;
    const uint64_t *m = mod->m;
    // t is k + 1 limbs: the running sum, below 2m after every round when
    // b is below m, so its top limb is 0 or 1.
    uint64_t t[RSA_MONT64_LIMBS_MAX + 1];
    memset(t, 0, (k + 1) * sizeof(uint64_t));
    // Round i adds a[i] * b and u * m to t and moves t down one limb. u is
    // the multiple of m that makes the low limb of that sum zero, which is
    // what lets the limb go. One pass over the limbs carries both
    // products, each with its own carry: the sum of the a[i] * b terms
    // feeds the sum of the u * m terms, limb by limb.
    for (size_t i = 0; i < k; i++) {
        uint64_t x = a[i];
        ct_u128 ab = ct_mul128(x, b[0]) + t[0];
        // u is the low limb of that sum times m0inv, modulo 2^64: the
        // low half of one more product.
        uint64_t u = (uint64_t)ct_mul128((uint64_t)ab, mod->m0inv);
        ct_u128 um = ct_mul128(u, m[0]) + (uint64_t)ab;
        uint64_t ab_carry = (uint64_t)(ab >> 64);
        uint64_t um_carry = (uint64_t)(um >> 64);
        for (size_t j = 1; j < k; j++) {
            ab = ct_mul128(x, b[j]) + t[j] + ab_carry;
            ab_carry = (uint64_t)(ab >> 64);
            um = ct_mul128(u, m[j]) + (uint64_t)ab + um_carry;
            um_carry = (uint64_t)(um >> 64);
            t[j - 1] = (uint64_t)um;
        }
        ct_u128 top = (ct_u128)t[k] + ab_carry + um_carry;
        t[k - 1] = (uint64_t)top;
        t[k] = (uint64_t)(top >> 64);
    }
    reduce_once(o, t, t[k], m, k);
    // t held a * b / R before its last subtraction, which is as secret as
    // the product.
    ct_wipe(t, (k + 1) * sizeof(uint64_t));
}

void rsa_mont64_modulus_init(rsa_mont64_modulus *mod, const uint8_t *m, size_t m_len, size_t bits) {
    CH_ASSERT(m_len >= 1 && m_len <= CH_RSA_MODULUS_MAX && bits >= 1 && bits <= 8 * m_len);
    size_t k = (m_len + 7) >> 3;
    mod->limbs = k;
    rsa_mont64_from_bytes(mod->m, k, m, m_len);
    mod->m0inv = neg_inverse(mod->m[0]);

    // r2 = R^2 mod m, with R = 2^(64k). 2^(bits - 1) is below m, because
    // m has that bit and is odd. One doubling for each power of two from
    // there up to 2^(66k) gives 2^(2k) * R mod m, the Montgomery form of
    // 2^(2k): the first 64k - (bits - 1) of them give R mod m, and the
    // last 2k the rest. Squaring that form five times raises 2^(2k) to
    // the 32nd power, which is 2^(64k) = R, and the Montgomery form of R
    // is R^2 mod m.
    power_of_two(mod->r2, k, bits - 1);
    for (size_t i = bits - 1; i < 66 * k; i++) {
        double_mod(mod->r2, mod->m, k);
    }
    for (int i = 0; i < 5; i++) {
        rsa_mont64_mont_mul(mod->r2, mod->r2, mod->r2, mod);
    }
}

void rsa_mont64_public(uint8_t *out, const uint8_t *base, size_t len,
                       const rsa_mont64_modulus *mod) {
    size_t k = mod->limbs;
    CH_ASSERT(len <= 8 * k);
    // Zeroed at declaration, as rsa_mont.c's are: the limbs past k are
    // never read, and starting them at zero lets a reader see that
    // without following the length.
    uint64_t x[RSA_MONT64_LIMBS_MAX] = {0};
    uint64_t acc[RSA_MONT64_LIMBS_MAX] = {0};
    rsa_mont64_from_bytes(x, k, base, len);

    // acc holds the running power in the Montgomery domain: base * R,
    // then sixteen squarings to base^65536 * R. The last product is by
    // base itself, outside the domain, so it multiplies by base and
    // divides by R at once: base^65537. In each product the second
    // operand is below m, which is all rsa_mont64_mont_mul needs, so base
    // may be any number of k limbs.
    rsa_mont64_mont_mul(acc, x, mod->r2, mod);
    for (int i = 0; i < 16; i++) {
        rsa_mont64_mont_mul(acc, acc, acc, mod);
    }
    rsa_mont64_mont_mul(acc, x, acc, mod);
    rsa_mont64_to_bytes(out, len, acc);
    ct_wipe(x, sizeof x);
    ct_wipe(acc, sizeof acc);
}

#endif // CH_CPU_RUNTIME
