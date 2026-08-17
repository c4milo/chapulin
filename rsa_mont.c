// RSA modular exponentiation with the fixed public exponent 65537
// (RSAVP1, RFC 8017 5.2.2). Verify only: the modulus, the signature, and
// the result are all public, so the arithmetic is variable time and skips
// the constant-time discipline the secret-handling modules carry. Limbs
// are little-endian uint32 and every product or carry lives in uint64,
// the same shape as p256.c. Montgomery CIOS multiplication drives a
// square-and-multiply exponentiation; 65537 = 2^16 + 1 costs 16 squares
// and one multiply. Sizes run up to RSA-3072.
#include "rsa.h"

#include <string.h>

#define LIMBS_MAX 96 // limb: one 32-bit word of a big number; RSA-3072 = 96 limbs

// 32 big-endian bytes per limb -> k little-endian limbs, byte by byte.
static void from_bytes(uint32_t *o, const uint8_t *b, size_t k) {
    for (size_t i = 0; i < k; i++) {
        size_t j = (k - 1 - i) * 4; // most significant limb sits at the front
        o[i] = ((uint32_t)b[j] << 24) | ((uint32_t)b[j + 1] << 16) | ((uint32_t)b[j + 2] << 8) |
               (uint32_t)b[j + 3];
    }
}

// k little-endian limbs -> big-endian bytes.
static void to_bytes(uint8_t *b, const uint32_t *a, size_t k) {
    for (size_t i = 0; i < k; i++) {
        size_t j = (k - 1 - i) * 4;
        b[j] = (uint8_t)(a[i] >> 24);
        b[j + 1] = (uint8_t)(a[i] >> 16);
        b[j + 2] = (uint8_t)(a[i] >> 8);
        b[j + 3] = (uint8_t)a[i];
    }
}

static int cmp(const uint32_t *a, const uint32_t *b, size_t k) {
    for (size_t i = k; i-- > 0;) {
        if (a[i] != b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

static uint32_t sub_raw(uint32_t *o, const uint32_t *a, const uint32_t *b, size_t k) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t v = (uint64_t)a[i] - b[i] - borrow;
        o[i] = (uint32_t)v;
        borrow = (v >> 32) & 1;
    }
    return (uint32_t)borrow;
}

// -m^-1 mod 2^32 by Newton iteration. m0 is odd (n is a product of odd
// primes), so x doubles its correct low bits each step and five steps
// cover all 32.
static uint32_t mont_m0inv(uint32_t m0) {
    uint32_t x = 1;
    for (int i = 0; i < 5; i++) {
        x *= 2U - m0 * x;
    }
    return 0U - x;
}

// r2 = 2^(64k) mod m, the entry ticket to the Montgomery domain. Start at
// 1 and double 64k times; each double is a shift with one conditional
// subtract, since the pre-shift value is below m.
static void mont_r2(uint32_t *r2, const uint32_t *m, size_t k) {
    memset(r2, 0, k * sizeof(uint32_t));
    r2[0] = 1;
    for (size_t i = 0; i < 64 * k; i++) {
        uint32_t carry = 0;
        for (size_t j = 0; j < k; j++) {
            uint32_t shifted = (r2[j] << 1) | carry;
            carry = r2[j] >> 31;
            r2[j] = shifted;
        }
        if (carry || cmp(r2, m, k) >= 0) {
            (void)sub_raw(r2, r2, m, k);
        }
    }
}

// Montgomery product o = a*b / 2^(32k) mod m (CIOS, Koç et al.). Inputs
// below m, result below m; o may alias a or b, since o is written only
// after both are fully read. Each round adds one limb of a into t, folds
// a multiple of m in to zero t's low limb, and shifts down one limb.
static void mont_mul(uint32_t *o, const uint32_t *a, const uint32_t *b, const uint32_t *m,
                     uint32_t m0inv, size_t k) {
    uint32_t t[LIMBS_MAX + 2];
    memset(t, 0, (k + 2) * sizeof(uint32_t));
    for (size_t i = 0; i < k; i++) {
        uint64_t c = 0;
        for (size_t j = 0; j < k; j++) {
            uint64_t v = (uint64_t)a[i] * b[j] + t[j] + c;
            t[j] = (uint32_t)v;
            c = v >> 32;
        }
        uint64_t v = (uint64_t)t[k] + c;
        t[k] = (uint32_t)v;
        t[k + 1] = (uint32_t)(v >> 32);

        uint32_t u = t[0] * m0inv;
        c = ((uint64_t)u * m[0] + t[0]) >> 32;
        for (size_t j = 1; j < k; j++) {
            v = (uint64_t)u * m[j] + t[j] + c;
            t[j - 1] = (uint32_t)v;
            c = v >> 32;
        }
        v = (uint64_t)t[k] + c;
        t[k - 1] = (uint32_t)v;
        t[k] = t[k + 1] + (uint32_t)(v >> 32);
        t[k + 1] = 0;
    }
    // t < 2m with at most one bit in t[k]; the subtraction's borrow
    // cancels that bit exactly, so the low limbs are the answer.
    if (t[k] || cmp(t, m, k) >= 0) {
        (void)sub_raw(o, t, m, k);
    } else {
        memcpy(o, t, k * sizeof(uint32_t));
    }
}

void rsa_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em) {
    size_t k = n_len / 4;
    uint32_t m[LIMBS_MAX] = {0};
    uint32_t base[LIMBS_MAX] = {0};
    uint32_t r2[LIMBS_MAX];
    uint32_t base_mont[LIMBS_MAX];
    uint32_t acc[LIMBS_MAX];
    uint32_t one[LIMBS_MAX];
    from_bytes(m, n, k);
    from_bytes(base, sig, k);
    uint32_t m0inv = mont_m0inv(m[0]);
    mont_r2(r2, m, k);

    // acc holds the running power in the Montgomery domain. Start at
    // base*R (sig^1), square 16 times to reach sig^(2^16), then one
    // multiply by base*R for the +1, giving sig^65537.
    mont_mul(base_mont, base, r2, m, m0inv, k);
    memcpy(acc, base_mont, k * sizeof(uint32_t));
    for (int i = 0; i < 16; i++) {
        mont_mul(acc, acc, acc, m, m0inv, k);
    }
    mont_mul(acc, acc, base_mont, m, m0inv, k);

    // Multiply by 1 to strip the R factor, then serialize.
    memset(one, 0, k * sizeof(uint32_t));
    one[0] = 1;
    mont_mul(acc, acc, one, m, m0inv, k);
    to_bytes(em, acc, k);
}
