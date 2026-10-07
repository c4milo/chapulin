// RSA modular exponentiation with the fixed public exponent 65537
// (RSAVP1, RFC 8017 5.2.2). Verify only: the modulus, the signature, and
// the result are all public, so the arithmetic is variable time and skips
// the constant-time discipline the secret-handling modules carry. Words
// are little-endian uint32 and every product or carry lives in uint64,
// the same shape as p256.c. Montgomery CIOS multiplication drives a
// square-and-multiply exponentiation; 65537 = 2^16 + 1 costs 16 squares
// and one multiply. Sizes run up to CH_RSA_MODULUS_MAX bytes (rsa.h):
// RSA-3072, or RSA-4096 under CH_TRUST_WEBPKI.
//
// That is a device object's rsa_vp1, and the reference. A host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) compiles the first arm below in its
// place: the same exponentiation on rsa_mont64.c's 64-bit words, in every
// session, because nothing here is secret and so no caller has to state
// the multiply's timing (docs/decisions.md 95). That arm computes R^2 by
// a long division of its own, which branches on the modulus
// (docs/decisions.md 103). bin/rsa_equiv_test compiles both arms into one
// binary and requires the same bytes from each.
#include "rsa.h"

#ifdef CH_CPU_RUNTIME

#include "ct.h"
#include "rsa_mont64.h"

// The bit length of the n_len-byte n: the position of its top set bit,
// plus one, and 0 for n == 0, which no caller passes. rsa.c holds the
// same count for emBits; n is public, so both read it byte by byte.
static size_t bit_length(const uint8_t *n, size_t n_len) {
    size_t i = 0;
    while (i < n_len && n[i] == 0) {
        i++;
    }
    if (i == n_len) {
        return 0;
    }
    size_t bits = 8 * (n_len - i);
    uint8_t top = n[i];
    while ((top & 0x80) == 0) {
        bits--;
        top = (uint8_t)(top << 1);
    }
    return bits;
}

// rem = rem * 2^64 mod m, for rem below m and an m of k >= 2 words whose
// top bit is set. It is one step of a long division, Knuth's algorithm D
// (The Art of Computer Programming, vol. 2, 4.3.1), whose dividend is rem
// with a zero word below it.
//
// The estimate of the quotient divides the dividend's top two words by
// m's top word. The quotient is below 2^64, because rem is below m. When
// rem's top word equals m's, that division passes 2^64, and the estimate
// is 2^64 - 1. Knuth's Theorem B says the estimate is the quotient or at
// most 2 above it, because m's top word is at least 2^63. So the step
// subtracts the estimate times m and then adds m back, at most twice.
//
// m is public, so every value here is public: the step branches on them,
// and the division takes whatever time it takes.
static void times_word_mod(uint64_t *rem, const uint64_t *m, size_t k) {
    uint64_t top = rem[k - 1];
    uint64_t estimate = UINT64_MAX;
    if (top < m[k - 1]) {
        estimate = (uint64_t)((((ct_u128)top << 64) | rem[k - 2]) / m[k - 1]);
    }
    // The dividend less the estimate times m, from the bottom word up.
    // Word j of the dividend is rem[j - 1], and word 0 is zero. A
    // subtraction adds the complement and one, as rsa_mont64.c's do, so
    // the carry out is 1 where no borrow happened.
    uint64_t dividend_word = 0;
    uint64_t product_carry = 0;
    uint64_t carry = 1;
    for (size_t j = 0; j < k; j++) {
        ct_u128 product = ct_mul128(estimate, m[j]) + product_carry;
        product_carry = (uint64_t)(product >> 64);
        ct_u128 difference = (ct_u128)dividend_word + ~(uint64_t)product + carry;
        dividend_word = rem[j];
        rem[j] = (uint64_t)difference;
        carry = (uint64_t)(difference >> 64);
    }
    // The difference's word above the k, in two's complement: 0 when the
    // difference is at or above zero, and 2^64 - 1 or 2^64 - 2 when the
    // estimate was 1 or 2 too large. Each pass adds m, and the carry out
    // of its top word moves that word toward 0, where it wraps on purpose.
    uint64_t above = (uint64_t)((ct_u128)dividend_word + ~product_carry + carry);
    for (int pass = 0; pass < 2 && above != 0; pass++) {
        uint64_t sum_carry = 0;
        for (size_t j = 0; j < k; j++) {
            ct_u128 sum = (ct_u128)rem[j] + m[j] + sum_carry;
            rem[j] = (uint64_t)sum;
            sum_carry = (uint64_t)(sum >> 64);
        }
        above += sum_carry;
    }
}

// r2 = R^2 mod m, with R = 2^(64k), for an m of k >= 2 words whose top
// bit is set. R mod m is R - m, because m is below R and at least R / 2,
// and k steps of times_word_mod multiply it by R modulo m.
static void r2_by_division(uint64_t *r2, const uint64_t *m, size_t k) {
    // R - m over k words: the complement of m, plus one.
    uint64_t carry = 1;
    for (size_t j = 0; j < k; j++) {
        ct_u128 sum = (ct_u128)~m[j] + carry;
        r2[j] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    for (size_t i = 0; i < k; i++) {
        times_word_mod(r2, m, k);
    }
}

// A modulus whose top word has its top bit set, as every RSA key's does,
// takes R^2 by the division above, about a sixth of the time
// rsa_mont64_modulus_init takes for RSA-2048 (docs/decisions.md 103). That
// setup doubles 2k + 1 times and squares five times, in a time that
// depends on the modulus's length alone, which the signer needs for its
// secret primes and the verifier does not. Any other modulus still takes
// it.
void rsa_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em) {
    rsa_mont64_modulus mod;
    size_t k = (n_len + 7) / 8;
    size_t bits = bit_length(n, n_len);
    if (k >= 2 && bits == 64 * k) {
        rsa_mont64_modulus_load(&mod, n, n_len);
        r2_by_division(mod.r2, mod.m, k);
    } else {
        rsa_mont64_modulus_init(&mod, n, n_len, bits);
    }
    rsa_mont64_public(em, sig, n_len, &mod);
}

#else // !CH_CPU_RUNTIME

#include <string.h>

// The most 32-bit words a big number holds: 96 for RSA-3072 and 128 for
// RSA-4096. The count follows the one modulus bound rsa.h defines.
#define WORDS_MAX (CH_RSA_MODULUS_MAX / 4)

// 32 big-endian bytes per word -> k little-endian words, byte by byte.
static void from_bytes(uint32_t *o, const uint8_t *b, size_t k) {
    for (size_t i = 0; i < k; i++) {
        size_t j = (k - 1 - i) * 4; // most significant word sits at the front
        o[i] = ((uint32_t)b[j] << 24) | ((uint32_t)b[j + 1] << 16) | ((uint32_t)b[j + 2] << 8) |
               (uint32_t)b[j + 3];
    }
}

// k little-endian words -> big-endian bytes.
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
// after both are fully read. Each round adds one word of a into t, folds
// a multiple of m in to zero t's low word, and shifts down one word.
static void mont_mul(uint32_t *o, const uint32_t *a, const uint32_t *b, const uint32_t *m,
                     uint32_t m0inv, size_t k) {
    uint32_t t[WORDS_MAX + 2];
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
    // cancels that bit exactly, so the low words are the answer.
    if (t[k] || cmp(t, m, k) >= 0) {
        (void)sub_raw(o, t, m, k);
    } else {
        memcpy(o, t, k * sizeof(uint32_t));
    }
}

void rsa_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em) {
    size_t k = n_len / 4;
    uint32_t m[WORDS_MAX] = {0};
    uint32_t base[WORDS_MAX] = {0};
    uint32_t r2[WORDS_MAX];
    uint32_t base_mont[WORDS_MAX];
    uint32_t acc[WORDS_MAX];
    uint32_t one[WORDS_MAX];
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

#endif // CH_CPU_RUNTIME
