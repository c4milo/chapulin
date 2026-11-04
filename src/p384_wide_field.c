// NIST P-384 field and scalar arithmetic on six 64-bit words, which a
// host object holds (p384_wide_field.h). It is p384_field.c routine for
// routine: the same word-by-word Montgomery reduction (CIOS), one
// constant set per modulus so the field prime p and the group order n
// share every routine, and Fermat inverses. Variable time on purpose —
// every input is public (see p384.h).
//
// Every sum here is written so that it cannot wrap. A product is one
// ct_mul128, at most (2^64 - 1)^2, and two more words fit above it in 128
// bits: (2^64 - 1)^2 + 2 * (2^64 - 1) = 2^128 - 1. A subtraction adds the
// complement of the subtrahend and one, and reads the carry where a
// borrow would be. proof/p384_wide_field_harness.c runs with
// --unsigned-overflow-check on, over a contract of ct_mul128, so each of
// those sums is a property CBMC checks.
#include "p384_wide_field.h"

#ifdef CH_CPU_RUNTIME

#include <string.h>

#include "ct.h"

// SEC 2 curve constants; r2 and m0inv derived from them (2^768 mod m and
// -m^-1 mod 2^64). test/gen_p384_constants.py prints these words after
// checking every parameter against `openssl ecparam -name secp384r1
// -param_enc explicit -text -noout`. Each word is two of p384_field.c's,
// the higher one first, and r2 is the same number there and here.
const p384_wide_modulus p384_wide_modp = {
    {0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
     0xffffffffffffffff, 0xffffffffffffffff},
    {0xfffffffe00000001, 0x0000000200000000, 0xfffffffe00000000, 0x0000000200000000,
     0x0000000000000001, 0x0000000000000000},
    0x0000000100000001,
};

const p384_wide_modulus p384_wide_modn = {
    {0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff,
     0xffffffffffffffff, 0xffffffffffffffff},
    {0x2d319b2419b409a9, 0xff3d81e5df1aa419, 0xbc3e483afcb82947, 0xd40d49174aab1cc5,
     0x3fb05b7a28266895, 0x0c84ee012b39bf21},
    0x6ed46089e88fdc45,
};

int p384_wide_is_zero(const uint64_t a[P384_WIDE_WORDS]) {
    uint64_t v = 0;
    for (int i = 0; i < P384_WIDE_WORDS; i++) {
        v |= a[i];
    }
    return v == 0;
}

int p384_wide_compare(const uint64_t a[P384_WIDE_WORDS], const uint64_t b[P384_WIDE_WORDS]) {
    for (int i = P384_WIDE_WORDS - 1; i >= 0; i--) {
        if (a[i] != b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

// 48 big-endian bytes -> 6 little-endian words, byte by byte: byte j of
// word i, counted from the word's low end, is byte 8i + j from the end.
void p384_wide_from_bytes(uint64_t o[P384_WIDE_WORDS], const uint8_t b[P384_LEN]) {
    for (int i = 0; i < P384_WIDE_WORDS; i++) {
        uint64_t word = 0;
        for (int j = 0; j < 8; j++) {
            word |= (uint64_t)b[P384_LEN - 1 - 8 * i - j] << (8 * j);
        }
        o[i] = word;
    }
}

uint64_t p384_wide_add_raw(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                           const uint64_t b[P384_WIDE_WORDS]) {
    uint64_t carry = 0;
    for (int i = 0; i < P384_WIDE_WORDS; i++) {
        ct_u128 v = (ct_u128)a[i] + b[i] + carry;
        o[i] = (uint64_t)v;
        carry = (uint64_t)(v >> 64);
    }
    return carry;
}

// a - b as a + ~b + 1, word by word, which no step of wraps. The carry
// out of the top word is 1 when a is at or above b and 0 when the
// subtraction borrowed, so the borrow is its complement.
uint64_t p384_wide_sub_raw(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                           const uint64_t b[P384_WIDE_WORDS]) {
    uint64_t carry = 1;
    for (int i = 0; i < P384_WIDE_WORDS; i++) {
        ct_u128 v = (ct_u128)a[i] + ~b[i] + carry;
        o[i] = (uint64_t)v;
        carry = (uint64_t)(v >> 64);
    }
    return carry ^ 1;
}

// Inputs below m; one conditional subtract covers the sum (< 2m).
void p384_wide_mod_add(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                       const uint64_t b[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    uint64_t carry = p384_wide_add_raw(o, a, b);
    if (carry || p384_wide_compare(o, mod->m) >= 0) {
        (void)p384_wide_sub_raw(o, o, mod->m);
    }
}

void p384_wide_mod_sub(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                       const uint64_t b[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    if (p384_wide_sub_raw(o, a, b)) {
        (void)p384_wide_add_raw(o, o, mod->m);
    }
}

// One round of the Montgomery product below: t = (t + a_word * b + u * m)
// / 2^64, where u is the multiple of m that makes the sum's low word
// zero, which is what lets the word go. t is eight words: the running sum
// in seven, and a word above them that is zero between rounds.
static inline void mont_round(uint64_t t[P384_WIDE_WORDS + 2], uint64_t a_word,
                              const uint64_t b[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    uint64_t carry = 0;
    for (int j = 0; j < P384_WIDE_WORDS; j++) {
        ct_u128 v = ct_mul128(a_word, b[j]) + t[j] + carry;
        t[j] = (uint64_t)v;
        carry = (uint64_t)(v >> 64);
    }
    ct_u128 top = (ct_u128)t[P384_WIDE_WORDS] + carry;
    t[P384_WIDE_WORDS] = (uint64_t)top;
    t[P384_WIDE_WORDS + 1] = (uint64_t)(top >> 64);

    // u is the low word of t times m0inv, modulo 2^64: the low half of
    // one more product.
    uint64_t u = (uint64_t)ct_mul128(t[0], mod->m0inv);
    carry = (uint64_t)((ct_mul128(u, mod->m[0]) + t[0]) >> 64);
    for (int j = 1; j < P384_WIDE_WORDS; j++) {
        ct_u128 v = ct_mul128(u, mod->m[j]) + t[j] + carry;
        t[j - 1] = (uint64_t)v;
        carry = (uint64_t)(v >> 64);
    }
    top = (ct_u128)t[P384_WIDE_WORDS] + carry;
    t[P384_WIDE_WORDS - 1] = (uint64_t)top;
    t[P384_WIDE_WORDS] = t[P384_WIDE_WORDS + 1] + (uint64_t)(top >> 64);
    t[P384_WIDE_WORDS + 1] = 0;
}

// Montgomery product o = a*b / 2^384 mod m (CIOS, Koç et al.). Inputs
// below m, result below m; o may alias a or b. Each round adds one word
// of a into t, then adds a multiple of m to zero t's low word and
// shifts down one word. The six rounds are six calls and not a loop:
// clang 21 keeps t in registers across six calls and in memory across a
// loop's iterations, which measured 37 ns a product against 40 on an M1.
void p384_wide_mont_mul(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                        const uint64_t b[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    uint64_t t[P384_WIDE_WORDS + 2] = {0};
    mont_round(t, a[0], b, mod);
    mont_round(t, a[1], b, mod);
    mont_round(t, a[2], b, mod);
    mont_round(t, a[3], b, mod);
    mont_round(t, a[4], b, mod);
    mont_round(t, a[5], b, mod);
    // t < 2m with at most one bit in t[P384_WIDE_WORDS]; the subtraction's
    // borrow cancels that bit exactly, so the low words are the answer.
    if (t[P384_WIDE_WORDS] || p384_wide_compare(t, mod->m) >= 0) {
        (void)p384_wide_sub_raw(o, t, mod->m);
    } else {
        memcpy(o, t, P384_WIDE_WORDS * sizeof(uint64_t));
    }
}

// Plain product mod m: into the Montgomery domain and back in one extra
// multiply (a*b/R, then *R^2/R).
void p384_wide_mod_mul(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                       const uint64_t b[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    uint64_t t[P384_WIDE_WORDS];
    p384_wide_mont_mul(t, a, b, mod);
    p384_wide_mont_mul(o, t, mod->r2, mod);
}

// o = a^(m-2) mod m: Fermat inverse, square-and-multiply in the
// Montgomery domain. The exponent is a public constant, so the
// bit-dependent multiply leaks nothing.
void p384_wide_mod_inverse(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                           const p384_wide_modulus *mod) {
    static const uint64_t one[P384_WIDE_WORDS] = {1};
    static const uint64_t two[P384_WIDE_WORDS] = {2};
    uint64_t e[P384_WIDE_WORDS];
    uint64_t a_mont[P384_WIDE_WORDS];
    uint64_t acc[P384_WIDE_WORDS];
    (void)p384_wide_sub_raw(e, mod->m, two);     // both moduli are above 2: no borrow
    p384_wide_mont_mul(a_mont, a, mod->r2, mod); // a*R
    p384_wide_mont_mul(acc, one, mod->r2, mod);  // 1*R
    for (int i = 383; i >= 0; i--) {
        p384_wide_mont_mul(acc, acc, acc, mod);
        if ((e[i / 64] >> (i % 64)) & 1) {
            p384_wide_mont_mul(acc, acc, a_mont, mod);
        }
    }
    p384_wide_mont_mul(o, acc, one, mod); // strip the R factor
}

#endif // CH_CPU_RUNTIME
