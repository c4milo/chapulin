// Constant-time arithmetic modulo the P-256 group order (see
// p256_scalar.h for the contracts and for why p256.c's arithmetic cannot
// be reused). Scalars are eight little-endian uint32 words; products and
// carries live in uint64. Multiplication reduces word by word (CIOS, Koç
// et al.), the inverse is a Fermat power, and every conditional
// subtraction is a mask and a select rather than an `if`.
//
// The layout and the routine bodies follow p256_field.c deliberately: an
// auditor who has read that file reads this one by diffing it, and the
// two differ only in the modulus, the Montgomery constants, the exponent
// and three wipes this file has and that one lacks (p256_scalar.h). The
// two files do not share a modulus argument, because a shared routine
// that took one would put the field prime and the group order behind the
// same pointer and let a caller pass the wrong one.
#include "p256_scalar.h"

#include <stddef.h>

#include "ct.h"

#define WORDS P256_SCALAR_WORDS

// SEC 2 secp256r1's group order and the constants derived from it,
// R = 2^256. The same words appear in p256.c's MODN.
// test/gen_p256_sign_vectors.py recomputes n, 2^512 mod n, R mod n,
// -n^-1 mod 2^32 and n-2 from n's definition and stops if any word below
// differs.
static const uint32_t N[WORDS] = {0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad,
                                  0xffffffff, 0xffffffff, 0x00000000, 0xffffffff};
// 2^512 mod n: multiplying by it enters the Montgomery domain.
static const uint32_t RR[WORDS] = {0xbe79eea2, 0x83244c95, 0x49bd6fa6, 0x4699799c,
                                   0x2b6bec59, 0x2845b239, 0xf3d95620, 0x66e12d94};
// -n^-1 mod 2^32. Unlike the field prime's, it is not 1: n's low word is
// 0xfc632551, so the CIOS multiplier below costs one multiply per round.
#define N0_INV 0xee00bc4fU

// n - 2, the Fermat exponent, least significant word first. It is a
// constant of this build, so p256_scalar_inverse's walk over its bits is
// the same walk on every call.
static const uint32_t N_MINUS_2[WORDS] = {0xfc63254f, 0xf3b9cac2, 0xa7179e84, 0xbce6faad,
                                          0xffffffff, 0xffffffff, 0x00000000, 0xffffffff};

// R mod n, the Montgomery form of 1 and the starting accumulator for the
// Fermat power below.
static const uint32_t ONE_MONT[WORDS] = {0x039cdaaf, 0x0c46353d, 0x58e8617b, 0x43190552,
                                         0x00000000, 0x00000000, 0xffffffff, 0x00000000};

static const uint32_t ONE[WORDS] = {1, 0, 0, 0, 0, 0, 0, 0};

const p256_scalar p256_scalar_zero = {
    {0, 0, 0, 0, 0, 0, 0, 0}
};

// o = a + b over the words; the return value is the carry out, 0 or 1.
static uint32_t add_words(uint32_t o[WORDS], const uint32_t a[WORDS], const uint32_t b[WORDS]) {
    uint64_t carry = 0;
    for (int i = 0; i < WORDS; i++) {
        carry += (uint64_t)a[i] + b[i];
        o[i] = (uint32_t)carry;
        carry >>= 32;
    }
    return (uint32_t)carry;
}

// o = a - b over the words; the return value is the borrow out as a mask,
// all ones when a < b and zero otherwise. The mask comes straight out of
// the last difference's high word, the way p256_field.c's sub_words
// builds it, so no caller has to negate a bit to get a mask.
static uint32_t sub_words(uint32_t o[WORDS], const uint32_t a[WORDS], const uint32_t b[WORDS]) {
    uint64_t borrow = 0;
    uint64_t diff = 0;
    for (int i = 0; i < WORDS; i++) {
        diff = (uint64_t)a[i] - b[i] - borrow;
        o[i] = (uint32_t)diff;
        borrow = (diff >> 32) & 1;
    }
    return (uint32_t)(diff >> 32);
}

// o = a when mask is all ones, o = b when mask is zero.
static void select_words(uint32_t o[WORDS], const uint32_t a[WORDS], const uint32_t b[WORDS],
                         uint32_t mask) {
    for (int i = 0; i < WORDS; i++) {
        o[i] = (a[i] & mask) | (b[i] & ~mask);
    }
}

// o = (high:t) - n when that 257-bit value is at or above n, o = t
// otherwise. high is 0 or 1: a sum of two scalars below n carries at most
// one bit past the eight words, and the CIOS loop below leaves at most one
// there too (proof/p256_sign_harness.c).
//
// reduced is t less n modulo 2^256, which gives t to whoever reads it, so
// it is wiped: p256_scalar_add hands this routine z + r*d.
static void reduce_once(uint32_t o[WORDS], const uint32_t t[WORDS], uint32_t high) {
    uint32_t reduced[WORDS];
    uint32_t borrow = sub_words(reduced, t, N) & 1U;
    // high and borrow are each 0 or 1, and high:t is below n exactly when
    // high is 0 and the low subtraction borrowed out. Their difference in
    // uint64 arithmetic is negative in that one case, so its high word is
    // all ones there and zero elsewhere; the complement is the mask that
    // takes the reduced words.
    uint64_t below = (uint64_t)high - borrow;
    select_words(o, reduced, t, ~(uint32_t)(below >> 32));
    ct_wipe(reduced, sizeof reduced);
}

// All ones when v is zero, zero otherwise.
static uint32_t zero_mask_word(uint32_t v) {
    uint32_t nonzero = v | (~v + 1U); // bit 31 is set exactly when v is nonzero
    return (nonzero >> 31) - 1U;
}

// o = a*b/R mod n (CIOS, Koç et al.). Each round adds one word of a into
// t, then adds a multiple of n that zeroes t's low word and shifts t down
// by one word. Every product goes through ct_widemul, so no widening
// multiply instruction reads a word.
static void mont_mul(uint32_t o[WORDS], const uint32_t a[WORDS], const uint32_t b[WORDS]) {
    uint32_t t[WORDS + 2] = {0};
    for (int i = 0; i < WORDS; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < WORDS; j++) {
            uint64_t v = ct_widemul(a[i], b[j]) + t[j] + carry;
            t[j] = (uint32_t)v;
            carry = v >> 32;
        }
        uint64_t v = (uint64_t)t[WORDS] + carry;
        t[WORDS] = (uint32_t)v;
        t[WORDS + 1] = (uint32_t)(v >> 32);

        uint32_t u = (uint32_t)ct_widemul(t[0], N0_INV);
        carry = (ct_widemul(u, N[0]) + t[0]) >> 32;
        for (int j = 1; j < WORDS; j++) {
            v = ct_widemul(u, N[j]) + t[j] + carry;
            t[j - 1] = (uint32_t)v;
            carry = v >> 32;
        }
        v = (uint64_t)t[WORDS] + carry;
        t[WORDS - 1] = (uint32_t)v;
        t[WORDS] = t[WORDS + 1] + (uint32_t)(v >> 32);
        t[WORDS + 1] = 0;
    }
    // t is below 2n with at most one bit in t[WORDS], so one conditional
    // subtraction finishes it. o may alias a or b: nothing writes o before
    // this line.
    reduce_once(o, t, t[WORDS]);
}

void p256_scalar_from_bytes(p256_scalar *o, const uint8_t in[P256_SCALAR_LEN]) {
    for (size_t i = 0; i < WORDS; i++) {
        const uint8_t *bytes = in + P256_SCALAR_LEN - 4 * (i + 1);
        o->word[i] = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
                     ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
    }
}

void p256_scalar_to_bytes(uint8_t out[P256_SCALAR_LEN], const p256_scalar *a) {
    for (size_t i = 0; i < WORDS; i++) {
        uint8_t *bytes = out + P256_SCALAR_LEN - 4 * (i + 1);
        bytes[0] = (uint8_t)(a->word[i] >> 24);
        bytes[1] = (uint8_t)(a->word[i] >> 16);
        bytes[2] = (uint8_t)(a->word[i] >> 8);
        bytes[3] = (uint8_t)a->word[i];
    }
}

uint32_t p256_scalar_reduced_mask(const p256_scalar *a) {
    // discard is a less n modulo 2^256, which gives a to whoever reads it,
    // and a is a private key or a nonce here.
    uint32_t discard[WORDS];
    uint32_t mask = sub_words(discard, a->word, N);
    ct_wipe(discard, sizeof discard);
    return mask;
}

uint32_t p256_scalar_zero_mask(const p256_scalar *a) {
    uint32_t bits = 0;
    for (int i = 0; i < WORDS; i++) {
        bits |= a->word[i];
    }
    return zero_mask_word(bits);
}

void p256_scalar_cmov(p256_scalar *o, const p256_scalar *a, uint32_t mask) {
    select_words(o->word, a->word, o->word, mask);
}

void p256_scalar_reduce(p256_scalar *o, const p256_scalar *a) {
    // Any 256-bit value is below 2n, because n is above 2^255, so the
    // carry word handed to reduce_once is zero and one subtraction is
    // enough.
    reduce_once(o->word, a->word, 0);
}

void p256_scalar_add(p256_scalar *o, const p256_scalar *a, const p256_scalar *b) {
    // sum is the answer before its reduction. The signer's one call adds z
    // to r*d, and that sum gives d to whoever holds the signature.
    uint32_t sum[WORDS];
    uint32_t carry = add_words(sum, a->word, b->word);
    reduce_once(o->word, sum, carry);
    ct_wipe(sum, sizeof sum);
}

void p256_scalar_mul(p256_scalar *o, const p256_scalar *a, const p256_scalar *b) {
    // Two Montgomery products make one plain product: the first leaves
    // a*b/R, the second multiplies by R^2/R. Both operands stay outside
    // the domain, which is what p256_scalar.h promises its callers.
    uint32_t t[WORDS];
    mont_mul(t, a->word, b->word);
    mont_mul(o->word, t, RR);
}

void p256_scalar_inverse(p256_scalar *o, const p256_scalar *a) {
    uint32_t base[WORDS];
    uint32_t acc[WORDS];
    mont_mul(base, a->word, RR);
    for (int i = 0; i < WORDS; i++) {
        acc[i] = ONE_MONT[i];
    }
    // Square and multiply over the bits of n-2, most significant first.
    // The bit decides whether the round multiplies, and it is a bit of a
    // build constant, so the sequence of operations is the same on every
    // call and depends on nothing in a. The index reads the constant,
    // never a. Shifts stand in for / and % (INV-23).
    for (int i = 256 - 1; i >= 0; i--) {
        mont_mul(acc, acc, acc);
        if ((N_MINUS_2[i >> 5] >> (i & 31)) & 1U) {
            mont_mul(acc, acc, base);
        }
    }
    mont_mul(o->word, acc, ONE);
}
