// RSA's Montgomery arithmetic on 64-bit words: multiplication modulo an
// odd number, on little-endian words in uint64_t, every product one
// ct_mul128, the 64x64->128 multiply ct.h defines for a host object alone.
// A host object (-DCH_CPU_RUNTIME, cpu_cfg.h) holds it, and a device
// object holds none of it: rsa_mont.c's 32-bit words are what a device
// object runs, and they stay the reference that bin/rsa_equiv_test
// compares this file with (docs/decisions.md 95).
//
// Its caller is rsa_vp1 (rsa_mont.c), the public operation both verifiers
// run, in every session of a host object. A modulus, a signature and an
// encoded message are public, so the multiply's timing needs no statement
// from anybody there.
//
// Everything here is constant time in every word all the same: no branch
// and no memory index depends on a word's value. A loop counts words, and
// rsa_mont64_modulus_init counts doublings from its bits argument; both
// are public for every caller. The one instruction whose timing the C
// cannot state is the multiply.
#ifndef CH_RSA_MONT64_H
#define CH_RSA_MONT64_H

#include <stddef.h>
#include <stdint.h>

#include "ct.h"
#include "rsa.h" // CH_RSA_MODULUS_MAX

#ifdef CH_CPU_RUNTIME

// One word per 8 bytes of modulus: RSA-2048 is 32 words, RSA-3072 is 48
// and RSA-4096 is 64. The count follows the one bound rsa.h defines, as
// rsa_mont.c's does.
#define RSA_MONT64_WORDS_MAX (CH_RSA_MODULUS_MAX / 8)

// A modulus and what a Montgomery multiplication under it reads. R is
// 2^(64 * words).
typedef struct {
    uint64_t m[RSA_MONT64_WORDS_MAX];  // the modulus, odd
    uint64_t r2[RSA_MONT64_WORDS_MAX]; // R^2 mod m, which moves a number into the Montgomery domain
    uint64_t m0inv;                    // -m^-1 mod 2^64
    size_t words;                      // 1..RSA_MONT64_WORDS_MAX
} rsa_mont64_modulus;

// A value of up to 128 bits as two words.
typedef struct {
    uint64_t low;
    uint64_t high;
} rsa_mont64_sum;

// The two forms of the step below, and the one each compiler reads: the compare form under
// clang and the 128-bit sum under any other compiler (docs/decisions.md 117). A build may name
// either with -DRSA_MONT64_STEP=, as the proofs and bin/rsa_equiv_test_compare and
// bin/rsa_equiv_test_sum do, so that each form runs whatever compiler builds them.
#define RSA_MONT64_STEP_COMPARE 1
#define RSA_MONT64_STEP_SUM 2
#ifndef RSA_MONT64_STEP
#ifdef __clang__
#define RSA_MONT64_STEP RSA_MONT64_STEP_COMPARE
#else
#define RSA_MONT64_STEP RSA_MONT64_STEP_SUM
#endif
#endif
#if RSA_MONT64_STEP != RSA_MONT64_STEP_COMPARE && RSA_MONT64_STEP != RSA_MONT64_STEP_SUM
#error "RSA_MONT64_STEP names neither form of rsa_mont64_mul_add_add"
#endif

// x * y + a + b, which is at most (2^64 - 1)^2 + 2 * (2^64 - 1) = 2^128 - 1. rsa_mont64.c runs
// one for each product of a multiplication's and a square's inner loops, where b is the carry
// from the word below.
//
// The sum form is one 128-bit sum, the form the rest of rsa_mont64.c takes. Apple clang 21 for
// arm64 adds a and b first there, and each word of a loop then waits three instructions on the
// carry of the word before it. In the compare form two 64-bit adds wrap on purpose, the compare
// after each is its carry, and b goes in last, so the carry waits two. gcc 13 for x86-64 keeps
// the compare form's product in a stack slot of its own, which holds a secret word after a
// signer's last product, so gcc reads the sum form, where its carry waits two already. The
// proofs replace this function with the 128-bit sum (proof/rsa_mont64_stubs.h), and
// proof/rsa_mont64_step_harness.c and proof/rsa_mont64_step_sum_harness.c prove each form
// equal to it for every input.
static inline rsa_mont64_sum rsa_mont64_mul_add_add(uint64_t x, uint64_t y, uint64_t a,
                                                    uint64_t b) {
#if RSA_MONT64_STEP == RSA_MONT64_STEP_COMPARE
    ct_u128 product = ct_mul128(x, y);
    uint64_t low = (uint64_t)product;
    uint64_t high = (uint64_t)(product >> 64);
    uint64_t first = low + a;
    high += (uint64_t)(first < low);
    uint64_t second = first + b;
    high += (uint64_t)(second < first);
    rsa_mont64_sum sum = {second, high};
#else
    ct_u128 value = ct_mul128(x, y) + a + b;
    rsa_mont64_sum sum = {(uint64_t)value, (uint64_t)(value >> 64)};
#endif
    return sum;
}

// words[0..count) = the len big-endian bytes at bytes, as a number. It
// needs len <= 8 * count, and the words past the number are zero.
void rsa_mont64_from_bytes(uint64_t *words, size_t count, const uint8_t *bytes, size_t len);

// The low len bytes of the number in words, big-endian, at bytes. It
// reads the words that hold those bytes, (len + 7) / 8 of them.
void rsa_mont64_to_bytes(uint8_t *bytes, size_t len, const uint64_t *words);

// Writes *mod for the modulus in the m_len big-endian bytes at m, in
// (m_len + 7) / 8 words. bits is the modulus's bit length, the position
// of its top set bit plus one, which the caller knows without reading a
// secret: rsa_mont.c counts it from a public modulus.
//
// It needs 1 <= m_len <= CH_RSA_MODULUS_MAX and 1 <= bits <= 8 * m_len,
// which CH_ASSERT holds, and an odd modulus with that bit length, which
// it does not check: for any other modulus it writes words that are no
// function a caller can use, inside the same bounds and in the same time.
//
// The time is that of 66 * words - bits + 1 doublings and five
// multiplications, so it depends on m_len and bits alone.
void rsa_mont64_modulus_init(rsa_mont64_modulus *mod, const uint8_t *m, size_t m_len, size_t bits);

// Writes what rsa_mont64_modulus_init writes but r2: the modulus's words,
// m0inv and words, for 1 <= m_len <= CH_RSA_MODULUS_MAX, which CH_ASSERT
// holds. rsa_mont64_modulus_init calls it first. rsa_mont.c calls it for
// a public modulus and writes r2 itself, by a division whose time depends
// on the modulus (docs/decisions.md 103).
void rsa_mont64_modulus_load(rsa_mont64_modulus *mod, const uint8_t *m, size_t m_len);

// o = a * b / R mod m, the Montgomery product, over mod->words words. It
// needs b below m, and takes any a; the result is below m. o may be a or
// b, or both.
void rsa_mont64_mont_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                         const rsa_mont64_modulus *mod);

// o = a * a / R mod m, the Montgomery square: the words
// rsa_mont64_mont_mul(o, a, a, mod) writes, from about three quarters of
// its products. It needs a below m, and the result is below m. o may be
// a.
void rsa_mont64_mont_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod);

// o = a + b mod m, for a and b below m. o may be a or b.
void rsa_mont64_add(uint64_t *o, const uint64_t *a, const uint64_t *b,
                    const rsa_mont64_modulus *mod);

// o = a - b mod m, for a and b below m. o may be a or b.
void rsa_mont64_sub(uint64_t *o, const uint64_t *a, const uint64_t *b,
                    const rsa_mont64_modulus *mod);

// o = a mod m, for a below 2m: one subtraction of m, chosen by a mask.
// o may be a.
void rsa_mont64_reduce_once(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod);

// o = a * b + c, the plain product and not a Montgomery one: a, b and c
// are k words each and o is 2k words, which the sum always fits. o
// overlaps none of the three.
void rsa_mont64_mul_add(uint64_t *o, const uint64_t *a, const uint64_t *b, const uint64_t *c,
                        size_t k);

// out = base^65537 mod m (RSAVP1, RFC 8017 5.2.2), base and out both len
// big-endian bytes, len <= 8 * mod->words. It takes any base of that
// length: the result is a function of base mod m.
void rsa_mont64_public(uint8_t *out, const uint8_t *base, size_t len,
                       const rsa_mont64_modulus *mod);

#endif // CH_CPU_RUNTIME

#endif
