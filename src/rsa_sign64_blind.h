// The blinded exponents of rsa_sign64.c, which alone includes this header (docs/decisions.md
// 187). Each half of a signature walks dp + r_p (p - 1)
// modulo p and dq + r_q (q - 1) modulo q, for r_p and r_q the two 64-bit numbers of the
// caller's blind. Its functions are static, and proof/rsa_sign64_crt_harness.c proves them
// through rsa_sign64.c.
#ifndef CH_RSA_SIGN64_BLIND_H
#define CH_RSA_SIGN64_BLIND_H

#include <stddef.h>
#include <stdint.h>

#include "ch_assert.h"
#include "rsa_mont64.h"
#include "rsa_sign.h"

// The bytes of one prime's r, and the bytes a blinded exponent takes
// beyond its prime's: r is below 2^64, so d + r (p - 1) is below 2^64 p.
// The caller's blind holds r_p and then r_q.
#define BLIND_R_LEN 8
// The words of the largest prime: half the largest modulus's words.
#define BLIND_PRIME_WORDS_MAX (RSA_MONT64_WORDS_MAX / 2)
#define EXPONENT_LEN_MAX (CH_RSA_MODULUS_MAX / 2 + BLIND_R_LEN)

_Static_assert(2 * BLIND_R_LEN == RSA_BLIND_LEN, "the blind holds r_p and then r_q");

// e = d + r (p - 1) in half_len + BLIND_R_LEN big-endian bytes: one
// prime's blinded exponent. d and p are the half_len big-endian bytes of
// the prime's exponent and the prime, and r is the BLIND_R_LEN bytes at
// r_bytes read as a little-endian number. p is odd (rsa_sign64_key_ok), so
// p - 1 is p with its low bit cleared and no borrow. m^e = m^d mod p for
// every m (spec/lean/Spec/RsaBlind.lean, crt_blinded_pow_mod). Each word is
// one rsa_mont64_mul_add_add, whose product is one ct_mul128, so no branch
// or index reads d, p or r. Its arrays lie under rsa_sign64_sp1's frame,
// where that wrapper's wipe clears them, so it wipes none of them.
static void blinded_prime_exponent(uint8_t *e, const uint8_t *d, const uint8_t *p, size_t half_len,
                                   const uint8_t r_bytes[BLIND_R_LEN]) {
    size_t k = (half_len + 7) >> 3;
    CH_ASSERT(k >= 1 && k <= BLIND_PRIME_WORDS_MAX);
    uint64_t d_words[BLIND_PRIME_WORDS_MAX];
    uint64_t p_words[BLIND_PRIME_WORDS_MAX];
    uint64_t sum[BLIND_PRIME_WORDS_MAX + 1];
    rsa_mont64_from_bytes(d_words, k, d, half_len);
    rsa_mont64_from_bytes(p_words, k, p, half_len);
    p_words[0] &= ~(uint64_t)1;
    uint64_t r = 0;
    for (size_t i = BLIND_R_LEN; i-- > 0;) {
        r = (r << 8) | r_bytes[i];
    }
    uint64_t carry = 0;
    for (size_t i = 0; i < k; i++) {
        rsa_mont64_sum step = rsa_mont64_mul_add_add(r, p_words[i], d_words[i], carry);
        sum[i] = step.low;
        carry = step.high;
    }
    sum[k] = carry;
    rsa_mont64_to_bytes(e, half_len + BLIND_R_LEN, sum);
}

// e_p and e_q, the blinded dp and dq of k, each half_len + BLIND_R_LEN
// bytes: dp under r_p, the first BLIND_R_LEN bytes of blind, and dq under
// r_q, the last.
static void blinded_exponents(uint8_t *e_p, uint8_t *e_q, const ch_rsa_priv *k, size_t half_len,
                              const uint8_t blind[RSA_BLIND_LEN]) {
    blinded_prime_exponent(e_p, k->dp, k->p, half_len, blind);
    blinded_prime_exponent(e_q, k->dq, k->q, half_len, blind + BLIND_R_LEN);
}

#endif
