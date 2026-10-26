// The encodings, the roundings and the three samplers of ML-DSA-87
// signing (FIPS 204 sections 7.1 to 7.4), private to the signer's files
// (docs/decisions.md 159). Every input may be a secret, so no function
// here branches on a coefficient or on a sampled byte, and none indexes
// memory with one. Each loop's count is a constant or a public length.
//
// Two samplers read a secret stream and keep a value only when a test
// passes: RejBoundedPoly, for s1 and s2, and SampleInBall, for c. Here
// each one reads a fixed number of bytes, computes each test as a mask,
// and writes each kept value to every position by mask. So the time and
// the addresses are the same for every stream.
#ifndef CH_MLDSA_SIGN_PACK_H
#define CH_MLDSA_SIGN_PACK_H

#include <stddef.h>
#include <stdint.h>

#include "mldsa_poly.h"

#define MLDS_ETA 2                  // the range of s1 and s2 (FIPS 204 Table 1)
#define MLDS_ETA_BYTES 96           // one s1 or s2 polynomial at 3 bits a coefficient
#define MLDS_T0_BYTES 416           // one t0 polynomial at 13 bits a coefficient
#define MLDS_MASK_BYTES MLD_Z_BYTES // ExpandMask's 20 bits a coefficient
// The SHAKE256 bytes RejBoundedPoly reads: FIPS 204 Appendix C Table 3's
// limit, 481. Fewer than 256 of their 962 half-bytes are under 15 with a
// probability below 2^-256. At that bound key generation fails.
#define MLDS_ETA_STREAM_BYTES 481

// A mask of all ones when a == b, and 0 otherwise.
static inline uint32_t mlds_mask_eq(uint32_t a, uint32_t b) {
    uint32_t d = a ^ b;
    return ((d | (0U - d)) >> 31) - 1U;
}

// b when mask is all ones, and a when it is 0.
static inline uint32_t mlds_select(uint32_t mask, uint32_t a, uint32_t b) {
    return a ^ (mask & (a ^ b));
}

// 1 when |a| >= bound, and 0 otherwise, for |a| below 2^31 - bound and a
// bound from 1 to 2^30.
static inline uint32_t mlds_at_least(int32_t a, int32_t bound) {
    uint32_t sign = (uint32_t)(a >> 31);
    uint32_t magnitude = ((uint32_t)a ^ sign) - sign;
    return ((uint32_t)(bound - 1) - magnitude) >> 31;
}

// FIPS 204 Algorithm 36, Decompose, at gamma2 = (q - 1) / 32, for r in
// [0, q): writes r0 and returns r1, with r = r1 * 2 * gamma2 + r0 mod q.
// mld_use_hint_coefficient computes r1 and r0 the same way.
static inline int32_t mlds_decompose(int32_t r, int32_t *r0) {
    int32_t r1 = (r + 127) >> 7;
    r1 = (r1 * 1025 + (1 << 21)) >> 22;
    r1 &= 15;
    int32_t low = r - r1 * 2 * MLD_GAMMA2;
    *r0 = low - ((((MLD_Q - 1) / 2) - low) >> 31 & MLD_Q);
    return r1;
}

// FIPS 204 Algorithm 35, Power2Round, for r in [0, q): writes t0 in
// (-2^12, 2^12] and returns t1, with r = t1 * 2^13 + t0.
static inline int32_t mlds_power2round(int32_t r, int32_t *t0) {
    int32_t t1 = (r + (1 << (MLD_D - 1)) - 1) >> MLD_D;
    *t0 = r - (t1 << MLD_D);
    return t1;
}

// FIPS 204 Algorithm 16, SimpleBitPack, and Algorithm 17, BitPack: bits
// bits a coefficient, the low bits first. With offset 0 each value is the
// coefficient, and otherwise offset minus the coefficient. out holds
// 32 * bits bytes. bits is 3, 4, 10, 13 or 20.
void mlds_pack(uint8_t *out, const mld_poly *p, unsigned bits, int32_t offset);

// The inverse of mlds_pack with an offset: each coefficient is offset
// minus its bits-bit value.
void mlds_unpack(mld_poly *p, const uint8_t *in, unsigned bits, int32_t offset);

// One polynomial of skDecode's s1 or s2 (FIPS 204 Algorithm 19,
// BitUnpack with a = b = eta). Returns 1 when every 3-bit value is at most
// 2 * eta, so every coefficient is in [-eta, eta], and 0 otherwise. The
// polynomial is written either way.
uint32_t mlds_unpack_eta(mld_poly *p, const uint8_t in[MLDS_ETA_BYTES]);

// FIPS 204 Algorithm 31, RejBoundedPoly, at eta = 2, for the polynomial
// SHAKE256(rho' || nonce) gives (Algorithm 33, ExpandS). Returns 1 when
// MLDS_ETA_STREAM_BYTES bytes give all 256 coefficients, and 0 otherwise.
uint32_t mlds_sample_eta(mld_poly *p, const uint8_t rho_prime[64], uint16_t nonce);

// FIPS 204 Algorithm 34, ExpandMask, for one polynomial: SHAKE256(rho'' ||
// nonce) at 20 bits a coefficient, as gamma1 minus each value.
void mlds_expand_mask(mld_poly *p, const uint8_t rho2[64], uint16_t nonce);

// FIPS 204 Algorithm 29, SampleInBall, over the same MLD_BALL_BYTES bytes
// that mld_sample_in_ball reads. Returns 1 when they place all 60
// coefficients, and 0 otherwise. c is the same polynomial that
// mld_sample_in_ball writes.
uint32_t mlds_sample_in_ball(mld_poly *c, const uint8_t c_tilde[64]);

#endif
