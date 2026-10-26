// Z_q arithmetic and the ring R_q = Z_q[X]/(X^256 + 1) for ML-DSA-87, at
// q = 8380417 (FIPS 204 sections 7.4 to 7.6). Private to mldsa.c and
// mldsa_poly.c.
//
// A polynomial is 256 int32_t coefficients. Every function below takes
// every int32_t value in every coefficient: each one reduces its inputs
// before it adds or multiplies them, so no input makes it overflow. The
// CBMC harnesses prove that on all of int32_t (docs/verification.md).
//
// The arithmetic is a multiply and a shift, never a divide, and it runs
// on public values alone. The coefficient functions sit in this header,
// so that a harness can replace each one with its contract
// (proof/mldsa_stubs.h).
#ifndef CH_MLDSA_POLY_H
#define CH_MLDSA_POLY_H

#include <stddef.h>
#include <stdint.h>

#define MLD_N 256
#define MLD_Q 8380417
#define MLD_QINV 58728449U                 // q^-1 mod 2^32
#define MLD_D 13                           // the bits t0 drops from t (FIPS 204 Table 1)
#define MLD_K 8                            // rows of A
#define MLD_L 7                            // columns of A
#define MLD_TAU 60                         // the nonzero coefficients of c
#define MLD_BETA 120                       // tau * eta
#define MLD_GAMMA1 (1 << 19)               // the range of z
#define MLD_GAMMA2 ((MLD_Q - 1) / 32)      // the low-order rounding range, 261888
#define MLD_OMEGA 75                       // the most hints a signature carries
#define MLD_RHO_BYTES 32                   // the seed of A at the head of pk
#define MLD_T1_BYTES 320                   // one t1 polynomial at 10 bits a coefficient
#define MLD_Z_BYTES 640                    // one z polynomial at 20 bits a coefficient
#define MLD_W1_BYTES 128                   // one w1 polynomial at 4 bits a coefficient
#define MLD_HINT_BYTES (MLD_OMEGA + MLD_K) // the hint encoding at the end of sig
// The SHAKE128 blocks RejNTTPoly reads for one entry of A: 336 three-byte
// groups. Fewer than 256 of them fall under q with a probability below
// 2^-546. At that bound the sampler stops and verification fails
// (docs/decisions.md 154).
#define MLD_SAMPLE_BLOCKS 6
#define MLD_SAMPLE_BLOCK_GROUPS 56 // 168 bytes a block, three to a group
// The SHAKE256 bytes SampleInBall reads: the 8 sign bytes and 264 index
// bytes, two blocks. The 60 positions need more than 264 index bytes with a
// probability below 2^-347. At that bound the sampler stops and
// verification fails.
#define MLD_BALL_BYTES 272

typedef struct {
    int32_t coeffs[MLD_N];
} mld_poly;

// A value congruent to a mod q, with |result| <= 6291200, for every int32_t
// a: a minus round(a / 2^23) times q.
static inline int32_t mld_reduce32(int32_t a) {
    int32_t t = (int32_t)(((int64_t)a + (1 << 22)) >> 23);
    return (int32_t)((int64_t)a - (int64_t)t * MLD_Q);
}

// a * 2^-32 mod q, for |a| below 2^62 (FIPS 204 Appendix A). t is the low
// 32 bits of a * q^-1, so a - t * q is a multiple of 2^32. For |a| at most
// 2^31 * q the result is under q in absolute value.
static inline int32_t mld_montgomery_reduce(int64_t a) {
    int32_t t = (int32_t)(uint32_t)((uint64_t)a * MLD_QINV);
    return (int32_t)((a - (int64_t)t * MLD_Q) >> 32);
}

// zeta * a * 2^-32 mod q. For |zeta| <= (q - 1) / 2, the bound every entry
// of MLD_ZETAS and the inverse transform's scale meet, the product is under
// 2^31 * q / 2, so the result is under q in absolute value for every
// int32_t a.
static inline int32_t mld_mul_zeta(int32_t zeta, int32_t a) {
    return mld_montgomery_reduce((int64_t)zeta * a);
}

// a * b * 2^-32 mod q, under q in absolute value, for every int32_t a and
// b: each operand is reduced first, so the product is under 6291200^2.
static inline int32_t mld_mul_reduced(int32_t a, int32_t b) {
    return mld_montgomery_reduce((int64_t)mld_reduce32(a) * mld_reduce32(b));
}

// FIPS 204 Algorithm 40, UseHint, at gamma2 = (q - 1) / 32: the high bits
// r1 of w mod q, moved one step around 0..15 when hint is 1. r1 comes from
// Algorithm 36, Decompose, as a multiply and a shift: (r + 127) >> 7 is
// ceil(r / 128), and times 1025 / 2^22 it rounds to r / (2 * gamma2). At
// r1 = 16, the case r - r0 = q - 1, the mask gives 0, and r0 goes below 0.
// Returns a value in 0..15 for every int32_t w.
static inline uint32_t mld_use_hint_coefficient(int32_t w, uint32_t hint) {
    int32_t r = mld_reduce32(w);
    r += (r >> 31) & MLD_Q;
    int32_t r1 = (r + 127) >> 7;
    r1 = (r1 * 1025 + (1 << 21)) >> 22;
    r1 &= 15;
    int32_t r0 = r - r1 * 2 * MLD_GAMMA2;
    r0 -= (((MLD_Q - 1) / 2 - r0) >> 31) & MLD_Q;
    if (hint == 0) {
        return (uint32_t)r1;
    }
    if (r0 > 0) {
        return (uint32_t)(r1 + 1) & 15U;
    }
    return (uint32_t)(r1 - 1) & 15U;
}

// FIPS 204 Algorithm 41, NTT. The coefficients are reduced first, and the
// output stays under 2^27 in absolute value.
void mld_poly_ntt(mld_poly *p);

// FIPS 204 Algorithm 42, NTT^-1, times 2^32: the factor that cancels the
// 2^-32 each product below leaves. The coefficients are reduced first, and
// the output is under q in absolute value.
void mld_poly_invntt_tomont(mld_poly *p);

// r = a o b * 2^-32, the product in the NTT domain (FIPS 204 Algorithm 45,
// MultiplyNTT). r may be a or b.
void mld_poly_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b);

// acc = acc + a o b * 2^-32, with acc reduced before the sum. acc may be a
// or b.
void mld_poly_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b);

// r = a - b, each reduced before the difference. r may be a or b.
void mld_poly_sub(mld_poly *r, const mld_poly *a, const mld_poly *b);

// One polynomial of pkDecode's t1 (FIPS 204 Algorithm 23, SimpleBitUnpack
// at 10 bits), times 2^d: each coefficient is in 0..2^23 - 2^13.
void mld_poly_unpack_t1_shifted(mld_poly *p, const uint8_t in[MLD_T1_BYTES]);

// One polynomial of sigDecode's z (FIPS 204 Algorithm 27, BitUnpack with
// a = gamma1 - 1 and b = gamma1). Returns 1 when every coefficient is under
// gamma1 - beta in absolute value, and 0 otherwise.
int mld_poly_unpack_z(mld_poly *p, const uint8_t in[MLD_Z_BYTES]);

// w1Encode of one row (FIPS 204 Algorithm 28): UseHint on each coefficient
// of w, packed at 4 bits. The hints are hint_count coefficient positions at
// hints, in increasing order, as HintBitUnpack reads them.
void mld_poly_use_hint(uint8_t out[MLD_W1_BYTES], const mld_poly *w, const uint8_t *hints,
                       size_t hint_count);

// FIPS 204 Algorithm 30, RejNTTPoly, for entry A[r][s]: SHAKE128(rho || s ||
// r). Returns 1 when MLD_SAMPLE_BLOCKS blocks give all 256 coefficients,
// and 0 otherwise.
int mld_sample_ntt(mld_poly *p, const uint8_t rho[MLD_RHO_BYTES], uint8_t s, uint8_t r);

// RejNTTPoly's step over groups three-byte groups at buf (FIPS 204
// Algorithm 14, CoeffFromThreeBytes): each group whose 23-bit value is
// under q becomes coefficient j of p, then j + 1, until p holds 256.
// Returns how many p then holds, for a j from 0 to 256 on entry.
unsigned mld_sample_groups(mld_poly *p, unsigned j, const uint8_t *buf, size_t groups);

// FIPS 204 Algorithm 29, SampleInBall: tau coefficients of +1 or -1 from
// SHAKE256(c_tilde). Returns 1 when MLD_BALL_BYTES bytes place all 60, and
// 0 otherwise.
int mld_sample_in_ball(mld_poly *c, const uint8_t c_tilde[64]);

#endif
