// Z_q arithmetic and the Ring R_q = Z_q[X]/(X^256+1) for ML-KEM-768.
// Private to the mlkem_*.c files; nothing below tls.h includes it.
//
// A polynomial is 256 signed coefficients. Coefficients stay in the
// signed range roughly (-q, q) between operations; every routine that
// serializes first freezes to the canonical [0, q). All reduction is
// multiply-shift (Barrett) or Montgomery multiply, never a divide
// instruction (INV-23).
#ifndef CH_MLKEM_POLY_H
#define CH_MLKEM_POLY_H

#include <stdint.h>

#include "mlkem.h"

#define MLK_ETA 2               // CBD parameter: noise is centered binomial with eta=2
#define MLK_DU 10               // ciphertext u compression bits
#define MLK_DV 4                // ciphertext v compression bits
#define MLK_POLY_BYTES 384      // 256 coefficients at 12 bits each
#define MLK_POLYVEC_BYTES 1152  // MLK_POLY_BYTES * 3
#define MLK_POLY_COMP_BYTES 128 // one poly at dv=4 bits: 256*4/8
// Rejection-sampling read cap, in three-byte groups: 1536 XOF bytes.
// 704 already put the probability of needing more below 2^-128, and
// the cap is what makes the sampling loop CBMC-unwindable.
#define MLK_SAMPLE_GROUPS 512
#define MLK_POLYVEC_COMP_BYTES 960 // three polys at du=10 bits: 3*256*10/8
#define MLK_CBD_BYTES 128          // PRF output feeding CBD: 64*eta

typedef struct {
    int16_t coeffs[MLKEM_N];
} mlk_poly;

typedef struct {
    mlk_poly vec[MLKEM_K];
} mlk_polyvec;

// Number-theoretic transform and its inverse, matched to the coefficient
// order SampleNTT and ByteEncode_12 use, so an NTT-domain polynomial
// serializes directly. mlk_poly_ntt Barrett-reduces the result.
void mlk_poly_ntt(mlk_poly *p);
void mlk_poly_invntt(mlk_poly *p);

// Pointwise product in the NTT domain (FIPS 203 MultiplyNTTs). The
// result carries a Montgomery R^-1 factor; callers correct it with
// mlk_poly_tomont or absorb it in a later inverse NTT.
void mlk_poly_basemul(mlk_poly *r, const mlk_poly *a, const mlk_poly *b);

void mlk_poly_add(mlk_poly *r, const mlk_poly *a, const mlk_poly *b);
void mlk_poly_sub(mlk_poly *r, const mlk_poly *a, const mlk_poly *b);
void mlk_poly_reduce(mlk_poly *p); // Barrett-reduce every coefficient
void mlk_poly_tomont(mlk_poly *p); // multiply every coefficient by R mod q

// ByteEncode_12 / ByteDecode_12: canonical 12-bit packing of one poly.
void mlk_poly_tobytes(uint8_t out[MLK_POLY_BYTES], const mlk_poly *p);
void mlk_poly_frombytes(mlk_poly *p, const uint8_t in[MLK_POLY_BYTES]);

// Compress_du / Decompress_du over the u vector (du=10 bits).
void mlk_polyvec_compress(uint8_t out[MLK_POLYVEC_COMP_BYTES], const mlk_polyvec *v);
void mlk_polyvec_decompress(mlk_polyvec *v, const uint8_t in[MLK_POLYVEC_COMP_BYTES]);

// Compress_dv / Decompress_dv over the v poly (dv=4 bits).
void mlk_poly_compress(uint8_t out[MLK_POLY_COMP_BYTES], const mlk_poly *p);
void mlk_poly_decompress(mlk_poly *p, const uint8_t in[MLK_POLY_COMP_BYTES]);

// One message bit per coefficient: Decompress_1 on encode, Compress_1 on
// decode (FIPS 203 ByteDecode_1 / ByteEncode_1 with compression).
void mlk_poly_frommsg(mlk_poly *p, const uint8_t msg[32]);
void mlk_poly_tomsg(uint8_t msg[32], const mlk_poly *p);

// SampleNTT: rejection-sample one NTT-domain poly from SHAKE128(seed ||
// x0 || x1). seed is the 32-byte public rho.
void mlk_sample_ntt(mlk_poly *p, const uint8_t seed[32], uint8_t x0, uint8_t x1);

// SamplePolyCBD_eta: centered binomial noise from PRF(seed, nonce) =
// SHAKE256(seed || nonce).
void mlk_sample_cbd(mlk_poly *p, const uint8_t seed[32], uint8_t nonce);

#endif
