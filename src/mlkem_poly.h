// Z_q arithmetic and the Ring R_q = Z_q[X]/(X^256+1) for ML-KEM, at the
// ranks mlkem.h's mlkem_rank_held names.
// Private to the mlkem_*.c files; nothing below tls.h includes it.
//
// A polynomial is 256 signed coefficients. Coefficients stay in the
// signed range roughly (-q, q) between operations; every routine that
// serializes first freezes to the canonical [0, q). All reduction is
// multiply-shift (Barrett) or Montgomery multiply, never a divide
// instruction (INV-23).
#ifndef CH_MLKEM_POLY_H
#define CH_MLKEM_POLY_H

#include <stddef.h>
#include <stdint.h>

#include "mlkem.h"

// eta1 and eta2 are 2 in both parameter sets (FIPS 203 Table 2).
#define MLK_ETA 2 // CBD parameter: noise is centered binomial with eta=2

// Which compression widths the object compiles: du=10 and dv=4 for
// ML-KEM-768, du=11 and dv=5 for ML-KEM-1024 (FIPS 203 Table 2).
#if !defined(CH_MLKEM_1024) || defined(CH_MLKEM_TWO_RANKS)
#define MLK_HOLDS_768 1
#else
#define MLK_HOLDS_768 0
#endif
#if defined(CH_MLKEM_1024) || defined(CH_MLKEM_TWO_RANKS)
#define MLK_HOLDS_1024 1
#else
#define MLK_HOLDS_1024 0
#endif

// The rank a call runs: MLKEM_K in an object that holds one rank, and
// under CH_MLKEM_TWO_RANKS 4 for 4 and 3 for any other value. Every loop
// and length below takes its rank from here, so no rank value reads or
// writes past a vector of MLKEM_K_MAX polys.
static inline unsigned mlk_rank(unsigned rank) {
#ifdef CH_MLKEM_TWO_RANKS
    return rank == MLKEM_RANK_1024 ? MLKEM_RANK_1024 : MLKEM_RANK_768;
#else
    (void)rank;
    return MLKEM_K;
#endif
}

// du and dv at a rank mlk_rank returned.
static inline unsigned mlk_du(unsigned rank) {
    return rank == MLKEM_RANK_1024 ? 11U : 10U;
}

static inline unsigned mlk_dv(unsigned rank) {
    return rank == MLKEM_RANK_1024 ? 5U : 4U;
}

#define MLK_POLY_BYTES 384 // 256 coefficients at 12 bits each
// One poly at dv bits, 256*dv/8 bytes; one poly of u at du bits; and the
// rank polys of u, which a ciphertext holds ahead of v.
static inline size_t mlk_poly_comp_bytes(unsigned rank) {
    return (size_t)32 * mlk_dv(rank);
}

static inline size_t mlk_poly_comp_du_bytes(unsigned rank) {
    return (size_t)32 * mlk_du(rank);
}

static inline size_t mlk_polyvec_comp_bytes(unsigned rank) {
    return mlk_poly_comp_du_bytes(rank) * rank;
}
// Rejection-sampling read cap, in three-byte groups: 1536 XOF bytes.
// 704 already put the probability of needing more below 2^-128, and
// the cap is what makes the sampling loop CBMC-unwindable.
#define MLK_SAMPLE_GROUPS 512
// The sampler squeezes eight groups, 24 bytes, a call: MLK_SAMPLE_CHUNKS
// calls at most. 24 divides SHAKE128's 168-byte block, so a group never
// spans two blocks.
#define MLK_SAMPLE_CHUNK_GROUPS 8
#define MLK_SAMPLE_CHUNKS 64
#define MLK_CBD_BYTES 128 // PRF output feeding CBD: 64*eta

typedef struct {
    int16_t coeffs[MLKEM_N];
} mlk_poly;

typedef struct {
    mlk_poly vec[MLKEM_K_MAX];
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

// Compress_du / Decompress_du over one poly of the u vector, at du=10
// bits for rank 3 or 11 for rank 4, over mlk_poly_comp_du_bytes bytes.
// rank is a value mlk_rank returned. A ciphertext's u is the rank polys
// side by side, so K-PKE codes one poly at a time and keeps no u vector.
void mlk_poly_compress_du(uint8_t *out, const mlk_poly *p, unsigned rank);
void mlk_poly_decompress_du(mlk_poly *p, const uint8_t *in, unsigned rank);

// Compress_dv / Decompress_dv over the v poly, at dv=4 bits for rank 3 or
// 5 for rank 4, over mlk_poly_comp_bytes bytes.
void mlk_poly_compress(uint8_t *out, const mlk_poly *p, unsigned rank);
void mlk_poly_decompress(mlk_poly *p, const uint8_t *in, unsigned rank);

// One message bit per coefficient: Decompress_1 on encode, Compress_1 on
// decode (FIPS 203 ByteDecode_1 / ByteEncode_1 with compression).
void mlk_poly_frommsg(mlk_poly *p, const uint8_t msg[32]);
void mlk_poly_tomsg(uint8_t msg[32], const mlk_poly *p);

// SampleNTT: rejection-sample one NTT-domain poly from SHAKE128(seed ||
// x0 || x1). seed is the 32-byte public rho.
void mlk_sample_ntt(mlk_poly *p, const uint8_t seed[32], uint8_t x0, uint8_t x1);

// SampleNTT's rejection step (FIPS 203 Algorithm 7) over groups three-byte
// groups at buf: each group gives two 12-bit candidates, and each one
// below q becomes coefficient j of p, then j + 1, until p holds 256.
// Returns how many p then holds, for a j from 0 to 256 on entry.
// mlk_sample_ntt runs it on each chunk it squeezes, and a host object's
// mlkem_avx2.c on each block of the streams it squeezes side by side, so
// both read a stream by the one rule CBMC proves. The candidates come from
// the public seed, so the branches read nothing secret.
static inline unsigned mlk_sample_groups(mlk_poly *p, unsigned j, const uint8_t *buf,
                                         size_t groups) {
    for (size_t group = 0; group < groups && j < 256; group++) {
        const uint8_t *b = buf + 3 * group;
        uint16_t d1 = (uint16_t)(b[0] | ((uint16_t)(b[1] & 0x0f) << 8));
        uint16_t d2 = (uint16_t)((b[1] >> 4) | ((uint16_t)b[2] << 4));
        if (d1 < MLKEM_Q) {
            p->coeffs[j] = (int16_t)d1;
            j++;
        }
        if (d2 < MLKEM_Q && j < 256) {
            p->coeffs[j] = (int16_t)d2;
            j++;
        }
    }
    return j;
}

// SamplePolyCBD_eta: centered binomial noise from PRF(seed, nonce) =
// SHAKE256(seed || nonce).
void mlk_sample_cbd(mlk_poly *p, const uint8_t seed[32], uint8_t nonce);

#ifdef CH_CPU_RUNTIME
// The native copies of the entries above that are built on the widening multiply,
// which a host object holds beside them (mlkem_poly_native.c, widemul_native.h) and
// widemul.h's dispatchers call for WIDEMUL_CONSTANT_TIME.
void mlk_poly_compress_du_native(uint8_t *out, const mlk_poly *p, unsigned rank);
void mlk_poly_compress_native(uint8_t *out, const mlk_poly *p, unsigned rank);
void mlk_poly_tomsg_native(uint8_t msg[32], const mlk_poly *p);
#endif

#endif
