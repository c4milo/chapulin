// A host object's ML-KEM NTT arithmetic: mlkem_poly.c's forward and
// inverse transforms and its base multiplication on eight 16-bit lanes at
// a time, NEON on arm64 and SSE2 on x86-64. mlkem.c calls them in place of
// mlk_poly_ntt, mlk_poly_invntt and mlk_poly_basemul in a host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h), and mlkem_poly.c's loops stay the
// reference and a device object's path: bin/mlkem_vector_equiv_test
// compares the two over the same inputs.
//
// Each lane computes the value mlkem_poly.c's loops compute for its
// coefficient: the same Montgomery and Barrett reductions, to the same
// int16 result, for every int16 input. mlkem_vector.c shows why each lane
// formula is exact.
//
// It is constant time: adds, subtracts, 16x16 multiplies and fixed lane
// shuffles, each on every lane, with no branch on a coefficient and no
// address computed from one. Only the loop indices, which are public,
// choose which coefficients and which twiddle factors a step reads.
#ifndef CH_MLKEM_VECTOR_H
#define CH_MLKEM_VECTOR_H

// cpu_cfg.h refuses CH_CPU_RUNTIME for a target with neither NEON nor
// SSE2, so mlkem_vector.c picks between the two on __ARM_NEON alone. The
// compiler's own macros are the whole detection, as in chacha20_vector.h:
// every AArch64 core has NEON and every x86-64 core has SSE2.
#include "cpu_cfg.h"
#include "mlkem_poly.h"

// Everything below exists only in a host object, the way
// chacha20_vector.h's ChaCha20 does.
#ifdef CH_CPU_RUNTIME

// mlk_poly_ntt's transform of p, the Barrett reduction at its end
// included, over the same twiddle factors (mlkem_zetas.h).
void mlk_vector_ntt(mlk_poly *p);

// mlk_poly_invntt's transform of p, the multiply by 1441 at its end
// included.
void mlk_vector_invntt(mlk_poly *p);

// mlk_poly_basemul's product of a and b into r, which must not overlap
// either.
void mlk_vector_basemul(mlk_poly *r, const mlk_poly *a, const mlk_poly *b);

#endif // CH_CPU_RUNTIME

#endif
