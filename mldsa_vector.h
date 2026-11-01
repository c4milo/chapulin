// A host object's ML-DSA-87 NTT arithmetic: mldsa_poly.c's forward and
// inverse transforms and its two products in the NTT domain on 32-bit
// lanes, four to a NEON register on arm64 (docs/decisions.md 172) and
// eight to an AVX2 register on x86-64 (docs/decisions.md 174). mldsa.c
// calls them in place of mld_poly_ntt, mld_poly_invntt_tomont,
// mld_poly_pointwise and mld_poly_pointwise_acc, and the signer calls them
// through mldsa_sign_poly.h's dispatchers, each for a session whose
// ch_cfg.cpu mld_vector_runs takes. mldsa_poly.c's and mldsa_sign_poly.c's
// loops stay the references and a device object's path:
// bin/mldsa_vector_equiv_test compares the lanes with both.
//
// Each lane computes the value the loops compute for its coefficient: the
// same reductions, to the same int32 result, for every int32 input.
// mldsa_vector.c shows why each lane formula is exact.
//
// It has no branch on a coefficient and no address computed from one. The
// loop indices, which are public, alone choose which coefficients and
// which twiddle factors a step reads. Its multiplies are 32 bits by 32,
// wider than ct.h's pieces, so the signer runs it only under the multiply
// bit, the caller's statement about every widening multiply the session
// runs. On x86-64 each entry ends with VZEROALL, which writes zero to ymm0
// to ymm15, because the signer's lanes hold secrets there.
#ifndef CH_MLDSA_VECTOR_H
#define CH_MLDSA_VECTOR_H

#include <stdint.h>

#include "cpu_cfg.h"
#include "mldsa_poly.h"

// MLD_VECTOR is 1 where the object holds the lanes: a host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) for arm64 or x86-64. It is 0 in every
// other object, so a caller tests it and mld_vector_runs, and never an
// architecture macro.
#if defined(CH_CPU_RUNTIME) && (defined(__ARM_NEON) || defined(__x86_64__))
#define MLD_VECTOR 1
#else
#define MLD_VECTOR 0
#endif

// Whether a call runs the lanes for a session whose ch_cfg.cpu is cpu.
// secret is 1 for the signer, whose operands are s1, s2, t0, y and c, and
// 0 for the verifier, whose operands are public.
//
//   - The signer needs CH_CPU_CONSTANT_TIME_MULTIPLY: the lanes' 32x32
//     products are wider than ct.h's pieces.
//   - On x86-64 both need CH_CPU_AVX2, because AVX2 is not on every x86-64
//     CPU. Every arm64 CPU has NEON, so there the verifier needs no bit.
//
// cpu is the caller's description and not a secret. A call that holds no
// cpu passes 0, which names no lanes on x86-64.
static inline int mld_vector_runs(uint32_t cpu, int secret) {
#if MLD_VECTOR
    uint32_t need = secret ? CH_CPU_CONSTANT_TIME_MULTIPLY : 0;
#ifdef __x86_64__
    need |= CH_CPU_AVX2;
#endif
    return (cpu & need) == need;
#else
    (void)cpu;
    (void)secret;
    return 0;
#endif
}

#if MLD_VECTOR

// mld_poly_ntt's transform of p, the reduction at its start included.
void mld_vector_ntt(mld_poly *p);

// mld_poly_invntt_tomont's transform of p, the reduction at its start and
// the multiply by 41978 at its end included.
void mld_vector_invntt_tomont(mld_poly *p);

// mld_poly_pointwise's product of a and b into r. r may be a or b.
void mld_vector_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b);

// mld_poly_pointwise_acc's sum into acc. acc may be a or b.
void mld_vector_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b);

#endif // MLD_VECTOR

#endif
