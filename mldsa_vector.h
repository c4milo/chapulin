// A host object's ML-DSA-87 NTT arithmetic: mldsa_poly.c's forward and
// inverse transforms and its two products in the NTT domain on four
// 32-bit NEON lanes at a time (docs/decisions.md 172). mldsa.c calls them
// in place of mld_poly_ntt, mld_poly_invntt_tomont, mld_poly_pointwise and
// mld_poly_pointwise_acc in every session, because the verifier's inputs
// are public. The signer calls them through mldsa_sign_poly.h's
// dispatchers, for a session whose ch_cfg.cpu holds
// CH_CPU_CONSTANT_TIME_MULTIPLY alone. mldsa_poly.c's and
// mldsa_sign_poly.c's loops stay the references and a device object's
// path: bin/mldsa_vector_equiv_test compares the lanes with both.
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
// runs.
//
// Only NEON holds the lanes in this release. An x86-64 host object runs
// the loops: an AVX2 copy will need a bit of ch_cfg.cpu, because AVX2 is
// not on every x86-64 CPU.
#ifndef CH_MLDSA_VECTOR_H
#define CH_MLDSA_VECTOR_H

#include "cpu_cfg.h"
#include "mldsa_poly.h"

// MLD_VECTOR is 1 where the object holds the lanes: a host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) for arm64. It is 0 in every other object,
// so a caller tests it and never an architecture macro.
#if defined(CH_CPU_RUNTIME) && defined(__ARM_NEON)
#define MLD_VECTOR 1
#else
#define MLD_VECTOR 0
#endif

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
