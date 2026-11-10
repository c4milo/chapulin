// The arm64 P-256 field: the wide P-256 files (p256_wide_field.h) compiled
// once more, with the Montgomery product and square in arm64 inline
// assembly on registers (p256_arm64_asm.h). An arm64 host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) holds it beside the wide files. widemul.h
// runs a session's scalar multiplications, point decode, affine conversion
// and curve check on it in place of the wide files, where the session's
// ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_MULTIPLY. p256.c runs the ECDSA
// verification on it in every session, because every input of a
// verification is public (docs/decisions.md 215).
//
// Five files make the copy, as p256_adx.h's five make the x86-64 copy.
// p256_arm64_point.c, p256_arm64_mul.c, p256_arm64_verify_point.c and
// p256_arm64_verify.c each include p256_arm64_names.h and then the wide
// file of the same stem, so the point arithmetic is the same source text
// as the wide files'. The renames make every call of those files to
// p256_wide_fe_mul or p256_wide_fe_sqr a call of p256_arm64_field_inline.h's
// always_inline functions over the assembly, which the two point files
// include. p256_arm64_field.c defines p256_arm64_fe_mul and
// p256_arm64_fe_sqr over the same functions for the tests and the
// harnesses. Every other field routine, the scalar arithmetic, the binary
// GCD and the table of multiples of G are the wide files' own.
//
// The model build, under CH_P256_ARM64_MODEL, takes the two routines from
// test/p256_arm64_model.h, portable C that writes the same words. The CBMC
// harnesses, the model test and the differential compile the copy that way
// on any host, and bin/p256_arm64_equiv_test holds the assembly to the
// model on arm64.
#ifndef CH_P256_ARM64_H
#define CH_P256_ARM64_H

#include <stdint.h>

#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_wide_field.h"

#if defined(CH_CPU_RUNTIME) && (defined(__aarch64__) || defined(CH_P256_ARM64_MODEL))

// The entries widemul.h and p256.c call: p256_wide_mul.h's two scalar
// multiplications, p256_wide_point.h's decode, affine conversion and curve
// check, and p256_wide_verify.h's check of r and s, under the same
// contracts, on this field.
void p256_arm64_mul(p256_point *o, const p256_scalar *k, const p256_point *p);
void p256_arm64_base_mul(p256_point *o, const p256_scalar *k);
uint32_t p256_arm64_point_from_bytes(p256_point *o, const uint8_t in[P256_POINT_LEN]);
uint32_t p256_arm64_point_affine(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN],
                                 const p256_point *a);
uint32_t p256_arm64_point_on_curve(const uint8_t x[P256_FE_LEN], const uint8_t y[P256_FE_LEN]);
int p256_arm64_verify_rs(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t r_be[32],
                         const uint8_t s_be[32]);

// p256_wide_fe_mul and p256_wide_fe_sqr (p256_wide_field.h) on the
// assembly, under the same contract.
void p256_arm64_fe_mul(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b);
void p256_arm64_fe_sqr(p256_wide_fe *o, const p256_wide_fe *a);

#endif

#endif
