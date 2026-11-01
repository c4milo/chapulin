// The x86-64 P-256 field: the wide P-256 files (p256_wide_field.h) compiled
// once more, with the Montgomery product and square on MULX, ADCX and ADOX
// in inline assembly (p256_adx_asm.h). An x86-64 host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) holds it beside the wide files, and
// widemul.h runs a session's P-256 operations on it where the session's
// ch_cfg.cpu holds CH_CPU_BMI2_ADX: the scalar multiplications, the point
// decode and the affine conversion where it holds the multiply bit too, and
// the ECDSA verification on the bit alone, because every input of a
// verification is public (docs/decisions.md 171).
//
// Five files make the copy. p256_adx_field.c defines p256_adx_fe_mul and
// p256_adx_fe_sqr over the assembly, and p256_adx_point.c, p256_adx_mul.c,
// p256_adx_verify_point.c and p256_adx_verify.c each include
// p256_adx_names.h and then the wide file of the same stem, so the point
// arithmetic is the same source text as the wide files'. The renames make
// every call of those files to p256_wide_fe_mul or p256_wide_fe_sqr a call
// of the assembly. Every other field routine, the scalar arithmetic, the
// binary GCD and the table of multiples of G are the wide files' own: they
// multiply on the wide field's rows where they multiply at all, which is a
// few products per operation, in p256_wide_fe_to_mont and p256_wide_fe_inv.
//
// The model build, under CH_P256_ADX_MODEL, takes the two routines from
// test/p256_adx_model.h, portable C that writes the same words. The CBMC
// harnesses, the model test and the differential compile the copy that way
// on any host, and bin/p256_adx_equiv_test holds the assembly to the model
// on a CPU with BMI2 and ADX.
#ifndef CH_P256_ADX_H
#define CH_P256_ADX_H

#include <stdint.h>

#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_wide_field.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_P256_ADX_MODEL))

// The entries widemul.h and p256.c call: p256_wide_mul.h's two scalar
// multiplications, p256_wide_point.h's decode, affine conversion and curve
// check, and p256_wide_verify.h's check of r and s, under the same
// contracts, on this field.
void p256_adx_mul(p256_point *o, const p256_scalar *k, const p256_point *p);
void p256_adx_base_mul(p256_point *o, const p256_scalar *k);
uint32_t p256_adx_point_from_bytes(p256_point *o, const uint8_t in[P256_POINT_LEN]);
uint32_t p256_adx_point_affine(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN], const p256_point *a);
uint32_t p256_adx_point_on_curve(const uint8_t x[P256_FE_LEN], const uint8_t y[P256_FE_LEN]);
int p256_adx_verify_rs(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t r_be[32],
                       const uint8_t s_be[32]);

// p256_wide_fe_mul and p256_wide_fe_sqr (p256_wide_field.h) on the
// assembly, under the same contract.
void p256_adx_fe_mul(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b);
void p256_adx_fe_sqr(p256_wide_fe *o, const p256_wide_fe *a);

#endif

#endif
