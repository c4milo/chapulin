// The names of the x86-64 P-256 field's copy of the wide files (p256_adx.h).
// p256_adx_point.c, p256_adx_mul.c, p256_adx_verify_point.c and
// p256_adx_verify.c include this header and then the wide file of the same
// stem, so the copy is the same source text compiled once more, as
// widemul_native.h's copies are.
//
// The renames give every function the four copied files define outside
// their translation unit a second name, with p256_adx_ in place of
// p256_wide_, so the two copies define no name twice. They rename the
// declarations each file's header gives as well as the definitions, and a
// call from one copied file to another calls the copy of the callee. The
// first two make each copied file's products and squares p256_adx_field.c's
// assembly. A name left out is defined by both copies, and the link of the
// object refuses it.
#ifndef CH_P256_ADX_NAMES_H
#define CH_P256_ADX_NAMES_H

// p256_adx_field.c's two routines.
#define p256_wide_fe_mul p256_adx_fe_mul
#define p256_wide_fe_sqr p256_adx_fe_sqr

// p256_wide_point.c.
#define p256_wide_point_from_portable p256_adx_point_from_portable
#define p256_wide_point_to_portable p256_adx_point_to_portable
#define p256_wide_point_add p256_adx_point_add
#define p256_wide_point_add_affine p256_adx_point_add_affine
#define p256_wide_point_add_affine_incomplete p256_adx_point_add_affine_incomplete
#define p256_wide_point_to_jacobian p256_adx_point_to_jacobian
#define p256_wide_point_from_jacobian p256_adx_point_from_jacobian
#define p256_wide_point_double_jacobian p256_adx_point_double_jacobian
#define p256_wide_point_add_jacobian_incomplete p256_adx_point_add_jacobian_incomplete
#define p256_wide_point_from_bytes p256_adx_point_from_bytes
#define p256_wide_point_on_curve p256_adx_point_on_curve
#define p256_wide_point_affine p256_adx_point_affine

// p256_wide_mul.c.
#define p256_wide_mul p256_adx_mul
#define p256_wide_base_mul p256_adx_base_mul

// p256_wide_verify_point.c.
#define p256_wide_jacobian_from_key p256_adx_jacobian_from_key
#define p256_wide_jacobian_double_mul p256_adx_jacobian_double_mul
#define p256_wide_jacobian_is_infinity p256_adx_jacobian_is_infinity
#define p256_wide_jacobian_x_is_r p256_adx_jacobian_x_is_r

// p256_wide_verify.c.
#define p256_wide_verify_rs p256_adx_verify_rs

#endif
