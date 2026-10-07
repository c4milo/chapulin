// P-256 points over the wide field (p256_wide_field.h): the formulas the scalar multiplications
// are built from, in two coordinate systems, and the two entries of p256_point.h that read and
// write bytes. A host object (-DCH_CPU_RUNTIME,
// cpu_cfg.h) holds this file beside p256_point.c, and widemul.h runs it for a session whose
// ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_MULTIPLY (docs/decisions.md 89 and 94).
// p256_wide_mul.c holds the two scalar multiplications over these formulas.
//
// A p256_wide_point is p256_point.h's point in the wide field's words: homogeneous projective
// (X : Y : Z), every coordinate in the Montgomery domain, Z = 0 the point at infinity. The two
// files hold the same numbers, so a p256_point one of them wrote is a point the other reads.
// The entries widemul.h calls take and leave p256_point, and keep the wide words inside the
// call. A p256_wide_jacobian holds a point in Jacobian coordinates, the form p256_wide_mul
// doubles in.
//
// Every routine is constant time in every operand: no branch and no memory index reads a
// coordinate. p256_wide_point_from_bytes is the one exception, as p256_point_from_bytes is: it
// reads a peer's point, which arrived in the clear.
#ifndef CH_P256_WIDE_POINT_H
#define CH_P256_WIDE_POINT_H

#include <stdint.h>

#include "p256_point.h"
#include "p256_wide_field.h"

#ifdef CH_CPU_RUNTIME

typedef struct {
    p256_wide_fe x;
    p256_wide_fe y;
    p256_wide_fe z;
} p256_wide_point;

// A finite point in affine coordinates, each in the Montgomery domain. The type has no
// encoding of the point at infinity.
typedef struct {
    p256_wide_fe x;
    p256_wide_fe y;
} p256_wide_affine;

// The same point in the other field's words.
void p256_wide_point_from_portable(p256_wide_point *o, const p256_point *a);
void p256_wide_point_to_portable(p256_point *o, const p256_wide_point *a);

// o = a + b, by p256_point_add's formula, the complete addition for curves with a = -3 (Renes,
// Costello and Batina, EUROCRYPT 2016, Algorithm 4), step for step. It is correct for every
// pair of inputs, including a = b, a = -b and either operand at infinity. o may alias a or b.
void p256_wide_point_add(p256_wide_point *o, const p256_wide_point *a, const p256_wide_point *b);

// o = a + b for an affine b: the complete mixed addition for curves with a = -3 (the same
// paper, Algorithm 5), step for step. It is correct for every a: a = b, a = -b and a at
// infinity among them. o may alias a.
void p256_wide_point_add_affine(p256_wide_point *o, const p256_wide_point *a,
                                const p256_wide_affine *b);

// o = a + b for an affine b, where a is finite and a's x is not b's: the Explicit-Formulas
// Database's madd-1998-cmo, 9 products and 2 squares where the complete mixed addition above
// runs 13 products (docs/decisions.md 111). spec/lean/Spec/P256WidePoint.lean proves that the
// steps compute a + b under that condition, on every curve y^2 = x^3 - 3x + b over every field.
// Outside it, a = b and a at infinity give (0 : 0 : 0), which names no point, and a = -b gives
// (0 : Y : 0) with Y not zero, the point at infinity. o may alias a.
void p256_wide_point_add_affine_incomplete(p256_wide_point *o, const p256_wide_point *a,
                                           const p256_wide_affine *b);

// A point in Jacobian coordinates: (X : Y : Z) is the affine point (X / Z^2, Y / Z^3) where Z is
// not zero, and the point at infinity where Z is zero, whatever X and Y are. Every coordinate is
// in the Montgomery domain and below p. p256_wide_mul runs on it in constant time with the four
// routines below (docs/decisions.md 112), and p256_wide_verify_point.c's verifier in variable
// time with its own (docs/decisions.md 104).
typedef struct {
    p256_wide_fe x;
    p256_wide_fe y;
    p256_wide_fe z;
} p256_wide_jacobian;

// The same point in the other coordinates: Jacobian (X Z : Y Z^2 : Z) from homogeneous
// (X : Y : Z), and homogeneous (X Z : Y : Z^3) from Jacobian (X : Y : Z), with one masked move
// that makes the point at infinity (0 : 1 : 0). Both are correct for every point of the curve,
// the point at infinity among them, and spec/lean/Spec/P256WidePoint.lean proves it of the steps.
void p256_wide_point_to_jacobian(p256_wide_jacobian *o, const p256_wide_point *a);
void p256_wide_point_from_jacobian(p256_wide_point *o, const p256_wide_jacobian *a);

// o = 2a: the Explicit-Formulas Database's dbl-1986-cc-2 for curves with a = -3, 4 products and
// 4 squares. It is correct for every point of the curve: Z3 = 2 Y1 Z1 is zero where Z1 is, so
// the point at infinity doubles to itself with no masked move. spec/lean/Spec/P256WidePoint.lean
// proves this of the steps on every curve y^2 = x^3 - 3x + b, over every field in which 2 is not
// zero. o may alias a.
void p256_wide_point_double_jacobian(p256_wide_jacobian *o, const p256_wide_jacobian *a);

// o = a + b, where a and b are finite and a's x is not b's: the Explicit-Formulas Database's
// add-1998-cmo-2, 12 products and 4 squares. spec/lean/Spec/P256WidePoint.lean proves that the
// steps compute a + b under that condition, on every curve y^2 = x^3 - 3x + b over every field.
// Outside it Z3 is zero, so o is the point at infinity: the sum for a = -b and for two points at
// infinity, and a wrong answer for a = b and for one point at infinity. o may alias a or b.
void p256_wide_point_add_jacobian_incomplete(p256_wide_jacobian *o, const p256_wide_jacobian *a,
                                             const p256_wide_jacobian *b);

// p256_point_from_bytes on the wide field: reads an uncompressed point and returns all ones
// when the leading byte is 0x04, X and Y are both below p, and the pair satisfies
// y^2 = x^3 - 3x + b. o holds the point on all ones and nothing a caller may use on zero. The
// two early returns read the peer's bytes, which are public.
uint32_t p256_wide_point_from_bytes(p256_point *o, const uint8_t in[P256_POINT_LEN]);

// p256_point_affine on the wide field: writes a's affine coordinates as 32 big-endian bytes
// each, and returns all ones when a is a finite point and zero when it is the point at
// infinity. y may be NULL for a caller that wants X alone. Both outputs are written either
// way, and the mask is how the caller learns to discard them.
uint32_t p256_wide_point_affine(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN],
                                const p256_point *a);

#endif // CH_CPU_RUNTIME

#endif
