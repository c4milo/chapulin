// The x86-64 P-256 field's product and square as always_inline functions
// (p256_adx.h): p256_adx_asm.h's two statements, or under CH_P256_ADX_MODEL
// test/p256_adx_model.h's portable C. p256_adx_names.h renames
// p256_wide_fe_mul and p256_wide_fe_sqr to these two, so p256_adx_point.c and
// p256_adx_verify_point.c, which include this header after the renames, run
// each product of a point formula in the formula's own frame. p256_adx_field.c
// defines p256_adx_fe_mul and p256_adx_fe_sqr over them for the tests and the
// harnesses.
//
// Why inline: each statement writes rbx and r12 to r15, which the calling
// convention saves for the caller. As a call, every product saved and
// restored those five registers and moved its operands through memory. In
// the formula's frame the compiler saves them once per formula and keeps the
// operands' pointers in registers. On an AMD EPYC 7763 a doubling took 0.82 of
// its time under gcc and 0.90 of it under clang (docs/decisions.md 175).
#ifndef CH_P256_ADX_FIELD_INLINE_H
#define CH_P256_ADX_FIELD_INLINE_H

#include "p256_wide_field.h"

#ifdef CH_P256_ADX_MODEL
#include "p256_adx_model.h"
#else
#include "p256_adx_asm.h"
#endif // CH_P256_ADX_MODEL

// o = a b / 2^256 mod p and o = a a / 2^256 mod p, for elements below p. o may
// be a or b.
static inline __attribute__((always_inline)) void
p256_adx_fe_mul_inline(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b) {
    p256_adx_mul_mont(o->word, a->word, b->word);
}

static inline __attribute__((always_inline)) void p256_adx_fe_sqr_inline(p256_wide_fe *o,
                                                                         const p256_wide_fe *a) {
    p256_adx_sqr_mont(o->word, a->word);
}

#endif
