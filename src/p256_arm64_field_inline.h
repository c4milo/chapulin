// The arm64 P-256 field's product and square as always_inline functions
// (p256_arm64.h): p256_arm64_asm.h's two statements, or under
// CH_P256_ARM64_MODEL test/p256_arm64_model.h's portable C.
// p256_arm64_names.h renames p256_wide_fe_mul and p256_wide_fe_sqr to these
// two, so p256_arm64_point.c and p256_arm64_verify_point.c, which include
// this header after the renames, run each product of a point formula in the
// formula's own frame. p256_arm64_field.c defines p256_arm64_fe_mul and
// p256_arm64_fe_sqr over them for the tests and the harnesses.
//
// Why inline: each statement takes its words in registers and gives its
// words in registers. Inline, the compiler keeps a formula's elements in
// registers from one product to the next, and a doubling stores and loads
// none of them (docs/decisions.md 215).
#ifndef CH_P256_ARM64_FIELD_INLINE_H
#define CH_P256_ARM64_FIELD_INLINE_H

#include "p256_wide_field.h"

#ifdef CH_P256_ARM64_MODEL
#include "p256_arm64_model.h"
#else
#include "p256_arm64_asm.h"
#endif // CH_P256_ARM64_MODEL

// o = a b / 2^256 mod p and o = a a / 2^256 mod p, for elements below p. o may
// be a or b.
static inline __attribute__((always_inline)) void
p256_arm64_fe_mul_inline(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b) {
    p256_arm64_mul_mont(o->word, a->word, b->word);
}

static inline __attribute__((always_inline)) void p256_arm64_fe_sqr_inline(p256_wide_fe *o,
                                                                           const p256_wide_fe *a) {
    p256_arm64_sqr_mont(o->word, a->word);
}

#endif
