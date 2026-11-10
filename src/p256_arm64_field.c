// The arm64 P-256 field's two routines (p256_arm64.h): p256_wide_fe_mul and
// p256_wide_fe_sqr on the assembly of p256_arm64_asm.h, or under
// CH_P256_ARM64_MODEL on its model, test/p256_arm64_model.h, through
// p256_arm64_field_inline.h. Both write the element p256_wide_field.c's
// routines write: the one element below p that is a b / 2^256 mod p. The
// copied point files call the inline functions themselves, and the tests and
// the harnesses call these two.
#include "p256_arm64.h"

#if defined(CH_CPU_RUNTIME) && (defined(__aarch64__) || defined(CH_P256_ARM64_MODEL))

#include "p256_arm64_field_inline.h"

void p256_arm64_fe_mul(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b) {
    p256_arm64_fe_mul_inline(o, a, b);
}

void p256_arm64_fe_sqr(p256_wide_fe *o, const p256_wide_fe *a) {
    p256_arm64_fe_sqr_inline(o, a);
}

#endif
