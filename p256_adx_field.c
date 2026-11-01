// The x86-64 P-256 field's two routines (p256_adx.h): p256_wide_fe_mul and
// p256_wide_fe_sqr on the assembly of p256_adx_asm.h, or under
// CH_P256_ADX_MODEL on its model, test/p256_adx_model.h. Both write the
// element p256_wide_field.c's routines write: the one element below p that
// is a b / 2^256 mod p.
#include "p256_adx.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_P256_ADX_MODEL))

#ifdef CH_P256_ADX_MODEL
#include "p256_adx_model.h"
#else
#include "p256_adx_asm.h"
#endif // CH_P256_ADX_MODEL

void p256_adx_fe_mul(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b) {
    p256_adx_mul_mont(o->word, a->word, b->word);
}

void p256_adx_fe_sqr(p256_wide_fe *o, const p256_wide_fe *a) {
    p256_adx_sqr_mont(o->word, a->word);
}

#endif
