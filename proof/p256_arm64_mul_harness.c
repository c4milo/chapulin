// Proves: p256_arm64_fe_mul, over test/p256_arm64_model.h, is memory-safe,
// free of UB and wraps no unsigned value (--unsigned-overflow-check on the
// launch line), with the real 64x64->128 multiply, on any four words of each
// operand. The model's four rows are p256_wide_mul_row's two carry chains, as
// the assembly's are, and its reduction is test/p256_adx_model.h's
// model_reduce, which proof/p256_adx_reduce_harness.c runs on any eight
// words. spec/lean/Spec/P256Adx.lean proves what the product and the
// reduction compute.
//
// The product runs with the output apart from both operands, over the
// first and over the second, the shapes a point formula calls it in.
// proof/p256_arm64_sqr_harness.c proves the square, apart, so each formula
// holds one routine's products.
#include "harness.h"

// The carry steps as clang compiles them: CBMC reads no intrinsic, so the
// line names one form on every machine (p256_wide_word.h).
#define P256_WIDE_CARRY P256_WIDE_CARRY_BUILTIN
#include "p256_arm64_field.c"
// p256_arm64_field.c read the model under -DCH_P256_ARM64_MODEL, so its
// guard makes this line read nothing. It names the model by its path, which
// is how tools/impact_read.py learns that this harness compiles it.
#include "test/p256_arm64_model.h"

uint64_t nondet_u64(void);

static void havoc(p256_wide_fe *f) {
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        f->word[i] = nondet_u64();
    }
}

int main(void) {
    p256_wide_fe a;
    p256_wide_fe b;
    p256_wide_fe o;

    havoc(&a);
    havoc(&b);
    p256_arm64_fe_mul(&o, &a, &b);
    havoc(&a);
    havoc(&b);
    p256_arm64_fe_mul(&a, &a, &b);
    havoc(&a);
    havoc(&b);
    p256_arm64_fe_mul(&b, &a, &b);
    return 0;
}
