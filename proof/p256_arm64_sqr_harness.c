// Proves: p256_arm64_fe_sqr, over test/p256_arm64_model.h, is memory-safe,
// free of UB and wraps no unsigned value (--unsigned-overflow-check on the
// launch line), with the real 64x64->128 multiply, on any four words, with
// the output apart from the operand and over it. The model's square is
// p256_wide_sqr_product's ten products, as the assembly's square is, then
// test/p256_adx_model.h's model_reduce; proof/p256_arm64_mul_harness.c says
// why the two sit in two formulas.
#include "harness.h"

// The carry steps as clang compiles them, as in proof/p256_arm64_mul_harness.c.
#define P256_WIDE_CARRY P256_WIDE_CARRY_BUILTIN
#include "p256_arm64_field.c"
// Named by its path for tools/impact_read.py, as in
// proof/p256_arm64_mul_harness.c.
#include "test/p256_arm64_model.h"

uint64_t nondet_u64(void);

static void havoc(p256_wide_fe *f) {
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        f->word[i] = nondet_u64();
    }
}

int main(void) {
    p256_wide_fe a;
    p256_wide_fe o;

    havoc(&a);
    p256_arm64_fe_sqr(&o, &a);
    havoc(&a);
    p256_arm64_fe_sqr(&a, &a);
    return 0;
}
