// Proves: x25519_adx.c's product, over test/x25519_adx_model.h, is
// memory-safe, free of UB and wrap no unsigned value
// (--unsigned-overflow-check on the launch line), with the real 64x64->128
// multiply, on any four words. Each column sum of model_product adds a word,
// a product of two words and a carry, below 2^128; the reduction of its
// eight words is proof/x25519_adx_ops_harness.c's model_reduce.
//
// The product also runs with the output on its first operand, as adx_step
// and adx_invert call it. proof/x25519_adx_sqr_harness.c proves the square,
// apart, so each formula holds one shape's products.
#include "harness.h"

#include "x25519_adx.c"
// x25519_adx.c read the model under -DCH_X25519_ADX_MODEL, so its guard makes
// this line read nothing. It names the model by its path, which is how
// tools/impact_read.py learns that this harness compiles it.
#include "test/x25519_adx_model.h"

uint64_t nondet_u64(void);

static void havoc(fe f) {
    for (size_t i = 0; i < 4; i++) {
        f[i] = nondet_u64();
    }
}

int main(void) {
    fe a;
    fe b;
    fe o;

    havoc(a);
    havoc(b);
    adx_mul(o, a, b);
    havoc(a);
    havoc(b);
    adx_mul(a, a, b);
    return 0;
}
