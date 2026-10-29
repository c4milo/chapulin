// Proves: x25519_adx.c's square, over test/x25519_adx_model.h, is
// memory-safe, free of UB and wraps no unsigned value
// (--unsigned-overflow-check on the launch line), with the real 64x64->128
// multiply, on any four words, as proof/x25519_adx_mul_harness.c proves the
// product. It also runs with the output on its operand, as adx_sqr_times
// calls it.
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
    fe o;

    havoc(a);
    adx_sqr(o, a);
    havoc(a);
    adx_sqr(a, a);
    return 0;
}
