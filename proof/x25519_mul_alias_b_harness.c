// Proves: mul's memory-safe index walk with the output aliasing the second
// input — the ladder's mul(a, c, a), at the 2^24 limb
// bounds x25519_harness.c states, one caller shape per formula: a
// single 64-bit limb multiply fills a formula near the solver cap, so
// each aliasing shape the ladder and invert use gets its own slow-tier
// leg. x25519_harness.c holds the distinct-operand shape and the
// reason these run without the signed-overflow class.
#include "harness.h"

#include "x25519.c"

#define GEN ((int64_t)1 << 24)

static void assume_range(fe f, int64_t lo, int64_t hi) {
    for (size_t i = 0; i < 16; i++) {
        f[i] = nondet_i64();
        __CPROVER_assume(f[i] >= lo && f[i] < hi);
    }
}

int main(void) {
    fe a;
    fe b;

    assume_range(a, -GEN, GEN);
    assume_range(b, -GEN, GEN);
    mul(a, b, a);
    return 0;
}
