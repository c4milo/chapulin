// Proves: x25519's linear field ops — carry, add, sub, pack, cswap,
// unpack — are memory-safe and UB-free with the signed-overflow check
// on, at the documented caller bounds (|limb| < 2^58 into carry, the
// range any product fold produces; |limb| < 2^24 into add/sub/pack,
// far above the ~2^17 the ladder produces). add and sub are also
// driven with the output aliasing the first input, the shape the
// ladder uses at every step. This closes the overflow class for every
// op except mul: mul's memory safety is x25519_harness.c (run without
// the overflow class) and its overflow lemma is x25519_mul_harness.c —
// together the three harnesses cover every field op, each with the
// strongest check set that converges. The last block walks the
// ladder's scalar bit index over its whole range, so the z[i >> 3]
// read the ladder does 255 times is proven in bounds. Includes the
// module .c to reach the statics, as the unit tests do.
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
    fe o;
    uint8_t bytes[X25519_LEN];

    assume_range(a, -((int64_t)1 << 58), (int64_t)1 << 58);
    carry(a);

    assume_range(a, -GEN, GEN);
    assume_range(b, -GEN, GEN);
    add(o, a, b);
    assume_range(a, -GEN, GEN);
    assume_range(b, -GEN, GEN);
    sub(o, a, b);
    // The ladder's shapes: the output aliases the first input.
    assume_range(a, -GEN, GEN);
    assume_range(b, -GEN, GEN);
    add(a, a, b);
    assume_range(a, -GEN, GEN);
    assume_range(b, -GEN, GEN);
    sub(a, a, b);

    assume_range(a, -GEN, GEN);
    uint8_t out[X25519_LEN];
    pack(out, a);

    assume_range(a, -GEN, GEN);
    assume_range(b, -GEN, GEN);
    int64_t bit = nondet_i64();
    __CPROVER_assume(bit == 0 || bit == 1);
    cswap(a, b, bit);

    fill_nondet(bytes, sizeof bytes);
    unpack(o, bytes);
    for (size_t i = 0; i < 16; i++) {
        __CPROVER_assert(o[i] >= 0 && o[i] < (int64_t)1 << 16, "unpack is carried");
    }

    // The ladder reads z[i >> 3] for i = 254..0; every index is inside
    // the 32-byte scalar.
    uint8_t z[X25519_LEN];
    fill_nondet(z, sizeof z);
    for (int i = 254; i >= 0; i--) {
        int64_t r = (z[i >> 3] >> (i & 7)) & 1;
        __CPROVER_assert(r == 0 || r == 1, "scalar bit is a bit");
    }
    return 0;
}
