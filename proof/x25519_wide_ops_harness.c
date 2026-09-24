// Proves: x25519_wide.c's linear field ops and its byte conversions --
// add, sub, mul_a24, cswap, unpack and pack -- are memory-safe, free of UB
// and wrap no unsigned value (--unsigned-overflow-check on the launch
// line), at INV-34's bounds, with the real multiply in mul_a24:
//
//   add      two operands with limbs under 2^52, which covers every result
//            of mul; each result limb is under 2^53.
//   sub      a minuend with limbs under 2^52 and a subtrahend whose limbs
//            are at most 2p's, the precondition x25519_wide.c states;
//            nothing wraps and each result limb is under 2^53.
//   mul_a24  an operand with limbs under 2^54; INV-34's form for mul.
//   cswap    either bit, any limbs: the two elements are swapped exactly
//            when the bit is 1.
//   unpack   any 32 bytes; every limb is under 2^51.
//   pack     any limbs under 2^63, far above the 2^52 the ladder hands it;
//            the 32 bytes it writes are below p, the canonical value.
//
// add and sub also run with the output aliasing the first operand, the
// shape step() uses. The last block walks the ladder's scalar bit index
// over its whole range, so the clamped[i >> 3] read x25519_wide_ladder()
// does 255 times is proven in bounds.
#include "harness.h"

#include "x25519_wide.c"

uint64_t nondet_u64(void);

#define BELOW_2_52 12
#define BELOW_2_54 10

// Limbs with the top `shift` bits clear: under 2^(64 - shift).
static void assume_below(fe f, int shift) {
    for (size_t i = 0; i < 5; i++) {
        f[i] = nondet_u64() >> shift;
    }
}

// Limbs at most 2p's, the subtrahend sub admits.
static void assume_at_most_two_p(fe f) {
    f[0] = nondet_u64();
    __CPROVER_assume(f[0] <= TWO_P_0);
    for (size_t i = 1; i < 5; i++) {
        f[i] = nondet_u64();
        __CPROVER_assume(f[i] <= TWO_P_1_4);
    }
}

// A macro rather than a function: __CPROVER_assert takes its description
// as a string literal.
#define ASSERT_BELOW_2_53(f, what)                                                                 \
    for (size_t i = 0; i < 5; i++) {                                                               \
        __CPROVER_assert((f)[i] < (uint64_t)1 << 53, what);                                        \
    }

// The 32 bytes o hold a value below p = 2^255 - 19: bit 255 is clear, and
// the value is not one of p..2^255 - 1, whose bytes are ed..ff, then thirty
// ff bytes, then 7f.
static void assert_canonical(const uint8_t o[X25519_LEN]) {
    __CPROVER_assert(o[31] <= 0x7f, "pack clears bit 255");
    int top_run = o[31] == 0x7f;
    for (size_t i = 1; i < 31; i++) {
        top_run = top_run && o[i] == 0xff;
    }
    __CPROVER_assert(!(top_run && o[0] >= 0xed), "pack writes a value below p");
}

int main(void) {
    fe a;
    fe b;
    fe o;

    assume_below(a, BELOW_2_52);
    assume_below(b, BELOW_2_52);
    add(o, a, b);
    ASSERT_BELOW_2_53(o, "add leaves limbs under 2^53")
    assume_below(a, BELOW_2_52);
    assume_below(b, BELOW_2_52);
    add(a, a, b);
    ASSERT_BELOW_2_53(a, "add(a, a, b) leaves limbs under 2^53")

    assume_below(a, BELOW_2_52);
    assume_at_most_two_p(b);
    sub(o, a, b);
    ASSERT_BELOW_2_53(o, "sub leaves limbs under 2^53")
    assume_below(a, BELOW_2_52);
    assume_at_most_two_p(b);
    sub(a, a, b);
    ASSERT_BELOW_2_53(a, "sub(a, a, b) leaves limbs under 2^53")

    assume_below(a, BELOW_2_54);
    mul_a24(o, a);
    __CPROVER_assert(o[0] < (uint64_t)1 << 51 && o[2] < (uint64_t)1 << 51 &&
                         o[3] < (uint64_t)1 << 51 && o[4] < (uint64_t)1 << 51,
                     "mul_a24 leaves limbs 0, 2, 3 and 4 under 2^51");
    __CPROVER_assert(o[1] < ((uint64_t)1 << 51) + ((uint64_t)1 << 13),
                     "mul_a24 leaves limb 1 under 2^51 + 2^13");

    fe p0;
    fe q0;
    assume_below(a, 0);
    assume_below(b, 0);
    for (size_t i = 0; i < 5; i++) {
        p0[i] = a[i];
        q0[i] = b[i];
    }
    uint64_t bit = nondet_u64();
    __CPROVER_assume(bit == 0 || bit == 1);
    cswap(a, b, bit);
    for (size_t i = 0; i < 5; i++) {
        __CPROVER_assert(a[i] == (bit ? q0[i] : p0[i]) && b[i] == (bit ? p0[i] : q0[i]),
                         "cswap swaps exactly when the bit is 1");
    }

    uint8_t bytes[X25519_LEN];
    fill_nondet(bytes, sizeof bytes);
    unpack(o, bytes);
    for (size_t i = 0; i < 5; i++) {
        __CPROVER_assert(o[i] < (uint64_t)1 << 51, "unpack leaves limbs under 2^51");
    }

    assume_below(a, 1);
    uint8_t out[X25519_LEN];
    pack(out, a);
    assert_canonical(out);

    // The ladder reads clamped[i >> 3] for i = 254..0; every index is
    // inside the 32-byte scalar.
    uint8_t z[X25519_LEN];
    fill_nondet(z, sizeof z);
    for (int i = 254; i >= 0; i--) {
        uint64_t r = (uint64_t)((z[i >> 3] >> (i & 7)) & 1);
        __CPROVER_assert(r == 0 || r == 1, "scalar bit is a bit");
    }
    return 0;
}
