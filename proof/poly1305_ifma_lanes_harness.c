// Proves: the model's two lane multiplications meet the contracts
// proof/poly1305_ifma_stubs.h replaces them with. For any sum and any x and
// y whose lanes are below 2^52, with a and b the bit lengths of a lane of x
// and of y:
//
// - lanes_multiply_add_low adds to the lane of sum a value below 2^52 and
//   below 2^(a + b);
// - lanes_multiply_add_high adds a value below 2^(a + b - 52), and 0 where
//   a + b is at most 52.
//
// The difference of a lane after and before is that value: the lane add
// wraps modulo 2^64, as the instruction's does, and the difference wraps
// back. That is the set each stub draws from, so a proof over the stubs
// covers every half of every product the model computes. It is a bound,
// not an equality, for the reason docs/proofs.md gives.
//
// The line runs without --unsigned-overflow-check, because the lane add
// and the difference wrap on purpose, and with -DCH_CPU_RUNTIME, under
// which ct.h defines the 64x64->128 multiply the model's product runs on.
// It needs no -Itest: it reads the model header by its path and compiles
// no poly1305_ifma.c.
#include "harness.h"

#include "ct.h"
#include "test/poly1305_ifma_model_lanes.h"

uint64_t nondet_u64(void);

static unsigned bit_length(uint64_t x) {
    return x == 0 ? 0U : 64U - (unsigned)__builtin_clzll(x);
}

static poly1305_ifma_lanes havoc_lanes(void) {
    poly1305_ifma_lanes lanes;
    for (int j = 0; j < 8; j++) {
        lanes.lane[j] = nondet_u64();
    }
    return lanes;
}

static poly1305_ifma_lanes havoc_operand(void) {
    poly1305_ifma_lanes lanes = havoc_lanes();
    for (int j = 0; j < 8; j++) {
        __CPROVER_assume(lanes.lane[j] <= MODEL_LOW_52_BITS);
    }
    return lanes;
}

int main(void) {
    poly1305_ifma_lanes sum = havoc_lanes();
    poly1305_ifma_lanes x = havoc_operand();
    poly1305_ifma_lanes y = havoc_operand();
    poly1305_ifma_lanes low = lanes_multiply_add_low(sum, x, y);
    poly1305_ifma_lanes high = lanes_multiply_add_high(sum, x, y);
    for (int j = 0; j < 8; j++) {
        unsigned bits = bit_length(x.lane[j]) + bit_length(y.lane[j]);
        uint64_t added_low = low.lane[j] - sum.lane[j];
        uint64_t added_high = high.lane[j] - sum.lane[j];
        __CPROVER_assert(added_low < (UINT64_C(1) << (bits < 52 ? bits : 52)),
                         "lanes_multiply_add_low adds a value below 2^52 and 2^(a + b)");
        __CPROVER_assert(bits > 52 ? added_high < (UINT64_C(1) << (bits - 52)) : added_high == 0,
                         "lanes_multiply_add_high adds a value below 2^(a + b - 52)");
    }
    return 0;
}
