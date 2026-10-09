// Proves: the model's two lane multiplications and the multiply under them
// meet the contracts proof/rsa_ifma_stubs.h replaces them with.
//
// - ct_mul128 of two operands below 2^52 is at or below (2^52 - 1)^2. The
//   operands are x & (2^52 - 1) and y & (2^52 - 1) for any words x and y,
//   which is every pair below 2^52, through test/rsa_ifma_model_lanes.h's
//   model_lane_product, the one multiply both operations make.
// - lanes_multiply_add_low adds to each lane of sum a value below 2^52,
//   and lanes_multiply_add_high adds one at or below 2^52 - 2, for any sum
//   and any x and y. The difference of a lane after and before is that
//   value: the lane add wraps modulo 2^64, as the instruction's does, and
//   the difference wraps back.
// - lanes_load and lanes_store, run on arrays of exactly eight words, read
//   and write inside them, which is the contract the memory harnesses'
//   stubs assert: eight words readable at a load's pointer and eight
//   writable at a store's.
//
// That is what the stubs give each lane, any value below 2^52, and what
// the refined multiply gives digits, any value below 2^104, so a proof
// over the stubs covers every product the model computes. It is a bound,
// not an equality, for the reason docs/proofs.md gives.
//
// The line runs without --unsigned-overflow-check, because the lane add
// and the difference wrap on purpose. It needs no -Itest: it reads the
// model header by its path and compiles no rsa_ifma.c.
#include "harness.h"

#include "ct.h"
#include "test/rsa_ifma_model_lanes.h"

uint64_t nondet_u64(void);

static rsa_ifma_lanes havoc_lanes(void) {
    rsa_ifma_lanes lanes;
    for (int j = 0; j < 8; j++) {
        lanes.lane[j] = nondet_u64();
    }
    return lanes;
}

int main(void) {
    uint64_t x = nondet_u64();
    uint64_t y = nondet_u64();
    ct_u128 digit_max = ((ct_u128)1 << 52) - 1;
    __CPROVER_assert(model_lane_product(x, y) <= digit_max * digit_max,
                     "a product of two digits is at or below (2^52 - 1)^2");

    rsa_ifma_lanes sum = havoc_lanes();
    rsa_ifma_lanes low = lanes_multiply_add_low(sum, havoc_lanes(), havoc_lanes());
    for (int j = 0; j < 8; j++) {
        __CPROVER_assert(low.lane[j] - sum.lane[j] <= MODEL_LOW_52_BITS,
                         "lanes_multiply_add_low adds a value below 2^52");
    }

    sum = havoc_lanes();
    rsa_ifma_lanes high = lanes_multiply_add_high(sum, havoc_lanes(), havoc_lanes());
    for (int j = 0; j < 8; j++) {
        __CPROVER_assert(high.lane[j] - sum.lane[j] <= MODEL_LOW_52_BITS - 1,
                         "lanes_multiply_add_high adds a value at or below 2^52 - 2");
    }

    uint64_t words[8];
    for (int j = 0; j < 8; j++) {
        words[j] = nondet_u64();
    }
    rsa_ifma_lanes loaded = lanes_load(words);
    lanes_store(words, havoc_lanes());
    (void)loaded;
    return 0;
}
