// Proves: the model's lane multiplication meets the contract
// proof/rsa_avx2_stubs.h replaces it with, and its loads and stores touch
// four words.
//
// - lanes_multiply gives each lane a value at or below (2^32 - 1)^2 for any
//   two lanes, and at or below (2^29 - 1)^2 where both lanes are below
//   2^29, through test/rsa_avx2_model_lanes.h's product of bits 31..0 of
//   each lane.
// - lanes_load and lanes_store, run on arrays of exactly four words, read
//   and write inside them, which is the contract the memory harnesses'
//   stubs assert: four words readable at a load's pointer and four
//   writable at a store's.
//
// That is what the stub gives each lane, so a proof over the stubs covers
// every product the model computes. It is a bound, not an equality, for
// the reason docs/proofs.md gives.
//
// The line runs with --unsigned-overflow-check: the model's product of two
// 32-bit halves is below 2^64, and no other operation here wraps. It needs
// no -Itest: it reads the model header by its path and compiles no
// rsa_avx2.c.
#include "harness.h"

#include "test/rsa_avx2_model_lanes.h"

uint64_t nondet_u64(void);

static rsa_avx2_lanes havoc_lanes(void) {
    rsa_avx2_lanes lanes;
    for (int j = 0; j < 4; j++) {
        lanes.lane[j] = nondet_u64();
    }
    return lanes;
}

int main(void) {
    const uint64_t limit = (uint64_t)1 << 29;
    rsa_avx2_lanes x = havoc_lanes();
    rsa_avx2_lanes y = havoc_lanes();
    rsa_avx2_lanes product = lanes_multiply(x, y);
    for (int j = 0; j < 4; j++) {
        __CPROVER_assert(product.lane[j] <= MODEL_LOW_32_BITS * MODEL_LOW_32_BITS,
                         "a product of two 32-bit halves is at or below (2^32 - 1)^2");
        if (x.lane[j] < limit && y.lane[j] < limit) {
            __CPROVER_assert(product.lane[j] <= (limit - 1) * (limit - 1),
                             "a product of two lanes below 2^29 is at or below (2^29 - 1)^2");
        }
    }

    uint64_t words[4];
    for (int j = 0; j < 4; j++) {
        words[j] = nondet_u64();
    }
    rsa_avx2_lanes loaded = lanes_load(words);
    lanes_store(words, havoc_lanes());
    (void)loaded;
    return 0;
}
