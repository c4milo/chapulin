// Proves the arithmetic lemma behind mul: with every limb bounded by
// 2^24 in magnitude, the worst-case product accumulation — 16 products
// into one int64 — cannot overflow, nor can the 38x fold of one such sum
// into another, and the fold result stays under 2^58, the bound the
// carry() proof assumes for its input. mul's memory safety (concrete
// index walk) is proven separately in x25519_harness; together they
// cover mul without asking SAT to chew 256 symbolic multiplies at once.
//
// The last block is the product bound x25519_step_harness.c replaces
// ct_widemul_s with: two operands under 2^18, the range that harness
// proves the ladder hands mul, multiply to a value under 2^36. It runs
// the real ct_widemul_s.
#include "harness.h"

#include "ct.h"

#include <stdint.h>

#define GEN ((int64_t)1 << 24)
#define STEP_IN ((int64_t)1 << 18)
#define STEP_PRODUCT ((int64_t)1 << 36)

int32_t nondet_i32(void);

static int64_t product_sum(void) {
    int64_t s = 0;
    for (int i = 0; i < 16; i++) {
        int64_t a = nondet_i64();
        int64_t b = nondet_i64();
        __CPROVER_assume(a >= -GEN && a < GEN);
        __CPROVER_assume(b >= -GEN && b < GEN);
        s += a * b; // overflow-checked by CBMC
    }
    return s;
}

int main(void) {
    int64_t lo = product_sum();
    int64_t hi = product_sum();
    int64_t folded = lo + 38 * hi; // overflow-checked by CBMC
    __CPROVER_assert(folded > -((int64_t)1 << 58) && folded < ((int64_t)1 << 58),
                     "fold stays within the carry proof's input bound");

    int32_t a = nondet_i32();
    int32_t b = nondet_i32();
    __CPROVER_assume(a > -STEP_IN && a < STEP_IN);
    __CPROVER_assume(b > -STEP_IN && b < STEP_IN);
    int64_t product = ct_widemul_s(a, b);
    __CPROVER_assert(product > -STEP_PRODUCT && product < STEP_PRODUCT,
                     "a product of two ladder operands stays under 2^36");
    return 0;
}
