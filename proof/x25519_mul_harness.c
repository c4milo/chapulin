// Proves the arithmetic lemma behind mul: with every limb bounded by
// 2^24 in magnitude, the worst-case product accumulation — 16 products
// into one int64 — cannot overflow, nor can the 38x fold of one such sum
// into another, and the fold result stays under 2^58, the bound the
// carry() proof assumes for its input. mul's memory safety (concrete
// index walk) is proven separately in x25519_harness; together they
// cover mul without asking SAT to chew 256 symbolic multiplies at once.
#include "harness.h"

#include <stdint.h>

#define GEN ((int64_t)1 << 24)

static int64_t product_sum(void) {
    int64_t s = 0;
    for (int i = 0; i < 16; i++) {
        int64_t a = nondet_i64();
        int64_t b = nondet_i64();
        __CPROVER_assume(a > -GEN && a < GEN);
        __CPROVER_assume(b > -GEN && b < GEN);
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
    return 0;
}
