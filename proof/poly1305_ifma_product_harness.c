// Proves: multiplier_product, from any two multipliers whose digits keep
// the bounds proof/poly1305_ifma_stubs.h names, digits 0 and 1 below
// 2^44 + 2^17 and digit 2 below 2^42 + 2^17, wraps no sum, takes no operand
// of 2^52 or more, and writes a product whose digits keep those bounds
// again. The launch line's --unsigned-overflow-check makes every unsigned
// +, - and * a property, and the stubs assert the operands' bound. It runs
// both shapes compute_powers calls it in: a square, a and b the same
// struct, and a product of two others.
//
// That is the step compute_powers repeats. Its first multiplier is r, whose
// digits digits_of_words writes within the bounds from words below 2^26, as
// poly1305_ifma_sums' start proves. Each of its five products takes two
// multipliers the steps before it wrote, and each select and broadcast
// copies lanes of those or the constant 1. So all four multipliers the
// groups take keep the bounds, by induction over the function's statements.
// spec/lean/Spec/Poly1305Ifma.lean's powers_mod proves that composition,
// with the power of r each lane holds, on a model of the C. One formula
// that ran compute_powers whole, five products, took 315 s and 2.9 GB, and
// poly1305_ifma_blocks runs the whole function for its memory accesses.
//
// The products are the contracts in proof/poly1305_ifma_stubs.h, which
// poly1305_ifma_lanes_harness.c discharges.
#include "poly1305_ifma_stubs.h"

#include "poly1305_ifma.c"

_Bool nondet_bool(void);

static lanes havoc_below(uint64_t bound) {
    lanes x;
    for (int j = 0; j < 8; j++) {
        x.lane[j] = nondet_u64();
        __CPROVER_assume(x.lane[j] < bound);
    }
    return x;
}

static void havoc_multiplier(multiplier *by) {
    by->r0 = havoc_below(STUB_DIGIT_BOUND);
    by->r1 = havoc_below(STUB_DIGIT_BOUND);
    by->r2 = havoc_below(STUB_TOP_BOUND);
    multiplier_complete(by);
}

int main(void) {
    multiplier a;
    multiplier b;
    multiplier out;
    havoc_multiplier(&a);
    havoc_multiplier(&b);
    const multiplier *second = nondet_bool() ? &a : &b;
    multiplier_product(&out, &a, second);
    for (int j = 0; j < 8; j++) {
        __CPROVER_assert(out.r0.lane[j] < STUB_DIGIT_BOUND, "digit 0 below 2^44 + 2^17");
        __CPROVER_assert(out.r1.lane[j] < STUB_DIGIT_BOUND, "digit 1 below 2^44 + 2^17");
        __CPROVER_assert(out.r2.lane[j] < STUB_TOP_BOUND, "digit 2 below 2^42 + 2^17");
    }
    return 0;
}
