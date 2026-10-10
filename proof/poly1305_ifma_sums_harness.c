// Proves: no sum in poly1305_ifma.c's group loop wraps, every operand of a
// lane multiplication is below 2^52, and every carried number keeps the
// bounds proof/poly1305_ifma_stubs.h names, digits 0 and 1 below 2^44 + 2^17
// and digit 2 below 2^42 + 2^17. The check is --unsigned-overflow-check on
// the launch line, which makes every unsigned +, - and * a property; the
// stubs assert the operands' bound at each multiplication; and the asserts
// below hold the carried digits. The bound is what the next step reads, so
// the steps below are an induction over the kernel's loop:
//
// - the start: digits_of_words on any accumulator whose words are at most
//   2^26, the bounds poly1305.c's loop and every vector path leave;
// - a group: group_sums and carry from any lanes within the bounds, the
//   blocks load_blocks reads from any 256 bytes, and any two multipliers
//   whose digits are within them, which multiplier_complete completes, as
//   poly1305_ifma_product proves of the four compute_powers writes;
// - the end: the eight lanes' totals of any lanes within the bounds, and
//   words_of_totals and carry_scalar over them.
//
// The products are the contracts in proof/poly1305_ifma_stubs.h, which
// poly1305_ifma_lanes_harness.c discharges. spec/lean/Spec/Poly1305Ifma.lean
// proves the same bounds of a model of the group step, on the products
// themselves (groupStep_bounds).
#include "poly1305_ifma_stubs.h"

#include "poly1305_ifma.c"

static lanes havoc_below(uint64_t bound) {
    lanes x;
    for (int j = 0; j < 8; j++) {
        x.lane[j] = nondet_u64();
        __CPROVER_assume(x.lane[j] < bound);
    }
    return x;
}

static void assert_carried(lanes l0, lanes l1, lanes l2) {
    for (int j = 0; j < 8; j++) {
        __CPROVER_assert(l0.lane[j] < STUB_DIGIT_BOUND, "digit 0 below 2^44 + 2^17");
        __CPROVER_assert(l1.lane[j] < STUB_DIGIT_BOUND, "digit 1 below 2^44 + 2^17");
        __CPROVER_assert(l2.lane[j] < STUB_TOP_BOUND, "digit 2 below 2^42 + 2^17");
    }
}

static void havoc_multiplier(multiplier *by) {
    by->r0 = havoc_below(STUB_DIGIT_BOUND);
    by->r1 = havoc_below(STUB_DIGIT_BOUND);
    by->r2 = havoc_below(STUB_TOP_BOUND);
    multiplier_complete(by);
}

static void havoc_words(uint32_t w[5], uint32_t bound) {
    for (size_t i = 0; i < 5; i++) {
        w[i] = nondet_u32();
        __CPROVER_assume(w[i] <= bound);
    }
}

static void prove_start(void) {
    uint32_t h[5];
    havoc_words(h, UINT32_C(1) << 26);
    uint64_t start[3];
    digits_of_words(start, h);
    __CPROVER_assert(start[0] < STUB_DIGIT_BOUND && start[1] < STUB_DIGIT_BOUND &&
                         start[2] < STUB_TOP_BOUND,
                     "an accumulator's digits are within the bounds");
}

static void prove_group(void) {
    lanes h[3] = {havoc_below(STUB_DIGIT_BOUND), havoc_below(STUB_DIGIT_BOUND),
                  havoc_below(STUB_TOP_BOUND)};
    multiplier first;
    multiplier second;
    havoc_multiplier(&first);
    havoc_multiplier(&second);
    uint8_t m[POLY1305_IFMA_GROUP];
    fill_nondet(m, sizeof m);
    lanes lo[3];
    lanes hi[3];
    group_sums(lo, hi, h, m, &first, &second);
    carry(h, lo, hi);
    assert_carried(h[0], h[1], h[2]);
}

static void prove_end(void) {
    lanes h[3] = {havoc_below(STUB_DIGIT_BOUND), havoc_below(STUB_DIGIT_BOUND),
                  havoc_below(STUB_TOP_BOUND)};
    uint64_t total[3] = {lanes_total(h[0]), lanes_total(h[1]), lanes_total(h[2])};
    uint32_t words[5];
    words_of_totals(words, total);
}

int main(void) {
    prove_start();
    prove_group();
    prove_end();
    return 0;
}
