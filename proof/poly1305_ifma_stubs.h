// The contracts the poly1305_ifma harnesses run poly1305_ifma.c over, the
// way proof/rsa_ifma_stubs.h serves rsa_ifma.c.
//
// What the harnesses compile: poly1305_ifma.c's own text under
// CH_POLY1305_IFMA_MODEL, over test/poly1305_ifma_model_lanes.h, the model
// of each AVX-512 instruction in portable C that bin/poly1305_equiv_test
// runs on every machine. A launch line that includes this file passes
// -DCH_CPU_RUNTIME, -DCH_POLY1305_IFMA_MODEL and -Itest. CBMC cannot read
// the intrinsics in poly1305_ifma_lanes.h, so no harness compiles the file
// the way an x86-64 host object does; bin/poly1305_equiv_test holds the
// instructions to poly1305.c's loop on a CPU with AVX-512 IFMA.
//
// Why the contracts exist: a group of sixteen blocks runs 36 lane
// multiplications on eight lanes, 288 products of 52-bit operands, and
// compute_powers runs five products more. docs/proofs.md says SAT cost
// follows the multiply count, and every property here is a bound. So the
// model's two lane multiplications are the contracts below.
//
// WHAT THE STUBS MODEL: lanes_multiply_add_low and lanes_multiply_add_high,
// VPMADD52LUQ and VPMADD52HUQ, first assert that each lane of x and of y is
// below 2^52, so the instruction reads the whole operand and the product it
// takes apart is the product of the two lanes. They then add to each lane
// of sum any value below 2^52, and below 2^(a + b) where a and b are the
// bit lengths of the two operands, the fewest bits that hold each, for the
// low half, and any value below 2^(a + b - 52), or 0 where a + b is at most
// 52, for the high half. A product of an a-bit and a b-bit number is below
// 2^(a + b), so each half of every product is in the stub's set.
//
// WHAT DISCHARGES THE CONTRACTS: poly1305_ifma_lanes_harness.c runs the
// model's two multiplications on the real multiply and proves that each
// adds a value in that set, for every sum and every pair of operands below
// 2^52.
//
// What the contracts give up: every value. No harness over this file says
// that the kernel computes the accumulator poly1305.c's loop computes.
// spec/lean/Spec/Poly1305Ifma.lean proves that of a model of the C's group
// step and its carry, bin/diff_poly1305_ifma compares that model with the C
// over the lane model, and bin/poly1305_equiv_test holds the C to
// poly1305.c's loop.
//
// The model header is read first, by its path from the root, which
// tools/impact_read.py follows to select these harnesses when the model
// changes. The #defines then rename the two operations, and the header's
// include guard keeps poly1305_ifma.c's own #include of it, which -Itest
// finds, from reading the real definitions again. Each harness then
// includes poly1305_ifma.c itself, after this file, so that
// proof/coverage.py and tools/proof-cover.py, which read a harness's own
// #include lines, see which source it compiles.
#ifndef CH_POLY1305_IFMA_STUBS_H
#define CH_POLY1305_IFMA_STUBS_H

#include "harness.h"

#include "test/poly1305_ifma_model_lanes.h"

uint64_t nondet_u64(void);

#ifdef POLY1305_IFMA_STUBS_ANY_PRODUCT
// The memory harness's contract, which a harness that defines
// POLY1305_IFMA_STUBS_ANY_PRODUCT before it includes this file runs: each
// multiplication adds any value to each lane and asserts nothing. A
// memory access in poly1305_ifma.c reads no lane, so the products bear on
// none of its properties, and the operands' bound is poly1305_ifma_sums'
// and poly1305_ifma_product's to prove, one product or one group to a
// formula, where the memory harness runs five products and two groups.
static poly1305_ifma_lanes stub_any_product(poly1305_ifma_lanes sum) {
    for (int j = 0; j < 8; j++) {
        sum.lane[j] = nondet_u64();
    }
    return sum;
}

static poly1305_ifma_lanes
stub_lanes_multiply_add_low(poly1305_ifma_lanes sum, poly1305_ifma_lanes x, poly1305_ifma_lanes y) {
    (void)x;
    (void)y;
    return stub_any_product(sum);
}

static poly1305_ifma_lanes stub_lanes_multiply_add_high(poly1305_ifma_lanes sum,
                                                        poly1305_ifma_lanes x,
                                                        poly1305_ifma_lanes y) {
    (void)x;
    (void)y;
    return stub_any_product(sum);
}
#else
// The fewest bits that hold x: 0 for 0.
static unsigned stub_bit_length(uint64_t x) {
    return x == 0 ? 0U : 64U - (unsigned)__builtin_clzll(x);
}

// Any value below 2^bits, for bits at most 52.
static uint64_t stub_below_power(unsigned bits) {
    uint64_t v = nondet_u64();
    __CPROVER_assume(v < (UINT64_C(1) << bits));
    return v;
}

// VPMADD52LUQ's contract: both operands below 2^52, asserted, and each lane
// of sum plus a value below 2^52 and below 2^(a + b).
static poly1305_ifma_lanes
stub_lanes_multiply_add_low(poly1305_ifma_lanes sum, poly1305_ifma_lanes x, poly1305_ifma_lanes y) {
    for (int j = 0; j < 8; j++) {
        __CPROVER_assert(x.lane[j] <= MODEL_LOW_52_BITS && y.lane[j] <= MODEL_LOW_52_BITS,
                         "a multiplication's operands are below 2^52");
        unsigned bits = stub_bit_length(x.lane[j]) + stub_bit_length(y.lane[j]);
        sum.lane[j] += stub_below_power(bits < 52 ? bits : 52);
    }
    return sum;
}

// VPMADD52HUQ's contract: both operands below 2^52, asserted, and each lane
// of sum plus a value below 2^(a + b - 52), or 0 where a + b is at most 52.
static poly1305_ifma_lanes stub_lanes_multiply_add_high(poly1305_ifma_lanes sum,
                                                        poly1305_ifma_lanes x,
                                                        poly1305_ifma_lanes y) {
    for (int j = 0; j < 8; j++) {
        __CPROVER_assert(x.lane[j] <= MODEL_LOW_52_BITS && y.lane[j] <= MODEL_LOW_52_BITS,
                         "a multiplication's operands are below 2^52");
        unsigned bits = stub_bit_length(x.lane[j]) + stub_bit_length(y.lane[j]);
        sum.lane[j] += stub_below_power(bits > 52 ? bits - 52 : 0);
    }
    return sum;
}
#endif

#define lanes_multiply_add_low stub_lanes_multiply_add_low
#define lanes_multiply_add_high stub_lanes_multiply_add_high

// The bounds every lane of a carried number keeps, which the sums harness
// proves a group step and a product of two powers keep: digits 0 and 1 below
// 2^44 + 2^17, and digit 2 below 2^42 + 2^17. The 2^17 holds what one round
// of carries adds above each digit's own bits, and the 2^16 that
// digits_of_words leaves above digit 2's 42 bits.
#define STUB_DIGIT_BOUND ((UINT64_C(1) << 44) + (UINT64_C(1) << 17))
#define STUB_TOP_BOUND ((UINT64_C(1) << 42) + (UINT64_C(1) << 17))

#endif
