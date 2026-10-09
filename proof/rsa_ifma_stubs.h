// The contracts the rsa_ifma harnesses run rsa_ifma.c over, the way
// proof/rsa_mont64_stubs.h serves rsa_mont64.c.
//
// What the harnesses compile: rsa_ifma.c's own text under
// CH_RSA_IFMA_MODEL, over test/rsa_ifma_model_lanes.h, the model of each
// AVX-512 instruction in portable C that bin/rsa_ifma_model_test runs. A
// launch line that includes this file passes -DCH_RSA_IFMA_MODEL and
// -Itest, the way the Makefile builds that test. CBMC cannot read the
// intrinsics in rsa_ifma_lanes.h, so no harness compiles the file the
// way an x86-64 host object does; bin/rsa_ifma_equiv_test holds each
// instruction to the model.
//
// Why the contracts exist: a product at 10 registers runs 79 rounds of
// four lane multiplications on 80 lanes, 25,280 products of 52-bit
// digits, and rsa_ifma_public makes eighteen products. docs/proofs.md
// says SAT cost follows the multiply count. So the model's two lane
// multiplications and the scalar multiply are the contracts below.
//
// WHAT THE STUBS MODEL:
//
// - lanes_multiply_add_low and lanes_multiply_add_high, VPMADD52LUQ and
//   VPMADD52HUQ, add to each lane of sum any value below 2^52, and read
//   neither x nor y. The real operations add bits 51..0 and bits 103..52
//   of a lane product, which is at most (2^52 - 1)^2, so the low half is
//   below 2^52 and the high half is at most 2^52 - 2. The stub's set holds
//   both halves of every product.
// - ct_mul128, the scalar multiply of add_round, is
//   proof/rsa_mont64_stubs.h's contract, any value at or below
//   (2^64 - 1)^2, and where both operands are below 2^52 it is any value
//   below 2^104, which holds every product at or below (2^52 - 1)^2.
// - Under RSA_IFMA_STUB_EVERY_LANE_OPERATION, which the memory harnesses
//   define, every lane operation: a load reads the eight words at its
//   pointer, a store writes them, and every operation returns any value.
//
// WHAT DISCHARGES THE CONTRACTS: rsa_ifma_lanes_harness.c runs the model's
// real operations on the real ct_mul128. It proves that each
// multiplication adds a value in the stub's set to each lane, for every
// sum and every operand, that ct_mul128 of two operands below 2^52 is at
// or below (2^52 - 1)^2, and that a load and a store touch nothing outside
// eight words. rsa_mont64_mul128_harness.c proves the rest of ct_mul128's
// contract. Every property the harnesses over this file hold is a bound or
// a memory access, and none reads a value beyond its contract.
//
// What the contracts give up: every value. No harness over this file says
// that a product is a * b / 2^(52n) mod m, that it is below 2m, or that
// rsa_ifma_public writes base^65537 mod m. bin/rsa_ifma_model_test holds
// those against rsa_mont64.c.
//
// The model header is read first, by its path from the root, which
// tools/impact_read.py follows to select these harnesses when the model
// changes. The #defines then rename the operations, and the header's
// include guard keeps rsa_ifma.c's own #include of it, which -Itest finds,
// from reading the real definitions again. Each harness then includes
// rsa_ifma.c itself, after this file, so that proof/coverage.py and
// tools/proof-cover.py, which read a harness's own #include lines, see
// which source it compiles.
#ifndef CH_RSA_IFMA_STUBS_H
#define CH_RSA_IFMA_STUBS_H

// harness.h, ct.h with ct_mul128 renamed to its contract, and rsa_mont64.c,
// which holds the marshalling and the last reduction rsa_ifma_public calls.
#include "rsa_mont64_stubs.h"

// A digit's 52 bits, the bound of each operand the refined multiply below
// reads and of each half a lane stub adds.
#define STUB_DIGIT_MASK ((UINT64_C(1) << 52) - 1)

// rsa_mont64_stubs.h's contract, and below 2^104 where both operands are
// below 2^52. The mask keeps every value the contract allows below 2^104,
// so the set it returns there is every value below 2^104.
static ct_u128 stub_digit_mul128(uint64_t a, uint64_t b) {
    ct_u128 product = stub_mul128(a, b);
    if ((a >> 52) == 0 && (b >> 52) == 0) {
        product &= ((ct_u128)1 << 104) - 1;
    }
    return product;
}

#undef ct_mul128
#define ct_mul128 stub_digit_mul128

#include "test/rsa_ifma_model_lanes.h"

// VPMADD52LUQ's contract: each lane of sum plus a value below 2^52.
static rsa_ifma_lanes stub_lanes_multiply_add_low(rsa_ifma_lanes sum, rsa_ifma_lanes x,
                                                  rsa_ifma_lanes y) {
    (void)x;
    (void)y;
    for (int j = 0; j < 8; j++) {
        sum.lane[j] += nondet_u64() & STUB_DIGIT_MASK;
    }
    return sum;
}

// VPMADD52HUQ's contract: each lane of sum plus a value below 2^52.
static rsa_ifma_lanes stub_lanes_multiply_add_high(rsa_ifma_lanes sum, rsa_ifma_lanes x,
                                                   rsa_ifma_lanes y) {
    (void)x;
    (void)y;
    for (int j = 0; j < 8; j++) {
        sum.lane[j] += nondet_u64() & STUB_DIGIT_MASK;
    }
    return sum;
}

#define lanes_multiply_add_low stub_lanes_multiply_add_low
#define lanes_multiply_add_high stub_lanes_multiply_add_high

#ifdef RSA_IFMA_STUB_EVERY_LANE_OPERATION
// The memory harnesses define this, and every lane operation is then a
// contract: lanes_load reads the eight words at its pointer, lanes_store
// writes them, and every operation returns any value. No index and no
// branch in rsa_ifma.c reads a lane's value, so a proof of memory safety
// over these covers every value the real operations return. VMOVDQU64,
// the instruction under lanes_load and lanes_store, reads or writes the
// same 64 bytes.
//
// Each operation is a macro that evaluates its operands and discards them,
// so every read of an array element that rsa_ifma.c passes stays a
// property, and neither the model's loops over eight lanes, which are test
// code, nor a copy of a register into a parameter enters the formula. With
// the model's loops a product at 5 registers took 10 s and 340 MB of
// symbolic execution, and rsa_ifma_public's eighteen took 204 s and
// 5.6 GB; with each operation a function of the same contract, the
// parameter copies still took a product 4.5 s and 280 MB.
rsa_ifma_lanes nondet_lanes(void);

static rsa_ifma_lanes stub_lanes_load(const uint64_t *words) {
    __CPROVER_assert(__CPROVER_r_ok(words, 8 * sizeof(uint64_t)),
                     "lanes_load: eight words are readable");
    return nondet_lanes();
}

static void stub_lanes_store(uint64_t *words) {
    __CPROVER_assert(__CPROVER_w_ok(words, 8 * sizeof(uint64_t)),
                     "lanes_store: eight words are writable");
    for (int j = 0; j < 8; j++) {
        words[j] = nondet_u64();
    }
}

#undef lanes_multiply_add_low
#undef lanes_multiply_add_high
#define lanes_zero() nondet_lanes()
#define lanes_broadcast(value) ((void)(value), nondet_lanes())
#define lanes_load(words) stub_lanes_load(words)
#define lanes_store(words, lanes) ((void)(lanes), stub_lanes_store(words))
#define lanes_multiply_add_low(sum, x, y) ((void)(sum), (void)(x), (void)(y), nondet_lanes())
#define lanes_multiply_add_high(sum, x, y) ((void)(sum), (void)(x), (void)(y), nondet_lanes())
#define lanes_down_one(high, low) ((void)(high), (void)(low), nondet_lanes())
#define lanes_up_one(high, low) ((void)(high), (void)(low), nondet_lanes())
#define lanes_first(lanes) ((void)(lanes), nondet_u64())
#define lanes_replace_first(lanes, value) ((void)(lanes), (void)(value), nondet_lanes())
#define lanes_shift_right_52(lanes) ((void)(lanes), nondet_lanes())
#define lanes_and(a, b) ((void)(a), (void)(b), nondet_lanes())
#define lanes_add(a, b) ((void)(a), (void)(b), nondet_lanes())
#define lanes_above(a, b) ((void)(a), (void)(b), nondet_u8())
#define lanes_equal(a, b) ((void)(a), (void)(b), nondet_u8())
#define lanes_add_where(source, bits, a, b)                                                        \
    ((void)(source), (void)(bits), (void)(a), (void)(b), nondet_lanes())
#endif

// count digits, each any value below 2^52, through the array's own type.
static void havoc_digits(uint64_t *digits, size_t count) {
    for (size_t i = 0; i < count; i++) {
        digits[i] = nondet_u64() & STUB_DIGIT_MASK;
    }
}

#endif
