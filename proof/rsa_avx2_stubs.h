// The contracts the rsa_avx2 harnesses run rsa_avx2.c over, the way
// proof/rsa_ifma_stubs.h serves rsa_ifma.c.
//
// What the harnesses compile: rsa_avx2.c's own text under
// CH_RSA_AVX2_MODEL, over test/rsa_avx2_model_lanes.h, the model of each
// AVX2 instruction in portable C that bin/rsa_avx2_model_test runs. A
// launch line that includes this file passes -DCH_RSA_AVX2_MODEL and
// -Itest, the way the Makefile builds that test. CBMC cannot read the
// intrinsics in rsa_avx2_lanes.h, so no harness compiles the file the way
// an x86-64 host object does; bin/rsa_avx2_equiv_test holds each
// instruction to the model.
//
// Why the contracts exist: docs/proofs.md says SAT cost follows the
// multiply count, and a product at 19 groups runs about 2,900 lane
// multiplications, four products of 32-bit halves each.
//
// WHAT THE STUBS MODEL:
//
// - lanes_multiply, VPMULUDQ, gives each lane any value at or below
//   (2^32 - 1)^2, the most a product of two 32-bit halves holds, and any
//   value at or below (2^29 - 1)^2 where both operands' lanes are below
//   2^29. Every operand the kernel multiplies is a digit below 2^28, twice
//   one, a y below 2^28, or a blend of those.
// - Under RSA_AVX2_STUB_EVERY_LANE_OPERATION, which the memory harnesses
//   define, every lane operation: a load reads the four words at its
//   pointer, a store writes them, and every operation returns any value.
//
// WHAT DISCHARGES THE CONTRACTS: rsa_avx2_lanes_harness.c runs the model's
// real multiplication and proves both bounds for every pair of lanes, and
// that a load and a store touch nothing outside four words. Every property
// the harnesses over this file hold is a bound or a memory access, and
// none reads a value beyond its contract.
//
// What the contracts give up: every value. No harness over this file says
// that a product is a * b / 2^(Dn) mod m, that it is below 2m, or that
// rsa_avx2_public writes base^65537 mod m. spec/lean/Spec/RsaAvx2.lean
// proves those of its model of the C, bin/diff_rsa_avx2 holds the C to
// that model, and bin/rsa_avx2_model_test holds the C against
// rsa_mont64.c.
//
// The model header is read first, by its path from the root, which
// tools/impact_read.py follows to select these harnesses when the model
// changes, and its include guard keeps rsa_avx2.c's own #include of it,
// which -Itest finds, from reading it again. Each harness then includes
// rsa_avx2.c itself, after this file, so that proof/coverage.py and
// tools/proof-cover.py, which read a harness's own #include lines, see
// which source it compiles.
#ifndef CH_RSA_AVX2_STUBS_H
#define CH_RSA_AVX2_STUBS_H

// harness.h, ct.h with ct_mul128 renamed to its contract, and rsa_mont64.c,
// which holds the marshalling and the last reduction rsa_avx2_public calls.
#include "rsa_mont64_stubs.h"

#include "test/rsa_avx2_model_lanes.h"

// The bound below which both of a multiplication's operands give a product
// at or below (2^29 - 1)^2.
#define STUB_OPERAND_LIMIT ((uint64_t)1 << 29)

// VPMULUDQ's contract, as the header says.
static rsa_avx2_lanes stub_lanes_multiply(rsa_avx2_lanes x, rsa_avx2_lanes y) {
    rsa_avx2_lanes result;
    for (int j = 0; j < 4; j++) {
        uint64_t product = nondet_u64();
        if (x.lane[j] < STUB_OPERAND_LIMIT && y.lane[j] < STUB_OPERAND_LIMIT) {
            __CPROVER_assume(product <= (STUB_OPERAND_LIMIT - 1) * (STUB_OPERAND_LIMIT - 1));
        } else {
            __CPROVER_assume(product <= MODEL_LOW_32_BITS * MODEL_LOW_32_BITS);
        }
        result.lane[j] = product;
    }
    return result;
}

#define lanes_multiply stub_lanes_multiply

#ifdef RSA_AVX2_STUB_EVERY_LANE_OPERATION
// The memory harnesses define this, and every lane operation is then a
// contract: lanes_load reads the four words at its pointer, lanes_store
// writes them, and every operation returns any value. No index and no
// branch in rsa_avx2.c reads a lane's value, so a proof of memory safety
// over these covers every value the real operations return. VMOVDQU, the
// instruction under lanes_load and lanes_store, reads or writes the same
// 32 bytes.
//
// Each operation is a macro that evaluates its operands and discards them,
// so every read of an array element that rsa_avx2.c passes stays a
// property, and neither the model's loops over four lanes, which are test
// code, nor a copy of a register into a parameter enters the formula, as
// in proof/rsa_ifma_stubs.h.
rsa_avx2_lanes nondet_lanes(void);

static rsa_avx2_lanes stub_lanes_load(const uint64_t *words) {
    __CPROVER_assert(__CPROVER_r_ok(words, 4 * sizeof(uint64_t)),
                     "lanes_load: four words are readable");
    return nondet_lanes();
}

static void stub_lanes_store(uint64_t *words) {
    __CPROVER_assert(__CPROVER_w_ok(words, 4 * sizeof(uint64_t)),
                     "lanes_store: four words are writable");
    for (int j = 0; j < 4; j++) {
        words[j] = nondet_u64();
    }
}

#undef lanes_multiply
#define lanes_zero() nondet_lanes()
#define lanes_broadcast(value) ((void)(value), nondet_lanes())
#define lanes_load(words) stub_lanes_load(words)
#define lanes_store(words, lanes) ((void)(lanes), stub_lanes_store(words))
#define lanes_multiply(x, y) ((void)(x), (void)(y), nondet_lanes())
#define lanes_add(a, b) ((void)(a), (void)(b), nondet_lanes())
#define lanes_first_from(high, low) ((void)(high), (void)(low), nondet_lanes())
#define lanes_upper_two(high, low) ((void)(high), (void)(low), nondet_lanes())
#endif

// count lanes, each any value below 2^bits, through the array's own type.
static void havoc_digits(uint64_t *digits, size_t count, unsigned bits) {
    for (size_t i = 0; i < count; i++) {
        digits[i] = nondet_u64() & (((uint64_t)1 << bits) - 1);
    }
}

#endif
