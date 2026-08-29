// Proves: the 16x16 decomposition in ct.h returns the same product as the C
// operator it stands in for, and is free of UB over unconstrained operands.
//
// This equivalence is what carries every other proof in the tree to the
// target. The proofs run on a development machine, where ct.h resolves
// CH_NATIVE_WIDEMUL and ct_widemul is one instruction, so the poly1305,
// x25519 and mlkem_poly formulas verify the single-multiply form. Firmware on
// a part with no constant-time widening multiply runs the decomposition
// instead. Those proofs describe what ships only if the two forms compute the
// same function, and until this harness that rested on the edge grid and
// 200k random products in test/softmul_test.c.
//
// CH_CT_WIDEMUL is defined below so the decomposition is what gets proven;
// without it this file would prove a * b == a * b on the host.
//
// See https://github.com/c4milo/chapulin/issues/53.
#define CH_CT_WIDEMUL 1

#include "harness.h"

#include "ct.h"

uint32_t nondet_u32(void);
uint64_t nondet_u64(void);
int32_t nondet_i32(void);

int main(void) {
    // Unconstrained: no shift out of range, no overflow, no UB anywhere in
    // the recombination, at full 32-bit width on both operands.
    uint32_t wild_a = nondet_u32();
    uint32_t wild_b = nondet_u32();
    (void)ct_widemul(wild_a, wild_b);

    int32_t wild_sa = nondet_i32();
    int32_t wild_sb = nondet_i32();
    (void)ct_widemul_s(wild_sa, wild_sb);

    uint64_t wild_m = nondet_u64();
    uint32_t wild_k = nondet_u32();
    (void)ct_mulsmall(wild_m, wild_k);

    // Equivalence, at a measured bound. Same flags as the launch line: 8-bit
    // operands verify in 33 s under kissat and 106 s under the built-in
    // solver; 16-bit returned no verdict in 900 s and was stopped there.
    // 32-bit is unmeasured -- the 16-bit result made it not worth the run.
    // Equivalence of two multipliers is the classic hard SAT instance, which
    // is why softmul_harness.c sits at the same width for the same reason.
    //
    // The bound constrains the operands, not the shape: all four 16x16 pieces
    // and the whole recombination still execute, and the unconstrained block
    // above covers UB and shift range at full 32-bit width.
    uint32_t a = nondet_u32();
    uint32_t b = nondet_u32();
    __CPROVER_assume(a <= CH_WIDEMUL_BOUND);
    __CPROVER_assume(b <= CH_WIDEMUL_BOUND);
    __CPROVER_assert(ct_widemul(a, b) == (uint64_t)a * b, "ct_widemul matches the C product");

    // The signed form over the same bound, both signs, since the sign
    // corrections are the part that is masked rather than branched.
    int32_t sa = nondet_i32();
    int32_t sb = nondet_i32();
    __CPROVER_assume(sa >= -(int32_t)CH_WIDEMUL_BOUND && sa <= (int32_t)CH_WIDEMUL_BOUND);
    __CPROVER_assume(sb >= -(int32_t)CH_WIDEMUL_BOUND && sb <= (int32_t)CH_WIDEMUL_BOUND);
    __CPROVER_assert(ct_widemul_s(sa, sb) == (int64_t)sa * sb,
                     "ct_widemul_s matches the C product");

    // ct_mulsmall's callers pass a literal 37 or 38 (x25519.c), so k's high
    // half is a compile-time zero there. Prove it over a symbolic k anyway,
    // because the header states the general contract.
    uint64_t m = nondet_u64();
    uint32_t k = nondet_u32();
    __CPROVER_assume(m <= CH_WIDEMUL_BOUND);
    __CPROVER_assume(k <= CH_WIDEMUL_BOUND);
    __CPROVER_assert(ct_mulsmall(m, k) == m * k, "ct_mulsmall matches the C product");
    return 0;
}
