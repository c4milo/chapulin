// Proves: the constant-time software multiply is free of UB over
// unconstrained 32-bit and 64-bit inputs, its loops run the fixed counts
// it claims, and it returns the same product as the C operator at the
// widths bounded below.
//
// The equivalence is bounded because equivalence of two multipliers is the
// classic hard SAT instance, and docs/proofs.md says a launch line that has
// not been seen to converge proves nothing. Measured here, same flags: 8-bit
// operands verify in 9 s, 12-bit returns no verdict in 5 minutes, and the
// unconstrained 32x32 formula none in 10. Bounding one operand and leaving
// the other full width does not help -- the multiplicand's width is what
// costs, not the number of set multiplier bits, and b <= 0xFF with a
// unconstrained also gave no verdict in 5 minutes.
//
// So the bound is 8 bits on both operands. It constrains the operands, not
// the loop: both functions still run every one of their 32 and 64
// iterations, and the masked-add path is covered for a set bit and a clear
// one. It does not reach the accumulator's upper half, since an 8x8 product
// is 16 bits. The UB, pointer and unwinding checks above it carry no such
// bound -- those run on unconstrained 32-bit and 64-bit inputs.
//
// See https://github.com/c4milo/chapulin/issues/53.
#define CH_SOFT_MUL 1

#include "harness.h"

#include "softmul.c"

uint32_t nondet_u32(void);
uint64_t nondet_u64(void);

// The largest width whose formula has been seen to converge; see above.
#define SOFTMUL_BOUND 0xFFU

int main(void) {
    // Unconstrained: shifts stay in range, no overflow, loops terminate.
    uint32_t wild32_a = nondet_u32();
    uint32_t wild32_b = nondet_u32();
    (void)__mulsi3(wild32_a, wild32_b);
    uint64_t wild64_a = nondet_u64();
    uint64_t wild64_b = nondet_u64();
    (void)__muldi3(wild64_a, wild64_b);

    // Bounded: the product itself matches the operator it stands in for.
    uint32_t a32 = nondet_u32();
    uint32_t b32 = nondet_u32();
    __CPROVER_assume(a32 <= SOFTMUL_BOUND);
    __CPROVER_assume(b32 <= SOFTMUL_BOUND);
    __CPROVER_assert(__mulsi3(a32, b32) == (uint32_t)(a32 * b32), "__mulsi3 matches the C product");

    uint64_t a64 = nondet_u64();
    uint64_t b64 = nondet_u64();
    __CPROVER_assume(a64 <= SOFTMUL_BOUND);
    __CPROVER_assume(b64 <= SOFTMUL_BOUND);
    __CPROVER_assert(__muldi3(a64, b64) == (uint64_t)(a64 * b64), "__muldi3 matches the C product");
    return 0;
}
