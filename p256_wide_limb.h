// The steps on 64-bit limbs that the wide P-256 arithmetic is built from: an add with carry, a
// subtract with borrow, one row of a product, and a mask from a bit. p256_wide_field.c and
// p256_wide_scalar.c include this header and no other file does, so the two moduli share these
// four and nothing else, as p256_field.c and p256_scalar.c share none of their constants.
//
// Every step runs the same instructions whatever its operands hold. No branch and no index
// reads a limb. The one instruction whose timing the C cannot state is the 64x64->128 multiply,
// ct_mul128, which the session's CH_CPU_CONSTANT_TIME_MULTIPLY bit states (cpu_cfg.h).
#ifndef CH_P256_WIDE_LIMB_H
#define CH_P256_WIDE_LIMB_H

#include <stdint.h>

#include "ct.h"

#ifdef CH_CPU_RUNTIME

// All ones when bit is 1 and zero when it is 0. The bit moves to the top and an arithmetic
// shift spreads it down, the form x25519.c's cswap takes: gcc rewrites `x & -bit` as a multiply
// by the bit (https://github.com/c4milo/chapulin/issues/106).
static inline uint64_t p256_wide_mask(uint64_t bit) {
    return (uint64_t)((int64_t)(bit << 63) >> 63);
}

// a + b + *carry: returns the low 64 bits and leaves the carry out, 0 or 1, in *carry. *carry
// is 0 or 1 on entry.
//
// The two carries come from __builtin_add_overflow, which gcc and clang both have, and at most
// one of them is set. clang makes one add-with-carry instruction of this form, so a chain of
// calls is a chain of them. A 128-bit sum of the three terms compiles to more: measured under
// Apple clang 21 at -O2 for arm64, a field add is 26 instructions this way and 46 that way,
// and a field multiply 141 and 168 (docs/decisions.md 94).
static inline uint64_t p256_wide_add_carry(uint64_t *carry, uint64_t a, uint64_t b) {
    uint64_t partial;
    uint64_t sum;
    uint64_t first = __builtin_add_overflow(a, b, &partial);
    uint64_t second = __builtin_add_overflow(partial, *carry, &sum);
    *carry = first | second;
    return sum;
}

// a - b - *borrow: returns the low 64 bits and leaves the borrow out, 0 or 1, in *borrow.
// *borrow is 0 or 1 on entry.
static inline uint64_t p256_wide_sub_borrow(uint64_t *borrow, uint64_t a, uint64_t b) {
    uint64_t partial;
    uint64_t difference;
    uint64_t first = __builtin_sub_overflow(a, b, &partial);
    uint64_t second = __builtin_sub_overflow(partial, *borrow, &difference);
    *borrow = first | second;
    return difference;
}

// One row of a product: adds x * (b3 : b2 : b1 : b0) to (*t3 : *t2 : *t1 : *t0) and returns
// the limb above them. The low halves of the four products go down one carry chain and the
// high halves down another.
//
// The sum is at most (2^64 - 1) * (2^256 - 1) + 2^256 - 1, which is below 2^320, so the limb
// returned holds everything above the four: the last line cannot wrap.
// proof/p256_wide_row_harness.c proves that on the real multiply.
static inline uint64_t p256_wide_mul_row(uint64_t *t0, uint64_t *t1, uint64_t *t2, uint64_t *t3,
                                         uint64_t x, uint64_t b0, uint64_t b1, uint64_t b2,
                                         uint64_t b3) {
    ct_u128 p0 = ct_mul128(x, b0);
    ct_u128 p1 = ct_mul128(x, b1);
    ct_u128 p2 = ct_mul128(x, b2);
    ct_u128 p3 = ct_mul128(x, b3);
    uint64_t low_carry = 0;
    *t0 = p256_wide_add_carry(&low_carry, *t0, (uint64_t)p0);
    *t1 = p256_wide_add_carry(&low_carry, *t1, (uint64_t)p1);
    *t2 = p256_wide_add_carry(&low_carry, *t2, (uint64_t)p2);
    *t3 = p256_wide_add_carry(&low_carry, *t3, (uint64_t)p3);
    uint64_t high_carry = 0;
    *t1 = p256_wide_add_carry(&high_carry, *t1, (uint64_t)(p0 >> 64));
    *t2 = p256_wide_add_carry(&high_carry, *t2, (uint64_t)(p1 >> 64));
    *t3 = p256_wide_add_carry(&high_carry, *t3, (uint64_t)(p2 >> 64));
    return (uint64_t)(p3 >> 64) + low_carry + high_carry;
}

#endif // CH_CPU_RUNTIME

#endif
