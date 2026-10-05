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

// The add with carry and the subtract with borrow below have three forms, and P256_WIDE_CARRY
// names the one a build compiles. The compiler picks it (docs/decisions.md 94):
//
//   P256_WIDE_CARRY_BUILTIN    clang: __builtin_add_overflow and __builtin_sub_overflow. clang
//                              makes a flag of each and no branch at every optimization
//                              level, and at -O2 one add-with-carry instruction, so a chain of
//                              calls is a chain of them.
//   P256_WIDE_CARRY_INTRINSIC  gcc for x86-64: _addcarry_u64 and _subborrow_u64, which gcc
//                              expands to ADC and SBB at every level.
//   P256_WIDE_CARRY_SUM        gcc for any other machine: a 128-bit sum.
//
// gcc compiles neither builtin here. It expands one to an add and a jump on the add's carry,
// and leaves the jump for its if-conversion passes to remove. Below -O1 those passes do not
// run, and the carry is a limb's: under gcc 13.3 for x86-64 the builtins left 73 such jumps in
// the wide files at -Og, and 214 at -O2 with the two passes turned off. On the other two forms
// gcc 13.3 and 15.2 left none, at any level and with the passes off.
//
// clang compiles the builtins because the other two forms cost it instructions: under Apple
// clang 21 at -O2 for arm64 a field multiply is 141 instructions on the builtins and 166 on
// the sums.
//
// The harnesses in proof/, the rule of bin/p256_equiv_test_sum and two rows of
// test/aes-runtime-qemu.sh define P256_WIDE_CARRY and so name the form themselves. CBMC reads
// no intrinsic, and it reads one form on every machine that way. The tests run a form whatever
// compiler builds them.
#define P256_WIDE_CARRY_BUILTIN 1
#define P256_WIDE_CARRY_INTRINSIC 2
#define P256_WIDE_CARRY_SUM 3
#ifndef P256_WIDE_CARRY
#ifdef __clang__
#define P256_WIDE_CARRY P256_WIDE_CARRY_BUILTIN
#elif defined(__x86_64__)
#define P256_WIDE_CARRY P256_WIDE_CARRY_INTRINSIC
#else
#define P256_WIDE_CARRY P256_WIDE_CARRY_SUM
#endif
#endif

#if P256_WIDE_CARRY == P256_WIDE_CARRY_INTRINSIC
#include <immintrin.h>
#elif P256_WIDE_CARRY != P256_WIDE_CARRY_BUILTIN && P256_WIDE_CARRY != P256_WIDE_CARRY_SUM
#error "P256_WIDE_CARRY names none of the three forms of the carry steps"
#endif

// All ones when bit is 1 and zero when it is 0. The bit moves to the top and an arithmetic
// shift spreads it down, the form x25519.c's cswap takes: gcc rewrites `x & -bit` as a multiply
// by the bit (https://github.com/c4milo/chapulin/issues/106).
static inline uint64_t p256_wide_mask(uint64_t bit) {
    return (uint64_t)((int64_t)(bit << 63) >> 63);
}

// a + b + *carry: returns the low 64 bits and leaves the carry out, 0 or 1, in *carry. *carry
// is 0 or 1 on entry.
static inline uint64_t p256_wide_add_carry(uint64_t *carry, uint64_t a, uint64_t b) {
#if P256_WIDE_CARRY == P256_WIDE_CARRY_BUILTIN
    // Two adds, and at most one of them carries.
    uint64_t partial;
    uint64_t sum;
    uint64_t first = __builtin_add_overflow(a, b, &partial);
    uint64_t second = __builtin_add_overflow(partial, *carry, &sum);
    *carry = first | second;
    return sum;
#elif P256_WIDE_CARRY == P256_WIDE_CARRY_INTRINSIC
    unsigned long long sum;
    *carry = _addcarry_u64((unsigned char)*carry, a, b, &sum);
    return sum;
#else
    ct_u128 sum = (ct_u128)a + b + *carry;
    *carry = (uint64_t)(sum >> 64);
    return (uint64_t)sum;
#endif
}

// a - b - *borrow: returns the low 64 bits and leaves the borrow out, 0 or 1, in *borrow.
// *borrow is 0 or 1 on entry.
static inline uint64_t p256_wide_sub_borrow(uint64_t *borrow, uint64_t a, uint64_t b) {
#if P256_WIDE_CARRY == P256_WIDE_CARRY_BUILTIN
    // Two subtractions, and at most one of them borrows.
    uint64_t partial;
    uint64_t difference;
    uint64_t first = __builtin_sub_overflow(a, b, &partial);
    uint64_t second = __builtin_sub_overflow(partial, *borrow, &difference);
    *borrow = first | second;
    return difference;
#elif P256_WIDE_CARRY == P256_WIDE_CARRY_INTRINSIC
    unsigned long long difference;
    *borrow = _subborrow_u64((unsigned char)*borrow, a, b, &difference);
    return difference;
#else
    // a with bit 64 set is 2^64 + a, and 2^64 + a - b - *borrow is never below zero, so the
    // 128 bits wrap nothing. Bit 64 of the difference is clear when the subtraction borrowed.
    // An OR sets the bit, and not a sum: of a sum, gcc 15.2 for arm64 at -O2 folds a constant b
    // into the 2^64 and makes a jump of the carry of the add that is left, for its
    // if-conversion passes to remove (docs/decisions.md 94).
    ct_u128 difference = (((ct_u128)1 << 64) | a) - b - *borrow;
    *borrow = (uint64_t)(difference >> 64) ^ 1U;
    return (uint64_t)difference;
#endif
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
