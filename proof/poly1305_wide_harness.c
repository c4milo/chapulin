// Proves: poly1305_wide_block in poly1305_wide.h, on the real 64x64->128
// multiply, wraps no unsigned value and leaves h2 at most 4, for every
// accumulator whose h0 and h1 are any 64-bit values and whose h2 is at most
// 4, every r that RFC 8439 §2.5.1's clamp leaves (r0 and r1 below 2^60,
// r1 a multiple of 4, and s1 = r1 + r1 / 4), and every 16-byte block. The
// wrap check is --unsigned-overflow-check on the launch line: each 128-bit
// sum of products, each carry and the fold's product by 5 is a property of
// its own. spec/lean/Spec/Poly1305Wide.lean's block_mod proves what the
// step computes on the numbers these checks keep in range
// (docs/decisions.md 206).
//
// The bound is the loop invariant of aead_avx2.c's pass_hashing: a step
// from h2 at most 4 leaves h2 at most 4, so every step of every pass is
// inside the domain proved here.
// The sum's statement of ADD, ADC and ADC is off, as the rows of
// proof/rsa_mont64_stubs.h are: the prove job's cbmc preprocesses as gcc
// does for x86-64, which would turn it on, and CBMC reads no assembly. The
// harness proves the comparisons, and bin/aead_avx2_equiv_test holds the
// statement to a 128-bit sum (docs/decisions.md 211).
#define POLY1305_WIDE_ADC 0
#include "harness.h"

#include "poly1305_wide.h"

uint64_t nondet_u64(void);
uint8_t nondet_u8(void);

int main(void) {
    poly1305_wide_key k;
    k.r0 = nondet_u64() & UINT64_C(0x0ffffffc0fffffff);
    k.r1 = nondet_u64() & UINT64_C(0x0ffffffc0ffffffc);
    k.s1 = k.r1 + (k.r1 >> 2);
    poly1305_wide_acc a;
    a.h0 = nondet_u64();
    a.h1 = nondet_u64();
    a.h2 = nondet_u64();
    __CPROVER_assume(a.h2 <= 4);
    uint8_t m[16];
    for (size_t i = 0; i < sizeof m; i++) {
        m[i] = nondet_u8();
    }
    poly1305_wide_block(&a, &k, m);
    __CPROVER_assert(a.h2 <= 4, "a block step leaves h2 at most 4");
    return 0;
}
