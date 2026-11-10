// Proves: the conversions of poly1305_wide.h between poly1305.c's five
// 26-bit words and three 64-bit limbs wrap no unsigned value, and keep the
// bounds each side takes (docs/decisions.md 206):
//
//   - poly1305_wide_from_words, from words that poly1305.c's loop leaves
//     (h0, h2, h3 and h4 below 2^26, h1 at most 2^26), leaves h2 at most 4,
//     the bound poly1305_wide_block takes;
//   - poly1305_wide_key_of, from r's words, each below 2^26 and together
//     below 2^124, leaves r0 below 2^64 and s1 equal to r1 + r1 / 4;
//   - poly1305_wide_to_words, from any limbs whose h2 is at most 4, leaves
//     every word below 2^26, which poly1305.c's final takes.
//
// --unsigned-overflow-check on the launch line checks each shift and sum.
// The values the conversions keep rest on bin/aead_avx2_equiv_test, which
// compares every tag with the two-pass AEAD's.
// The sum's statement of ADD, ADC and ADC is off, as the rows of
// proof/rsa_mont64_stubs.h are: the prove job's cbmc preprocesses as gcc
// does for x86-64, which would turn it on, and CBMC reads no assembly. The
// harness proves the comparisons, and bin/aead_avx2_equiv_test holds the
// statement to a 128-bit sum (docs/decisions.md 211).
#define POLY1305_WIDE_ADC 0
#include "harness.h"

#include "poly1305_wide.h"

uint32_t nondet_u32(void);
uint64_t nondet_u64(void);

int main(void) {
    uint32_t h[5];
    for (size_t i = 0; i < 5; i++) {
        h[i] = nondet_u32() & POLY1305_WIDE_WORD;
    }
    h[1] = nondet_u32();
    __CPROVER_assume(h[1] <= ((uint32_t)1 << 26));
    poly1305_wide_acc a;
    poly1305_wide_from_words(&a, h);
    __CPROVER_assert(a.h2 <= 4, "the limbs of poly1305.c's words hold h2 at most 4");

    uint32_t r[5];
    for (size_t i = 0; i < 5; i++) {
        r[i] = nondet_u32() & POLY1305_WIDE_WORD;
    }
    __CPROVER_assume(r[4] < ((uint32_t)1 << 20));
    poly1305_wide_key k;
    poly1305_wide_key_of(&k, r);
    __CPROVER_assert(k.r1 < ((uint64_t)1 << 60), "r1 is below 2^60");

    poly1305_wide_acc b;
    b.h0 = nondet_u64();
    b.h1 = nondet_u64();
    b.h2 = nondet_u64();
    __CPROVER_assume(b.h2 <= 4);
    uint32_t w[5];
    poly1305_wide_to_words(w, &b);
    for (size_t i = 0; i < 5; i++) {
        __CPROVER_assert(w[i] <= POLY1305_WIDE_WORD, "each word is below 2^26");
    }
    return 0;
}
