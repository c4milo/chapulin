// poly1305_wide.h's sum of three words, for test/aead_avx2_equiv_test.c
// alone, which declares the generator and the failure count this file
// uses.
//
// The sum has two forms (docs/decisions.md 211): a statement of ADD, ADC
// and ADC that a gcc build for x86-64 compiles, and comparisons in C that
// every other build compiles. run_sum holds the form this binary compiled
// to the same sum in 128-bit arithmetic, which reads no carry flag and no
// comparison. CI's check job compiles with gcc for x86-64, and the
// aead-avx2 part of test/docker-aes-runtime-qemu.sh does on every machine,
// so the statement is the form both run.
//
// The cases: every combination of the words below for the two low words of
// each operand, which carry out of neither word, of either and of both,
// with each top word the block step and the fold pass; then random words.
#ifndef CH_AEAD_AVX2_EQUIV_SUM_H
#define CH_AEAD_AVX2_EQUIV_SUM_H

#include "ct.h"
#include "poly1305_wide.h"

#define SUM_RANDOM_CASES 4096

static void check_sum(uint64_t h0, uint64_t h1, uint64_t h2, uint64_t m0, uint64_t m1,
                      uint64_t m2) {
    ct_u128 low = (ct_u128)h0 + m0;
    ct_u128 middle = (ct_u128)h1 + m1 + (uint64_t)(low >> 64);
    uint64_t high = h2 + m2 + (uint64_t)(middle >> 64);
    uint64_t sum0 = h0;
    uint64_t sum1 = h1;
    uint64_t sum2 = h2;
    poly1305_wide_sum(&sum0, &sum1, &sum2, m0, m1, m2);
    compared++;
    if (sum0 != (uint64_t)low || sum1 != (uint64_t)middle || sum2 != high) {
        failures++;
        (void)fprintf(stderr,
                      "aead avx2 equivalence: the sum of (%llu : %016llx : %016llx) and "
                      "(%llu : %016llx : %016llx) differs from the 128-bit sum\n",
                      (unsigned long long)h2, (unsigned long long)h1, (unsigned long long)h0,
                      (unsigned long long)m2, (unsigned long long)m1, (unsigned long long)m0);
    }
}

static void run_sum(void) {
    static const uint64_t words[] = {
        0, 1, 2, UINT64_C(1) << 63, UINT64_MAX - 1, UINT64_MAX,
    };
    const size_t count = sizeof words / sizeof words[0];
    for (size_t i = 0; i < count * count * count * count; i++) {
        uint64_t h0 = words[i % count];
        uint64_t h1 = words[i / count % count];
        uint64_t m0 = words[i / (count * count) % count];
        uint64_t m1 = words[i / (count * count * count)];
        // The block step adds the block's 2^128 bit to a top word of at
        // most 4, and the fold adds nothing to one of at most 3.
        for (uint64_t h2 = 0; h2 <= 4; h2++) {
            check_sum(h0, h1, h2, m0, m1, 1);
            check_sum(h0, h1, h2, m0, m1, 0);
        }
    }
    for (size_t i = 0; i < SUM_RANDOM_CASES; i++) {
        uint64_t h0 = rng_next();
        uint64_t h1 = rng_next();
        uint64_t m0 = rng_next();
        uint64_t m1 = rng_next();
        uint64_t h2 = rng_next() >> 62;
        uint64_t m2 = rng_next() >> 63;
        check_sum(h0, h1, h2, m0, m1, m2);
    }
}

#endif
