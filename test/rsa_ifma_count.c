// rsa_ifma_public as a count and a call to rsa_mont64_public, which writes
// the bytes rsa_ifma_public writes under the same contract
// (test/rsa_ifma_count.h). It compiles under the condition rsa_ifma.h
// declares the entry under, so on arm64 this file holds the count alone.
#include "rsa_ifma_count.h"

#include <string.h>

#include "rsa_ifma.h"
#include "rsa_mont64.h"

unsigned long rsa_ifma_public_calls;

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL))

// rsa_vp1_cpu leaves mod->r2 unwritten (rsa_ifma.h), so this writes R^2 mod
// m, R = 2^(64k), into a copy of the modulus before it runs
// rsa_mont64_public. It takes R^2 from the digit_r2 = 2^(104n) mod m the
// call passed, by one Montgomery product: with shift = 52n - 64k, from 2
// to 53, 2^(64k - 2 shift) is below m, and its product with digit_r2,
// divided by R, is 2^(128k) mod m, because 104n = 128k + 2 shift. So a
// digit_r2 that is not that power of two gives other bytes, and the
// verifier rows that run this fail.
void rsa_ifma_public(uint8_t *out, const uint8_t *base, size_t len, const rsa_mont64_modulus *mod,
                     const uint64_t *digit_r2) {
    rsa_ifma_public_calls++;
    size_t k = mod->words;
    size_t shift = 52 * rsa_ifma_digit_count(k) - 64 * k;
    size_t bit = 64 * k - 2 * shift;
    rsa_mont64_modulus with_r2;
    memset(&with_r2, 0, sizeof with_r2);
    memcpy(with_r2.m, mod->m, k * sizeof(uint64_t));
    with_r2.m0inv = mod->m0inv;
    with_r2.words = k;
    with_r2.r2[bit >> 6] = (uint64_t)1 << (bit & 63);
    rsa_mont64_mont_mul(with_r2.r2, with_r2.r2, digit_r2, &with_r2);
    rsa_mont64_public(out, base, len, &with_r2);
}

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_RSA_IFMA_MODEL)
