// The stub of rsa_ifma.h's rsa_ifma_public, which a later commit replaces
// with the AVX-512 IFMA kernel. It writes rsa_mont64_public's bytes on
// rsa_mont64.c's words and runs no AVX-512 instruction, so rsa_vp1_cpu's
// dispatch, its callers and their tests run before the kernel exists, on
// any x86-64 CPU.
#include "rsa_ifma.h"

// The whole file compiles only in a host object on x86-64, or in the test
// build that names CH_RSA_IFMA_MODEL, which a later commit adds
// (rsa_ifma.h).
#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL))

#include <string.h>

#include "ch_assert.h"

// rsa_vp1_cpu leaves mod->r2 unwritten, so the stub writes R^2 mod m, R =
// 2^(64k), into a copy of the modulus from digit_r2 = 2^(104n) mod m, by
// one Montgomery product. shift = 52n - 64k is from 2 to 53, so
// 2^(64k - 2 shift) is at most 2^(64k - 4), which is below m, whose top
// bit is set. Its product with digit_r2, divided by R, is
// 2^(64k - 2 shift + 104n - 64k) = 2^(128k) = R^2 mod m, because
// 104n = 128k + 2 shift. Every value here is public, and nothing is wiped.
void rsa_ifma_public(uint8_t *out, const uint8_t *base, size_t len, const rsa_mont64_modulus *mod,
                     const uint64_t *digit_r2) {
    size_t k = mod->words;
    CH_ASSERT(k >= RSA_IFMA_WORDS_MIN && k <= RSA_MONT64_WORDS_MAX);
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
