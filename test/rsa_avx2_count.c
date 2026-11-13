// rsa_avx2_public as a count and a public operation on rsa_mont64.c, which
// writes the bytes rsa_avx2_public writes under the same contract
// (test/rsa_avx2_count.h). It compiles under the condition rsa_avx2.h
// declares the entry under, so on arm64 this file holds the count alone.
#include "rsa_avx2_count.h"

#include <string.h>

#include "rsa_avx2.h"
#include "rsa_mont64.h"

unsigned long rsa_avx2_public_calls;

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_AVX2_MODEL))

// rsa_vp1_cpu passes power_words = base 2^(Dn) mod m, below m
// (rsa_avx2.h), and leaves mod->r2 unwritten. This runs the steps of
// rsa_mont.c's public_by_division from that power. With shift = Dn - 64k,
// from 2 to D + 1, 2^(64k - shift) is below m, and its Montgomery product
// with the power, divided by R = 2^(64k), is base R mod m. Sixteen squares
// and a product by the base follow. So words that are not base 2^(Dn) mod
// m give other bytes, and the verifier rows that run this fail.
void rsa_avx2_public(uint8_t *out, const uint8_t *base, size_t len, const rsa_mont64_modulus *mod,
                     const uint64_t *power_words) {
    rsa_avx2_public_calls++;
    size_t k = mod->words;
    size_t bit = 64 * k - (rsa_avx2_r_exponent(k) - 64 * k);
    uint64_t acc[RSA_MONT64_WORDS_MAX] = {0};
    uint64_t words[RSA_MONT64_WORDS_MAX] = {0};
    acc[bit >> 6] = (uint64_t)1 << (bit & 63);
    rsa_mont64_mont_mul(acc, acc, power_words, mod);
    for (int i = 0; i < 16; i++) {
        rsa_mont64_mont_square(acc, acc, mod);
    }
    rsa_mont64_from_bytes(words, k, base, len);
    rsa_mont64_reduce_once(words, words, mod);
    rsa_mont64_mont_mul(acc, words, acc, mod);
    rsa_mont64_to_bytes(out, len, acc);
}

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_RSA_AVX2_MODEL)
