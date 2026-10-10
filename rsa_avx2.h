// RSA's public operation on AVX2, for verification alone: base^65537 mod m
// in digits of 28 bits, or 27 above RSA-3072, one digit to each 64-bit
// lane, four to a 256-bit register, which VPMULUDQ multiplies 32 x 32 ->
// 64. rsa_mont.c's rsa_vp1_cpu calls it in an x86-64 host object for a
// session whose ch_cfg.cpu holds CH_CPU_AVX2 and not CH_CPU_AVX512_IFMA
// (cpu_cfg.h), and is the one library source besides rsa_avx2.c that
// includes this header. rsa_sign64.c never calls it: the compiler keeps
// 256-bit registers in stack slots that no wipe can name, so its input must
// be public, and a modulus, a signature and an encoded message are.
//
// rsa_avx2.c writes rsa_mont64_public's bytes for every base. Its
// Montgomery products divide by R' = 2^(Dn), for n digits of D bits, in
// place of rsa_mont64.c's R = 2^(64k), which is why it takes 2^(2Dn) mod
// m, R'^2, where rsa_mont64.c takes R^2 (docs/decisions.md 122).
//
// The declarations exist in a host object (-DCH_CPU_RUNTIME) on x86-64,
// and in a test unit that defines CH_RSA_AVX2_MODEL, which compiles
// rsa_avx2.c over test/rsa_avx2_model_lanes.h, a model of each instruction
// in portable C, on any host. No library build names that define, which
// test/widemul-builds.sh checks.
#ifndef CH_RSA_AVX2_H
#define CH_RSA_AVX2_H

#include <stddef.h>
#include <stdint.h>

#include "rsa_mont64.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_AVX2_MODEL))

// The fewest words of a modulus rsa_avx2_public takes: 32, RSA-2048, the
// smallest modulus either verifier admits (rsa.h).
#define RSA_AVX2_WORDS_MIN 32

// The digit width D for a modulus of `words` words: 28 bits up to
// RSA-3072's 48 words, and 27 above, which only the 512-byte bound of
// TRUST=webpki admits. A lane of the product sums up to 2n digit products
// below 2^(2D) and one carry below 2^(64 - D), which must stay below 2^64:
// RSA-3072's 110 digits of 28 bits leave room, and RSA-4096's 147 would
// not, where its 152 digits of 27 bits do (rsa_avx2.c).
#define RSA_AVX2_DIGIT_BITS(words) ((words) <= 48 ? 28U : 27U)

// The digits that hold `words` 64-bit words with two bits to spare, n =
// ceil((64 * words + 2) / D), so that 4m < 2^(Dn) for a modulus m of that
// many words: 74 for RSA-2048, 110 for RSA-3072 and 152 for RSA-4096. Each
// arm divides by its own constant, which the compiler turns into a
// multiplication, so no division instruction runs.
#define RSA_AVX2_DIGIT_COUNT(words)                                                                \
    ((words) <= 48 ? (64 * (words) + 2 + 27) / 28 : (64 * (words) + 2 + 26) / 27)
static inline size_t rsa_avx2_digit_count(size_t words) {
    return RSA_AVX2_DIGIT_COUNT(words);
}

// The exponent of R'^2 = 2^(2Dn), which rsa_avx2_public takes mod m as
// digit_r2: 4144, 6160 and 8208 for RSA-2048, RSA-3072 and RSA-4096.
static inline size_t rsa_avx2_r2_exponent(size_t words) {
    return 2 * (size_t)RSA_AVX2_DIGIT_BITS(words) * RSA_AVX2_DIGIT_COUNT(words);
}

// out = base^65537 mod m (RSAVP1, RFC 8017 5.2.2), base and out both len
// big-endian bytes, len <= 8 * mod->words: the bytes rsa_mont64_public
// writes, for any base of that length. It needs an odd m of k =
// mod->words words, RSA_AVX2_WORDS_MIN <= k <= RSA_MONT64_WORDS_MAX, whose
// top bit is set, and digit_r2 = 2^rsa_avx2_r2_exponent(k) mod m in k
// words. It reads mod->m, mod->m0inv and mod->words, and not mod->r2,
// which rsa_vp1_cpu leaves unwritten.
//
// Requires: a CPU with AVX2 whose operating system saves the 256-bit
// registers. rsa_vp1_cpu decides that from the session's CH_CPU_AVX2 bit;
// on a CPU without them the first instruction faults.
void rsa_avx2_public(uint8_t *out, const uint8_t *base, size_t len, const rsa_mont64_modulus *mod,
                     const uint64_t *digit_r2);

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_RSA_AVX2_MODEL)

#endif
