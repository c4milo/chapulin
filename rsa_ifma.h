// RSA's public operation on AVX-512 IFMA, for verification alone: base^65537
// mod m in digits of 52 bits, eight to a 512-bit register, which
// VPMADD52LUQ and VPMADD52HUQ multiply. rsa_mont.c's rsa_vp1_cpu calls it
// in an x86-64 host object for a session whose ch_cfg.cpu holds
// CH_CPU_AVX512_IFMA (cpu_cfg.h), and is the one library source besides
// rsa_ifma.c that includes this header. rsa_sign64.c never calls it: the
// compiler keeps words of the 512-bit registers in stack slots that no
// wipe can name, so its input must be public, and a modulus, a signature
// and an encoded message are.
//
// rsa_ifma.c in this tree is a stub, which a later commit replaces with
// the kernel: it writes rsa_mont64_public's bytes on rsa_mont64.c's words
// and runs no AVX-512 instruction.
//
// The declarations exist in a host object (-DCH_CPU_RUNTIME) on x86-64,
// and in a test build that names CH_RSA_IFMA_MODEL. A later commit adds
// that build, which compiles the kernel over a scalar model of each
// instruction on any host. No library build names that define.
#ifndef CH_RSA_IFMA_H
#define CH_RSA_IFMA_H

#include <stddef.h>
#include <stdint.h>

#include "rsa_mont64.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL))

// The fewest words of a modulus rsa_ifma_public takes: 32, RSA-2048, the
// smallest modulus either verifier admits (rsa.h). That is 40 digits, in
// five registers.
#define RSA_IFMA_WORDS_MIN 32

// The digits of 52 bits that hold `words` 64-bit words with two bits to
// spare, n = ceil((64 * words + 2) / 52), so that 4m < 2^(52n) for a
// modulus m of that many words: 40 for RSA-2048, 60 for RSA-3072 and 79
// for RSA-4096.
#define RSA_IFMA_DIGIT_COUNT(words) ((64 * (words) + 2 + 51) / 52)
static inline size_t rsa_ifma_digit_count(size_t words) {
    return RSA_IFMA_DIGIT_COUNT(words);
}

// The most registers of eight digits a number takes: 10 under
// CH_TRUST_WEBPKI, whose bound is RSA-4096, and 8 below it, RSA-3072.
#define RSA_IFMA_REGISTERS_MAX ((RSA_IFMA_DIGIT_COUNT(RSA_MONT64_WORDS_MAX) + 7) / 8)

// out = base^65537 mod m (RSAVP1, RFC 8017 5.2.2), base and out both len
// big-endian bytes, len <= 8 * mod->words: the bytes rsa_mont64_public
// writes, for any base of that length. It needs an odd m of k =
// mod->words words, RSA_IFMA_WORDS_MIN <= k <= RSA_MONT64_WORDS_MAX, whose
// top bit is set, and digit_r2 = 2^(104n) mod m in k words, with n =
// rsa_ifma_digit_count(k). It reads mod->m, mod->m0inv and mod->words, and
// not mod->r2, which rsa_vp1_cpu leaves unwritten.
//
// Requires: a CPU with AVX-512F and AVX-512 IFMA whose operating system
// saves the 512-bit registers. rsa_vp1_cpu decides that from the session's
// CH_CPU_AVX512_IFMA bit; on a CPU without them the first instruction
// faults.
void rsa_ifma_public(uint8_t *out, const uint8_t *base, size_t len, const rsa_mont64_modulus *mod,
                     const uint64_t *digit_r2);

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_RSA_IFMA_MODEL)

#endif
