// RSA signing's two exponentiations on AVX-512 IFMA: the halves of a
// signature by the Chinese remainder theorem, m1^dp mod p and m2^dq mod
// q, in digits of 52 bits, eight to a 512-bit register, on the
// almost-Montgomery product of rsa_ifma_product.h (docs/decisions.md 120).
// rsa_sign64.c calls it in an x86-64 host object for a session whose
// ch_cfg.cpu holds CH_CPU_AVX512_IFMA and CH_CPU_CONSTANT_TIME_MULTIPLY,
// and is the one library source besides rsa_ifma_sign.c that includes
// this header. The multiply bit's statement covers the 52-bit products of
// VPMADD52LUQ and VPMADD52HUQ, and the IFMA bit says the CPU has them
// (cpu_cfg.h).
//
// It computes what two calls of rsa_sign64_power compute: o = base^e mod
// m in rsa_mont64.c's Montgomery domain, R = 2^(64k), for a base in that
// domain below m. Each exponentiation reads its exponent four bits at a
// time against a table of the base's first sixteen powers, as
// rsa_sign64_power does, and the two run side by side: each round of a
// product under one prime beside the same round under the other, as
// OpenSSL's ossl_rsaz_mod_exp_avx512_x2 runs them.
//
// The operands are secret: the primes, dp and dq, and every power. Every
// branch and every memory index depends on a count or an index, the table
// is read whole and one entry kept by masks that pass through a volatile
// word, and every array the call names is wiped before it returns. The
// compiler also keeps words and 512-bit registers in stack slots of its
// own, which no wipe written in C names, and the vector and mask
// registers hold what the last product left in them. So the function that
// calls rsa_ifma_sign_power_pair calls rsa_ifma_sign_wipe_below and then
// avx512_wipe_registers (avx512_wipe.h) right after it.
//
// The declarations exist in a host object (-DCH_CPU_RUNTIME) on x86-64,
// and in a test unit that defines CH_RSA_IFMA_MODEL, which compiles the
// kernel over test/rsa_ifma_model_lanes.h, a model of each instruction in
// portable C, on any host.
#ifndef CH_RSA_IFMA_SIGN_H
#define CH_RSA_IFMA_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "rsa_mont64.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL))

// The words of a prime the kernel takes: 16, the primes of RSA-2048, the
// smallest modulus the signer admits (rsa_sign.h), to half of
// RSA_MONT64_WORDS_MAX, 24 at the 384-byte bound and 32 at the 512-byte
// one. A prime of k words takes n = RSA_IFMA_DIGIT_COUNT(k) digits
// (rsa_ifma.h): 20 in three registers at 16 words, 30 in four at 24 and
// 40 in five at 32.
#define RSA_IFMA_SIGN_WORDS_MIN 16
#define RSA_IFMA_SIGN_WORDS_MAX (RSA_MONT64_WORDS_MAX / 2)

// o_p = base_p^e_p mod p and o_q = base_q^e_q mod q, each in the
// Montgomery domain of its record and below its prime: the words
// rsa_sign64_power writes for each. mod_p and mod_q are records of two
// odd moduli of the same word count k, RSA_IFMA_SIGN_WORDS_MIN <= k <=
// RSA_IFMA_SIGN_WORDS_MAX, which CH_ASSERT holds. base_p and base_q are
// in that domain and below their moduli, and e_p and e_q are e_len
// big-endian bytes, every one of which is read. o_p may be base_p, and o_q
// may be base_q.
//
// Requires: a CPU with AVX-512F and AVX-512 IFMA whose operating system
// saves the 512-bit registers. rsa_sign64.c decides that from the
// session's CH_CPU_AVX512_IFMA bit; on a CPU without them the first
// instruction faults.
void rsa_ifma_sign_power_pair(uint64_t *o_p, const uint64_t *base_p, const uint8_t *e_p,
                              const rsa_mont64_modulus *mod_p, uint64_t *o_q,
                              const uint64_t *base_q, const uint8_t *e_q,
                              const rsa_mont64_modulus *mod_q, size_t e_len);

// The bytes of stack rsa_ifma_sign_wipe_below writes zeros over: 15,360
// at the 384-byte bound and 20,480 at the 512-byte one. The deepest call
// it follows is rsa_ifma_sign_power_pair, whose frames hold the two
// primes' tables. bin/rsa_ifma_sign_residue_test measures how far below
// its caller each call writes and requires it inside this array
// (docs/decisions.md 120). lint-stack holds the file's frames under
// STACK_BUDGET_RSA_IFMA_SIGN.
#define RSA_IFMA_SIGN_BELOW_LEN (40 * CH_RSA_MODULUS_MAX)

// Writes zero over the RSA_IFMA_SIGN_BELOW_LEN bytes of stack under the
// caller's frame, where the frames of rsa_ifma_sign_power_pair and of the
// signer's check lay, with the slots the compiler kept words and 512-bit
// registers in, as p256_wide_wipe_below does for P-256 (p256_wide_wipe.h).
// It clears no register.
void rsa_ifma_sign_wipe_below(void);

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_RSA_IFMA_MODEL)

#endif
