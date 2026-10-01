// AES-GCM's work over whole blocks on x86-64's 256-bit VAES and VPCLMULQDQ:
// the three contracts gcm_hw.h states for gcm_hw.c's entries, computed two
// blocks to a register. Every x86-64 host object that carries AES holds
// these kernels beside gcm_hw.c's 128-bit loops, and each of gcm_hw.c's
// three entries is to hand its blocks to the kernel of the same shape
// where the caller's ch_cfg.cpu sets CH_CPU_VAES, which says the CPU has
// VAES and VPCLMULQDQ, and CH_CPU_CONSTANT_TIME_AES, which claims the AES
// instructions and the carry-less multiply run in constant time. No call
// passes those bits to gcm_hw.c yet, so no call runs the kernels.
//
// A pair of its own rather than more entries in gcm_hw.c: these
// functions run on instructions the rest of the object may not use, so
// every function in gcm_vaes.c carries the target attribute that turns
// them on, and only those functions do, the way aes_hw.c's carry the AES
// instructions. The object needs no compiler flag for them, and the rest
// of it runs on any x86-64 CPU. chapulin probes no CPU: the caller's bits
// are to decide whether the kernels run (docs/decisions.md 89 and 90).
//
// Every name begins gcm_, so inv-26-aes-public-keys-only matches a call
// from any library source outside gcm.c and gcm_hw.c, and `make
// lint-quic-surface` reads this header for that prefix. The round keys are
// a public key's or a traffic key's, so INV-26 bounds these entries the way
// it bounds gcm_hw.c's.
#ifndef CH_GCM_VAES_H
#define CH_GCM_VAES_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#ifdef CH_CPU_RUNTIME

#include <stddef.h>
#include <stdint.h>

#include "aes.h"

// The kernels exist on x86-64 alone. On any other target gcm_vaes.c
// compiles to nothing but these includes.
#ifdef __x86_64__

// gcm_counter_blocks_hw's contract (gcm_hw.h), on the 256-bit
// instructions.
//
// Requires: what gcm_counter_blocks_hw requires, and a CPU with AVX2,
// VAES and VPCLMULQDQ, which the caller decides from its answer; on a CPU
// without them the first instruction faults.
void gcm_counter_blocks_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                             const uint8_t *in, size_t blocks, uint8_t *out);

// gcm_seal_passes_hw's contract (gcm_hw.h), on the 256-bit instructions.
//
// Requires: what gcm_seal_passes_hw requires, and the CPU
// gcm_counter_blocks_vaes requires.
void gcm_seal_passes_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                          uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *in, size_t passes, uint8_t *out);

// gcm_open_passes_hw's contract (gcm_hw.h), on the 256-bit instructions:
// each pass's ciphertext is hashed before any of its plaintext is written.
//
// Requires: what gcm_open_passes_hw requires, and the CPU
// gcm_counter_blocks_vaes requires.
void gcm_open_passes_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                          uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *in, size_t passes, uint8_t *out);

#endif // __x86_64__
#endif // CH_CPU_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
