// AES-GCM's work over whole blocks on x86-64's 256-bit VAES and VPCLMULQDQ:
// the three contracts gcm_hw.h states for gcm_hw.c's entries, computed two
// blocks to a register. Every x86-64 host object that carries AES holds
// these kernels beside gcm_hw.c's 128-bit loops. gcm.c calls the three
// entries at the foot of this header, and each hands a schedule's blocks
// to the kernel of gcm_hw.c's entry's shape where gcm_use_vaes says so:
// where the session's ch_cfg.cpu sets CH_CPU_VAES, which says the CPU has
// VAES and VPCLMULQDQ, and CH_CPU_CONSTANT_TIME_AES, which states that the
// AES instructions and the carry-less multiply run in constant time
// (aes_schedule.h).
//
// A pair of its own rather than more entries in gcm_hw.c: these
// functions run on instructions the rest of the object may not use, so
// every function in gcm_vaes.c carries the target attribute that turns
// them on, and only those functions do, the way aes_hw.c's carry the AES
// instructions. The object needs no compiler flag for them, and the rest
// of it runs on any x86-64 CPU. chapulin probes no CPU: the caller's bits
// decide whether the kernels run (docs/decisions.md 89 and 90).
//
// Every name begins gcm_, so inv-26-aes-public-keys-only matches a call
// from any library source outside gcm.c, and `make
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
#include "gcm_hw.h"

// The kernels exist on x86-64 alone. On any other target gcm_vaes.c
// compiles to nothing but these includes.
#ifdef __x86_64__

// gcm_counter_blocks_hw's contract (gcm_hw.h), on the 256-bit
// instructions.
//
// Requires: what gcm_counter_blocks_hw requires, and a CPU with AVX2,
// VAES and VPCLMULQDQ, which gcm_use_vaes decides from the session's
// bits; on a CPU without them the first instruction faults.
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

// Whether a schedule's whole blocks run on the kernels above in place of
// gcm_hw.c's 128-bit loops: where cpu, the description of the CPU the
// schedule records from its session's ch_cfg.cpu, holds both CH_CPU_VAES
// and CH_CPU_CONSTANT_TIME_AES. One bit without the other runs the 128-bit
// loops: the AES bit is the one statement that covers the 256-bit forms,
// and CH_CPU_VAES is what says the CPU has them. The value is the
// caller's and public, so the branch on it reads no key.
static inline int gcm_use_vaes(uint8_t cpu) {
    return (cpu & CH_CPU_VAES) != 0 && (cpu & CH_CPU_CONSTANT_TIME_AES) != 0;
}

#endif // __x86_64__

// gcm_hw.h's three entries as gcm.c calls them, with the schedule's cpu
// first: on x86-64 the kernel of the same shape where gcm_use_vaes says
// so, and gcm_hw.c's 128-bit loop for every other value and on arm64,
// which has no such kernel. One branch a call, on a value that is not
// secret, and no function pointer, as widemul.h picks a multiply.
static inline void gcm_counter_blocks_cpu(uint8_t cpu, const uint8_t *round_keys, size_t rounds,
                                          uint8_t counter[AES_BLOCK], const uint8_t *in,
                                          size_t blocks, uint8_t *out) {
#ifdef __x86_64__
    if (gcm_use_vaes(cpu)) {
        gcm_counter_blocks_vaes(round_keys, rounds, counter, in, blocks, out);
        return;
    }
#else
    (void)cpu;
#endif
    gcm_counter_blocks_hw(round_keys, rounds, counter, in, blocks, out);
}

static inline void gcm_seal_passes_cpu(uint8_t cpu, const uint8_t *round_keys, size_t rounds,
                                       uint8_t counter[AES_BLOCK], uint8_t acc[AES_BLOCK],
                                       const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                                       size_t passes, uint8_t *out) {
#ifdef __x86_64__
    if (gcm_use_vaes(cpu)) {
        gcm_seal_passes_vaes(round_keys, rounds, counter, acc, subkey, in, passes, out);
        return;
    }
#else
    (void)cpu;
#endif
    gcm_seal_passes_hw(round_keys, rounds, counter, acc, subkey, in, passes, out);
}

static inline void gcm_open_passes_cpu(uint8_t cpu, const uint8_t *round_keys, size_t rounds,
                                       uint8_t counter[AES_BLOCK], uint8_t acc[AES_BLOCK],
                                       const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                                       size_t passes, uint8_t *out) {
#ifdef __x86_64__
    if (gcm_use_vaes(cpu)) {
        gcm_open_passes_vaes(round_keys, rounds, counter, acc, subkey, in, passes, out);
        return;
    }
#else
    (void)cpu;
#endif
    gcm_open_passes_hw(round_keys, rounds, counter, acc, subkey, in, passes, out);
}

#endif // CH_CPU_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
