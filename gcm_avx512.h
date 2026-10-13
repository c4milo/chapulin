// AES-GCM's whole seal and whole open in one call each, four blocks to a 512-bit register, on
// x86-64's VAES and VPCLMULQDQ with AVX-512F and AVX-512BW (docs/decisions.md 130). gcm.c calls
// these two entries in place of its own seal and open for a schedule whose description of the
// CPU passes gcm_use_avx512 below.
//
// One call does every step of SP 800-38D §7.1 and §7.2 that gcm.c's seal_schedule and
// open_schedule do for a 96-bit IV: the hash subkey, the first counter block's keystream, GHASH
// over the associated data, counter mode and GHASH over the text, the lengths block and the tag.
// The open writes the tag the ciphertext should carry, and gcm.c compares it with the received
// tag and wipes the plaintext on a mismatch, as it does on every other path.
//
// Each entry runs gcm_avx512_kernel.c's kernel for the key size, then wipes
// GCM_AVX512_BELOW_LEN bytes of stack below its own frame, which held the kernel's frames, and
// then calls avx512_wipe_registers, which zeros every vector register and k1 to k7.
//
// A pair of its own rather than more entries in gcm_vaes.c: these entries hold no instruction
// beyond the rest of the object, and the kernel's functions carry their own target attribute,
// as gcm_vaes.c's do, so the object needs no compiler flag and the rest of it runs on any x86-64
// CPU. chapulin probes no CPU: the caller's bits decide whether the kernel runs
// (docs/decisions.md 89 and 130).
//
// Every name begins gcm_, so inv-26-aes-public-keys-only matches a call from any library source
// outside gcm.c, and `make lint-quic-surface` reads this header for that prefix. The round keys
// are a public key's or a traffic key's, so INV-26 bounds these entries the way it bounds
// gcm_hw.c's. Where the AES bit puts a QUIC Initial key on the instructions, its packets run
// here too: the key is public (docs/decisions.md 130).
#ifndef CH_GCM_AVX512_H
#define CH_GCM_AVX512_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#ifdef CH_CPU_RUNTIME

#include <stddef.h>
#include <stdint.h>

#include "aes.h"

// The kernel exists on x86-64 alone. On any other target gcm_avx512.c compiles to nothing but
// its includes, except in a proof unit that defines CH_GCM_AVX512_MODEL
// (proof/gcm_avx512_wipe_harness.c).
#if defined(__x86_64__) || defined(CH_GCM_AVX512_MODEL)

// SP 800-38D's GCM-AE for a 96-bit IV under round keys expanded for rounds rounds: ct gets n
// ciphertext bytes and tag the 16-byte tag.
//
// Requires: round_keys points at (rounds + 1) * AES_BLOCK readable bytes that
// aes_expand_round_keys or aes_expand_round_keys_256 wrote, and rounds is AES_128_ROUNDS, or
// AES_256_ROUNDS in a build with AES-256, to match; nonce points at AES_IV readable bytes; aad at
// aad_len readable bytes, and may be NULL when aad_len is 0; pt at n readable bytes and ct at n
// writable bytes, either NULL when n is 0, with pt == ct allowed and no other overlap; tag at
// AES_BLOCK writable bytes outside the others. The CPU has AVX-512F, AVX-512BW, VAES and
// VPCLMULQDQ, which gcm_use_avx512 decides from the session's bits: on a CPU without them the
// first instruction faults. Reads and writes no byte outside those ranges, and cannot fail.
void gcm_seal_avx512(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                     const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                     uint8_t tag[AES_BLOCK]);

// SP 800-38D's GCM-AD without the comparison: pt gets the n bytes of plaintext and want the tag
// the n bytes of ciphertext at ct and the associated data should carry. Every block of ct is
// hashed before any plaintext byte is written over it.
//
// Requires: what gcm_seal_avx512 requires, with ct readable and pt writable for n bytes, and
// pt == ct, pt below ct or no overlap allowed; want points at AES_BLOCK writable bytes outside
// the others.
void gcm_open_avx512(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                     const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                     uint8_t want[AES_BLOCK]);

// Whether a schedule's whole AEAD runs on the two entries above in place of gcm.c's seal and open
// over gcm_vaes.c's or gcm_hw.c's loops: where cpu, the description of the CPU the schedule
// records from its session's ch_cfg.cpu, holds CH_CPU_AVX512, which says the CPU has the
// instructions, CH_CPU_VAES and CH_CPU_CONSTANT_TIME_AES, the one statement about their timing.
// The value is the caller's and public, so the branch on it reads no key.
static inline int gcm_use_avx512(uint32_t cpu) {
    return (cpu & CH_CPU_AVX512) != 0 && (cpu & CH_CPU_VAES) != 0 &&
           (cpu & CH_CPU_CONSTANT_TIME_AES) != 0;
}

#endif // __x86_64__ || CH_GCM_AVX512_MODEL
#endif // CH_CPU_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
