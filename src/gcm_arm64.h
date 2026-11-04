// AES-GCM's whole seal and whole open in one call each on arm64's AES
// instructions and PMULL, with the passes in inline assembly
// (docs/decisions.md 158). gcm.c calls the entries at the foot of this
// header in place of its own seal and open for a schedule the AES
// instructions run, in a host object that targets arm64.
//
// One call does every step of SP 800-38D §7.1 and §7.2 that gcm.c's
// seal_schedule and open_schedule do for a 96-bit IV: the hash subkey, the
// first counter block's keystream, GHASH over the associated data, counter
// mode and GHASH over the text, the lengths block and the tag. The open
// writes the tag the ciphertext should carry, and gcm.c compares it with
// the received tag and wipes the plaintext on a mismatch, as it does on
// every other path. One call computes the hash subkey and its powers once
// for all of that, where gcm.c's steps compute them again in each call
// they make.
//
// Two copies of each entry. gcm_arm64.c's adds three values with two
// EORs. gcm_arm64_eor3.c compiles the same file once more with EOR3,
// FEAT_SHA3's three-way exclusive-or, under the _eor3 names, and
// gcm_use_eor3 below picks the copy from the session's bits.
//
// Every name begins gcm_, so inv-26-aes-public-keys-only matches a call
// from any library source outside gcm.c, and `make lint-quic-surface`
// reads this header for that prefix. The round keys are a public key's or
// a traffic key's, so INV-26 bounds these entries the way it bounds
// gcm_hw.c's. Where the AES bit puts a QUIC Initial key on the
// instructions, its packets run here too: the key is public.
#ifndef CH_GCM_ARM64_H
#define CH_GCM_ARM64_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#ifdef CH_CPU_RUNTIME

#include <stddef.h>
#include <stdint.h>

#include "aes.h"

#ifdef __aarch64__

// SP 800-38D's GCM-AE for a 96-bit IV under round keys expanded for rounds
// rounds: ct gets n ciphertext bytes and tag the 16-byte tag.
//
// Requires: round_keys points at (rounds + 1) * AES_BLOCK readable bytes
// that aes_expand_round_keys or aes_expand_round_keys_256 wrote, and rounds
// is AES_128_ROUNDS, or AES_256_ROUNDS in a build with AES-256, to match;
// nonce points at AES_IV readable bytes; aad at aad_len readable bytes,
// and may be NULL when aad_len is 0; pt at n readable bytes and ct at n
// writable bytes, either NULL when n is 0, with pt == ct allowed and no
// other overlap; tag at AES_BLOCK writable bytes outside the others. n is
// at most SP 800-38D's 2^36 - 32 bytes. Reads and writes no byte outside
// those ranges, and cannot fail.
void gcm_seal_arm64(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                    const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                    uint8_t tag[AES_BLOCK]);

// SP 800-38D's GCM-AD without the comparison: pt gets the n bytes of
// plaintext and want the tag the n bytes of ciphertext at ct and the
// associated data should carry. Every block of ct is hashed before any
// plaintext byte is written over it.
//
// Requires: what gcm_seal_arm64 requires, with ct readable and pt writable
// for n bytes, and pt == ct, pt below ct or no overlap allowed; want points
// at AES_BLOCK writable bytes outside the others.
void gcm_open_arm64(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                    const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                    uint8_t want[AES_BLOCK]);

// The same two on EOR3 as well: the same contracts and the same output.
void gcm_seal_arm64_eor3(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                         const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n,
                         uint8_t *ct, uint8_t tag[AES_BLOCK]);
void gcm_open_arm64_eor3(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                         const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                         uint8_t *pt, uint8_t want[AES_BLOCK]);

// Whether a schedule's AEAD runs on the EOR3 copy: where cpu, the
// description of the CPU the schedule records from its session's
// ch_cfg.cpu, holds CH_CPU_CONSTANT_TIME_SHA3, which says the CPU has
// FEAT_SHA3 and states that its instructions, EOR3 among them, run in
// constant time, beside CH_CPU_CONSTANT_TIME_AES. The value is the
// caller's and public, so the branch on it reads no key.
static inline int gcm_use_eor3(uint8_t cpu) {
    return (cpu & CH_CPU_CONSTANT_TIME_SHA3) != 0 && (cpu & CH_CPU_CONSTANT_TIME_AES) != 0;
}

// The entries as gcm.c calls them, with the schedule's cpu first: the EOR3
// copy where gcm_use_eor3 says so, and the other for every other value.
// One branch a call, on a value that is not secret, and no function
// pointer, as widemul.h picks a multiply.
static inline void gcm_seal_arm64_cpu(uint8_t cpu, const uint8_t *round_keys, size_t rounds,
                                      const uint8_t nonce[AES_IV], const uint8_t *aad,
                                      size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                                      uint8_t tag[AES_BLOCK]) {
    if (gcm_use_eor3(cpu)) {
        gcm_seal_arm64_eor3(round_keys, rounds, nonce, aad, aad_len, pt, n, ct, tag);
        return;
    }
    gcm_seal_arm64(round_keys, rounds, nonce, aad, aad_len, pt, n, ct, tag);
}

static inline void gcm_open_arm64_cpu(uint8_t cpu, const uint8_t *round_keys, size_t rounds,
                                      const uint8_t nonce[AES_IV], const uint8_t *aad,
                                      size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                                      uint8_t want[AES_BLOCK]) {
    if (gcm_use_eor3(cpu)) {
        gcm_open_arm64_eor3(round_keys, rounds, nonce, aad, aad_len, ct, n, pt, want);
        return;
    }
    gcm_open_arm64(round_keys, rounds, nonce, aad, aad_len, ct, n, pt, want);
}

#endif // __aarch64__
#endif // CH_CPU_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
