// ChaCha20-Poly1305 AEAD (RFC 8439 §2.8). Verify-before-decrypt: open
// computes the tag over the ciphertext first and never releases a byte of
// plaintext on a bad tag.
#ifndef CH_AEAD_H
#define CH_AEAD_H

#include <stddef.h>
#include <stdint.h>

#include "chacha20.h"
#include "poly1305.h"

#define AEAD_KEY 32
#define AEAD_NONCE 12
#define AEAD_TAG 16

// ct gets n bytes of ciphertext; tag is written separately so record-layer
// callers can place it after the ciphertext. pt == ct allowed (in-place).
// Both calls take first the answer Poly1305's block loop runs under, a
// WIDEMUL_ value, and hand it to widemul.h's dispatchers.
void aead_seal(uint8_t widemul, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
               const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
               uint8_t tag[AEAD_TAG]);

// Returns 1 and writes n plaintext bytes on tag match; returns 0 and
// writes nothing on mismatch. pt == ct is allowed, and so is pt below ct
// (pt <= ct): decryption copies forward, so writing each byte before or
// at the address it was read from is safe. The record layer depends on
// this to decrypt in place over its own 5-byte header.
int aead_open(uint8_t widemul, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
              const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
              const uint8_t tag[AEAD_TAG], uint8_t *pt);

#ifdef CH_CPU_RUNTIME
// aead_seal and aead_open for one session of a host object, under the same
// contracts. Both take the session's ch_cfg.cpu in place of the answer,
// and read two bits of it: CH_CPU_CONSTANT_TIME_MULTIPLY gives the answer
// Poly1305 runs under (widemul_of_cpu), and chacha20_xor_cpu runs the
// keystream on the path the value names. A record and a QUIC packet go
// through these two. aead_seal and aead_open run the keystream on the
// 128-bit path, for a caller with an answer and no description of the
// CPU.
void aead_seal_cpu(uint32_t cpu, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
                   const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                   uint8_t tag[AEAD_TAG]);
int aead_open_cpu(uint32_t cpu, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
                  const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                  const uint8_t tag[AEAD_TAG], uint8_t *pt);
#endif

// The seal and the open as a record or a QUIC packet calls them, with its
// session's ch_cfg.cpu first. A host object passes it to the two entries
// above. A device object holds one keystream path and one multiply, so it
// calls aead_seal and aead_open under the answer its build states,
// WIDEMUL_BUILD_ANSWER, which the calling file takes from widemul.h, and
// never evaluates cpu: the expression may name a field that build does
// not declare, as REC_DIR_INIT_SUITE does with a suite (record.h).
#ifdef CH_CPU_RUNTIME
#define AEAD_SEAL_CPU(cpu, ...) aead_seal_cpu((cpu), __VA_ARGS__)
#define AEAD_OPEN_CPU(cpu, ...) aead_open_cpu((cpu), __VA_ARGS__)
#else
#define AEAD_SEAL_CPU(cpu, ...) aead_seal(WIDEMUL_BUILD_ANSWER, __VA_ARGS__)
#define AEAD_OPEN_CPU(cpu, ...) aead_open(WIDEMUL_BUILD_ANSWER, __VA_ARGS__)
#endif

#endif
