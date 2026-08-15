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
void aead_seal(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
               size_t aadlen, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]);

// Returns 1 and writes n plaintext bytes on tag match; returns 0 and
// writes nothing on mismatch. pt == ct is allowed, and so is pt below ct
// (pt <= ct): decryption copies forward, so writing each byte before or
// at the address it was read from is safe. The record layer leans on
// this to decrypt in place over its own 5-byte header.
int aead_open(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
              size_t aadlen, const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG], uint8_t *pt);

#endif
