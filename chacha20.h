// ChaCha20 stream cipher (RFC 8439 §2.4). Constant time by construction:
// adds, XORs, and fixed rotations only — no tables, no secret-indexed
// loads, which is why AES never made the cut.
#ifndef MS_CHACHA20_H
#define MS_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_KEY 32
#define CHACHA20_NONCE 12
#define CHACHA20_BLOCK 64

// out = in XOR keystream(key, nonce, counter...). out == in is allowed,
// as is out below in (out <= in): bytes are produced in ascending order,
// so each address is written only after it was last read. counter is the
// initial 32-bit block counter; AEAD uses 1 for data and 0 for the
// Poly1305 key block.
void chacha20_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                  uint32_t counter, const uint8_t *in, uint8_t *out, size_t n);

// Single keystream block, used to derive the Poly1305 one-time key.
void chacha20_block(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    uint32_t counter, uint8_t out[CHACHA20_BLOCK]);

#endif
