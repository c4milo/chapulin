// ChaCha20 stream cipher (RFC 8439 §2.4). Constant time by construction:
// adds, XORs, and fixed rotations only — no tables, no secret-indexed
// loads, which is why AES never made the cut.
#ifndef CH_CHACHA20_H
#define CH_CHACHA20_H

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

#ifdef CH_CPU_RUNTIME
// chacha20_xor for one session of a host object: the same bytes under the
// same contract, on the widest path cpu names. cpu is the session's
// ch_cfg.cpu. On x86-64 a value with CH_CPU_AVX512_IFMA runs
// chacha20_avx512.c's kernel, sixteen blocks a pass in 512-bit vectors, any
// other value with CH_CPU_AVX2 chacha20_avx2.c's kernel, eight blocks a
// pass in 256-bit vectors, and every other value chacha20_vector.c's SSE2
// path. On arm64 every value runs that file's NEON path (docs/decisions.md
// 89, 90 and 121). The AEAD calls it for a record
// or a packet. chacha20_xor in a host object runs the 128-bit path, which
// every CPU of the architecture has, for a caller that holds no session's
// description of the CPU.
void chacha20_xor_cpu(uint32_t cpu, const uint8_t key[CHACHA20_KEY],
                      const uint8_t nonce[CHACHA20_NONCE], uint32_t counter, const uint8_t *in,
                      uint8_t *out, size_t n);
#endif

#endif
