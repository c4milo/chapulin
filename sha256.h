// SHA-256 (FIPS 180-4). Streaming, because the handshake transcript hash
// absorbs messages as they cross the wire; no message is ever buffered
// whole for hashing.
#ifndef MS_SHA256_H
#define MS_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_LEN 32
#define SHA256_BLOCK 64

typedef struct {
    uint32_t h[8];
    uint64_t nbytes; // total message bytes absorbed
    uint8_t block[SHA256_BLOCK];
    size_t fill; // bytes pending in block
} sha256;

void sha256_init(sha256 *s);
void sha256_update(sha256 *s, const uint8_t *in, size_t n);
// Finalizes into out[32]. s is spent; re-init to reuse. Does not wipe —
// callers hashing secrets wipe the context themselves.
void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]);

void sha256_of(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]);

#endif
