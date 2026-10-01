// X25519 Diffie-Hellman (RFC 7748). Montgomery ladder over 2^255-19 with
// 16-bit limbs in int64 words: uniform schoolbook products, small enough
// bounds for machine checking, and constant time by construction — the
// ladder branches on nothing and indexes memory by nothing secret.
#ifndef CH_X25519_H
#define CH_X25519_H

#include <stdint.h>

#define X25519_LEN 32

// out = scalar * point. Returns 1, or 0 when the result is all zero — a
// low-order peer point, which TLS 1.3 requires the caller to reject.
int x25519(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
           const uint8_t point[X25519_LEN]);

// out = scalar * base point (9); the keygen path, never low-order.
void x25519_base(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]);

#ifdef CH_WIDEMUL_RUNTIME
// The native copies of the entries above that are built on the widening multiply,
// which a WIDEMUL=runtime object holds beside them (x25519_native.c, widemul_native.h)
// and widemul.h's dispatchers call for CH_WIDEMUL_CONSTANT_TIME.
int x25519_native(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                  const uint8_t point[X25519_LEN]);
void x25519_base_native(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]);
#endif

#endif
