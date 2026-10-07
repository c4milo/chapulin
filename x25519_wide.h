// The wide X25519 field: the RFC 7748 Montgomery ladder over 2^255-19 in
// radix 2^51, five words in uint64_t, every product on the 64x64->128
// multiply ct.h names ct_mul128. A host object (-DCH_CPU_RUNTIME,
// cpu_cfg.h) holds it beside x25519.c's 16-word field, and widemul.h runs
// it for a session whose ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_MULTIPLY,
// the caller's statement about the multiply at both widths
// (docs/decisions.md 52 and 89). A session without the bit runs the
// 16-word field on ct.h's 16x16 decomposition, and a device object holds
// that field alone.
#ifndef CH_X25519_WIDE_H
#define CH_X25519_WIDE_H

#include <stdint.h>

#include "x25519.h"

#ifdef CH_CPU_RUNTIME
// x25519 and x25519_base (x25519.h) on this field, under the same
// contracts. x25519_wide.c compiles both from x25519.c, so the clamp and
// the all-zero check are that file's for both fields.
int x25519_wide(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                const uint8_t point[X25519_LEN]);
void x25519_wide_base(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]);

// out = the u-coordinate of clamped * point, for a scalar x25519.c has
// already clamped. It reports nothing: whether out is all zero is
// x25519_wide()'s return value (INV-3), decided after this returns.
void x25519_wide_ladder(uint8_t out[X25519_LEN], const uint8_t clamped[X25519_LEN],
                        const uint8_t point[X25519_LEN]);
#endif

#endif
