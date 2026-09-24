// X25519=wide: the RFC 7748 Montgomery ladder over 2^255-19 in radix 2^51,
// five limbs in uint64_t, every product on the 64x64->128 multiply ct.h
// names ct_mul128. x25519.c calls it in place of its own 16-limb ladder
// when the build defines CH_X25519_WIDE, and ct.h stops that build unless
// the compiler has unsigned __int128 and the build asserts CH_NATIVE_MUL128.
// x25519.c keeps the clamp and the all-zero check for both fields.
#ifndef CH_X25519_WIDE_H
#define CH_X25519_WIDE_H

#include <stdint.h>

#include "x25519.h"

// out = the u-coordinate of clamped * point, for a scalar x25519.c has
// already clamped. It reports nothing: whether out is all zero is
// x25519()'s return value (INV-3), decided after this returns.
void x25519_wide_ladder(uint8_t out[X25519_LEN], const uint8_t clamped[X25519_LEN],
                        const uint8_t point[X25519_LEN]);

#endif
