// p384_field.c and the 32-bit arm of p384.c, which a device object holds,
// in a host test binary (test/p384_portable.c). p384_field.h declares the
// field's routines, and this header the rest.
#ifndef CH_TEST_P384_PORTABLE_H
#define CH_TEST_P384_PORTABLE_H

#include <stddef.h>
#include <stdint.h>

#include "p384.h"

// p384.c's 32-bit arm, under a second name beside the host arm.
int p384_ecdsa_verify_portable(const uint8_t pub[P384_PUB_LEN], const uint8_t msg_hash[P384_LEN],
                               const uint8_t *sig_der, size_t sig_len);

// out = k1*G + k2*Q as X||Y, on that arm's points. Returns 1, or 0 with out
// untouched when the sum is the point at infinity. k1 and k2 are 48
// big-endian bytes each, and q is Q as X||Y, a point on the curve. A NULL
// q leaves the second term out.
int p384_portable_double_mul(uint8_t out[P384_PUB_LEN], const uint8_t k1[P384_LEN],
                             const uint8_t k2[P384_LEN], const uint8_t q[P384_PUB_LEN]);

// The 12 words as 48 big-endian bytes: the inverse of p384_from_bytes,
// which the library has no use for.
void p384_portable_to_bytes(uint8_t b[P384_LEN], const uint32_t a[P384_WORDS]);

#endif
