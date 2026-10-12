// The SHA-512 compression function (FIPS 180-4 §6.4.2), the block half of
// sha512.c in its own file. A proof takes the framing — update's block
// assembly and finalize's padding and length — with this function stubbed
// to its contract, and proves this function apart over one block of
// unconstrained state. One formula carrying both converged only at a
// 15.3 GB peak, above the nightly runner's memory; mlkem.c and
// mlkem_poly.c split the same way for the same reason.
//
// A device object runs this function, and it is the reference a host
// object's sha512_compress_blocks.c is held to (docs/decisions.md 127). In
// a TRUST=webpki object it reads public bytes alone. In a SUITE=aesgcm
// device object, which takes AES=extern, it also reads HMAC keys and the
// PSK, as sha512.h says. It wipes nothing: its eighty schedule words and
// its working variables stay in its dead frame, and sha512.c's calls that
// take a whole message leave their context in theirs (docs/invariants.md,
// INV-17).
#ifndef CH_SHA512_COMPRESS_H
#define CH_SHA512_COMPRESS_H

#include <stdint.h>

#include "sha512.h"

// Absorbs one 128-byte block into the eight-word state h
// (FIPS 180-4 §6.4.2 steps 1 to 4). Reads exactly SHA512_BLOCK bytes of
// block and writes exactly the eight words of h.
void sha512_compress(uint64_t h[8], const uint8_t block[SHA512_BLOCK]);

#endif
