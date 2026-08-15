// Reference ch_rand_bytes for parts without a hardware RNG: a
// fast-key-erasure generator over ChaCha20. The platform seeds it once
// at boot with 32 bytes assembled from its entropy sources (see
// docs/entropy.md — layered, never one source alone); every request
// then replaces the generator key from its own keystream before any
// output byte leaves, so compromising the state later reveals nothing
// generated earlier.
//
// Deliberately not part of the packaged library object: firmware with a
// real RNG never links it, and the test binaries provide their own
// ch_rand_bytes. Single-task, like the rest of the stack.
#ifndef CH_DRBG_H
#define CH_DRBG_H

#include <stdint.h>

// Mandatory before the first ch_rand_bytes call; generating without a
// seed is a programmer error (CH_ASSERT). Calling it again replaces the
// state, so a platform can fold in late-arriving entropy by reseeding
// with a mix of fresh bytes and output it just drew.
void ch_drbg_seed(const uint8_t seed[32]);

#endif
