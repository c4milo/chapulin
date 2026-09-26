// Reference ch_rand_bytes for parts without a hardware RNG: a
// fast-key-erasure generator over ChaCha20. The platform seeds it once
// at boot with its entropy sources concatenated into one seed (see
// docs/entropy.md — layered, never one source alone); every request
// then replaces the generator key from its own keystream before any
// output byte leaves, so compromising the state later reveals nothing
// generated earlier.
//
// A RAND=extern object leaves it out, so firmware with a real RNG never
// links it; a RAND=drbg object packages it and exports ch_drbg_seed.
// The test binaries provide their own ch_rand_bytes. Single-task, like
// the rest of the stack — and single instance: the generator state is
// the codebase's one piece of global mutable data, so every session in
// an image draws from the same stream and a reseed by one task changes
// what the others draw next. That is the right trade for a reference
// implementation meant to be replaced; an image that needs isolated
// generators wires its own ch_rand_bytes.
#ifndef CH_DRBG_H
#define CH_DRBG_H

#include <stddef.h>
#include <stdint.h>

// The shortest seed ch_drbg_seed takes, in bytes: the length of the
// ChaCha20 key the seed becomes.
#define CH_DRBG_SEED_MIN 32

// Mandatory before the first ch_rand_bytes call; generating without a
// seed is a programmer error (CH_ASSERT). The generator key becomes the
// SHA-256 of all seed_len bytes, so a caller concatenates its entropy
// sources into one buffer and passes the whole buffer; it needs no hash
// of its own. A seed shorter than CH_DRBG_SEED_MIN bytes is a
// programmer error too (CH_ASSERT). The call does not wipe the caller's
// buffer. The caller wipes it, because anyone who reads the seed can
// compute every byte the generator produces until the next call.
//
// Calling it again replaces the state. To add entropy that arrives
// after boot, concatenate the fresh bytes with output the generator
// just drew and pass that. Drawing that output takes a ch_rand_bytes
// call, which an image that compiles drbg.c itself can make; the
// packaged RAND=drbg object keeps ch_rand_bytes local.
void ch_drbg_seed(const uint8_t *seed, size_t seed_len);

#endif
