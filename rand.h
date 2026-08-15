// The one platform hook besides I/O: fill p with n cryptographically
// strong random bytes. A part with a hardware RNG wires this to it. A
// part without one — the RTL8382-class reference target has none — uses
// the seeded generator in drbg.[ch] and provisions its seed as
// docs/entropy.md describes; a bare counter or clock is not a seed.
// Either way the hook must not fail: a device without entropy has no
// business starting a handshake, so implementations block or fault.
// The host tests use the OS entropy source.
#ifndef CH_RAND_H
#define CH_RAND_H

#include <stddef.h>
#include <stdint.h>

void ch_rand_bytes(uint8_t *p, size_t n);

#endif
