// The one platform hook besides I/O: fill p with n cryptographically
// strong random bytes. Firmware wires this to its TRNG; the host tests
// use the OS entropy source. Must not fail — a device without entropy has
// no business starting a handshake, so implementations block or fault.
#ifndef CH_RAND_H
#define CH_RAND_H

#include <stddef.h>
#include <stdint.h>

void ch_rand_bytes(uint8_t *p, size_t n);

#endif
