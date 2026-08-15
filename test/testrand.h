// Host implementation of the ch_rand_bytes hook (rand.h) for test
// binaries. Included by exactly one translation unit per binary. Firmware
// never sees this file — it wires the hook to its TRNG.
#ifndef CH_TESTRAND_H
#define CH_TESTRAND_H

#include <stdlib.h>

#include "rand.h"

#ifdef __APPLE__
void ch_rand_bytes(uint8_t *p, size_t n) {
    arc4random_buf(p, n);
}
#else
#include <sys/random.h>
void ch_rand_bytes(uint8_t *p, size_t n) {
    while (n > 0) {
        // getrandom is capped per call; loop like read(2).
        ssize_t got = getrandom(p, n, 0);
        if (got <= 0) {
            abort(); // no entropy, no handshake
        }
        p += got;
        n -= (size_t)got;
    }
}
#endif

#endif
