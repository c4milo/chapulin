// Host implementation of the ch_rand_bytes hook (rand.h) for test
// binaries. Included by exactly one translation unit per binary. Firmware
// never sees this file — it wires the hook to its TRNG.
#ifndef CH_TEST_RANDOM_H
#define CH_TEST_RANDOM_H

#include <stdlib.h>

#include "rand.h"

#ifdef __APPLE__
void ch_rand_bytes(uint8_t *p, size_t n) {
    arc4random_buf(p, n);
}
#elif defined(__linux__)
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
#else
// Bare metal: no OS entropy to forward to, so the suites run on a
// seeded splitmix64. Deterministic on purpose -- the tests need varied
// bytes, not secret ones, and a fixed seed makes an on-target failure
// replay exactly. Never a source for ch_rand_bytes outside tests.
void ch_rand_bytes(uint8_t *p, size_t n) {
    static uint64_t s = 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < n; i++) {
        s += 0x9e3779b97f4a7c15ULL;
        uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        p[i] = (uint8_t)(z >> 56);
    }
}
#endif

#endif
