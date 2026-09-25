// The image test/lib-pair-check.sh links from two packaged objects of
// different transports: this file, the half of each transport
// (test/lib_pair_half.c) and the two objects. It defines each hook once
// for both objects, as docs/porting.md says an image does, and runs the
// half of each transport the script names with -DLIB_PAIR_TCP_BLOCKING,
// -DLIB_PAIR_TCP_NONBLOCKING or -DLIB_PAIR_QUIC_NONBLOCKING.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>

#include "ch_assert.h"
#include "lib_pair.h"
#include "rand.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// Not a generator: a byte counter both objects draw from. It never
// writes an all-zero draw of more than one byte, which is what every
// draw site in the library checks (INV-4), and no session here runs
// far enough for its values to matter.
void ch_rand_bytes(uint8_t *p, size_t n) {
    static uint8_t next = 1;
    for (size_t i = 0; i < n; i++) {
        p[i] = next;
        next = (uint8_t)(next + 1U);
    }
}

#ifdef LIB_PAIR_KEYLOG
// No session here derives a traffic secret, so the hook never runs.
void ch_keylog(void *io, const char *label, const uint8_t client_random[32],
               const uint8_t secret[32]) {
    (void)io;
    (void)label;
    (void)client_random;
    (void)secret;
    abort();
}
#endif

// Exits with the number of halves that failed, so 0 means both ran.
int main(void) {
    int failures = 0;
#ifdef LIB_PAIR_TCP_BLOCKING
    failures += lib_pair_tcp_blocking();
#endif
#ifdef LIB_PAIR_TCP_NONBLOCKING
    failures += lib_pair_tcp_nonblocking();
#endif
#ifdef LIB_PAIR_QUIC_NONBLOCKING
    failures += lib_pair_quic_nonblocking();
#endif
    return failures;
}
