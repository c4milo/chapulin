// A clock for tests: it answers the value its clock_io points at, so a
// test sets the instant an init call reads by writing that value. Each
// configuration points at a variable of its own, so a client and a
// server in one test can read two clocks.
#ifndef CH_TEST_CLOCK_H
#define CH_TEST_CLOCK_H

#include <stdint.h>

#include "cfg.h"

// Only the builds that read a clock declare ch_cfg.now_seconds.
#if defined(CH_TRUST_WEBPKI) || defined(CH_ROLE_SERVER)
static inline uint64_t test_clock(void *clock_io) {
    return *(const uint64_t *)clock_io;
}

// The variables a test's server and client clocks read, one each.
static inline uint64_t *test_server_seconds(void) {
    static uint64_t seconds;
    return &seconds;
}
static inline uint64_t *test_client_seconds(void) {
    static uint64_t seconds;
    return &seconds;
}

// Points cfg's clock at *slot, which the init call reads, and writes
// seconds there.
static inline void test_clock_set(ch_cfg *cfg, uint64_t *slot, uint64_t seconds) {
    *slot = seconds;
    cfg->now_seconds = test_clock;
    cfg->clock_io = slot;
}
#endif

#endif
