// Proves: in a host object's suite build (-DCH_CPU_RUNTIME), the default
// order suite.h's suite_session_default gives a session, under any 32-bit
// ch_cfg.cpu, is ChaCha20 alone unless the value holds
// CH_CPU_CONSTANT_TIME_AES, and suite_default_order when it does. So
// srv_first_offered_suite, which srv_select runs over that order, selects
// no AES-GCM suite for a session whose caller did not state the AES
// instructions, from any offer of the three suites, and the ClientHello,
// which offers the same order when the caller names none
// (handshake_message.h), lists none. Every suite chosen is one
// suite_runs_here admits for the session (docs/decisions.md 81 and 89).
#include "harness.h"

#include "suite.h"

#if !defined(CH_SUITE_AES_GCM) || !defined(CH_CPU_RUNTIME) || !defined(CH_ROLE_SERVER)
#error                                                                                             \
    "srv_select_runtime proves a host object's default order; pass -DCH_ROLE_SERVER -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME"
#endif

int main(void) {
    ch_cfg cfg;
    cfg.cpu = nondet_u32();
    size_t count = 0;
    const uint16_t *order = suite_session_default(&cfg, &count);
    if ((cfg.cpu & CH_CPU_CONSTANT_TIME_AES) != 0) {
        __CPROVER_assert(order == suite_default_order && count == SUITE_HELD_COUNT,
                         "the AES bit: the build's default order");
    } else {
        __CPROVER_assert(count == 1 && order[0] == SUITE_CHACHA20_POLY1305_SHA256,
                         "any value without it: ChaCha20 alone");
    }
    uint8_t offered = nondet_u8();
    __CPROVER_assume((offered & ~(SRV_SUITE_CHACHA20_POLY1305 | SRV_SUITE_AES_128_GCM |
                                  SRV_SUITE_AES_256_GCM)) == 0);
    uint16_t chosen = srv_first_offered_suite(order, count, offered);
    __CPROVER_assert(chosen == 0 || suite_runs_here(&cfg, chosen),
                     "the chosen suite runs under the session's ch_cfg.cpu");
    return 0;
}
