// Proves: in an AES=runtime suite build, the default order suite.h's
// suite_session_default gives a session, under any byte of the caller's
// answer about the AES instructions, is ChaCha20 alone unless the answer
// is CH_AES_INSTRUCTIONS_PRESENT, and suite_default_order when it is. So
// srv_first_offered_suite, which srv_select runs over that order, selects
// no AES-GCM suite for a session whose caller found no instructions, from
// any offer of the three suites, and the ClientHello, which offers the
// same order when the caller names none (handshake_message.h), lists
// none. Every suite chosen is one suite_runs_here admits for the session
// (docs/decisions.md 81).
#include "harness.h"

#include "suite.h"

#if !defined(CH_SUITE_AES_GCM) || !defined(CH_AES_RUNTIME) || !defined(CH_ROLE_SERVER)
#error                                                                                             \
    "srv_select_runtime proves the AES=runtime default order; pass -DCH_ROLE_SERVER -DCH_SUITE_AES_GCM -DCH_AES_RUNTIME"
#endif

int main(void) {
    ch_cfg cfg;
    cfg.aes_instructions = nondet_u8();
    size_t count = 0;
    const uint16_t *order = suite_session_default(&cfg, &count);
    if (cfg.aes_instructions == CH_AES_INSTRUCTIONS_PRESENT) {
        __CPROVER_assert(order == suite_default_order && count == SUITE_HELD_COUNT,
                         "present: the build's default order");
    } else {
        __CPROVER_assert(count == 1 && order[0] == SUITE_CHACHA20_POLY1305_SHA256,
                         "any other answer: ChaCha20 alone");
    }
    uint8_t offered = nondet_u8();
    __CPROVER_assume((offered & ~(SRV_SUITE_CHACHA20_POLY1305 | SRV_SUITE_AES_128_GCM |
                                  SRV_SUITE_AES_256_GCM)) == 0);
    uint16_t chosen = srv_first_offered_suite(order, count, offered);
    __CPROVER_assert(chosen == 0 || suite_runs_here(&cfg, chosen),
                     "the chosen suite runs on the session's answer");
    return 0;
}
