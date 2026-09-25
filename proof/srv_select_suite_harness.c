// Proves: the server's cipher suite choice, suite.h's
// srv_first_offered_suite, over every offer of the three SRV_SUITE_ bits
// and every order of up to three code points, including code points the
// build does not hold, which ch_srv_cfg.cipher_suites cannot carry past
// srv_config_ok (srv.c) but the walk must pass over all the same. The
// choice is 0 exactly when no suite in the order was offered; otherwise
// it is a suite the client offered, it is in the order, and no suite
// ahead of it in the order was offered. So the server never selects a
// suite the client did not list, which RFC 9846 §4.2.3 forbids
// (rfc9846.txt:1373-1376). srv_flight.c's select_suite passes this walk
// either the caller's order or its default one and adds nothing else.
#include "harness.h"

#include "suite.h"

#if !defined(CH_SUITE_AES_GCM) || !defined(CH_ROLE_SERVER)
#error "srv_select_suite proves the server's suite build; pass -DCH_ROLE_SERVER -DCH_SUITE_AES_GCM"
#endif

#define ORDER_MAX 3

int main(void) {
    uint16_t order[ORDER_MAX];
    for (size_t i = 0; i < ORDER_MAX; i++) {
        uint8_t hi = nondet_u8();
        uint8_t lo = nondet_u8();
        order[i] = (uint16_t)((hi << 8) | lo);
    }
    size_t count = nondet_size_t();
    __CPROVER_assume(count <= ORDER_MAX);
    uint8_t offered = nondet_u8();
    __CPROVER_assume((offered & ~(SRV_SUITE_CHACHA20_POLY1305 | SRV_SUITE_AES_128_GCM |
                                  SRV_SUITE_AES_256_GCM)) == 0);

    uint16_t chosen = srv_first_offered_suite(order, count, offered);
    int any_offered = 0;
    for (size_t i = 0; i < count; i++) {
        if ((offered & srv_suite_bit(order[i])) != 0) {
            any_offered = 1;
        }
    }
    __CPROVER_assert((chosen == 0) == !any_offered, "no choice exactly when nothing matches");
    if (chosen != 0) {
        __CPROVER_assert((offered & srv_suite_bit(chosen)) != 0, "the client offered it");
        __CPROVER_assert(suite_hash_len(chosen) != 0, "the build holds it");
        int seen = 0;
        for (size_t i = 0; i < count && !seen; i++) {
            if (order[i] == chosen) {
                seen = 1;
            } else {
                __CPROVER_assert((offered & srv_suite_bit(order[i])) == 0,
                                 "no offered suite ahead of it in the order");
            }
        }
        __CPROVER_assert(seen, "it is in the server's order");
    }
    return 0;
}
