// Proves: hs_build_client_hello — the one builder, and the last library
// source with no harness (#33) — writes nothing outside the caller's
// buffer for any capacity, and that CH_HELLO_MAX is a correct upper
// bound on what it can emit.
//
// Three properties. Memory safety over any cap, any cookie and any PSK
// identity within the lengths callers may pass. The return contract:
// zero on overflow, otherwise a length that fits the buffer it was
// given. And the one that makes CH_HELLO_MAX mean something — at that
// capacity the build always succeeds, so the constant handshake.c
// asserts against is sufficient rather than merely plausible.
//
// The wbuf writer is real, not stubbed: refusing to overflow is its
// contract, and the point here is that the builder uses it correctly.
#include "harness.h"

#include <string.h>

#include "handshake_message.h"
#include "handshake_parser.h"

uint32_t nondet_u32(void);
uint16_t nondet_u16(void);

#include "handshake_message.c"

int main(void) {
    static uint8_t out[CH_HELLO_MAX];
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof out);

    static uint8_t psk_id[CH_TICKET_ID_MAX];
    static uint8_t cookie[HSP_COOKIE_MAX];
    uint8_t pub[32];
    uint8_t random32[32];
    fill_nondet(psk_id, sizeof psk_id);
    fill_nondet(cookie, sizeof cookie);
    fill_nondet(pub, sizeof pub);
    fill_nondet(random32, sizeof random32);

    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    // Both auth modes: a NULL psk selects the pinned arm, which emits
    // signature_algorithms instead of pre_shared_key.
    if (nondet_u8() & 1) {
        cfg.psk = psk_id; // any non-NULL: the builder only tests the pointer
        cfg.psk_id = psk_id;
        cfg.psk_id_len = nondet_size_t();
        __CPROVER_assume(cfg.psk_id_len <= CH_TICKET_ID_MAX);
        cfg.resumption = nondet_u8() & 1;
        cfg.obfuscated_age = nondet_u32();
    }

    size_t cookie_len = nondet_size_t();
    __CPROVER_assume(cookie_len <= HSP_COOKIE_MAX);
    const uint8_t *ck = (nondet_u8() & 1) ? cookie : NULL;

    uint16_t limit = nondet_u16();

    size_t n = hs_build_client_hello(out, cap, &cfg, pub, random32, limit, ck, cookie_len);

    __CPROVER_assert(n <= cap, "a built hello fits the buffer it was given");
    // CH_HELLO_MAX is what handshake.c asserts CH_TX_STAGE against, so
    // it has to be sufficient for every hello this builder can emit.
    if (cap == CH_HELLO_MAX) {
        __CPROVER_assert(n != 0, "CH_HELLO_MAX always suffices");
    }
    return 0;
}
