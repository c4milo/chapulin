// A kept ticket written from its fields, for a test that presents a ticket
// that no session handed over: the PSK, the identity and the lifetime.
// Every other field stays zero, and a test sets the ones it needs.
#ifndef CH_TEST_TICKET_H
#define CH_TEST_TICKET_H

#include <string.h>

#include "ticket.h"

static inline void test_ticket_fill(ch_saved_ticket *out, const uint8_t *key, size_t key_len,
                                    const uint8_t *id, size_t id_len, uint32_t lifetime_s) {
    memset(out, 0, sizeof *out);
    memcpy(out->ticket.psk, key, key_len);
    out->ticket.psk_len = key_len;
    memcpy(out->identity, id, id_len);
    out->ticket.identity_len = id_len;
    out->ticket.lifetime_s = lifetime_s;
}

#endif
