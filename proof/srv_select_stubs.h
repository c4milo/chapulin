// Contract stubs for the two calls srv_select and srv_check_retry_hello
// make outside srv_flight.c: srv_auth.h's scheme choice and srv_resume.h's
// ticket selection. proof/srv_flight_harness.c includes this after its own
// helpers, whose nondet_rc, write_alert and fill_nondet it reads. It is a
// header of its own because that harness sits at the 500-line cap, and the
// two calls have harnesses of their own: srv_auth and srv_resume.
#ifndef CH_SRV_SELECT_STUBS_H
#define CH_SRV_SELECT_STUBS_H

#include "srv_resume.h"

uint16_t srv_select_sigalg(const ch_cfg *cfg, uint8_t offered) {
    __CPROVER_assert(__CPROVER_r_ok(cfg, sizeof *cfg), "select_sigalg: cfg readable");
    (void)offered;
    return nondet_u16();
}

// srv_resume.h's selection, proven in its own harness. It answers one of
// its three codes, writes the alert on a refusal, and leaves a ticket's
// early secret in h->early when it selects one.
int srv_select_auth(handshake_state *hs, const client_hello *ch, selection *s) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "select_auth: hello readable");
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "select_auth: selection writable");
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EAUTH || rc == CH_EPROTO);
    s->psk_selected = rc == CH_OK ? (uint8_t)(nondet_u8() & 1) : 0;
    s->psk_identity = nondet_u16();
    if (rc != CH_OK) {
        write_alert(&hs->alert);
    } else if (s->psk_selected) {
        fill_nondet(hs->early, sizeof hs->early);
    }
    return rc;
}

#endif
