// Contract stubs for the calls the two non-blocking server drivers make
// into srv.h, srv_flight.h and srv_resume.h: the configuration check, the
// key share draw and the fifteen handlers. proof/srv_tcp_nonblocking_harness.c
// and proof/srv_quic_harness.c include this after their own nondet
// declarations.
//
// Each stub asserts what its header requires of a caller and havocs what
// that header says it writes, so the driver's proof rests on no one
// handler's implementation. proof/srv_flight_harness.c is the other half
// of the pair: there the handlers are real and the driver is the stub.
#ifndef CH_SRV_FLIGHT_STUBS_H
#define CH_SRV_FLIGHT_STUBS_H

#include <string.h>

#include "srv_flight.h"
#include "srv_resume.h"

// Every handler answers CH_OK or one of the codes its header lists, and
// writes h->alert on failure. srv_flight.h leaves a failed handler's
// session to the driver, so none of these wipes anything. CH_EIO is in
// the set because srv_out.c's emit reports a refusing sink that way, and
// every send below goes through it.
static int handler_result(handshake_state *h) {
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EPROTO || rc == CH_EAUTH || rc == CH_ECAP ||
                     rc == CH_EINVAL || rc == CH_EIO);
    if (rc != CH_OK) {
        h->alert = nondet_u8();
    }
    return rc;
}

// The two handlers that read a message go through here.
// srv_tcp_nonblocking.c runs a step only after hsr_peek_message has
// found a whole message, so that is what this asserts, and a message it
// yields is at least its own 4-byte header. Consuming is what makes
// drive's loop terminate, so a stub that answered CH_OK without
// advancing pt_off would prove a loop this driver does not run.
static int take_message(handshake_state *h) {
    __CPROVER_assert(h != NULL && h->t != NULL, "msg: state valid");
    __CPROVER_assert(h->t->pt_len >= 4 && h->t->pt_off <= h->t->pt_len - 4,
                     "msg: a whole message is unread");
    int rc = handler_result(h);
    if (rc != CH_OK) {
        return rc;
    }
    size_t whole = nondet_size_t();
    __CPROVER_assume(whole >= 4 && whole <= h->t->pt_len - h->t->pt_off);
    h->t->pt_off += whole;
    return CH_OK;
}

// srv.c's configuration rules. The answer is free, but a 1 carries what
// srv.h promises a caller that got one: the receive buffer is live and at
// this build's floor, and the transport's own arm has checked that its
// callbacks are set. The init calls read them on the strength of that
// answer, so a stub that answered 1 for any cfg at all would prove
// arithmetic the real predicate never admits.
int srv_config_ok(const ch_cfg *cfg) {
    __CPROVER_assert(__CPROVER_r_ok(cfg, sizeof *cfg), "config: cfg readable");
    if (nondet_u8() & 1) {
        return 0;
    }
    __CPROVER_assume(cfg->buf != NULL && cfg->buf_len >= CH_MIN_RXBUF);
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    __CPROVER_assume(cfg->srv.on_crypto_out != NULL && cfg->on_level_ready != NULL);
#else
    __CPROVER_assume(cfg->srv.on_record_out != NULL);
#endif
    return 1;
}

// Draws this connection's key share into the state the caller zeroed.
void srv_begin(handshake_state *h) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "begin: state writable");
    __CPROVER_assert(h->t != NULL, "begin: the back pointer is set");
    fill_nondet(h->priv, sizeof h->priv);
    fill_nondet(h->pub, sizeof h->pub);
}

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// 1 or 0 for whether the last hello read carried transport parameters,
// and -1 before a hello is read.
static int hello_params = -1;
#endif

int srv_read_client_hello(handshake_state *h, client_hello *ch) {
    __CPROVER_assert(__CPROVER_w_ok(ch, sizeof *ch), "hello: parse target writable");
    int rc = take_message(h);
    if (rc != CH_OK) {
        return rc;
    }
    memset(ch, 0, sizeof *ch);
    // The two members srv_store_selection reads. record_size_limit runs over
    // the whole uint16_t, so both sides of its boundary are in the
    // formula: a value below this build's cap is adopted and every
    // larger one leaves it standing.
    ch->record_size_limit = nondet_u16();
    ch->alpn_selected = nondet_u8();
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    // srv_parser.h: the body of quic_transport_parameters inside the
    // message in cfg.buf, or NULL when the hello carried none.
    // hello_params records which, for proof/srv_quic_harness.c.
    hello_params = 0;
    if (nondet_u8() & 1) {
        hello_params = 1;
        size_t len = nondet_size_t();
        __CPROVER_assume(len <= h->t->cfg.buf_len);
        ch->transport_params = h->t->cfg.buf;
        ch->transport_params_len = len;
    }
#endif
    return CH_OK;
}

int srv_select(handshake_state *h, const client_hello *ch, selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "select: hello readable");
    __CPROVER_assert(__CPROVER_w_ok(sel, sizeof *sel), "select: selection writable");
    int rc = handler_result(h);
    if (rc != CH_OK) {
        return rc;
    }
    memset(sel, 0, sizeof *sel);
    sel->suite = nondet_u16();
    sel->hash_len = nondet_u8();
    sel->group = nondet_u16();
    sel->sigalg = nondet_u16();
    sel->need_retry = nondet_u8();
    sel->psk_selected = nondet_u8();
    return CH_OK;
}

int srv_check_retry_hello(handshake_state *h, const client_hello *ch, selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "retry: hello readable");
    __CPROVER_assert(__CPROVER_w_ok(sel, sizeof *sel), "retry: selection writable");
    int rc = handler_result(h);
    if (rc != CH_OK) {
        return rc;
    }
    memset(sel, 0, sizeof *sel);
    sel->suite = nondet_u16();
    sel->hash_len = nondet_u8();
    sel->group = nondet_u16();
    sel->sigalg = nondet_u16();
    sel->psk_selected = nondet_u8();
    // srv_flight.h: it never sets need_retry, which is what keeps a
    // second HelloRetryRequest unreachable. memset left it 0.
    return CH_OK;
}

int srv_send_hello_retry_request(handshake_state *h, const client_hello *ch, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "hrr: hello readable");
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "hrr: selection readable");
    __CPROVER_assert(sel->need_retry, "hrr: the selection asked for a retry");
    return handler_result(h);
}

int srv_send_compat_ccs(handshake_state *h, const client_hello *ch) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "ccs: hello readable");
    return handler_result(h);
}

int srv_send_server_hello(handshake_state *h, const client_hello *ch, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "server hello: hello readable");
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "server hello: selection readable");
    __CPROVER_assert(!sel->need_retry, "server hello: the retry is behind us");
    return handler_result(h);
}

int srv_derive_handshake_secrets(handshake_state *h, const client_hello *ch, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "derive: hello readable");
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "derive: selection readable");
    int rc = handler_result(h);
    if (rc == CH_OK) {
        fill_nondet(h->c_hs, sizeof h->c_hs);
        fill_nondet(h->s_hs, sizeof h->s_hs);
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
        h->encrypted = 1;
        h->t->keys = 1;
#endif
    }
    return rc;
}

int srv_send_encrypted_extensions(handshake_state *h, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "ee: selection readable");
    return handler_result(h);
}

int srv_send_certificate(handshake_state *h, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "certificate: selection readable");
    __CPROVER_assert(!sel->psk_selected, "certificate: no PSK authenticated this handshake");
    return handler_result(h);
}

int srv_send_certificate_verify(handshake_state *h, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "cert verify: selection readable");
    __CPROVER_assert(!sel->psk_selected, "cert verify: no PSK authenticated this handshake");
    return handler_result(h);
}

int srv_send_finished(handshake_state *h) {
    int rc = handler_result(h);
    if (rc == CH_OK) {
        // The application write key goes in here, one round trip before
        // the read key (srv_flight.c:425).
        fill_nondet(h->t->wr_secret, sizeof h->t->wr_secret);
    }
    return rc;
}

// srv_flight.h requires a srv_read_client_finished that answered CH_OK
// before srv_complete runs, and the server holds that order by call
// position rather than by a flag: handshake_state carries
// server_finished_ok for the client's side and no counterpart. So the
// order is counted here, the way proof/srv_accept_harness.c counts
// handler calls.
static int finished_read;

int srv_read_client_finished(handshake_state *h) {
    int rc = take_message(h);
    if (rc == CH_OK) {
        finished_read++;
    }
    return rc;
}

void srv_complete(handshake_state *h) {
    __CPROVER_assert(finished_read > 0, "complete: the client Finished verified first");
    fill_nondet(h->t->rd_secret, sizeof h->t->rd_secret);
    h->t->state = CH_ST_CONNECTED;
}

// srv_resume.h's issuing call, which the driver makes after srv_complete
// and before the wipe.
int srv_send_new_session_ticket(handshake_state *h) {
    __CPROVER_assert(h->t->state == CH_ST_CONNECTED, "ticket: only after the client Finished");
    return handler_result(h);
}

#endif // CH_SRV_FLIGHT_STUBS_H
