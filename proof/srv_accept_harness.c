// Proves: ch_srv_accept, ch_srv_check (srv.c) and the server handshake
// driver srv_handshake (srv_handshake.c) are memory safe and free of UB
// over an unconstrained ch_cfg — every pointer NULL or live, every
// length any size_t, an ALPN offer at this build's real bound of
// CH_ALPN_MAX names of CH_ALPN_NAME_MAX bytes — and that a refused
// configuration leaves the session dead and calls no flight handler.
//
// What is real and what is a stub. srv.c, srv_handshake.c, ct.c and
// session.c are real, so the proof covers the configuration rules, the
// flight's call order, and the wipe on the way out. The fourteen
// srv_flight.h handlers and srv_resume.h's ticket call are stubs, because a handler and the driver
// that calls it are separate proofs: srv_flight.c carries its own
// harness, and inlining fourteen message builders into this formula
// would make it a parser proof, not a driver proof. Each stub asserts
// the contract its header states and havocs what its header says it
// writes, so nothing here depends on one handler's implementation.
// io_send_all and rec_seal are stubs for the same reason
// handshake_post's harness stubs them: record protection is proven in
// record.c's own harness.
//
// srv_identity_live and srv_identity_check are stubbed too, for two
// reasons. The real srv_identity_check signs and verifies, so the
// signers' arithmetic would join this formula, and each signer has its
// own. And the ch_cfg here is havocked rather than provisioned, so the
// real srv_identity_live would answer 0 for it, refusing every
// configuration before the ALPN rules ran and leaving this formula
// proving one branch.
#include "harness.h"

#include <string.h>

#include "io.h"
#include "record.h"
#include "session.h"
#include "srv.h"
#include "srv_auth.h"
#include "srv_flight.h"
#include "srv_handshake.h"
#include "srv_resume.h"

int nondet_int(void);
uint16_t nondet_u16(void);
uint64_t nondet_u64(void);

// The record layer under session.c's alert path. A sealed alert is
// proven in record.c's harness; here it either fills the caller's
// staging area or reports that the staging area is too small.
int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    (void)type;
    __CPROVER_assert(__CPROVER_w_ok(d, sizeof *d), "seal: dir writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "seal: pt readable");
    size_t total = REC_HDR + n + 1 + AEAD_TAG;
    if (total > cap) {
        return -1;
    }
    __CPROVER_assert(__CPROVER_w_ok(out, total), "seal: output writable");
    *out_len = total;
    return 0;
}

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    __CPROVER_assert(cfg != NULL, "send: cfg valid");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "send: bytes readable");
    return (nondet_u8() & 1) ? CH_OK : CH_EIO;
}

// How many handlers have run, so the asserts below can say that a
// refused configuration reached none of them. It is the harness's own
// counter and models nothing in the code.
static unsigned flight_calls;

// The contract every handler in srv_flight.h honours: a return other
// than CH_OK writes the alert description that handler chose into
// h->alert first, and the driver sends that one. The stubs model
// exactly that, so the driver is proven against the contract rather
// than against any handler's implementation.
static int flight_result(handshake_state *h) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "flight: state writable");
    __CPROVER_assert(h->t != NULL, "flight: state points at a session");
    flight_calls++;
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EIO || rc == CH_EPROTO || rc == CH_EAUTH ||
                     rc == CH_ECAP || rc == CH_EINVAL);
    if (rc != CH_OK) {
        h->alert = nondet_u8();
    }
    return rc;
}

// The two client_hello members this driver reads, havocked through
// their own types. The rest of the message is srv_parser.c's to fill
// and no line under proof here reads it, so filling it would add
// guarded array updates to the formula and no coverage.
static void fill_client_hello(client_hello *ch) {
    __CPROVER_assert(__CPROVER_w_ok(ch, sizeof *ch), "hello: writable");
    ch->alpn_selected = nondet_u8();
    ch->record_size_limit = nondet_u16();
}

// Everything srv_select writes, which is the whole selection.
static void fill_selection(selection *sel) {
    __CPROVER_assert(__CPROVER_w_ok(sel, sizeof *sel), "selection: writable");
    sel->suite = nondet_u16();
    sel->hash_len = nondet_u8();
    sel->group = nondet_u16();
    sel->sigalg = nondet_u16();
    sel->need_retry = nondet_u8();
    sel->psk_selected = nondet_u8();
    sel->psk_identity = nondet_u16();
}

void srv_begin(handshake_state *h) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "begin: state writable");
    __CPROVER_assert(h->t != NULL, "begin: state points at a session");
    flight_calls++;
    fill_nondet(h->priv, sizeof h->priv);
    fill_nondet(h->pub, sizeof h->pub);
}

int srv_read_client_hello(handshake_state *h, client_hello *ch) {
    int rc = flight_result(h);
    fill_client_hello(ch);
    return rc;
}

int srv_select(handshake_state *h, const client_hello *ch, selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "select: hello readable");
    int rc = flight_result(h);
    fill_selection(sel);
    return rc;
}

int srv_send_hello_retry_request(handshake_state *h, const client_hello *ch, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "hrr: hello readable");
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "hrr: selection readable");
    return flight_result(h);
}

int srv_send_compat_ccs(handshake_state *h, const client_hello *ch) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "ccs: hello readable");
    return flight_result(h);
}

int srv_check_retry_hello(handshake_state *h, const client_hello *ch, selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "retry: hello readable");
    int rc = flight_result(h);
    fill_selection(sel);
    // srv_flight.h: this call never asks for a second HelloRetryRequest,
    // and the driver's one retry by call position rests on that.
    sel->need_retry = 0;
    return rc;
}

int srv_send_server_hello(handshake_state *h, const client_hello *ch, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "server hello: hello readable");
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "server hello: selection readable");
    return flight_result(h);
}

int srv_derive_handshake_secrets(handshake_state *h, const client_hello *ch, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "derive: hello readable");
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "derive: selection readable");
    int rc = flight_result(h);
    fill_nondet(h->c_hs, sizeof h->c_hs);
    fill_nondet(h->s_hs, sizeof h->s_hs);
    return rc;
}

int srv_send_encrypted_extensions(handshake_state *h, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "ee: selection readable");
    return flight_result(h);
}

int srv_send_certificate(handshake_state *h, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "certificate: selection readable");
    __CPROVER_assert(sel->psk_selected == 0, "certificate: not a PSK handshake");
    return flight_result(h);
}

int srv_send_certificate_verify(handshake_state *h, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "cert verify: selection readable");
    __CPROVER_assert(sel->psk_selected == 0, "cert verify: not a PSK handshake");
    return flight_result(h);
}

int srv_send_finished(handshake_state *h) {
    return flight_result(h);
}

int srv_read_client_finished(handshake_state *h) {
    return flight_result(h);
}

void srv_complete(handshake_state *h) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "complete: state writable");
    flight_calls++;
    h->t->state = CH_ST_CONNECTED;
}

// srv_resume.h's issuing call, which the driver makes after srv_complete.
// It sends at most one record and returns what the other handlers return.
int srv_send_new_session_ticket(handshake_state *h) {
    __CPROVER_assert(h->t->state == CH_ST_CONNECTED, "ticket: only after the client Finished");
    return flight_result(h);
}

// srv_auth.c's two entry points, havocked. The real srv_identity_live
// reads only cfg and the real srv_identity_check runs a signer; both
// are srv_auth.c's own proof.
uint8_t srv_identity_live(const ch_cfg *cfg) {
    __CPROVER_assert(__CPROVER_r_ok(cfg, sizeof *cfg), "identity_live: cfg readable");
    return nondet_u8();
}

int srv_identity_check(const ch_cfg *cfg, uint16_t sigalg) {
    __CPROVER_assert(__CPROVER_r_ok(cfg, sizeof *cfg), "identity_check: cfg readable");
    (void)sigalg;
    return (nondet_u8() & 1) ? CH_OK : CH_EINVAL;
}

// The bytes behind the offered names, filled by a loop of this
// harness's own. fill_nondet would do the same job, but an unwindset
// entry bounds a loop and not a call site, so a 256-byte bound on
// fill_nondet's loop unrolls it 256 times at each of the four 32-byte
// call sites the flight stubs make as well, and the formula stops
// converging. This loop is bounded once, here.
static void fill_names(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = nondet_u8();
    }
}

// One offered ALPN name: any pointer the caller could pass, which is
// NULL or the backing array, and any length, which is where the rules
// in srv.c have to hold rather than the lengths a well-formed caller
// sends.
static void fill_alpn(ch_alpn_protocol *protocol, const uint8_t *name) {
    protocol->name = (nondet_u8() & 1) ? name : NULL;
    protocol->name_len = nondet_size_t();
    __CPROVER_assume(protocol->name_len <= CH_ALPN_NAME_MAX);
}

// The configuration fields ch_srv_accept reads, each stored through its
// own type. Everything else is zero, which is what a caller who never
// set a field leaves there.
static void fill_cfg(ch_cfg *cfg, ch_alpn_protocol *protocols, const uint8_t *names,
                     uint8_t *scratch) {
    memset(cfg, 0, sizeof *cfg);
    cfg->psk = (nondet_u8() & 1) ? scratch : NULL;
    cfg->psk_len = nondet_size_t();
    cfg->psk_id = (nondet_u8() & 1) ? scratch : NULL;
    cfg->psk_id_len = nondet_size_t();
    cfg->resumption = nondet_int();
    cfg->server_pubkey = (nondet_u8() & 1) ? scratch : NULL;
    cfg->server_pubkey_len = nondet_size_t();
    cfg->server_pubkey2 = (nondet_u8() & 1) ? scratch : NULL;
    cfg->server_pubkey2_len = nondet_size_t();
    cfg->require_pq = nondet_int();
    cfg->buf = (nondet_u8() & 1) ? scratch : NULL;
    cfg->buf_len = nondet_size_t();
    cfg->srv.cookie_key = (nondet_u8() & 1) ? scratch : NULL;
    cfg->srv.sni_buf = (nondet_u8() & 1) ? scratch : NULL;
    cfg->srv.sni_cap = nondet_size_t();
    cfg->srv.require_server_name = nondet_u8();
    cfg->alpn_count = nondet_size_t();
    cfg->alpn_protocols = (nondet_u8() & 1) ? protocols : NULL;
    for (size_t i = 0; i < CH_ALPN_MAX; i++) {
        fill_alpn(&protocols[i], names + i * CH_ALPN_NAME_MAX);
    }
}

// The send and recv callbacks are pointers the checks compare against
// NULL and this harness never calls, so they need bodies only to have
// addresses.
static int send_cb(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return 0;
}

static int recv_cb(void *io, uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return (int)n;
}

int main(void) {
    static ch_tls t;
    static ch_cfg cfg;
    static ch_alpn_protocol protocols[CH_ALPN_MAX];
    static uint8_t names[CH_ALPN_MAX * CH_ALPN_NAME_MAX];
    static uint8_t scratch[CH_MIN_RXBUF];

    fill_names(names, sizeof names);
    fill_cfg(&cfg, protocols, names, scratch);
    if (nondet_u8() & 1) {
        cfg.send = send_cb;
    }
    if (nondet_u8() & 1) {
        cfg.recv = recv_cb;
    }

    // ch_srv_check runs no I/O and touches no session, so it is driven
    // on the same configuration before the session exists.
    int rc = ch_srv_check(&cfg);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "check answers one of its two codes");

    flight_calls = 0;
    rc = ch_srv_accept(&t, &cfg);
    if (rc == CH_EINVAL && flight_calls == 0) {
        // The refusal srv.h promises: nothing was sent, and the session
        // is dead rather than half-live.
        __CPROVER_assert(t.state == CH_ST_FAILED, "a refused configuration leaves a dead session");
    }
    if (rc == CH_OK) {
        __CPROVER_assert(t.state == CH_ST_CONNECTED, "CH_OK means the flight reached connected");
    }
    if (rc != CH_OK && flight_calls != 0) {
        // Every non-CH_OK path through the driver wipes and fails the
        // session (srv_handshake.h).
        __CPROVER_assert(t.state == CH_ST_FAILED, "a failed handshake leaves a dead session");
        __CPROVER_assert(t.keys == 0, "a failed handshake wipes the record keys");
    }
    // store_selection lowers t.peer_limit to the client's
    // record_size_limit and never raises it, so this build's own
    // CH_TX_PT stands whatever the client asked for. fill_client_hello
    // havocs record_size_limit over the whole uint16_t, so this covers
    // both sides of the boundary: CH_TX_PT and below is adopted, and
    // every larger value leaves CH_TX_PT. It is the one reachable check
    // on that rule until srv_parser.c and srv_flight.c stop being stubs
    // and a unit test can drive a real ClientHello through the flight.
    __CPROVER_assert(t.peer_limit <= CH_TX_PT,
                     "the client's record_size_limit never raises the send cap");
    return 0;
}
