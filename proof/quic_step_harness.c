// Proves: quic_step.c is memory-safe and UB-free over any saved state,
// including a step number no step wrote, and that hsq_advance keeps the
// contract quic_step.h states — it consumes the message, it raises the
// step below HSQ_STEP_COMPLETE, an error leaves the staged message
// alone, and a step number above the table kills the session instead of
// running a handler.
//
// Layered proof: every flight handler is a stub asserting the contract
// its own header states and havocing what that header says it writes,
// so the table's proof rests on no protocol rule. The handlers
// themselves stay with handshake_psk and handshake_pin, which compile
// handshake_flight.c and handshake_auth.c whole. quic_keys_init,
// quic_hp_key_init and quic_keys_update are stubs for the same reason:
// quic_keys.c owns them, and this file only chooses which set each one
// writes.
//
// The pairing with quic_driver. That harness stubs hsq_advance to the
// same contract this one proves, so the two read as a pair: what the
// driver assumes of a step is what this leg discharges.
//
// Bounds. CH_PROOF_RXBUF is 12, the value handshake_record's own
// harness uses. step runs over the whole byte range rather than one
// value, so the default arm is inside the formula. ct_wipe.0 is 441,
// one past sizeof(handshake_state), the one object a step wipes;
// fill_nondet.0 is 33, one past a traffic secret.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "handshake_flight.h"
#include "handshake_message.h"
#include "quic.h"

#ifndef CH_PROOF_RXBUF
#define CH_PROOF_RXBUF 12
#endif

uint64_t nondet_u64(void);
int nondet_int(void);

// Every handler answers CH_OK or one of the codes its header lists, and
// writes h->alert on failure. handshake_flight.h says a failure leaves
// the session to the driver, so none of these wipes anything.
static int handler_result(handshake_state *h) {
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EPROTO || rc == CH_EAUTH || rc == CH_ECAP ||
                     rc == CH_EINVAL);
    if (rc != CH_OK) {
        h->alert = nondet_u8();
    }
    return rc;
}

// The reader every handler goes through. quic_step.h requires a whole
// message at pt_off before a step runs, so this is where that is
// checked, and the message it yields is at least its 4-byte header.
static int take_message(handshake_state *h, uint8_t *type, const uint8_t **raw, size_t *raw_len) {
    __CPROVER_assert(h != NULL && h->t != NULL, "msg: state valid");
    __CPROVER_assert(h->t->pt_len >= 4 && h->t->pt_off <= h->t->pt_len - 4,
                     "msg: a whole message is unread");
    int rc = handler_result(h);
    if (rc != CH_OK) {
        return rc;
    }
    size_t whole = nondet_size_t();
    __CPROVER_assume(whole >= 4 && whole <= h->t->pt_len - h->t->pt_off);
    if (type != NULL) {
        *type = nondet_u8();
        *raw = h->t->cfg.buf + h->t->pt_off;
        *raw_len = whole;
    }
    h->t->pt_off += whole;
    return CH_OK;
}

int hsr_next_msg(handshake_state *h, uint8_t *type, const uint8_t **raw, size_t *raw_len) {
    return take_message(h, type, raw, raw_len);
}

int hsf_read_server_hello(handshake_state *h, server_hello_info *info) {
    __CPROVER_assert(__CPROVER_w_ok(info, sizeof *info), "server hello: info writable");
    int rc = take_message(h, NULL, NULL, NULL);
    if (rc != CH_OK) {
        return rc;
    }
    // handshake_flight.h: info->hrr says which of the two messages that
    // share the type arrived, and the caller decides what an HRR means.
    memset(info, 0, sizeof *info);
    info->hrr = nondet_int();
    return CH_OK;
}

size_t hsf_build_client_hello(handshake_state *h, uint8_t *out, size_t cap) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "hello: state writable");
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= cap);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return 0;
    }
    __CPROVER_assert(__CPROVER_w_ok(out, n), "hello: staging writable");
    return n;
}

// handshake_flight.h: on CH_OK the handler writes t->psk_selected, which
// the EncryptedExtensions step reads to choose the next one.
int hsf_accept_server_hello(handshake_state *h, const server_hello_info *info) {
    __CPROVER_assert(__CPROVER_r_ok(info, sizeof *info), "accept: info readable");
    __CPROVER_assert(info->hrr == 0, "accept: the message is not a HelloRetryRequest");
    int rc = handler_result(h);
    if (rc == CH_OK) {
        h->t->psk_selected = nondet_u8() & 1;
    }
    return rc;
}

int hsf_derive_handshake_secrets(handshake_state *h, const server_hello_info *info) {
    __CPROVER_assert(__CPROVER_r_ok(info, sizeof *info), "derive: info readable");
    int rc = handler_result(h);
    if (rc == CH_OK) {
        fill_nondet(h->c_hs, sizeof h->c_hs);
        fill_nondet(h->s_hs, sizeof h->s_hs);
    }
    return rc;
}

int hsf_read_encrypted_extensions(handshake_state *h) {
    return take_message(h, NULL, NULL, NULL);
}

int hsf_read_finished(handshake_state *h) {
    int rc = take_message(h, NULL, NULL, NULL);
    if (rc == CH_OK) {
        h->server_finished_ok = 1;
    }
    return rc;
}

size_t hsf_complete(handshake_state *h, uint8_t finished[HSF_FINISHED_MAX]) {
    __CPROVER_assert(h->server_finished_ok, "complete: the server Finished verified first");
    __CPROVER_assert(__CPROVER_w_ok(finished, HSF_FINISHED_MAX), "complete: staging writable");
    fill_nondet(finished, HSF_FINISHED_MAX);
    fill_nondet(h->t->wr_secret, sizeof h->t->wr_secret);
    fill_nondet(h->t->rd_secret, sizeof h->t->rd_secret);
    // The one suite this build holds hashes with SHA-256, so the message
    // is the header and 32 bytes of verify_data.
    return 4 + SHA256_LEN;
}

int hsa_server_auth(handshake_state *h) {
    return take_message(h, NULL, NULL, NULL);
}

int hsa_read_certificate_verify(handshake_state *h) {
    return take_message(h, NULL, NULL, NULL);
}

#ifdef CH_TRUST_CA
void hsa_epoch_commit(handshake_state *h) {
    __CPROVER_assert(h->server_finished_ok, "epoch: the server Finished verified first");
}
#endif

int hspost_take_ticket(ch_tls *t, const uint8_t *body, size_t n, uint8_t *alert,
                       uint64_t *error_code) {
    __CPROVER_assert(t != NULL, "ticket: session valid");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(body, n), "ticket: body readable");
    __CPROVER_assert(alert != NULL && error_code != NULL, "ticket: outputs valid");
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EPROTO);
    if (rc != CH_OK) {
        *alert = nondet_u8();
        if (nondet_u8() & 1) {
            *error_code = 0x0a;
        }
    }
    return rc;
}

// quic_keys.c's three derivations. Each writes the one set it is handed
// and nothing else; quic_keys_update also advances the secret in place,
// which is the invariant session.h states.
void quic_keys_init(quic_keys *k, const uint8_t secret[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(k, sizeof *k), "keys: set writable");
    __CPROVER_assert(__CPROVER_r_ok(secret, SHA256_LEN), "keys: secret readable");
    fill_nondet(k->key, sizeof k->key);
    fill_nondet(k->iv, sizeof k->iv);
}

void quic_hp_key_init(quic_hp_key *h, const uint8_t secret[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "keys: header key writable");
    __CPROVER_assert(__CPROVER_r_ok(secret, SHA256_LEN), "keys: secret readable");
    fill_nondet(h->key, sizeof h->key);
}

void quic_keys_update(uint8_t secret[SHA256_LEN], quic_keys *k) {
    __CPROVER_assert(__CPROVER_w_ok(secret, SHA256_LEN), "update: secret writable");
    __CPROVER_assert(__CPROVER_w_ok(k, sizeof *k), "update: set writable");
    fill_nondet(secret, SHA256_LEN);
    fill_nondet(k->key, sizeof k->key);
    fill_nondet(k->iv, sizeof k->iv);
}

#include "quic_step.c"

static uint8_t buf[CH_PROOF_RXBUF];
static ch_quic q;

// cfg.on_level_ready. quic_step.h has a step fire it twice for the one
// level it installed; ch_quic_init refuses a NULL, so a step may call
// it without a check.
static int ready_calls;
static void level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    __CPROVER_assert(level == CH_LEVEL_HANDSHAKE || level == CH_LEVEL_APPLICATION,
                     "ready: a step installs the Handshake or the 1-RTT level");
    __CPROVER_assert(direction == CH_KEY_READ || direction == CH_KEY_WRITE,
                     "ready: one direction per call");
    __CPROVER_assert((q.levels_ready & CH_QUIC_LEVEL_BIT(level, direction)) != 0,
                     "ready: the bit is set before the caller hears about it");
    ready_calls++;
}

int main(void) {
    memset(&q, 0, sizeof q);
    q.t.cfg.buf = buf;
    q.t.cfg.buf_len = sizeof buf;
    q.t.cfg.on_level_ready = level_ready;
    q.hs.t = &q.t;
    fill_nondet(buf, sizeof buf);
    fill_nondet(q.t.rd_secret, sizeof q.t.rd_secret);
    fill_nondet(q.t.wr_secret, sizeof q.t.wr_secret);
    fill_nondet(q.hs.c_hs, sizeof q.hs.c_hs);
    fill_nondet(q.hs.s_hs, sizeof q.hs.s_hs);

    // The saved state, unconstrained but for the two rules every public
    // entry establishes before it calls here: the unread window sits
    // inside the receive buffer and holds a whole message, and the
    // session is live.
    q.step = nondet_u8();
    q.rx_level = nondet_u8();
    q.tx_level = nondet_u8();
    q.levels_ready = nondet_u8();
    q.key_phase = nondet_u8();
    q.error_code = nondet_u64();
    q.open_failures = nondet_u64();
    q.initial_sealed = nondet_u64();
    q.hs.alert = nondet_u8();
    q.hs.server_finished_ok = nondet_u8();
    q.t.alpn_selected = nondet_u8();
    // Whether the ServerHello selected the PSK, which an earlier step
    // wrote: 0 or 1, the two values hsf_accept_server_hello writes.
    q.t.psk_selected = nondet_u8() & 1;
    uint8_t state = nondet_u8();
    __CPROVER_assume(state == CH_ST_START || state == CH_ST_CONNECTED);
    q.t.state = state;
    // Written as two wrap-free clauses: off + 4 <= len would also hold
    // for an off near SIZE_MAX, and the buffer pointer would then run
    // out of the object.
    size_t off = nondet_size_t();
    size_t len = nondet_size_t();
    __CPROVER_assume(len >= 4 && len <= sizeof buf);
    __CPROVER_assume(off <= len - 4);
    q.t.pt_off = off;
    q.t.pt_len = len;
    q.tx_len = 0; // ch_quic_crypto_in refuses input while a message is staged

    uint8_t was_step = q.step;
    uint8_t was_rx = q.rx_level;
    uint64_t was_failures = q.open_failures;
    uint64_t was_sealed = q.initial_sealed;
    uint8_t was_phase = q.key_phase;

    int rc = hsq_advance(&q);

    __CPROVER_assert(q.t.pt_off <= q.t.pt_len && q.t.pt_len <= q.t.cfg.buf_len,
                     "window inside the buffer");
    __CPROVER_assert(q.tx_len <= CH_TX_STAGE, "staged message inside the staging array");
    __CPROVER_assert(q.t.state == state, "a step never raises the state");
    __CPROVER_assert(q.open_failures == was_failures && q.initial_sealed == was_sealed &&
                         q.key_phase == was_phase,
                     "a step touches none of the packet calls' fields");
    if (was_step > HSQ_STEP_COMPLETE) {
        __CPROVER_assert(rc == CH_EPROTO, "a step number no step wrote kills the session");
        __CPROVER_assert(q.hs.alert == ALERT_UNEXPECTED_MESSAGE, "and names unexpected_message");
        __CPROVER_assert(q.step == was_step && q.rx_level == was_rx && q.tx_len == 0 &&
                             q.t.pt_off == off,
                         "and changes nothing else");
    }
    if (rc != CH_OK) {
        __CPROVER_assert(q.tx_len == 0, "an error stages nothing");
    }
    if (rc == CH_OK) {
        __CPROVER_assert(q.t.pt_off > off, "a step consumes its message");
        __CPROVER_assert(was_step <= HSQ_STEP_COMPLETE, "only a step in the table can succeed");
        if (was_step < HSQ_STEP_COMPLETE) {
            __CPROVER_assert(q.step > was_step || q.step == HSQ_STEP_AWAIT_RETRY_HELLO,
                             "a step raises the step number, or waits for the retry hello");
        }
        if (was_step == HSQ_STEP_AWAIT_ENCRYPTED_EXTENSIONS) {
            __CPROVER_assert(
                q.step == (q.t.psk_selected ? HSQ_STEP_AWAIT_FINISHED : HSQ_STEP_AWAIT_CERTIFICATE),
                "a Certificate comes next unless the ServerHello selected the PSK");
        }
        if (was_step == HSQ_STEP_AWAIT_RETRY_HELLO) {
            __CPROVER_assert(q.step == HSQ_STEP_AWAIT_ENCRYPTED_EXTENSIONS,
                             "a second HelloRetryRequest is refused, so this one was accepted");
        }
        if (was_step == HSQ_STEP_AWAIT_FINISHED) {
            __CPROVER_assert(q.step == HSQ_STEP_COMPLETE, "the Finished step ends the handshake");
            __CPROVER_assert(q.tx_len == 4 + SHA256_LEN, "and stages the client Finished");
            __CPROVER_assert(q.tx_level == CH_LEVEL_HANDSHAKE, "at the Handshake level");
            __CPROVER_assert(q.rx_level == CH_LEVEL_APPLICATION, "and moves to 1-RTT");
            __CPROVER_assert(q.hs.t == &q.t, "and writes the back pointer again after the wipe");
            __CPROVER_assert(ready_calls == 2, "and reports one level, both directions");
        }
    }
    return 0;
}
