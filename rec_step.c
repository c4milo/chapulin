// The record-mode step table. rec_step.h states the contract; this file
// is quic_step.c's mirror on the transport that keeps its records.
//
// It holds no protocol rule of its own. handshake_flight.[ch] holds the
// handlers both transports compile, handshake_auth.[ch] the server
// authentication flight, and this file calls them in order.
#include "rec_step.h"

#ifdef CH_TRANSPORT_RECORD

#include <string.h>

#include "ct.h"
#include "handshake_auth.h"
#include "handshake_flight.h"
#include "handshake_message.h"
#include "rec.h"
#include "record.h"

// rec_step.h states the contract. RFC 9846 section 5.1 fixes
// legacy_record_version at 0x0303 here.
void rec_stage_plain(ch_record *r, size_t n) {
    ch_tls *t = &r->t;
    t->tx[0] = REC_HANDSHAKE;
    t->tx[1] = 0x03;
    t->tx[2] = 0x03;
    t->tx[3] = (uint8_t)(n >> 8);
    t->tx[4] = (uint8_t)n;
    r->tx_len = REC_HDR + n;
    r->tx_off = 0;
}

// Stages one handshake message as a protected record. The client
// Finished is the only message this mode seals, and it seals under the
// handshake write key, before step_finished switches to the application
// key.
static int stage_sealed(ch_record *r, const uint8_t *pt, size_t n) {
    ch_tls *t = &r->t;
    size_t out_len = 0;
    if (rec_seal(&t->wr, REC_HANDSHAKE, pt, n, t->tx, sizeof t->tx, &out_len) != 0) {
        r->hs.alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    r->tx_len = out_len;
    r->tx_off = 0;
    return CH_OK;
}

// The ServerHello step, which HSR_STEP_AWAIT_SERVER_HELLO and
// HSR_STEP_AWAIT_RETRY_HELLO share. A HelloRetryRequest at the retry
// step is the second one, which RFC 9846 section 4.2.4 forbids; the
// blocking driver refuses it by call position and this one by the stored
// step.
//
// The derivation runs in this same call because info.server_ct points
// into cfg.buf under CH_KEX_HYBRID and the decapsulation reads those bytes, so
// nothing may read a further message in between.
static int step_server_hello(ch_record *r) {
    ch_tls *t = &r->t;
    server_hello_info info;
    int rc = hsf_read_server_hello(&r->hs, &info);
    if (rc != CH_OK) {
        return rc;
    }
    if (info.hrr) {
        if (r->step == HSR_STEP_AWAIT_RETRY_HELLO) {
            r->hs.alert = ALERT_UNEXPECTED_MESSAGE;
            return CH_EPROTO;
        }
        // t.tx is free here because ch_record_in refuses input while a
        // staged record is uncollected.
        size_t n = hsf_build_client_hello(&r->hs, t->tx + REC_HDR, sizeof t->tx - REC_HDR);
        if (n == 0) {
            return CH_ECAP;
        }
        rec_stage_plain(r, n);
        r->step = HSR_STEP_AWAIT_RETRY_HELLO;
        return CH_OK;
    }
    rc = hsf_accept_server_hello(&r->hs, &info);
    if (rc != CH_OK) {
        return rc;
    }
    rc = hsf_derive_handshake_secrets(&r->hs, &info);
    if (rc != CH_OK) {
        return rc;
    }
    // The server secret protects what this endpoint reads and the client
    // secret what it writes, the same assignment handshake.c makes.
    REC_DIR_INIT_SUITE(&t->rd, r->hs.s_hs, r->hs.suite);
    REC_DIR_INIT_SUITE(&t->wr, r->hs.c_hs, r->hs.suite);
    r->hs.encrypted = 1;
    t->keys = 1; // alerts encrypt from here on
    r->step = HSR_STEP_AWAIT_ENCRYPTED_EXTENSIONS;
    return CH_OK;
}

static int step_encrypted_extensions(ch_record *r) {
    int rc = hsf_read_encrypted_extensions(&r->hs);
    if (rc != CH_OK) {
        return rc;
    }
    // The one fork in the table: a server that selected the PSK sends no
    // certificate, and every other server sends one, a TRUST=webpki server
    // that declined the offered ticket included.
    r->step = r->t.psk_selected ? HSR_STEP_AWAIT_FINISHED : HSR_STEP_AWAIT_CERTIFICATE;
    return CH_OK;
}

static int step_certificate(ch_record *r) {
    int rc = hsa_server_auth(&r->hs);
    if (rc != CH_OK) {
        return rc;
    }
    r->step = HSR_STEP_AWAIT_CERTIFICATE_VERIFY;
    return CH_OK;
}

static int step_certificate_verify(ch_record *r) {
    int rc = hsa_read_certificate_verify(&r->hs);
    if (rc != CH_OK) {
        return rc;
    }
    r->step = HSR_STEP_AWAIT_FINISHED;
    return CH_OK;
}

// The server Finished, then everything the handshake owes after it: the
// client Finished sealed under the handshake write key, both directions
// switched to the application keys, and r->hs wiped. The wipe is INV-17's
// rule that handshake secrets die at CONNECTED. It clears hs.t with the
// rest, so this step writes the back pointer again.
//
// It does not raise r->t.state. ch_record_out does that in the call that
// hands the last Finished byte over, because until then this endpoint
// has not sent it.
static int step_finished(ch_record *r) {
    ch_tls *t = &r->t;
    int rc = hsf_read_finished(&r->hs);
    if (rc != CH_OK) {
        return rc;
    }
#ifdef CH_TRUST_CA
    hsa_epoch_commit(&r->hs);
#endif
    uint8_t finished[HSF_FINISHED_MAX];
    size_t finished_len = hsf_complete(&r->hs, finished);
    rc = stage_sealed(r, finished, finished_len);
    ct_wipe(finished, sizeof finished);
    if (rc != CH_OK) {
        return rc;
    }
    // Only now, with the Finished already sealed under the handshake
    // key, do both directions move to the application schedule.
    REC_DIR_INIT_SUITE(&t->rd, t->rd_secret, r->hs.suite);
    REC_DIR_INIT_SUITE(&t->wr, t->wr_secret, r->hs.suite);
    t->pt_off = 0;
    t->pt_len = 0;
    ct_wipe(&r->hs, sizeof r->hs);
    r->hs.t = t;
    r->step = HSR_STEP_COMPLETE;
    return CH_OK;
}

// Nothing is legal here. The caller moves to ch_read the moment
// ch_record_state answers CH_ST_CONNECTED, and ch_read handles every
// post-handshake message this tree accepts, a NewSessionTicket among
// them (handshake_post.h). Bytes fed to this driver after the handshake
// are a caller that did not move on.
static int step_complete(ch_record *r) {
    r->hs.alert = ALERT_UNEXPECTED_MESSAGE;
    return CH_EPROTO;
}

int hsr_advance(ch_record *r) {
    switch (r->step) {
    case HSR_STEP_AWAIT_SERVER_HELLO:
    case HSR_STEP_AWAIT_RETRY_HELLO:
        return step_server_hello(r);
    case HSR_STEP_AWAIT_ENCRYPTED_EXTENSIONS:
        return step_encrypted_extensions(r);
    case HSR_STEP_AWAIT_CERTIFICATE:
        return step_certificate(r);
    case HSR_STEP_AWAIT_CERTIFICATE_VERIFY:
        return step_certificate_verify(r);
    case HSR_STEP_AWAIT_FINISHED:
        return step_finished(r);
    case HSR_STEP_COMPLETE:
        return step_complete(r);
    default:
        // A step value no step wrote, which a one-byte corruption of
        // r->step produces. It kills the session instead of running a
        // handler or calling ch_assert_fail, because the step number is
        // data a fault can change and CH_ASSERT is for programmer error.
        r->hs.alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
}

#endif // CH_TRANSPORT_RECORD
