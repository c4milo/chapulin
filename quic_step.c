// The QUIC driver's step table: one whole handshake message per step.
// Contract in quic_step.h. This file holds no protocol logic of its
// own; every step calls a handler handshake_flight.c, handshake_auth.c
// or handshake_post.c defines, so no rule exists twice.
#include "quic_step.h"

#ifdef CH_TRANSPORT_QUIC

#include "ct.h"
#include "handshake_auth.h"
#include "handshake_flight.h"
#include "handshake_message.h"
#include "handshake_post.h"
#include "quic.h"

// Reports one encryption level usable in both directions: it sets the
// two bits ch_quic_seal and ch_quic_open read, then fires
// cfg.on_level_ready once per direction, which RFC 9001 §4.1.4 requires
// of a TLS stack (rfc9001.txt:526-528). Both happen in one place so the
// caller's view and q->levels_ready cannot disagree.
static void announce_level(ch_quic *q, uint8_t level) {
    q->levels_ready |= CH_QUIC_LEVEL_BIT(level, CH_KEY_READ);
    q->levels_ready |= CH_QUIC_LEVEL_BIT(level, CH_KEY_WRITE);
    q->t.cfg.on_level_ready(q->t.cfg.io, level, CH_KEY_READ);
    q->t.cfg.on_level_ready(q->t.cfg.io, level, CH_KEY_WRITE);
}

// The Handshake level's four keys, from the two handshake traffic
// secrets hsf_derive_handshake_secrets wrote. The header protection key
// of each direction is written once here and never again, which is
// §5.4's rule (rfc9001.txt:1172-1174).
static void install_handshake_keys(ch_quic *q) {
    quic_keys_init(&q->handshake_rx, q->hs.s_hs);
    quic_hp_key_init(&q->handshake_hp_rx, q->hs.s_hs);
    quic_keys_init(&q->handshake_tx, q->hs.c_hs);
    quic_hp_key_init(&q->handshake_hp_tx, q->hs.c_hs);
    announce_level(q, CH_LEVEL_HANDSHAKE);
}

// The 1-RTT keys, from the two application traffic secrets hsf_complete
// wrote into t.wr_secret and t.rd_secret. The last call advances
// t.rd_secret once with the "quic ku" label and writes the next receive
// set from it, so that set exists before any packet arrives under it
// and t.rd_secret afterwards names it, which is the invariant session.h
// states and ch_quic_key_update depends on. app_rx[CH_QUIC_KEY_PREVIOUS]
// stays zero until the first ch_quic_key_update.
static void install_application_keys(ch_quic *q) {
    quic_keys_init(&q->app_tx, q->t.wr_secret);
    quic_hp_key_init(&q->app_hp_tx, q->t.wr_secret);
    quic_keys_init(&q->app_rx[CH_QUIC_KEY_CURRENT], q->t.rd_secret);
    quic_hp_key_init(&q->app_hp_rx, q->t.rd_secret);
    quic_keys_update(q->t.rd_secret, &q->app_rx[CH_QUIC_KEY_NEXT]);
    announce_level(q, CH_LEVEL_APPLICATION);
}

// The ServerHello step, which HSQ_STEP_AWAIT_SERVER_HELLO and
// HSQ_STEP_AWAIT_RETRY_HELLO share. A HelloRetryRequest at the retry
// step is the second one, which RFC 9846 §4.2.4 forbids; the TLS driver
// refuses it by call position and this one by the stored step.
//
// The derivation runs in this same call because info.server_ct points
// into cfg.buf under CH_KEX_HYBRID and the decapsulation reads those bytes, so
// nothing may read a further message in between.
static int step_server_hello(ch_quic *q) {
    server_hello_info info;
    int rc = hsf_read_server_hello(&q->hs, &info);
    if (rc != CH_OK) {
        return rc;
    }
    if (info.hrr) {
        if (q->step == HSQ_STEP_AWAIT_RETRY_HELLO) {
            q->hs.alert = ALERT_UNEXPECTED_MESSAGE;
            return CH_EPROTO;
        }
        // t.tx is free here because ch_quic_crypto_in refuses input
        // while tx_len is not 0.
        size_t n = hsf_build_client_hello(&q->hs, q->t.tx, sizeof q->t.tx);
        if (n == 0) {
            return CH_ECAP;
        }
        q->tx_len = n;
        q->tx_level = CH_LEVEL_INITIAL;
        q->step = HSQ_STEP_AWAIT_RETRY_HELLO;
        return CH_OK;
    }
    rc = hsf_accept_server_hello(&q->hs, &info);
    if (rc != CH_OK) {
        return rc;
    }
    rc = hsf_derive_handshake_secrets(&q->hs, &info);
    if (rc != CH_OK) {
        return rc;
    }
    install_handshake_keys(q);
    q->rx_level = CH_LEVEL_HANDSHAKE;
    q->step = HSQ_STEP_AWAIT_ENCRYPTED_EXTENSIONS;
    return CH_OK;
}

static int step_encrypted_extensions(ch_quic *q) {
    int rc = hsf_read_encrypted_extensions(&q->hs);
    if (rc != CH_OK) {
        return rc;
    }
    // The one fork in the table: a PSK server sends no certificate.
    q->step = q->t.cfg.psk != NULL ? HSQ_STEP_AWAIT_FINISHED : HSQ_STEP_AWAIT_CERTIFICATE;
    return CH_OK;
}

static int step_certificate(ch_quic *q) {
    int rc = hsa_server_auth(&q->hs);
    if (rc != CH_OK) {
        return rc;
    }
    q->step = HSQ_STEP_AWAIT_CERTIFICATE_VERIFY;
    return CH_OK;
}

static int step_certificate_verify(ch_quic *q) {
    int rc = hsa_read_certificate_verify(&q->hs);
    if (rc != CH_OK) {
        return rc;
    }
    q->step = HSQ_STEP_AWAIT_FINISHED;
    return CH_OK;
}

// The server Finished, then everything the handshake owes after it: the
// client Finished staged at the Handshake level, the 1-RTT keys
// installed, and q->hs wiped. The wipe is INV-17's rule that handshake
// secrets die at CONNECTED, one round trip earlier than the TLS driver
// wipes them. It clears hs.t with the rest, so this step writes the
// back pointer again; every public entry writes it too.
//
// It does not raise q->t.state. ch_quic_crypto_out does that in the
// call that hands these bytes out, the moment RFC 9001 §4.1.1 names.
static int step_finished(ch_quic *q) {
    int rc = hsf_read_finished(&q->hs);
    if (rc != CH_OK) {
        return rc;
    }
#ifdef CH_TRUST_CA
    hsa_epoch_commit(&q->hs);
#endif
    hsf_complete(&q->hs, q->t.tx);
    q->tx_len = HSF_FINISHED_LEN;
    q->tx_level = CH_LEVEL_HANDSHAKE;
    install_application_keys(q);
    q->rx_level = CH_LEVEL_APPLICATION;
    ct_wipe(&q->hs, sizeof q->hs);
    q->hs.t = &q->t;
    q->step = HSQ_STEP_COMPLETE;
    return CH_OK;
}

// After the handshake only a NewSessionTicket is legal. RFC 9001 §4.4
// makes a post-handshake CertificateRequest a connection error of type
// PROTOCOL_VIOLATION (rfc9001.txt:735-738), so that one type writes
// q->error_code; every other type, a TLS KeyUpdate among them, leaves
// it 0 and ch_quic_error_code reports 0x0100 plus the alert, which is
// 0x010a for a KeyUpdate (§6, rfc9001.txt:1566-1568).
static int step_complete(ch_quic *q) {
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = hsr_next_msg(&q->hs, &type, &raw, &raw_len);
    if (rc != CH_OK) {
        return rc;
    }
    if (type == HS_NEW_SESSION_TICKET) {
        return hspost_take_ticket(&q->t, raw + 4, raw_len - 4, &q->hs.alert, &q->error_code);
    }
    if (type == HS_CERTIFICATE_REQUEST) {
        q->error_code = 0x0a;
    }
    q->hs.alert = ALERT_UNEXPECTED_MESSAGE;
    return CH_EPROTO;
}

int hsq_advance(ch_quic *q) {
    switch (q->step) {
    case HSQ_STEP_AWAIT_SERVER_HELLO:
    case HSQ_STEP_AWAIT_RETRY_HELLO:
        return step_server_hello(q);
    case HSQ_STEP_AWAIT_ENCRYPTED_EXTENSIONS:
        return step_encrypted_extensions(q);
    case HSQ_STEP_AWAIT_CERTIFICATE:
        return step_certificate(q);
    case HSQ_STEP_AWAIT_CERTIFICATE_VERIFY:
        return step_certificate_verify(q);
    case HSQ_STEP_AWAIT_FINISHED:
        return step_finished(q);
    case HSQ_STEP_COMPLETE:
        return step_complete(q);
    default:
        // A step value no step wrote, which a one-byte corruption of
        // q->step produces. It kills the session instead of running a
        // handler or calling ch_assert_fail, because the step number
        // is data a fault can change and CH_ASSERT is for programmer
        // error alone.
        q->hs.alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
}

#endif // CH_TRANSPORT_QUIC
