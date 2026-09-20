// The TLS 1.3 server handshake driver. srv_handshake.h states the
// contract; this file is the mirror of handshake.c's run and
// ch_handshake on the other side of the connection.
//
// The flight is one straight line of srv_flight.h calls, split into
// four functions because .clang-tidy caps cognitive complexity at 15
// and each `if (rc != CH_OK) return rc;` counts one. No function here
// holds a state variable, so the order is the call order and no message
// can run out of turn.
#include "srv_handshake.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "ct.h"
#include "srv_flight.h"

// Copies what the session keeps past the message that decided it, which
// session.h lists field by field. This driver is the only scope that
// holds the selection, the parsed ClientHello and the session at once,
// so the copy happens here.
//
// srv_send_encrypted_extensions reads alpn_selected off the session
// rather than off the hello, because its signature carries no
// client_hello, so this call runs before it.
static void store_selection(ch_tls *t, const client_hello *ch, const selection *sel) {
    t->suite = sel->suite;
    t->hash_len = sel->hash_len;
    t->group = sel->group;
    t->sigalg = sel->sigalg;
    t->alpn_selected = ch->alpn_selected;
    // The client's record_size_limit (RFC 8449) bounds every record this
    // server seals from the EncryptedExtensions on. 0 is the absent
    // extension, which leaves the 2^14 default, and srv_handshake seeded
    // CH_TX_PT, this build's own cap on one record's plaintext. Only a
    // smaller limit is stored, so t->peer_limit is the whole send cap and
    // a send site needs no second comparison against CH_TX_PT. The client
    // lowers its own the same way (handshake_parser.c:233).
    if (ch->record_size_limit != 0 && ch->record_size_limit < t->peer_limit) {
        t->peer_limit = ch->record_size_limit;
    }
}

// The HelloRetryRequest round: the retry goes out, the dummy
// change_cipher_spec follows it (RFC 9846 Appendix E.4,
// rfc9846.txt:6391-6393), the second ClientHello comes back, and
// srv_check_retry_hello compares it against the cookie before the
// ServerHello answers it.
//
// This is srv_send_hello_retry_request's one call site, so a second
// HelloRetryRequest is unreachable by call position rather than by a
// counter. srv_check_retry_hello writes sel from the cookie and never
// sets need_retry, which is what keeps that true.
static int retry_round(handshake_state *h, client_hello *ch, selection *sel) {
    int rc = srv_send_hello_retry_request(h, ch, sel);
    if (rc != CH_OK) {
        return rc;
    }
    rc = srv_send_compat_ccs(h, ch);
    if (rc != CH_OK) {
        return rc;
    }
    rc = srv_read_client_hello(h, ch);
    if (rc != CH_OK) {
        return rc;
    }
    rc = srv_check_retry_hello(h, ch, sel);
    if (rc != CH_OK) {
        return rc;
    }
    return srv_send_server_hello(h, ch, sel);
}

// The hello exchange: draw the server's secrets, read the ClientHello,
// choose this connection's parameters, and answer. On CH_OK sel holds
// what the connection uses and ch holds the hello the ServerHello
// answered, whose share still points into cfg.buf.
//
// The two paths each end in srv_send_server_hello because the dummy
// change_cipher_spec sits at a different place in each: after the
// HelloRetryRequest when there was one, and after the ServerHello when
// there was not. srv_flight.h states why that beats one call site and a
// flag.
static int hello_exchange(handshake_state *h, client_hello *ch, selection *sel) {
    srv_begin(h);
    int rc = srv_read_client_hello(h, ch);
    if (rc != CH_OK) {
        return rc;
    }
    rc = srv_select(h, ch, sel);
    if (rc != CH_OK) {
        return rc;
    }
    if (sel->need_retry) {
        return retry_round(h, ch, sel);
    }
    rc = srv_send_server_hello(h, ch, sel);
    if (rc != CH_OK) {
        return rc;
    }
    return srv_send_compat_ccs(h, ch);
}

// Everything under the handshake keys: the server's own flight, then
// the client Finished it reads before either direction advances to the
// application keys.
//
// A PSK handshake sends no Certificate and no CertificateVerify, which
// is why both calls sit under psk_selected. This build selects no PSK,
// so the arm is taken in every handshake it runs today.
static int auth_flight(handshake_state *h, const selection *sel) {
    int rc = srv_send_encrypted_extensions(h, sel);
    if (rc != CH_OK) {
        return rc;
    }
    if (!sel->psk_selected) {
        rc = srv_send_certificate(h, sel);
        if (rc != CH_OK) {
            return rc;
        }
        rc = srv_send_certificate_verify(h, sel);
        if (rc != CH_OK) {
            return rc;
        }
    }
    rc = srv_send_finished(h);
    if (rc != CH_OK) {
        return rc;
    }
    return srv_read_client_finished(h);
}

// The whole flight, first ClientHello to connected.
//
// ch and sel live on this frame and nowhere else. Neither holds a
// secret: every byte in them arrived in the clear in the ClientHello or
// went out in the clear in the ServerHello (srv_parser.h), so this
// function wipes neither, and srv_handshake wipes the handshake_state
// that does hold secrets.
static int run(handshake_state *h) {
    client_hello ch;
    selection sel;
    memset(&ch, 0, sizeof ch);
    memset(&sel, 0, sizeof sel);

    int rc = hello_exchange(h, &ch, &sel);
    if (rc != CH_OK) {
        return rc;
    }
    store_selection(h->t, &ch, &sel);
    rc = srv_derive_handshake_secrets(h, &ch, &sel);
    if (rc != CH_OK) {
        return rc;
    }
    rc = auth_flight(h, &sel);
    if (rc != CH_OK) {
        return rc;
    }
    srv_complete(h);
    return CH_OK;
}

int srv_handshake(ch_tls *t) {
    handshake_state h;
    memset(&h, 0, sizeof h);
    h.t = t;
    // The description a failure carries when no handler chose a more
    // specific one, seeded the way ch_handshake seeds it
    // (handshake.c:372-395).
    h.alert = ALERT_DECODE_ERROR;
    // This server's own record_size_limit, sized to the caller's buffer,
    // which srv_send_encrypted_extensions puts in the
    // EncryptedExtensions. store_selection lowers t->peer_limit to the
    // client's own limit once the hello has been read, when the client
    // asks for less than this build sends.
    size_t room = t->cfg.buf_len - REC_HDR - AEAD_TAG;
    h.record_size_limit = room > 0x4001 ? 0x4001 : (uint16_t)room;
    t->peer_limit = CH_TX_PT;
    // ch_srv_accept zeroed the session, and 0 is the first protocol in
    // ch_cfg.alpn_protocols, so the no-selection value has to be written
    // before the parser can report one.
    t->alpn_selected = CH_ALPN_NONE;

    int rc = run(&h);
    uint8_t alert = h.alert;
    ct_wipe(&h, sizeof h);
    if (rc != CH_OK) {
        tlsi_fail(t, alert);
    }
    return rc;
}

#endif // CH_ROLE_SERVER
