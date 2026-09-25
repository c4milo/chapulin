#include "handshake.h"

#include <string.h>

#include "ct.h"
#include "handshake_auth.h"
#include "handshake_flight.h"
#include "handshake_message.h"
#include "handshake_parser.h"
#include "handshake_record.h"
#include "io.h"

// The hello is built whole into the TX staging array (docs/decisions.md
// 22), so the array must hold the largest one this build can emit.
// Both builds size CH_TX_STAGE to exactly that, and this is where the
// two constants meet: session.h cannot see CH_HELLO_MAX, so it repeats
// the value, and a drift between them fails the build here.
#ifndef __cplusplus
_Static_assert(CH_HELLO_MAX <= CH_TX_STAGE, "the largest ClientHello must fit TX staging");
#endif

// Builds the ClientHello into the TX staging array past the record
// header, then sends it as a plaintext handshake record. The message
// itself, the binder and the transcript update are
// hsf_build_client_hello's.
static int send_client_hello(handshake_state *h) {
    ch_tls *t = h->t;
    uint8_t *msg = t->tx + REC_HDR;
    size_t n = hsf_build_client_hello(h, msg, sizeof t->tx - REC_HDR);
    if (n == 0) {
        return CH_ECAP;
    }
    t->tx[0] = REC_HANDSHAKE;
    t->tx[1] = 0x03;
    // The very first record may carry 0x0301 for old middleboxes; every
    // later one, including the post-HRR retry, must say 0x0303 (§5.1).
    // Every retry this client answers carries a cookie, so the cookie
    // marks the retry hello (hsf_read_server_hello).
    t->tx[2] = h->cookie_len > 0 ? 0x03 : 0x01;
    t->tx[3] = (uint8_t)(n >> 8);
    t->tx[4] = (uint8_t)n;
    return io_send_all(&t->cfg, t->tx, REC_HDR + n);
}

static int send_client_finished(handshake_state *h, const uint8_t *msg, size_t n) {
    ch_tls *t = h->t;
    size_t out_len = 0;
    if (rec_seal(&t->wr, REC_HANDSHAKE, msg, n, t->tx, sizeof t->tx, &out_len) != 0) {
        return CH_ECAP;
    }
    return io_send_all(&t->cfg, t->tx, out_len);
}

// ClientHello out, ServerHello in, with at most one HelloRetryRequest
// round; on CH_OK info holds an acceptable non-HRR ServerHello.
static int hello_exchange(handshake_state *h, server_hello_info *info) {
    int rc = send_client_hello(h);
    if (rc != CH_OK) {
        return rc;
    }
    rc = hsf_read_server_hello(h, info);
    if (rc != CH_OK) {
        return rc;
    }
    if (info->hrr) {
        rc = send_client_hello(h);
        if (rc != CH_OK) {
            return rc;
        }
        rc = hsf_read_server_hello(h, info);
        if (rc != CH_OK) {
            return rc;
        }
        if (info->hrr) {
            h->alert = ALERT_UNEXPECTED_MESSAGE;
            return CH_EPROTO;
        }
    }
    return hsf_accept_server_hello(h, info);
}

static int run(handshake_state *h) {
    ch_tls *t = h->t;
    hsf_begin(h);

    server_hello_info info;
    int rc = hello_exchange(h, &info);
    if (rc != CH_OK) {
        return rc;
    }
    rc = hsf_derive_handshake_secrets(h, &info);
    if (rc != CH_OK) {
        return rc;
    }
    REC_DIR_INIT_SUITE(&t->rd, h->s_hs, h->suite);
    REC_DIR_INIT_SUITE(&t->wr, h->c_hs, h->suite);
    h->encrypted = 1;
    t->keys = 1; // alerts encrypt from here on

    rc = hsf_read_encrypted_extensions(h);
    if (rc != CH_OK) {
        return rc;
    }
    // A server that selected the PSK authenticated with it and sends no
    // certificate (RFC 9846 §2.2). Every other server sends one: a full
    // handshake, and under TRUST=webpki a server that declined the ticket
    // this client offered.
    if (!t->psk_selected) {
        rc = hsa_server_auth(h);
        if (rc != CH_OK) {
            return rc;
        }
    }
    rc = hsf_read_finished(h);
    if (rc != CH_OK) {
        return rc;
    }
#ifdef CH_TRUST_CA
    hsa_epoch_commit(h);
#endif

    // Server Finished is in; derive the application schedule, answer with
    // our Finished under the handshake keys, then switch both directions.
    uint8_t finished[HSF_FINISHED_MAX];
    size_t finished_len = hsf_complete(h, finished);
    rc = send_client_finished(h, finished, finished_len);
    if (rc != CH_OK) {
        return rc;
    }
    REC_DIR_INIT_SUITE(&t->rd, t->rd_secret, h->suite);
    REC_DIR_INIT_SUITE(&t->wr, t->wr_secret, h->suite);
    t->pt_off = 0;
    t->pt_len = 0;
    t->state = CH_ST_CONNECTED;
    return CH_OK;
}

int ch_handshake(ch_tls *t) {
    handshake_state h;
    memset(&h, 0, sizeof h);
    h.t = t;
    h.alert = ALERT_DECODE_ERROR;
    size_t room = t->cfg.buf_len - REC_HDR - AEAD_TAG;
    h.record_size_limit = room > 0x4001 ? 0x4001 : (uint16_t)room;
    t->peer_limit = CH_TX_PT;
#ifdef CH_TRUST_WEBPKI
    // ch_connect zeroed the session, and 0 is the first protocol in
    // ch_cfg.alpn_protocols, so the no-selection value has to be written
    // before the parser can report one (RFC 7301 §3.2 lets the server
    // send no ALPN extension at all).
    t->alpn_selected = CH_ALPN_NONE;
#endif

    int rc = run(&h);
    uint8_t alert = h.alert;
    ct_wipe(&h, sizeof h);
    if (rc != CH_OK) {
        tlsi_fail(t, alert);
    }
    return rc;
}
