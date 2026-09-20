// chapulin's public API under TRANSPORT=record: the driver, the failure
// path and the record framing. Contract in rec.h. It is the file beside
// tls.c and quic.c, and it holds no protocol rule of its own: hsr_advance
// runs the handshake and record.[ch] protects what leaves.
#include "rec.h"

#ifdef CH_TRANSPORT_RECORD

#include "ch_assert.h"

#include <string.h>

#include "ct.h"
#include "handshake_flight.h"
#include "handshake_message.h"
#include "rec_step.h"
#include "record.h"

// Every secret the session holds, and the fields that say how much is
// staged or unread. session.h lists the same names beside the invariant
// they serve, so INV-17's claim that every failure path wipes can be
// checked against that list.
static void rec_wipe(ch_record *r) {
    ct_wipe(&r->hs, sizeof r->hs);
    ct_wipe(&r->t.rd, sizeof r->t.rd);
    ct_wipe(&r->t.wr, sizeof r->t.wr);
    ct_wipe(r->t.rd_secret, sizeof r->t.rd_secret);
    ct_wipe(r->t.wr_secret, sizeof r->t.wr_secret);
    ct_wipe(r->t.res_master, sizeof r->t.res_master);
    ct_wipe(r->t.tx, sizeof r->t.tx);
    r->tx_len = 0;
    r->tx_off = 0;
    r->t.pt_off = 0;
    r->t.pt_len = 0;
    r->t.keys = 0;
}

// What tlsi_fail is on the blocking transport, minus the alert record:
// this mode sends nothing itself, so the alert goes to r->alert and the
// caller sends it. Every secret is wiped and the session is dead.
static int rec_fail(ch_record *r, int rc) {
    r->alert = r->hs.alert;
    rec_wipe(r);
    r->t.state = CH_ST_FAILED;
    return rc;
}

static int session_dead(const ch_record *r) {
    return r->t.state == CH_ST_CLOSED || r->t.state == CH_ST_FAILED;
}

int ch_record_init(ch_record *r, const ch_cfg *cfg) {
    // Neither pointer is checked, as ch_connect does not check its own:
    // rec.h makes "r and cfg are not NULL" a caller requirement.
    memset(r, 0, sizeof *r);
    r->t.cfg = *cfg;
    // The callbacks go unused until the handshake is done; ch_read and
    // ch_write need them after it (rec.h).
    if (!tlsi_config_ok(cfg) || cfg->send == NULL || cfg->recv == NULL) {
        memset(r, 0, sizeof *r);
        r->t.state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    // A CA build loads its revocation epoch before the first message,
    // exactly as ch_connect does; every other build answers CH_OK.
    if (tlsi_epoch_init(&r->t, cfg, cfg->psk != NULL) != CH_OK) {
        memset(r, 0, sizeof *r);
        r->t.state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    r->hs.t = &r->t;
    r->hs.alert = ALERT_DECODE_ERROR;
    // This client's own record_size_limit, sized to the caller's buffer,
    // the same arithmetic ch_handshake does.
    size_t room = r->t.cfg.buf_len - REC_HDR - AEAD_TAG;
    r->hs.record_size_limit = room > 0x4001 ? 0x4001 : (uint16_t)room;
    r->t.peer_limit = CH_TX_PT;
#if defined(CH_TRUST_WEBPKI) || defined(CH_ROLE_SERVER)
    // Only the builds cfg.h gives the ALPN fields have a selection to
    // seed; a raw or ca client offers no protocol at all.
    r->t.alpn_selected = CH_ALPN_NONE;
#endif
    hsf_begin(&r->hs);
    size_t n = hsf_build_client_hello(&r->hs, r->t.tx + REC_HDR, sizeof r->t.tx - REC_HDR);
    if (n == 0) {
        memset(r, 0, sizeof *r);
        r->t.state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    rec_stage_plain(r, n);
    r->step = HSR_STEP_AWAIT_SERVER_HELLO;
    r->t.state = CH_ST_START;
    return CH_OK;
}

// Runs every whole handshake message the fed plaintext now holds. It is
// quic.c's drive loop without the level checks, and it terminates for the
// same reason: a copy that leaves bytes over means the buffer is full,
// and a full buffer always holds hsr_peek_message's 4-byte header.
static int drive(ch_record *r) {
    for (;;) {
        size_t raw_len = 0;
        int rc = hsr_peek_message(&r->hs, &raw_len, &r->hs.alert);
        if (rc == HSR_INCOMPLETE) {
            return CH_OK;
        }
        if (rc != CH_OK) {
            return rec_fail(r, rc);
        }
        rc = hsr_advance(r);
        if (rc != CH_OK) {
            return rec_fail(r, rc);
        }
        // A step that staged a record has said everything it can until
        // the caller collects it and the peer answers.
        if (r->tx_len != 0) {
            return CH_OK;
        }
    }
}

// Takes one record's plaintext into the handshake buffer. A record that
// arrives before the handshake keys is already plaintext; one after them
// is unprotected in place, which rec_open supports through pt == rec.
static int take_record(ch_record *r, uint8_t *rec, size_t body_len, uint8_t outer) {
    const uint8_t *pt = rec + REC_HDR;
    size_t pt_len = body_len;
    if (outer == REC_CCS) {
        // The compatibility-mode record of RFC 9846 Appendix E.4. It is
        // never protected, whatever keys are installed, so this test sits
        // ahead of the decryption rather than after it: a server that
        // sends one between the ServerHello and its flight is the common
        // case, and decrypting it would fail the connection.
        return CH_OK;
    }
    if (r->hs.encrypted) {
        uint8_t inner = 0;
        size_t opened = 0;
        if (rec_open(&r->t.rd, rec, REC_HDR + body_len, rec, body_len, &opened, &inner) != 0) {
            r->hs.alert = ALERT_BAD_RECORD_MAC;
            return CH_EPROTO;
        }
        // RFC 9846 section 5.4 keeps the dummy change_cipher_spec legal
        // until the handshake ends; every other non-handshake type here
        // is a message this mode has no state for.
        if (inner != REC_HANDSHAKE) {
            r->hs.alert = ALERT_UNEXPECTED_MESSAGE;
            return CH_EPROTO;
        }
        pt = rec;
        pt_len = opened;
    } else if (outer != REC_HANDSHAKE) {
        r->hs.alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    if (hsr_feed(&r->hs, pt, pt_len) != pt_len) {
        // The buffer could not hold this message, which is a peer record
        // larger than the record_size_limit this client advertised.
        r->hs.alert = ALERT_RECORD_OVERFLOW;
        return CH_ECAP;
    }
    return CH_OK;
}

int ch_record_in(ch_record *r, uint8_t *p, size_t n, size_t *consumed) {
    CH_ASSERT(r->t.state <= CH_ST_FAILED);
    r->hs.t = &r->t;
    *consumed = 0;
    if (session_dead(r)) {
        return CH_EPROTO;
    }
    // A staged record the caller has not collected means this endpoint
    // owes the peer bytes, so nothing the peer sent can be an answer yet.
    if (r->tx_len != 0) {
        return CH_EINVAL;
    }
    size_t off = 0;
    for (;;) {
        if (n - off < REC_HDR) {
            return CH_OK;
        }
        uint8_t *rec = p + off;
        size_t body_len = ((size_t)rec[3] << 8) | rec[4];
        if (body_len > 0x4000 + 256) {
            // RFC 9846 section 5.1 caps a record; anything larger names
            // no record this endpoint will ever read.
            r->hs.alert = ALERT_RECORD_OVERFLOW;
            return rec_fail(r, CH_EPROTO);
        }
        if (n - off < REC_HDR + body_len) {
            return CH_OK;
        }
        int rc = take_record(r, rec, body_len, rec[0]);
        if (rc != CH_OK) {
            return rec_fail(r, rc);
        }
        off += REC_HDR + body_len;
        *consumed = off;
        rc = drive(r);
        if (rc != CH_OK) {
            return rc;
        }
        if (r->tx_len != 0) {
            return CH_OK;
        }
    }
}

int ch_record_out(ch_record *r, uint8_t *out, size_t cap, size_t *out_len) {
    if (session_dead(r)) {
        return CH_EINVAL;
    }
    if (cap == 0) {
        return CH_ECAP;
    }
    size_t left = r->tx_len - r->tx_off;
    if (left == 0) {
        *out_len = 0;
        return CH_OK;
    }
    size_t take = left < cap ? left : cap;
    memcpy(out, r->t.tx + r->tx_off, take);
    r->tx_off += take;
    *out_len = take;
    if (r->tx_off == r->tx_len) {
        r->tx_len = 0;
        r->tx_off = 0;
        if (r->step == HSR_STEP_COMPLETE && r->t.state == CH_ST_START) {
            // These bytes were the client Finished: this endpoint has now
            // sent its own and verified the peer's, which is what the
            // handshake being done means.
            r->t.state = CH_ST_CONNECTED;
        }
    }
    return CH_OK;
}

uint8_t ch_record_state(const ch_record *r) {
    return r->t.state;
}

uint8_t ch_record_alert(const ch_record *r) {
    return r->alert;
}

void ch_record_close(ch_record *r) {
    rec_wipe(r);
    r->t.state = CH_ST_CLOSED;
}

#endif // CH_TRANSPORT_RECORD
