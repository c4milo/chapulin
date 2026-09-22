// chapulin's client driver under TRANSPORT=record, and the three calls
// either role exports. Contract in rec.h. It is the file beside tls.c
// and quic.c, and it holds no protocol rule of its own: hsr_advance runs
// the handshake and record.[ch] protects what leaves.
//
// ch_record_state, ch_record_alert and ch_record_close read no side, so
// a ROLE=server object compiles them from here and srv_rec.c adds its
// own two entry points beside them. The client driver above them is what
// that build has no use for, the way tls.c guards ch_connect.
#include "rec.h"

#ifdef CH_TRANSPORT_RECORD

#include "ch_assert.h"

#include <string.h>

#include "ct.h"
#include "handshake_flight.h"
#include "handshake_message.h"
#include "rec_frame.h"
#include "rec_step.h"
#include "record.h"

#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)

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

int ch_record_in(ch_record *r, uint8_t *p, size_t n, size_t *consumed) {
    CH_ASSERT(r->t.state <= CH_ST_FAILED);
    r->hs.t = &r->t;
    *consumed = 0;
    if (rec_session_dead(r)) {
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
        int rc = rec_take_record(r, rec, body_len, rec[0]);
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
    if (rec_session_dead(r)) {
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

#endif // CH_ROLE_SERVER

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
