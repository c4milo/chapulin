// ch_read_in_place: a connected TRANSPORT=tcp-nonblocking session opens each
// record where the caller holds it, and copies no record and no plaintext
// (tcp_nonblocking.h states the contract, docs/decisions.md 247 the
// reasons). It is the only read this transport has once the handshake is
// done: cfg.buf serves the handshake alone, and the session gave it back
// when it connected (session.h, tlsi_give_back_buf).
//
// The rules are the ones tls.c's ch_read keeps on the blocking transport,
// record for record: the same length checks io.c makes, the same
// record_open, the same post-handshake handler and the same answers to an
// alert. Two things differ. The bytes are the caller's, so a record that
// fails is wiped where it lies. And a post-handshake message in parts
// waits in the caller's input, not in cfg.buf.
#include "tls_calls.h"

#ifdef CH_TRANSPORT_TCP_NONBLOCKING

#include "ch_assert.h"

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake_message.h"
#include "handshake_post.h"
#include "handshake_record.h"
#include "record.h"

// One call's walk over the caller's p. off is where the next record
// starts: after the records a message in parts already holds, then past
// each record the call takes. opened counts the bytes at the front of p
// that this session has opened and the caller has not consumed, which a
// failure wipes. alert is what the failure owes.
typedef struct {
    uint8_t *p;
    size_t n;
    size_t off;
    size_t opened;
    uint8_t alert;
} read_walk;

// The header of the record at w->off and the length checks io.c's
// io_read_record makes, in its order. Returns CH_OK with the body length
// for a whole record of application_data, CH_TCP_AGAIN when p holds less
// than the whole record, and a refusal with its alert in w->alert
// otherwise.
static int record_at(const ch_tls_priv *t, read_walk *w, size_t *body_len) {
    CH_ASSERT(w->off <= w->n);
    rbuf r;
    rb_init(&r, w->p + w->off, w->n - w->off);
    uint8_t outer = rb_u8(&r);
    rb_skip(&r, 2); // legacy_record_version, which RFC 9846 §5.1 has the reader ignore
    size_t body = rb_u16(&r);
    if (r.err) {
        return CH_TCP_AGAIN;
    }
    if (body > rec_body_max(outer)) {
        w->alert = ALERT_RECORD_OVERFLOW; // RFC 9846 §5.2 caps the length (rfc9846.txt:3595-3596)
        return CH_EPROTO;
    }
    if (body == 0) {
        return CH_EPROTO; // a protected record holds at least its tag (RFC 9846 §5.2)
    }
    if (REC_HDR + body > t->cfg.buf_len) {
        // Over the record_size_limit this side sized from cfg.buf_len (RFC
        // 8449 §4), the answer io.c gives on the blocking transport.
        w->alert = t->limit_sent ? ALERT_RECORD_OVERFLOW : ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    if (w->off > 0 && w->off + REC_HDR + body > t->cfg.buf_len) {
        // The records of one message in parts take at most cfg.buf_len
        // bytes of p together (docs/decisions.md 247).
        w->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    if (rb_left(&r) < body) {
        return CH_TCP_AGAIN;
    }
    if (outer != REC_APPDATA) {
        // After the handshake every record is protected (RFC 9846 §5.2).
        w->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    *body_len = body;
    return CH_OK;
}

// Opens the record at w->off in place: its plaintext lands REC_HDR bytes
// after the record's start, where the ciphertext was, which every AEAD
// path allows (aead.h, gcm.h). From here the record's bytes count as
// opened, so a failure wipes them whether or not the tag matched.
static int open_at(ch_tls_priv *t, read_walk *w, size_t body, size_t *pt_len, uint8_t *inner) {
    uint8_t *rec = w->p + w->off;
    w->opened = w->off + REC_HDR + body;
    if (rec_open(&t->rd, rec, REC_HDR + body, rec + REC_HDR, body, pt_len, inner) != 0) {
        w->alert = ALERT_BAD_RECORD_MAC; // RFC 9846 §5.2
        return CH_EAUTH;
    }
    CH_ASSERT(*pt_len < body);
    return CH_OK;
}

// The handshake bytes of the record just opened, pt_len of them after its
// header. The bytes of a message in parts so far, t->held_fill, end where
// the record before this one ended, at w->off, so they move up by REC_HDR
// bytes to sit just before this record's plaintext and the message reads
// as one run. What the run leaves of a message in parts then moves to the
// end of this record, where the next call finds it (session.h, held_len).
static int take_handshake(ch_tls_priv *t, read_walk *w, size_t body, size_t pt_len) {
    size_t fill = t->held_fill;
    CH_ASSERT(fill <= w->off);
    uint8_t *start = w->p + w->off + REC_HDR;
    memmove(start - fill, w->p + w->off - fill, fill);
    uint8_t *run = start - fill;
    size_t run_len = fill + pt_len;
    size_t used = 0;
    // The answer hspost_read starts with on the blocking transport.
    w->alert = ALERT_UNEXPECTED_MESSAGE;
    int rc = hspost_handle(t, run, run_len, &used, &w->alert);
    if (rc != CH_OK) {
        return rc;
    }
    size_t end = w->off + REC_HDR + body;
    size_t left = run_len - used;
    CH_ASSERT(left < body + fill);
    memmove(w->p + end - left, run + used, left);
    t->held_fill = left;
    w->off = end;
    return CH_OK;
}

// One alert record that no message in parts waits behind. The two
// closure alerts act here, as tls.c's read_alert has them act: close_notify
// closes the peer's direction and returns CH_ECLOSED, and user_canceled is
// read past, because RFC 9846 §6.1 has the reader go on until the
// close_notify after it. Every other record fails the session, through
// hsr_refuse_alert's answers.
static int take_alert(ch_tls_priv *t, read_walk *w, size_t pt_len, ch_read_result *result) {
    const uint8_t *pt = w->p + w->off + REC_HDR;
    if (pt_len == 2 && pt[1] == ALERT_CLOSE_NOTIFY) {
        tlsi_close_read_side(t);
        result->consumed = w->opened;
        return CH_ECLOSED;
    }
    if (pt_len == 2 && pt[1] == ALERT_USER_CANCELED) {
        result->consumed = w->opened;
        return CH_OK;
    }
    w->alert = ALERT_UNEXPECTED_MESSAGE;
    return hsr_refuse_alert(t, pt, pt_len, &w->alert);
}

// A record that is not a handshake one. With a message in parts waiting,
// none is legal: RFC 9846 §5.1 lets no record of another type come
// between the parts of a handshake message (rfc9846.txt:3460-3462), and
// an alert record there is read for the peer's fatal alert alone.
// Otherwise a record of application data gives the caller its plaintext,
// and one byte or more of it ends a run of KeyUpdates (docs/decisions.md
// 138).
static int take_other(ch_tls_priv *t, read_walk *w, size_t pt_len, uint8_t inner,
                      ch_read_result *result) {
    if (t->held_fill != 0) {
        w->alert = ALERT_UNEXPECTED_MESSAGE;
        if (inner == REC_ALERT) {
            return hsr_refuse_alert(t, w->p + w->off + REC_HDR, pt_len, &w->alert);
        }
        return CH_EPROTO;
    }
    if (inner == REC_ALERT) {
        return take_alert(t, w, pt_len, result);
    }
    if (inner != REC_APPDATA) {
        w->alert = ALERT_UNEXPECTED_MESSAGE; // no other inner type exists (RFC 9846 §5.4)
        return CH_EPROTO;
    }
    result->consumed = w->opened;
    if (pt_len > 0) {
        result->pt_off = w->off + REC_HDR;
        result->pt_len = pt_len;
        t->key_update_run = 0;
    }
    return CH_OK;
}

// Takes records from w->off until one gives the caller a result. A record
// of handshake bytes that leaves a message in parts is held, and the walk
// goes on to the next one, so CH_TCP_AGAIN always means p holds less than
// the next whole record. The loop ends because each pass takes a whole
// record, which moves w->off forward by REC_HDR + 17 bytes or more, and p
// holds n bytes.
static int read_records(ch_tls_priv *t, read_walk *w, ch_read_result *result) {
    while (w->off < w->n) {
        size_t body = 0;
        int rc = record_at(t, w, &body);
        if (rc != CH_OK) {
            return rc;
        }
        size_t pt_len = 0;
        uint8_t inner = 0;
        rc = open_at(t, w, body, &pt_len, &inner);
        if (rc != CH_OK) {
            return rc;
        }
        if (inner != REC_HANDSHAKE) {
            return take_other(t, w, pt_len, inner, result);
        }
        rc = take_handshake(t, w, body, pt_len);
        if (rc != CH_OK) {
            return rc;
        }
        if (t->held_fill == 0) {
            t->held_len = 0;
            result->consumed = w->off;
            return CH_OK;
        }
        t->held_len = w->off;
    }
    return CH_TCP_AGAIN;
}

// The failure funnel of this read, tlsi_fail with the alert written into
// the caller's reply in place of cfg.send. Every byte the session opened
// in p is wiped first, so no plaintext of a record that failed, and none
// of a message in parts, stays there. After the peer's fatal alert this
// side owes none (RFC 9846 §6.2, rfc9846.txt:3890-3893), and alert_sent
// records nothing.
static void fail_into(ch_tls_priv *t, const read_walk *w, uint8_t *reply, ch_read_result *result) {
    if (w->opened > 0) {
        ct_wipe(w->p, w->opened);
    }
    size_t reply_len = 0;
    if (t->alert_received == 0) {
        t->alert_sent = w->alert;
        const uint8_t body[2] = {2, w->alert}; // level 2 is fatal (RFC 9846 §6)
        if (rec_seal(&t->wr, REC_ALERT, body, sizeof body, reply, CH_ALERT_RECORD_LEN,
                     &reply_len) != 0) {
            reply_len = 0; // the last sequence number (RFC 9846 §5.3), as tlsi_send_alert does
        }
    }
    tlsi_wipe(t);
    t->state = CH_ST_FAILED;
    result->consumed = 0;
    result->pt_off = 0;
    result->pt_len = 0;
    result->reply_len = reply_len;
}

int tls_read_in_place(ch_tls_priv *t, uint8_t *p, size_t n, uint8_t *reply, size_t reply_cap,
                      ch_read_result *result) {
    // Contract-point guard, as ch_read's: no input can set an undefined state.
    CH_ASSERT(t->state <= CH_ST_FAILED);
    CH_ASSERT(t->held_fill <= t->held_len);
    if (result == NULL || reply == NULL || reply_cap < CH_ALERT_RECORD_LEN ||
        (p == NULL && n != 0)) {
        return CH_EINVAL;
    }
    if (t->state != CH_ST_CONNECTED && t->state != CH_ST_CLOSED) {
        return CH_EPROTO;
    }
    if (t->state == CH_ST_CONNECTED && n < t->held_len) {
        return CH_EINVAL; // the caller did not present the bytes a message in parts holds
    }
    memset(result, 0, sizeof *result);
    if (t->state == CH_ST_CLOSED || t->read_closed) {
        return CH_ECLOSED; // nothing after a close is read (RFC 9846 §6.1)
    }
    read_walk w = {p, n, t->held_len, t->held_len, ALERT_DECODE_ERROR};
    int rc = read_records(t, &w, result);
    if (rc == CH_OK || rc == CH_TCP_AGAIN || rc == CH_ECLOSED) {
        return rc;
    }
    fail_into(t, &w, reply, result);
    return rc;
}

#endif // CH_TRANSPORT_TCP_NONBLOCKING
