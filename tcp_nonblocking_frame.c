// The inbound record framing and the session-death path both tcp-nonblocking
// drivers share. tcp_nonblocking_frame.h states the contract; this file is
// quic_fail.c's counterpart on the transport that keeps its records, and
// it holds no protocol rule beyond what one record is allowed to be. It
// also holds ch_record_whole_len, the public call that tells a caller of
// either role where one inbound record ends (tcp_nonblocking.h).
#include "tcp_nonblocking_frame.h"

#ifdef CH_TRANSPORT_TCP_NONBLOCKING

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake_message.h"
#include "handshake_record.h"
#include "record.h"

// The largest value RFC 9846 §5.2 lets a record's length field hold,
// 2^14 + 256 (rfc9846.txt:3595-3596).
#define RECORD_BODY_MAX (0x4000 + 256)

// tcp_nonblocking.h states the contract. The reader refuses a header p
// does not yet hold whole, and the length it reads is compared with the
// bytes after the header, so no sum here can wrap.
size_t ch_record_whole_len(const uint8_t *p, size_t n) {
    rbuf r;
    rb_init(&r, p, n);
    rb_skip(&r, 3); // the content type and legacy_record_version
    size_t body_len = rb_u16(&r);
    if (r.err) {
        return 0;
    }
    if (body_len > RECORD_BODY_MAX) {
        return REC_HDR;
    }
    return rb_left(&r) < body_len ? 0 : REC_HDR + body_len;
}

void tcp_nonblocking_wipe(ch_record *r) {
    ct_wipe(&r->hs, sizeof r->hs);
    ct_wipe(&r->t.rd, sizeof r->t.rd);
    ct_wipe(&r->t.wr, sizeof r->t.wr);
    ct_wipe(r->t.rd_secret, sizeof r->t.rd_secret);
    ct_wipe(r->t.wr_secret, sizeof r->t.wr_secret);
    ct_wipe(r->t.res_master, sizeof r->t.res_master);
#ifdef CH_EXPORTER
    ct_wipe(r->t.exp_master, sizeof r->t.exp_master);
#endif
    ct_wipe(r->t.tx, sizeof r->t.tx);
    r->tx_len = 0;
    r->tx_off = 0;
    r->t.pt_off = 0;
    r->t.pt_len = 0;
    r->t.keys = 0;
}

int tcp_nonblocking_fail(ch_record *r, int rc) {
    r->alert = r->hs.alert;
    tcp_nonblocking_wipe(r);
    r->t.state = CH_ST_FAILED;
    return rc;
}

int tcp_nonblocking_session_dead(const ch_record *r) {
    return r->t.state == CH_ST_CLOSED || r->t.state == CH_ST_FAILED;
}

int tcp_nonblocking_take_record(ch_record *r, uint8_t *rec, size_t body_len, uint8_t outer) {
    const uint8_t *pt = rec + REC_HDR;
    size_t pt_len = body_len;
    if (outer == REC_CCS) {
        // The compatibility-mode record of RFC 9846 Appendix E.4. It is
        // never protected, whatever keys are installed, so this test sits
        // ahead of the decryption rather than after it: a peer that sends
        // one in the middle of the handshake is the common case, and
        // decrypting it would fail the connection.
        return CH_OK;
    }
    if (r->hs.encrypted) {
        uint8_t inner = 0;
        size_t opened = 0;
        if (rec_open(&r->t.rd, rec, REC_HDR + body_len, rec, body_len, &opened, &inner) != 0) {
            r->hs.alert = ALERT_BAD_RECORD_MAC;
            return CH_EPROTO;
        }
        // RFC 9846 section 5 keeps the dummy change_cipher_spec legal
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
        // larger than the record_size_limit this endpoint advertised.
        r->hs.alert = ALERT_RECORD_OVERFLOW;
        return CH_ECAP;
    }
    return CH_OK;
}

#endif // CH_TRANSPORT_TCP_NONBLOCKING
