#include "session.h"

#include "ct.h"
#include "io.h"
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#include "ch_assert.h"
#include "tls.h"
#endif

#ifndef CH_TRANSPORT_TCP_NONBLOCKING
// A protected record can only be sealed with live keys; before any keys
// exist the alert goes out in plaintext, and once keys are wiped there is
// nothing legal left to say, so nothing is sent.
int tlsi_send_alert(ch_tls_priv *t, uint8_t level, uint8_t description) {
    const uint8_t body[2] = {level, description};
    if (t->keys) {
        size_t n = 0;
        if (rec_seal(&t->wr, REC_ALERT, body, 2, t->tx, sizeof t->tx, &n) != 0) {
            return CH_ECAP;
        }
        return io_send_all(&t->cfg, t->tx, n);
    }
    if (t->state == CH_ST_START) {
        uint8_t rec[REC_HDR + 2] = {REC_ALERT, 0x03, 0x03, 0, 2, level, description};
        return io_send_all(&t->cfg, rec, sizeof rec);
    }
    return CH_OK;
}
#endif // CH_TRANSPORT_TCP_NONBLOCKING

#ifdef CH_CPU_RUNTIME
void tlsi_record_cpu(ch_tls_priv *t) {
    t->rd.cpu = t->cfg.cpu;
    t->wr.cpu = t->cfg.cpu;
}
#endif

#ifdef CH_TRANSPORT_TCP_NONBLOCKING
void tlsi_give_back_buf(ch_tls_priv *t) {
    if (t->cfg.buf == NULL) {
        return;
    }
    // The buffer holds this connection's handshake plaintext, the peer's
    // certificates among them, and the next handshake that takes it from
    // the caller must not find a byte of it (docs/decisions.md 247). Every
    // byte the session wrote lies below buf_written_len, and the bytes
    // above it are the caller's own, so the wipe stops there
    // (docs/decisions.md 249).
    CH_ASSERT(t->buf_written_len <= t->cfg.buf_len);
    CH_ASSERT(t->pt_len <= t->buf_written_len);
    ct_wipe(t->cfg.buf, t->buf_written_len);
    t->cfg.buf = NULL;
    t->buf_written_len = 0;
    t->pt_off = 0;
    t->pt_len = 0;
}
#endif

void tlsi_wipe(ch_tls_priv *t) {
    ct_wipe(&t->rd, sizeof t->rd);
    ct_wipe(&t->wr, sizeof t->wr);
    ct_wipe(t->rd_secret, sizeof t->rd_secret);
    ct_wipe(t->wr_secret, sizeof t->wr_secret);
    ct_wipe(t->res_master, sizeof t->res_master);
#ifdef CH_EXPORTER
    ct_wipe(t->exp_master, sizeof t->exp_master);
#endif
    t->keys = 0;
    t->pt_off = 0;
    t->pt_len = 0;
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    t->held_len = 0;
    t->held_fill = 0;
    tlsi_give_back_buf(t);
#endif
}

// The peer's close_notify closes the peer's direction and no other (RFC
// 9846 §6, rfc9846.txt:3767-3768). This session reads nothing after it:
// §6.1 says data after a closure alert MUST be ignored
// (rfc9846.txt:3837-3839), and the read calls ignore it by never reading
// it. So the secrets only a read uses die here (INV-17): the read key and
// its secret, and the resumption master secret, which only taking a
// NewSessionTicket uses. The write key and its secret stay, because §6.1
// leaves this side's writes open (rfc9846.txt:3857-3859): the caller may
// still write, and ch_close sends this side's close_notify under that
// key. Nothing is sent here. TLS 1.2 answered a close_notify at once with
// one of its own, and TLS 1.3 dropped that rule (rfc9846.txt:3860-3864).
void tlsi_close_read_side(ch_tls_priv *t) {
    ct_wipe(&t->rd, sizeof t->rd);
    ct_wipe(t->rd_secret, sizeof t->rd_secret);
    ct_wipe(t->res_master, sizeof t->res_master);
    t->pt_off = 0;
    t->pt_len = 0;
    t->read_closed = 1;
}

// The failure funnel of the blocking drivers and of every connected TCP
// session; tcp_nonblocking_fail and quic_fail are the other two, and each
// writes alert_sent the way this one does. A reader that met the peer's
// fatal alert wrote alert_received before it failed the session, and RFC
// 9846 §6.2 has both sides close the connection at once on that alert
// (rfc9846.txt:3890-3893), so nothing goes out after it and no alert of
// this side's is recorded. It returns what tlsi_send_alert returned, CH_OK
// when nothing was sent, which ch_fail reports and every other caller
// discards.
#ifndef CH_TRANSPORT_TCP_NONBLOCKING
int tlsi_fail(ch_tls_priv *t, uint8_t description) {
    int rc = CH_OK;
    if (t->alert_received == 0) {
        t->alert_sent = description;
        rc = tlsi_send_alert(t, 2, description);
    }
    tlsi_wipe(t);
    t->state = CH_ST_FAILED;
    return rc;
}
#else
// tlsi_send_alert on the transport that sends nothing itself: the alert is
// sealed under the write key into the caller's out, CH_ALERT_RECORD_LEN
// bytes, in place of cfg.send. Each caller holds a connected session,
// whose write key is live. A key with no sequence number left seals
// nothing (RFC 9846 §5.3), as tlsi_send_alert sends nothing then.
int tlsi_seal_alert(ch_tls_priv *t, uint8_t level, uint8_t description, uint8_t *out,
                    size_t *out_len) {
    const uint8_t body[2] = {level, description};
    if (rec_seal(&t->wr, REC_ALERT, body, sizeof body, out, CH_ALERT_RECORD_LEN, out_len) != 0) {
        *out_len = 0; // record.h states no length for a record it refused
        return CH_ECAP;
    }
    return CH_OK;
}

// The same funnel as tlsi_fail, with the alert sealed into the caller's
// out by tlsi_seal_alert.
int tlsi_fail_into(ch_tls_priv *t, uint8_t description, uint8_t *out, size_t *out_len) {
    int rc = CH_OK;
    *out_len = 0;
    if (t->alert_received == 0) {
        t->alert_sent = description;
        rc = tlsi_seal_alert(t, 2, description, out, out_len); // level 2 is fatal (RFC 9846 §6)
    }
    tlsi_wipe(t);
    t->state = CH_ST_FAILED;
    return rc;
}
#endif
