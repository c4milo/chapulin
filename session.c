#include "session.h"

#include "ct.h"
#include "io.h"

// A protected record can only be sealed with live keys; before any keys
// exist the alert goes out in plaintext, and once keys are wiped there is
// nothing legal left to say, so nothing is sent.
int tlsi_send_alert(ch_tls *t, uint8_t level, uint8_t description) {
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

void tlsi_wipe(ch_tls *t) {
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
}

// The failure funnel of the blocking drivers and of every connected TCP
// session; tcp_nonblocking_fail and quic_fail are the other two, and each
// writes alert_sent the way this one does. A reader that met the peer's
// fatal alert wrote alert_received before it failed the session, and RFC
// 9846 §6.2 has both sides close the connection at once on that alert
// (rfc9846.txt:3890-3893), so nothing goes out after it and no alert of
// this side's is recorded.
void tlsi_fail(ch_tls *t, uint8_t description) {
    if (t->alert_received == 0) {
        t->alert_sent = description;
        (void)tlsi_send_alert(t, 2, description);
    }
    tlsi_wipe(t);
    t->state = CH_ST_FAILED;
}
