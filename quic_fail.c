// How a QUIC session dies: every secret wiped but the write keys the
// close needs, the session marked dead, and the alert kept for the caller
// to report. quic_fail.h states the contract.
//
// Its own pair because INV-17 rests on the wipe list being complete, and
// both drivers -- the client's in quic.c and the server's in srv_quic.c --
// have to die the same way. One list is checkable; two copies drift.
#include "quic_fail.h"

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include "ct.h"
#include "handshake_message.h"
#include "handshake_record.h"

// QUIC's PROTOCOL_VIOLATION (RFC 9000 section 20.1). ch_quic_error_code
// reports it for the refusals RFC 9001 makes a connection error of that
// type, and quic.h names them.
#define QUIC_PROTOCOL_VIOLATION 0x0a

// The write bit of every level: the only bits of q->levels_ready a failed
// session keeps.
#define QUIC_WRITE_BITS                                                                            \
    (CH_QUIC_LEVEL_BIT(CH_LEVEL_INITIAL, CH_KEY_WRITE) |                                           \
     CH_QUIC_LEVEL_BIT(CH_LEVEL_HANDSHAKE, CH_KEY_WRITE) |                                         \
     CH_QUIC_LEVEL_BIT(CH_LEVEL_APPLICATION, CH_KEY_WRITE))

// Every secret the session holds except the write keys, the read bits,
// and the two fields that say how many bytes are staged and unread.
// session.h lists the same names beside the invariant they serve, so
// INV-17's claim that every failure path wipes can be checked against
// that list.
static void wipe_all_but_write_keys(ch_quic *q) {
    ct_wipe(&q->hs, sizeof q->hs);
    ct_wipe(&q->handshake_rx, sizeof q->handshake_rx);
    ct_wipe(&q->handshake_hp_rx, sizeof q->handshake_hp_rx);
    ct_wipe(q->app_rx, sizeof q->app_rx);
    ct_wipe(&q->app_hp_rx, sizeof q->app_hp_rx);
    ct_wipe(q->t.rd_secret, sizeof q->t.rd_secret);
    ct_wipe(q->t.wr_secret, sizeof q->t.wr_secret);
    ct_wipe(q->t.res_master, sizeof q->t.res_master);
    q->levels_ready &= (uint8_t)QUIC_WRITE_BITS;
    q->tx_len = 0;
    q->t.pt_off = 0;
    q->t.pt_len = 0;
}

void quic_wipe_write_keys(ch_quic *q, uint8_t level) {
    if (level == CH_LEVEL_INITIAL) {
        // The level holds no key, only the connection ID the seal
        // derives one from, and it names a dead connection now.
        ct_wipe(q->initial_dcid, sizeof q->initial_dcid);
        q->initial_dcid_len = 0;
    } else if (level == CH_LEVEL_HANDSHAKE) {
        ct_wipe(&q->handshake_tx, sizeof q->handshake_tx);
        ct_wipe(&q->handshake_hp_tx, sizeof q->handshake_hp_tx);
    } else {
        ct_wipe(&q->app_tx, sizeof q->app_tx);
        ct_wipe(&q->app_hp_tx, sizeof q->app_hp_tx);
    }
    q->levels_ready &= (uint8_t)~CH_QUIC_LEVEL_BIT(level, CH_KEY_WRITE);
}

void quic_wipe(ch_quic *q) {
    wipe_all_but_write_keys(q);
    quic_wipe_write_keys(q, CH_LEVEL_INITIAL);
    quic_wipe_write_keys(q, CH_LEVEL_HANDSHAKE);
    quic_wipe_write_keys(q, CH_LEVEL_APPLICATION);
}

// A level whose write bit is clear keeps no write key either. The bit
// and the keys are installed in one call, so the keys are zero here
// already on every path this tree has; the wipe makes the kept set
// exactly what the bits name rather than resting on that.
static void wipe_write_keys_unless_ready(ch_quic *q, uint8_t level) {
    if ((q->levels_ready & CH_QUIC_LEVEL_BIT(level, CH_KEY_WRITE)) == 0) {
        quic_wipe_write_keys(q, level);
    }
}

// What tlsi_fail is on the TCP transports, minus the alert record, which
// QUIC has no way to carry: the alert goes to q->alert for
// ch_quic_alert to report and the session is dead. The write keys of
// each level whose write bit is set stay, for the one CONNECTION_CLOSE
// packet ch_quic_seal_close seals there (RFC 9001 section 4.8,
// docs/decisions.md 57). It leaves q->error_code alone, so a caller that
// wrote 0x0a before it called still reports that code.
int quic_fail(ch_quic *q, int rc) {
    q->alert = q->hs.alert;
    wipe_all_but_write_keys(q);
    wipe_write_keys_unless_ready(q, CH_LEVEL_INITIAL);
    wipe_write_keys_unless_ready(q, CH_LEVEL_HANDSHAKE);
    wipe_write_keys_unless_ready(q, CH_LEVEL_APPLICATION);
    q->t.state = CH_ST_FAILED;
    return rc;
}

// The §4.1.3 refusals that kill the session, in one place because both
// write the same transport error code (rfc9001.txt:482-486,
// rfc9001.txt:491-493).
int quic_fail_level(ch_quic *q) {
    q->error_code = QUIC_PROTOCOL_VIOLATION;
    q->hs.alert = ALERT_UNEXPECTED_MESSAGE;
    return quic_fail(q, CH_EPROTO);
}

int quic_refuse_unread(ch_quic *q) {
    uint8_t type = 0;
    int waiting = hsr_peek_type(&q->hs, &type) == CH_OK;
    if (!waiting || type != HS_KEY_UPDATE) {
        q->error_code = QUIC_PROTOCOL_VIOLATION;
    }
    q->hs.alert = ALERT_UNEXPECTED_MESSAGE;
    return CH_EPROTO;
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
