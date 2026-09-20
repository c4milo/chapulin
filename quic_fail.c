// How a QUIC session dies: every secret wiped, the session marked dead,
// and the alert kept for the caller to report. quic_fail.h states the
// contract.
//
// Its own pair because INV-17 rests on the wipe list being complete, and
// both drivers -- the client's in quic.c and the server's in srv_quic.c --
// have to die the same way. One list is checkable; two copies drift.
#include "quic_fail.h"

#ifdef CH_TRANSPORT_QUIC

#include "ct.h"
#include "handshake_message.h"

// QUIC's PROTOCOL_VIOLATION (RFC 9000 section 20.1). ch_quic_error_code
// reports it for the refusals RFC 9001 makes a connection error of that
// type, and quic.h names them.
#define QUIC_PROTOCOL_VIOLATION 0x0a

// Every secret the session holds, and the two fields that say which
// keys are usable and how many bytes are unread. session.h lists the
// same names beside the invariant they serve, so INV-17's claim that
// every failure path wipes can be checked against that list.
void quic_wipe(ch_quic *q) {
    ct_wipe(&q->hs, sizeof q->hs);
    ct_wipe(&q->handshake_rx, sizeof q->handshake_rx);
    ct_wipe(&q->handshake_tx, sizeof q->handshake_tx);
    ct_wipe(&q->handshake_hp_rx, sizeof q->handshake_hp_rx);
    ct_wipe(&q->handshake_hp_tx, sizeof q->handshake_hp_tx);
    ct_wipe(&q->app_tx, sizeof q->app_tx);
    ct_wipe(q->app_rx, sizeof q->app_rx);
    ct_wipe(&q->app_hp_rx, sizeof q->app_hp_rx);
    ct_wipe(&q->app_hp_tx, sizeof q->app_hp_tx);
    ct_wipe(q->t.rd_secret, sizeof q->t.rd_secret);
    ct_wipe(q->t.wr_secret, sizeof q->t.wr_secret);
    ct_wipe(q->t.res_master, sizeof q->t.res_master);
    // The Destination Connection ID holds no key, and is zeroed with the
    // rest rather than left naming a dead connection (session.h).
    ct_wipe(q->initial_dcid, sizeof q->initial_dcid);
    q->initial_dcid_len = 0;
    q->levels_ready = 0;
    q->tx_len = 0;
    q->t.pt_off = 0;
    q->t.pt_len = 0;
}

// What tlsi_fail is on the TLS transport, minus the alert record, which
// QUIC has no way to carry: the alert goes to q->alert for
// ch_quic_alert to report, every secret is wiped and the session is
// dead. It leaves q->error_code alone, so a caller that wrote 0x0a
// before it called still reports that code.
int quic_fail(ch_quic *q, int rc) {
    q->alert = q->hs.alert;
    quic_wipe(q);
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

#endif // CH_TRANSPORT_QUIC
