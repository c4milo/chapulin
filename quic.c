// chapulin's public API under TRANSPORT=quic: the driver, the failure
// path and the packet calls. Contract in quic.h. It is the file beside
// tls.c, and it holds no protocol rule of its own: hsq_advance runs the
// handshake and quic_initial.c, quic_packet.c and quic_retry.c protect
// the packets.
#include "quic.h"

#ifdef CH_TRANSPORT_QUIC

#include "ch_assert.h"

#include <string.h>

#include "ct.h"
#include "handshake_flight.h"
#include "handshake_message.h"
#include "handshake_record.h"
#include "quic_config.h"
#include "quic_initial.h"
#include "quic_packet.h"
#include "quic_retry.h"

// The hello is built whole into t.tx, so that array must hold the
// largest one this build can emit. session.h repeats CH_HELLO_MAX's
// QUIC values as literals because handshake_message.h sits above it;
// this is where both constants are visible, so a drift fails the build
// here rather than shipping.
#ifndef __cplusplus
_Static_assert(CH_HELLO_MAX <= CH_TX_STAGE, "the largest ClientHello must fit TX staging");
#endif

// QUIC's PROTOCOL_VIOLATION (RFC 9000 §20.1). ch_quic_error_code
// reports it for the four refusals RFC 9001 makes a connection error of
// that type, and quic.h names all four.
#define QUIC_PROTOCOL_VIOLATION 0x0a

// Every secret the session holds, and the two fields that say which
// keys are usable and how many bytes are unread. session.h lists the
// same names beside the invariant they serve, so INV-17's claim that
// every failure path wipes can be checked against that list.
static void quic_wipe(ch_quic *q) {
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
static int quic_fail(ch_quic *q, int rc) {
    q->alert = q->hs.alert;
    quic_wipe(q);
    q->t.state = CH_ST_FAILED;
    return rc;
}

// The §4.1.3 refusals that kill the session, in one place because both
// write the same transport error code (rfc9001.txt:482-486,
// rfc9001.txt:491-493).
static int quic_fail_level(ch_quic *q) {
    q->error_code = QUIC_PROTOCOL_VIOLATION;
    q->hs.alert = ALERT_UNEXPECTED_MESSAGE;
    return quic_fail(q, CH_EPROTO);
}

static int session_dead(const ch_quic *q) {
    return q->t.state == CH_ST_CLOSED || q->t.state == CH_ST_FAILED;
}

int ch_quic_init(ch_quic *q, const ch_cfg *cfg) {
    // Neither pointer is checked, as ch_connect does not check its own:
    // quic.h makes "q and cfg are not NULL" a caller requirement, and a
    // NULL here is a caller that never read the header rather than an
    // invariant this file can restore.
    memset(q, 0, sizeof *q);
    q->t.cfg = *cfg;
    if (quic_config_ok(&q->t, cfg) != CH_OK) {
        // Nothing went out and no secret was drawn, so a zeroed q with
        // a dead state is the whole answer.
        memset(q, 0, sizeof *q);
        q->t.state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    q->hs.t = &q->t;
    q->hs.alert = ALERT_DECODE_ERROR;
    // 0 is the first protocol in cfg.alpn_protocols, so the
    // no-selection value has to be written before the parser can report
    // one.
    q->t.alpn_selected = CH_ALPN_NONE;
    hsf_begin(&q->hs);
    size_t n = hsf_build_client_hello(&q->hs, q->t.tx, sizeof q->t.tx);
    if (n == 0) {
        memset(q, 0, sizeof *q);
        q->t.state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    q->tx_len = n;
    q->tx_level = CH_LEVEL_INITIAL;
    q->rx_level = CH_LEVEL_INITIAL;
    q->step = HSQ_STEP_AWAIT_SERVER_HELLO;
    q->t.state = CH_ST_START;
    return CH_OK;
}

int ch_quic_initial_keys(ch_quic *q, const uint8_t *dcid, size_t dcid_len) {
    if (session_dead(q) || dcid_len > CH_QUIC_DCID_MAX) {
        return CH_EINVAL;
    }
    // No key is derived or stored here: ch_quic_seal and ch_quic_open
    // hand these bytes to quic_initial.c, which derives the one
    // direction's key it needs on its own stack (INV-26).
    if (dcid_len > 0) {
        memcpy(q->initial_dcid, dcid, dcid_len);
    }
    q->initial_dcid_len = (uint8_t)dcid_len;
    q->levels_ready |= CH_QUIC_LEVEL_BIT(CH_LEVEL_INITIAL, CH_KEY_READ);
    q->levels_ready |= CH_QUIC_LEVEL_BIT(CH_LEVEL_INITIAL, CH_KEY_WRITE);
    return CH_OK;
}

// The input loop. It copies what fits, asks whether a whole message is
// present, runs one step if it is, and returns when it is not.
//
// It terminates because the copy compacts first, so a copy that leaves
// input bytes over means the buffer is full, and a full buffer holds at
// least cfg.buf_len bytes, which every term of CH_QUIC_MIN_RXBUF puts
// at 490 or more. So hsr_peek_message always reads its 4-byte header
// there and never answers HSR_INCOMPLETE, which makes that answer imply
// every input byte was taken. Each iteration then either returns or
// runs a step, and a step consumes at least four buffer bytes.
static int drive(ch_quic *q, const uint8_t *p, size_t n) {
    size_t off = 0;
    for (;;) {
        off += hsr_feed(&q->hs, p + off, n - off);
        size_t raw_len = 0;
        int rc = hsr_peek_message(&q->hs, &raw_len, &q->hs.alert);
        if (rc == HSR_INCOMPLETE) {
            return CH_OK;
        }
        if (rc != CH_OK) {
            return quic_fail(q, rc);
        }
        uint8_t was = q->rx_level;
        rc = hsq_advance(q);
        if (rc != CH_OK) {
            return quic_fail(q, rc);
        }
        // A step that moved rx_level or staged a message must have
        // consumed the whole delivery. A byte left over is data at a
        // level this client has left, which RFC 9001 §4.1.3 makes a
        // connection error of type PROTOCOL_VIOLATION
        // (rfc9001.txt:488-493). The same check covers the
        // HelloRetryRequest, whose answer cannot arrive before the
        // retry hello goes out.
        if ((q->rx_level != was || q->tx_len != 0) && (q->t.pt_off != q->t.pt_len || off != n)) {
            return quic_fail_level(q);
        }
    }
}

int ch_quic_crypto_in(ch_quic *q, uint8_t level, const uint8_t *p, size_t n) {
    CH_ASSERT(q->t.state <= CH_ST_FAILED);
    q->hs.t = &q->t;
    if (session_dead(q)) {
        return CH_EPROTO;
    }
    if (level > CH_LEVEL_APPLICATION || q->tx_len != 0) {
        return CH_EINVAL;
    }
    if (level > q->rx_level) {
        // Bytes for a level whose keys are not installed are QUIC's to
        // hold (rfc9001.txt:488-490), so an empty buffer is no error
        // and the caller may deliver them again. Bytes sitting unread
        // at the lower level make it one (rfc9001.txt:491-493).
        return q->t.pt_off == q->t.pt_len ? CH_EINVAL : quic_fail_level(q);
    }
    if (level < q->rx_level) {
        return quic_fail_level(q);
    }
    return drive(q, p, n);
}

int ch_quic_crypto_out(ch_quic *q, uint8_t level, uint8_t *out, size_t cap, size_t *out_len) {
    if (session_dead(q) || level > CH_LEVEL_APPLICATION) {
        return CH_EINVAL;
    }
    if (q->tx_len == 0 || level != q->tx_level) {
        *out_len = 0;
        return CH_OK;
    }
    if (cap < q->tx_len) {
        // The caller's buffer, not the peer's, so the session lives and
        // the same call runs again with a larger one.
        return CH_ECAP;
    }
    memcpy(out, q->t.tx, q->tx_len);
    *out_len = q->tx_len;
    q->tx_len = 0;
    if (q->step == HSQ_STEP_COMPLETE && q->t.state == CH_ST_START) {
        // These bytes are the client Finished, the moment RFC 9001
        // §4.1.1 names: this stack has sent its Finished and verified
        // the peer's.
        q->t.state = CH_ST_CONNECTED;
    }
    return CH_OK;
}

int ch_quic_seal(ch_quic *q, uint8_t level, uint64_t pn, size_t pn_len, const uint8_t *hdr,
                 size_t hdr_len, const uint8_t *pt, size_t pt_len, uint8_t *out, size_t cap,
                 size_t *out_len) {
    if (session_dead(q) || level > CH_LEVEL_APPLICATION ||
        (q->levels_ready & CH_QUIC_LEVEL_BIT(level, CH_KEY_WRITE)) == 0) {
        return CH_EINVAL;
    }
    if (level == CH_LEVEL_HANDSHAKE) {
        return quic_packet_seal(&q->handshake_tx, &q->handshake_hp_tx, level, pn, pn_len, hdr,
                                hdr_len, pt, pt_len, out, cap, out_len);
    }
    if (level == CH_LEVEL_APPLICATION) {
        return quic_packet_seal(&q->app_tx, &q->app_hp_tx, level, pn, pn_len, hdr, hdr_len, pt,
                                pt_len, out, cap, out_len);
    }
    // The Initial keys are the only ones here whose AEAD pays RFC 9001
    // §6.6's confidentiality limit (rfc9001.txt:1812-1813). The refusal
    // returns CH_EINVAL, the code quic.h leaves once CH_QUIC_DISCARD
    // and CH_QUIC_AEAD_LIMIT are ch_quic_open's alone.
    if (quic_confidentiality_limit_reached(q->initial_sealed)) {
        return CH_EINVAL;
    }
    int rc = quic_initial_seal(q->initial_dcid, q->initial_dcid_len, pn, pn_len, hdr, hdr_len, pt,
                               pt_len, out, cap, out_len);
    if (rc == CH_OK) {
        q->initial_sealed++;
    }
    return rc;
}

// One packet, at the level q->levels_ready says is usable. It reports
// the §5.4.2 length discard itself rather than reading it back out of
// the module's CH_QUIC_DISCARD, because that packet is never passed to
// the AEAD and §6.6 counts only packets that fail authentication
// (rfc9001.txt:1823-1827).
static int open_at_level(ch_quic *q, uint8_t level, uint8_t *pkt, size_t pkt_len, size_t pn_off,
                         uint64_t largest_pn, uint64_t current_phase_lowest_pn, uint8_t *key_set,
                         uint64_t *pn, size_t *pt_len) {
    if (level == CH_LEVEL_APPLICATION) {
        return quic_packet_open_application(q->app_rx, &q->app_hp_rx, q->key_phase, pkt, pkt_len,
                                            pn_off, largest_pn, current_phase_lowest_pn, key_set,
                                            pn, pt_len);
    }
    *key_set = CH_QUIC_KEY_CURRENT;
    if (level == CH_LEVEL_HANDSHAKE) {
        return quic_packet_open_handshake(&q->handshake_rx, &q->handshake_hp_rx, pkt, pkt_len,
                                          pn_off, largest_pn, pn, pt_len);
    }
    return quic_initial_open(q->initial_dcid, q->initial_dcid_len, pkt, pkt_len, pn_off, largest_pn,
                             pn, pt_len);
}

int ch_quic_open(ch_quic *q, uint8_t level, uint8_t *pkt, size_t pkt_len, size_t pn_off,
                 uint64_t largest_pn, uint64_t current_phase_lowest_pn, uint8_t *key_set,
                 uint64_t *pn, size_t *pt_len) {
    if (session_dead(q) || level > CH_LEVEL_APPLICATION ||
        (q->levels_ready & CH_QUIC_LEVEL_BIT(level, CH_KEY_READ)) == 0) {
        return CH_EINVAL;
    }
    if (level == CH_LEVEL_APPLICATION && q->t.state != CH_ST_CONNECTED) {
        // RFC 9001 §5.7 forbids a client from processing a 1-RTT packet
        // before the handshake completes, even holding the keys
        // (rfc9001.txt:1484-1486). The caller buffers it.
        return CH_EINVAL;
    }
    // Written so neither side can wrap. quic.h requires pn_off at most
    // pkt_len, and a caller that breaks that would make pn_off + 20
    // small again and hand a short packet to the AEAD at an offset past
    // its end.
    if (pn_off > pkt_len || pkt_len - pn_off < QUIC_PN_MAX_LEN + QUIC_HP_SAMPLE_LEN) {
        // Too short to hold a complete sample (§5.4.2,
        // rfc9001.txt:1280-1281). No field of q changes at all.
        return CH_QUIC_DISCARD;
    }
    int rc = open_at_level(q, level, pkt, pkt_len, pn_off, largest_pn, current_phase_lowest_pn,
                           key_set, pn, pt_len);
    if (rc != CH_QUIC_DISCARD) {
        return rc;
    }
    // The tag did not match, which is the authentication failure §6.6
    // counts. §5.5 says it does not necessarily indicate a protocol
    // error or an attack (rfc9001.txt:1373-1376).
    q->open_failures++;
    if (quic_integrity_limit_exceeded(q->open_failures)) {
        q->hs.alert = ALERT_BAD_RECORD_MAC;
        return quic_fail(q, CH_QUIC_AEAD_LIMIT);
    }
    return CH_QUIC_DISCARD;
}

uint8_t ch_quic_retry_ok(const ch_quic *q, const uint8_t *pseudo, size_t n,
                         const uint8_t tag[GCM_TAG]) {
    // The key and the nonce are the ones RFC 9001 §5.8 prints, so no
    // session field enters the computation.
    (void)q;
    return quic_retry_ok(pseudo, n, tag);
}

int ch_quic_key_update(ch_quic *q) {
    if (q->t.state != CH_ST_CONNECTED) {
        return CH_EINVAL;
    }
    quic_keys_update(q->t.wr_secret, &q->app_tx);
    q->key_phase ^= 1;
    // The moves copy key sets and derive nothing; the one derivation
    // below leaves t.rd_secret naming the new next set again, which is
    // the invariant session.h states.
    q->app_rx[CH_QUIC_KEY_PREVIOUS] = q->app_rx[CH_QUIC_KEY_CURRENT];
    q->app_rx[CH_QUIC_KEY_CURRENT] = q->app_rx[CH_QUIC_KEY_NEXT];
    quic_keys_update(q->t.rd_secret, &q->app_rx[CH_QUIC_KEY_NEXT]);
    return CH_OK;
}

uint8_t ch_quic_key_phase(const ch_quic *q) {
    return q->key_phase;
}

void ch_quic_drop_previous_keys(ch_quic *q) {
    ct_wipe(&q->app_rx[CH_QUIC_KEY_PREVIOUS], sizeof q->app_rx[CH_QUIC_KEY_PREVIOUS]);
}

int ch_quic_discard(ch_quic *q, uint8_t level) {
    if (level > CH_LEVEL_APPLICATION) {
        return CH_EINVAL;
    }
    if (level == CH_LEVEL_INITIAL) {
        // The level holds no key, only the connection ID the packet
        // calls derive one from; zeroing it leaves nothing to derive.
        ct_wipe(q->initial_dcid, sizeof q->initial_dcid);
        q->initial_dcid_len = 0;
    } else if (level == CH_LEVEL_HANDSHAKE) {
        ct_wipe(&q->handshake_rx, sizeof q->handshake_rx);
        ct_wipe(&q->handshake_tx, sizeof q->handshake_tx);
        ct_wipe(&q->handshake_hp_rx, sizeof q->handshake_hp_rx);
        ct_wipe(&q->handshake_hp_tx, sizeof q->handshake_hp_tx);
    } else {
        ct_wipe(&q->app_tx, sizeof q->app_tx);
        ct_wipe(q->app_rx, sizeof q->app_rx);
        ct_wipe(&q->app_hp_rx, sizeof q->app_hp_rx);
        ct_wipe(&q->app_hp_tx, sizeof q->app_hp_tx);
    }
    q->levels_ready &= (uint8_t)~CH_QUIC_LEVEL_BIT(level, CH_KEY_READ);
    q->levels_ready &= (uint8_t)~CH_QUIC_LEVEL_BIT(level, CH_KEY_WRITE);
    return CH_OK;
}

uint8_t ch_quic_state(const ch_quic *q) {
    return q->t.state;
}

uint8_t ch_quic_alert(const ch_quic *q) {
    return q->alert;
}

uint64_t ch_quic_error_code(const ch_quic *q) {
    if (q->t.state != CH_ST_FAILED) {
        return 0; // QUIC's NO_ERROR: a live or closed session says nothing
    }
    if (q->error_code != 0) {
        return q->error_code;
    }
    // RFC 9001 §4.8 carries a TLS alert as 0x0100 plus its description.
    return 0x0100 + (uint64_t)q->alert;
}

void ch_quic_close(ch_quic *q) {
    quic_wipe(q);
    q->t.state = CH_ST_CLOSED;
}

#endif // CH_TRANSPORT_QUIC
