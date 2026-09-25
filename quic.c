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
#include "quic_fail.h"
#include "quic_initial.h"
#include "quic_packet.h"
#include "quic_retry.h"
#ifdef CH_TRUST_WEBPKI
#include "webpki_ticket.h"
#endif

// Which endpoint session q is. quic.c holds no other role: every other
// call in it takes key sets and bytes and reads no side, which is why a
// ROLE=server build compiles this file unchanged. The two Initial calls
// are the exception, because RFC 9001 section 5.2 gives each endpoint its
// own Initial secret and a server that named the client's would seal
// under "client in" and open under "server in", inverted both ways.
//
// A one-role build is one side, so the build names it. A ROLE=both object
// holds both drivers and names no side, so each session carries the one
// its init call gave it (ch_quic.endpoint). That build first took the
// server's side for every session, because it defines CH_ROLE_SERVER, and
// a client session sealed and opened under the server's labels.
#ifdef CH_ROLE_BOTH
#define CH_QUIC_SELF(q) ((q)->endpoint)
#elif defined(CH_ROLE_SERVER)
#define CH_QUIC_SELF(q) CH_QUIC_ENDPOINT_SERVER
#else
#define CH_QUIC_SELF(q) CH_QUIC_ENDPOINT_CLIENT
#endif

// The hello is built whole into t.tx, so that array must hold the
// largest one this build can emit. session.h repeats CH_HELLO_MAX's
// QUIC values as literals because handshake_message.h sits above it;
// this is where both constants are visible, so a drift fails the build
// here rather than shipping.
#ifndef __cplusplus
_Static_assert(CH_HELLO_MAX <= CH_TX_STAGE, "the largest ClientHello must fit TX staging");
#endif

static int session_dead(const ch_quic *q) {
    return q->t.state == CH_ST_CLOSED || q->t.state == CH_ST_FAILED;
}

// Everything from here to ch_quic_crypto_out is the client's driver, and
// a ROLE=server build compiles none of it: srv_quic.c holds the server's,
// under its own names. The guard is on the definitions and not only on the
// declarations, because a compiled ch_quic_init would reference the
// ClientHello builder a server object does not carry, and the object would
// build with a dangling import the way tls.c's ch_connect once did.
#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
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
    q->endpoint = CH_QUIC_ENDPOINT_CLIENT;
#ifdef CH_TRUST_WEBPKI
    // The hash every ticket this session receives is bound to, taken now
    // so the binding does not depend on the caller's hostname and anchor
    // bytes after this call, as ch_connect and ch_record_init take it
    // (webpki_ticket.h).
    webpki_ticket_config_hash(cfg, q->t.ticket_config_hash);
#endif
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

#endif // CH_ROLE_SERVER
// Shared: both roles derive Initial keys from the same connection ID, and
// quic_initial.c takes the endpoint from the caller's role rather than
// deciding one (INV-26 names the three public keys it may see).
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

#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
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
#endif // CH_ROLE_SERVER

// One packet, at a level whose write bit q->levels_ready holds. The two
// seal entries share it and differ only in the session state each admits
// and in what ch_quic_seal_close wipes after it.
static int seal_at_level(ch_quic *q, uint8_t level, uint64_t pn, size_t pn_len, const uint8_t *hdr,
                         size_t hdr_len, const uint8_t *pt, size_t pt_len, uint8_t *out, size_t cap,
                         size_t *out_len) {
    if (level > CH_LEVEL_APPLICATION ||
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
    // The Initial keys pay RFC 9001 §6.6's confidentiality limit here,
    // and an AES-GCM suite's keys pay it in quic_packet_seal
    // (rfc9001.txt:1812-1813). The refusal returns CH_EINVAL, the code
    // quic.h leaves once CH_QUIC_DISCARD and CH_QUIC_AEAD_LIMIT are
    // ch_quic_open's alone.
    if (quic_confidentiality_limit_reached(q->initial_sealed)) {
        return CH_EINVAL;
    }
    // Both Initial calls name this endpoint, never the peer:
    // quic_initial.c derives this endpoint's secret for the seal and the
    // other one's for the open (quic_initial.h, rfc9001.txt:1057-1061).
    // CH_QUIC_SELF is this session's role, because these two calls are
    // the one place in this file that does read a side.
    int rc = quic_initial_seal(CH_QUIC_SELF(q), q->initial_dcid, q->initial_dcid_len, pn, pn_len,
                               hdr, hdr_len, pt, pt_len, out, cap, out_len);
    if (rc == CH_OK) {
        q->initial_sealed++;
    }
    return rc;
}

int ch_quic_seal(ch_quic *q, uint8_t level, uint64_t pn, size_t pn_len, const uint8_t *hdr,
                 size_t hdr_len, const uint8_t *pt, size_t pt_len, uint8_t *out, size_t cap,
                 size_t *out_len) {
    if (session_dead(q)) {
        return CH_EINVAL;
    }
    return seal_at_level(q, level, pn, pn_len, hdr, hdr_len, pt, pt_len, out, cap, out_len);
}

// The Initial packet carries a GCM tag and the other two levels a
// ChaCha20-Poly1305 one, and the close bound below counts one length for
// both.
#ifndef __cplusplus
_Static_assert(GCM_TAG == AEAD_TAG, "every level's packet carries a 16-byte tag");
#endif

// A failed session's one packet per level. quic_fail kept the write keys
// of each level whose write bit it left set, and this call wipes them
// right after it seals, so the bit it clears is what refuses a second
// call at that level (docs/decisions.md 57). A refusal and a short
// buffer seal nothing, so both leave the keys for the call that does.
int ch_quic_seal_close(ch_quic *q, uint8_t level, uint64_t pn, size_t pn_len, const uint8_t *hdr,
                       size_t hdr_len, const uint8_t *pt, size_t pt_len, uint8_t *out, size_t cap,
                       size_t *out_len) {
    // Written so no sum of caller lengths can wrap past the bound.
    if (q->t.state != CH_ST_FAILED || hdr_len > CH_QUIC_CLOSE_MAX ||
        pt_len > CH_QUIC_CLOSE_MAX - hdr_len || CH_QUIC_CLOSE_MAX - hdr_len - pt_len < AEAD_TAG) {
        return CH_EINVAL;
    }
    int rc = seal_at_level(q, level, pn, pn_len, hdr, hdr_len, pt, pt_len, out, cap, out_len);
    if (rc == CH_OK) {
        quic_wipe_write_keys(q, level);
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
    return quic_initial_open(CH_QUIC_SELF(q), q->initial_dcid, q->initial_dcid_len, pkt, pkt_len,
                             pn_off, largest_pn, pn, pt_len);
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
