#include "tls.h"

#include "ch_assert.h"

#include <string.h>

#include "ct.h"
#include "handshake.h"
#include "handshake_message.h"
#include "handshake_post.h"
#include "handshake_record.h"
#include "io.h"
#include "rand_draw.h"
#ifdef CH_CPU_RUNTIME
#include "cpu.h"
#endif

// A ROLE=server build compiles nothing from here to the end of
// ch_connect. tls.h declares ch_connect only in the objects that define
// it: a server build compiles no handshake.c, so a compiled ch_connect
// would leave ch_handshake undefined and the object could not go into an
// executable at all, and a TRANSPORT=tcp-nonblocking one guards it below.
// tlsi_epoch_init is inside the guard because only client entries call it,
// ch_connect here and ch_record_init in tcp_nonblocking.c, in either trust
// mode. lib-check's import check holds the rule for every axis.
#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)

// Loads the stored epoch and checks a resuming ticket against it
// (docs/ca.md). Storage that fails or answers out of range stops
// the connection at config time, not mid-handshake, so revocation
// state stays out of any path a peer can influence. Returns CH_OK
// when no epoch is configured.
int tlsi_epoch_init(ch_tls *t, const ch_cfg *cfg, int psk_ok) {
#ifdef CH_TRUST_CA
    // The callbacks come as a pair; one alone is a provisioning
    // mistake, and store is the only way to write the epoch back.
    if ((cfg->epoch_load == NULL) != (cfg->epoch_store == NULL)) {
        return CH_EINVAL;
    }
    if (cfg->epoch_load == NULL) {
        return CH_OK;
    }
    uint32_t stored = 0;
    if (cfg->epoch_load(cfg->epoch_io, &stored) != 0 || stored > CH_EPOCH_MAX) {
        return CH_EINVAL;
    }
    t->epoch = stored;
    // A resumed session presents no certificate, so the ticket's epoch
    // is the only revocation check left: a ticket below the stored
    // epoch was retired by that bump. A ticket epoch over CH_EPOCH_MAX
    // is corrupt ticket storage. Each is refused before a byte is sent,
    // so each returns CH_EINVAL (cfg.h, INV-13), and only the retired
    // ticket sets epoch_status, to CH_EPOCH_REVOKED.
    if (!psk_ok || !cfg->resumption) {
        return CH_OK;
    }
    if (cfg->ticket_epoch > CH_EPOCH_MAX) {
        return CH_EINVAL;
    }
    t->epoch_seen = cfg->ticket_epoch;
    if (cfg->ticket_epoch < stored) {
        t->epoch_status = CH_EPOCH_REVOKED;
        return CH_EINVAL;
    }
    // A ticket above the stored epoch means the store lost a bump that
    // an earlier session wrote. The device would again trust the
    // certificates that bump retired. Reported as CH_EPOCH_AHEAD.
    t->epoch_status = cfg->ticket_epoch > stored ? CH_EPOCH_AHEAD : CH_EPOCH_MATCHED;
    return CH_OK;
#else
    // No CA mode here, so nothing enforces an epoch. Reject such a
    // config: unenforced revocation is worse than a failed connect.
    (void)t;
    (void)psk_ok;
    return (cfg->epoch_load != NULL || cfg->epoch_store != NULL) ? CH_EINVAL : CH_OK;
#endif
}
#ifndef CH_TRUST_WEBPKI
// The pin length the build's one algorithm takes: 64 raw P-256 bytes
// under CH_PIN_ECDSA, an RSA-2048..3072 modulus, a whole number of
// 8-byte words, otherwise. Both pin slots obey it.
static int pin_len_ok(size_t len) {
#ifdef CH_PIN_ECDSA
    return len == 64;
#else
    return len >= 256 && len <= 384 && len % 8 == 0;
#endif
}

// The length a PSK identity takes: at least the one byte RFC 9846
// §4.3.11 gives an identity (rfc9846.txt:2468-2471), and at most
// CH_TICKET_ID_MAX, the most a ticket's identity holds. hello_build
// proves that CH_HELLO_MAX, which ch_tls.tx holds, fits every hello whose
// identity is in this range, and nothing else bounds the identity, so this
// check is what keeps the drivers' branches for a hello that does not fit
// unreachable (docs/decisions.md 84). webpki_cfg_ok holds a ticket's
// identity to the same range.
static int psk_id_len_ok(size_t len) {
    return len >= 1 && len <= CH_TICKET_ID_MAX;
}

// Whether a PSK is the configured auth mode. Both callers below ask, and
// tlsi_epoch_init takes the answer.
static int psk_configured(const ch_cfg *cfg) {
    return cfg->psk != NULL && cfg->psk_len > 0 && cfg->psk_id != NULL &&
           psk_id_len_ok(cfg->psk_id_len) && cfg->server_pubkey == NULL;
}

// Every rule a client configuration must keep whatever drives it. The I/O
// callbacks are not among them: the blocking driver's ch_connect and
// TRANSPORT=tcp-nonblocking's ch_record_init each require both, and each
// checks that itself. Under RAND=session the source of random bytes is
// among them, because both drivers draw the key share before a byte goes
// out (rand.h).
int tlsi_config_ok(const ch_cfg *cfg) {
    // Exactly one auth mode: a config carrying both a PSK and a pin is a
    // provisioning mistake and gets rejected, not silently resolved.
    int psk_ok = psk_configured(cfg);
    int pin_ok =
        cfg->psk == NULL && cfg->server_pubkey != NULL && pin_len_ok(cfg->server_pubkey_len);
    // The optional second pin (key rotation) obeys every slot-A rule and
    // never stands alone: pinned mode still requires server_pubkey.
    if (cfg->server_pubkey2 != NULL && (!pin_ok || !pin_len_ok(cfg->server_pubkey2_len))) {
        return 0;
    }
    if ((!psk_ok && !pin_ok) || cfg->buf == NULL || cfg->buf_len < CH_MIN_RXBUF) {
        return 0;
    }
#ifdef CH_RAND_SESSION
    if (!rand_source_ok(cfg)) {
        return 0;
    }
#endif
#ifdef CH_CPU_RUNTIME
    // The caller's description of its CPU (cpu_cfg.h). A raw or ca client
    // is a host object only in ROLE=both, and that object asks every
    // session for it.
    if (!cpu_bits_ok(cfg)) {
        return 0;
    }
#endif
#ifndef CH_KEX_PQ
    // require_pq asks that the key exchange be post-quantum, and this
    // build offers x25519 alone, so no handshake it runs can satisfy the
    // flag. A request the build cannot enforce is a provisioning mistake,
    // not a no-op.
    if (cfg->require_pq) {
        return 0;
    }
#endif
#ifndef CH_PIN_ECDSA
    // Every real modulus is odd (a product of odd primes); an even pin in
    // either slot is provisioning corruption. Rejected here so the failure
    // points at the config -- inside the handshake it would surface as
    // CH_EAUTH and read like an attack.
    if ((pin_ok && (cfg->server_pubkey[cfg->server_pubkey_len - 1] & 1) == 0) ||
        (cfg->server_pubkey2 != NULL &&
         (cfg->server_pubkey2[cfg->server_pubkey2_len - 1] & 1) == 0)) {
        return 0;
    }
#endif
    // A ticket past its lifetime, or past the 7 days RFC 9846 allows any
    // ticket (handshake_post.h).
    return hspost_ticket_age_ok(cfg);
}

#ifndef CH_TRANSPORT_TCP_NONBLOCKING
int ch_connect(ch_tls *t, const ch_cfg *cfg) {
    memset(t, 0, sizeof *t);
    t->cfg = *cfg;
    int psk_ok = psk_configured(cfg);
    if (!tlsi_config_ok(cfg) || cfg->send == NULL || cfg->recv == NULL) {
        t->state = CH_ST_FAILED;
        return CH_EINVAL;
    }
#ifdef CH_CPU_RUNTIME
    tlsi_record_widemul(t);
#endif
    int rc = tlsi_epoch_init(t, cfg, psk_ok);
    if (rc != CH_OK) {
        t->state = CH_ST_FAILED;
        return rc;
    }
    return ch_handshake(t);
}
#endif // CH_TRANSPORT_TCP_NONBLOCKING
#endif
#endif // CH_ROLE_SERVER
// The peer's close_notify closes the peer's direction and no other (RFC
// 9846 §6, rfc9846.txt:3767-3768). This session reads nothing after it:
// §6.1 says data after a closure alert MUST be ignored
// (rfc9846.txt:3837-3839), and ch_read ignores it by never reading it. So
// the secrets only a read uses die here (INV-17): the read key and its
// secret, and the resumption master secret, which only taking a
// NewSessionTicket uses. The write key and its secret stay, because
// §6.1 leaves this side's writes open (rfc9846.txt:3857-3859): the caller
// may still ch_write, and ch_close sends this side's close_notify under
// that key. Nothing is sent here. TLS 1.2 answered a close_notify at
// once with one of its own, and TLS 1.3 dropped that rule
// (rfc9846.txt:3860-3864).
static void close_read_side(ch_tls *t) {
    ct_wipe(&t->rd, sizeof t->rd);
    ct_wipe(t->rd_secret, sizeof t->rd_secret);
    ct_wipe(t->res_master, sizeof t->res_master);
    t->pt_off = 0;
    t->pt_len = 0;
    t->read_closed = 1;
}

// One protected alert record, pt_len bytes at the front of cfg.buf. The
// two closure alerts act here: close_notify closes the peer's direction
// and returns CH_ECLOSED, and user_canceled is read past, because RFC 9846
// §6.1 has the reader go on until the close_notify after it. Every other
// record goes to hsr_refuse_alert: one that is not a single 2-byte alert
// fails the session with decode_error, and an error alert fails it with
// nothing sent, because the peer has closed the connection (§6.2).
static int read_alert(ch_tls *t, size_t pt_len) {
    const uint8_t *pt = t->cfg.buf;
    if (pt_len == 2 && pt[1] == ALERT_CLOSE_NOTIFY) {
        close_read_side(t);
        return CH_ECLOSED;
    }
    if (pt_len == 2 && pt[1] == ALERT_USER_CANCELED) {
        // ch_read's quiet cap bounds a hostile stream of these like any
        // other record that carries no data.
        return CH_OK;
    }
    uint8_t alert = ALERT_UNEXPECTED_MESSAGE;
    int rc = hsr_refuse_alert(t, pt, pt_len, &alert);
    tlsi_fail(t, alert);
    return rc;
}

// Reads and dispatches one record: application data lands in the buffer,
// post-handshake messages are handled, and close_notify closes the read
// side and returns CH_ECLOSED.
static int dispatch_one_record(ch_tls *t) {
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    if (t->post_fill > 0) { // the next record continues a message (session.h)
        size_t fill = t->post_fill;
        t->post_fill = 0;
        return hspost_read(t, fill);
    }
#endif
    uint8_t outer = 0;
    size_t record_len = 0;
    int rc = io_read_record(&t->cfg, t->cfg.buf, t->cfg.buf_len, &outer, &record_len);
    if (rc == CH_RECORD_AGAIN) {
        return rc; // TRANSPORT=tcp-nonblocking alone returns it (tcp_nonblocking.h)
    }
    if (rc != CH_OK) {
        tlsi_fail(t, ALERT_DECODE_ERROR);
        return rc;
    }
    if (outer != REC_APPDATA) {
        tlsi_fail(t, ALERT_UNEXPECTED_MESSAGE);
        return CH_EPROTO;
    }
    size_t pt_len = 0;
    uint8_t inner_type = 0;
    if (rec_open(&t->rd, t->cfg.buf, record_len, t->cfg.buf, t->cfg.buf_len, &pt_len,
                 &inner_type) != 0) {
        tlsi_fail(t, ALERT_BAD_RECORD_MAC);
        return CH_EAUTH;
    }
    if (inner_type == REC_APPDATA) {
        t->pt_off = 0;
        t->pt_len = pt_len;
        return CH_OK;
    }
    if (inner_type == REC_HANDSHAKE) {
        return hspost_read(t, pt_len);
    }
    if (inner_type == REC_ALERT) {
        return read_alert(t, pt_len);
    }
    tlsi_fail(t, ALERT_UNEXPECTED_MESSAGE);
    return CH_EPROTO;
}

int ch_read(ch_tls *t, uint8_t *p, size_t n) {
    // Contract-point guard: no input can set an undefined state; only
    // programmer error or corrupted memory can. TigerStyle-class
    // defense priced at zero per-byte cost (docs/decisions.md).
    CH_ASSERT(t->state <= CH_ST_FAILED);

    if (n == 0) {
        return CH_EINVAL; // 0 is the close sentinel; a zero-byte read is a caller bug
    }
    if (t->state == CH_ST_CLOSED) {
        return 0;
    }
    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    if (t->read_closed) {
        return 0; // the peer's close_notify arrived; nothing after it is read
    }
    // A peer may legally send records that yield no application data
    // (tickets, key updates, empty records), but not an endless stream of
    // them; the cap turns that into a protocol error instead of a spin.
    for (int quiet = 0; quiet < CH_QUIET_CAP; quiet++) {
        if (t->pt_len > t->pt_off) {
            size_t take = t->pt_len - t->pt_off;
            if (take > n) {
                take = n;
            }
            memcpy(p, t->cfg.buf + t->pt_off, take);
            t->pt_off += take;
            return (int)take;
        }
        int rc = dispatch_one_record(t);
        if (rc == CH_ECLOSED) {
            return 0;
        }
        if (rc != CH_OK) {
            return rc;
        }
    }
    tlsi_fail(t, ALERT_UNEXPECTED_MESSAGE);
    return CH_EPROTO;
}

void ch_close(ch_tls *t) {
    CH_ASSERT(t->state <= CH_ST_FAILED); // the guard ch_read states

    if (t->keys) {
        (void)tlsi_send_alert(t, 1, ALERT_CLOSE_NOTIFY);
    }
    tlsi_wipe(t);
    t->state = CH_ST_CLOSED;
}

#ifdef CH_TRUST_WEBPKI
// A TRUST=webpki build's ch_connect and the config rules it checks. They
// sit below every CH_ASSERT in this file, not beside the raw and ca
// ch_connect above, because CH_ASSERT passes __LINE__: a line added
// above an assertion changes the raw and ca objects, and this mode
// leaves those objects byte for byte as they were (docs/webpki.md).

// webpki_ticket.h is included here rather than at the top of the file
// for the same reason: an include line above the assertions would move
// them.
#include "webpki_ticket.h"

// cfg.h writes CH_TRUST_MIN_RXBUF out as numbers because webpki.h,
// which names the two flight terms, includes cfg.h, and record.h, which
// names the record overhead, sits above it. This is where all of them
// are visible, so a drift between them fails the build here: the
// largest admitted Certificate message plus REC_OVERHEAD, the bytes of
// the record that completes it (cfg.h, CH_MIN_RXBUF).
_Static_assert(CH_TRUST_MIN_RXBUF ==
                   CH_WEBPKI_FLIGHT_ENTRIES * (CH_WEBPKI_CERT_MAX + 5) + 8 + REC_OVERHEAD,
               "cfg.h's webpki receive floor is the flight formula over webpki.h's bounds");

// The mode's own rules (webpki_cfg.c) plus the buffer terms, the ticket
// age rule and the source of random bytes the raw and ca definition above
// checks. ch_record_init calls this and no
// ch_connect, so it too refuses a short receive buffer in this mode
// (https://github.com/c4milo/chapulin/issues/171). It admits require_pq
// in every build: every webpki client offers the hybrid
// (docs/decisions.md 53).
int tlsi_config_ok(const ch_cfg *cfg) {
#ifdef CH_RAND_SESSION
    if (!rand_source_ok(cfg)) {
        return 0;
    }
#endif
#ifdef CH_CPU_RUNTIME
    // The caller's description of its CPU (cpu_cfg.h), before
    // webpki_cfg_ok's suite rule reads it.
    if (!cpu_bits_ok(cfg)) {
        return 0;
    }
#endif
    return webpki_cfg_ok(cfg) && cfg->buf != NULL && cfg->buf_len >= CH_MIN_RXBUF &&
           hspost_ticket_age_ok(cfg);
}

// Guarded as the raw and ca ch_connect above is: this transport filters
// handshake.c out, so a compiled ch_connect leaves ch_handshake
// undefined.
#ifndef CH_TRANSPORT_TCP_NONBLOCKING
int ch_connect(ch_tls *t, const ch_cfg *cfg) {
    memset(t, 0, sizeof *t);
    t->cfg = *cfg;
    if (!tlsi_config_ok(cfg) || cfg->send == NULL || cfg->recv == NULL) {
        t->state = CH_ST_FAILED;
        return CH_EINVAL;
    }
#ifdef CH_CPU_RUNTIME
    tlsi_record_widemul(t);
#endif
    webpki_ticket_config_hash(cfg, t->ticket_config_hash);
    // psk_ok matters only to a CA build, so it is 0; tlsi_epoch_init
    // refuses the epoch callbacks, as it does in every build but a CA mode.
    int rc = tlsi_epoch_init(t, cfg, 0);
    if (rc != CH_OK) {
        t->state = CH_ST_FAILED;
        return rc;
    }
    return ch_handshake(t);
}
#endif // CH_TRANSPORT_TCP_NONBLOCKING
#endif

#ifdef CH_TRUST_CA
// The ca floor's record term, checked against record.h the same way.
// This block sits below every CH_ASSERT in the file, so it adds no
// line above one (docs/webpki.md, "Bounds").
_Static_assert(
    CH_TRUST_MIN_RXBUF == 2 * (CH_X509_MAX + 5) + 8 + REC_OVERHEAD,
    "cfg.h's ca receive floor is the two-entry flight plus the record that completes it");
#endif

#ifdef CH_EXPORTER
// The exporter of RFC 9846 §7.5. This block sits below every CH_ASSERT
// in the file, so it adds no line above one and the objects of every
// build without this axis are unchanged (docs/webpki.md, "Bounds").
//
// keysched.h and hkdf.h are included here for the same reason: an
// include at the top of the file would move every assertion under it.
#include "hkdf.h"
#include "keysched.h"

_Static_assert(CH_EXPORT_LABEL_MAX == HKDF_LABEL_MAX,
               "the public label cap and the one hkdf.c serializes must be the same number");

int ch_export(const ch_tls *t, const char *label, const uint8_t *context, size_t context_len,
              uint8_t *out, size_t out_len) {
    // Every refusal below is a caller's argument rather than a peer's
    // input, and each one returns instead of asserting, because a label
    // is data a caller may compute. hkdf_expand_label's CH_ASSERT on the
    // label length, which ks_exporter reaches, is therefore unreachable
    // from here.
    if (t->state != CH_ST_CONNECTED) {
        // The secret does not exist until the peer's Finished verified,
        // and a closed session has wiped it.
        return CH_EINVAL;
    }
    if (label == NULL || out == NULL || out_len == 0 || out_len > CH_EXPORT_MAX) {
        return CH_EINVAL;
    }
    if (context_len != 0 && context == NULL) {
        return CH_EINVAL;
    }
    size_t label_len = strlen(label);
    if (label_len == 0 || label_len > CH_EXPORT_LABEL_MAX) {
        return CH_EINVAL;
    }
    ks_exporter(tls_hash_len(t), t->exp_master, label, context, context_len, out, out_len);
    return CH_OK;
}
#endif

// alert.h states both contracts. Every TCP object compiles this file, in
// either role, so both calls are defined here, below every CH_ASSERT;
// quic.c defines the QUIC object's.
uint8_t ch_alert_sent(const ch_tls *t) {
    return t->alert_sent;
}

uint8_t ch_alert_received(const ch_tls *t) {
    return t->alert_received;
}
