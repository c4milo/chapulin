#include "tls.h"

#include "ch_assert.h"

#include <string.h>

#include "handshake.h"
#include "handshake_message.h"
#include "handshake_post.h"
#include "io.h"

// A ROLE=server build compiles nothing from here to the end of
// ch_connect. tls.h declares ch_connect only when CH_ROLE_SERVER is unset,
// and the definition has to follow the declaration: a server build
// compiles no handshake.c, so a compiled ch_connect leaves ch_handshake
// undefined and the packaged object cannot go into an executable at all.
// epoch_init is inside the guard because ch_connect is its only caller in
// either trust mode. lib-check's import check holds the rule for every axis.
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
    // is corrupt ticket storage, so it returns CH_EINVAL, not CH_EAUTH.
    if (!psk_ok || !cfg->resumption) {
        return CH_OK;
    }
    if (cfg->ticket_epoch > CH_EPOCH_MAX) {
        return CH_EINVAL;
    }
    t->epoch_seen = cfg->ticket_epoch;
    if (cfg->ticket_epoch < stored) {
        t->epoch_status = CH_EPOCH_REVOKED;
        return CH_EAUTH;
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

// Whether a PSK is the configured auth mode. Both callers below ask, and
// epoch_init takes the answer.
static int psk_configured(const ch_cfg *cfg) {
    return cfg->psk != NULL && cfg->psk_len > 0 && cfg->psk_id != NULL &&
           cfg->server_pubkey == NULL;
}

// Every rule a client configuration must keep whatever drives it. The I/O
// callbacks are not among them: the blocking driver requires both and
// TRANSPORT=record refuses both, so each caller checks that itself.
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
    return 1;
}

#ifndef CH_TRANSPORT_RECORD
int ch_connect(ch_tls *t, const ch_cfg *cfg) {
    memset(t, 0, sizeof *t);
    t->cfg = *cfg;
    int psk_ok = psk_configured(cfg);
    if (!tlsi_config_ok(cfg) || cfg->send == NULL || cfg->recv == NULL) {
        t->state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    int rc = tlsi_epoch_init(t, cfg, psk_ok);
    if (rc != CH_OK) {
        t->state = CH_ST_FAILED;
        return rc;
    }
    return ch_handshake(t);
}
#endif // CH_TRANSPORT_RECORD
#endif
#endif // CH_ROLE_SERVER
// Hands the handshake plaintext at the front of cfg.buf to hspost_read.
// Any result but CH_OK and CH_RECORD_AGAIN ends the session.
static int post_handshake(ch_tls *t, size_t pt_len) {
    int rc = hspost_read(t, pt_len);
    if (rc != CH_OK && rc != CH_RECORD_AGAIN) {
        tlsi_fail(t, rc == CH_EAUTH ? ALERT_BAD_RECORD_MAC : ALERT_UNEXPECTED_MESSAGE);
    }
    return rc;
}

// Reads and dispatches one record: application data lands in the buffer,
// post-handshake messages are handled, close_notify returns CH_ECLOSED.
static int dispatch_one_record(ch_tls *t) {
#ifdef CH_TRANSPORT_RECORD
    if (t->post_fill > 0) { // the next record continues a message (session.h)
        size_t fill = t->post_fill;
        t->post_fill = 0;
        return post_handshake(t, fill);
    }
#endif
    uint8_t outer = 0;
    size_t record_len = 0;
    int rc = io_read_record(&t->cfg, t->cfg.buf, t->cfg.buf_len, &outer, &record_len);
    if (rc == CH_RECORD_AGAIN) {
        return rc; // TRANSPORT=record alone returns it (rec.h)
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
        return post_handshake(t, pt_len);
    }
    if (inner_type == REC_ALERT && pt_len == 2 && t->cfg.buf[1] == ALERT_CLOSE_NOTIFY) {
        t->state = CH_ST_CLOSED;
        ch_close(t);
        return CH_ECLOSED;
    }
    if (inner_type == REC_ALERT && pt_len == 2 && t->cfg.buf[1] == ALERT_USER_CANCELED) {
        // RFC 9846 §6.1: user_canceled precedes a close_notify; keep
        // reading for it. ch_read's quiet cap bounds a hostile stream of
        // these like any other dataless record.
        return CH_OK;
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

int ch_write(ch_tls *t, const uint8_t *p, size_t n) {
    CH_ASSERT(t->state <= CH_ST_FAILED); // the guard ch_read states

    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    size_t limit = t->peer_limit < CH_TX_PT ? t->peer_limit : CH_TX_PT;
    while (n > 0) {
        size_t take = n < limit ? n : limit;
        size_t out_len = 0;
        if (rec_seal(&t->wr, REC_APPDATA, p, take, t->tx, sizeof t->tx, &out_len) != 0) {
            tlsi_fail(t, ALERT_INTERNAL_ERROR);
            return CH_ECAP;
        }
        int rc = io_send_all(&t->cfg, t->tx, out_len);
        if (rc != CH_OK) {
            tlsi_fail(t, ALERT_INTERNAL_ERROR);
            return rc;
        }
        p += take;
        n -= take;
    }
    return CH_OK;
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

// ct.h is included here rather than at the top of the file for the same
// reason: an include line above the assertions would move them.
#include "ct.h"

// cfg.h writes CH_TRUST_MIN_RXBUF out as numbers because webpki.h,
// which names the two flight terms, includes cfg.h, and record.h, which
// names the record overhead, sits above it. This is where all of them
// are visible, so a drift between them fails the build here: the
// largest admitted Certificate message plus REC_OVERHEAD, the bytes of
// the record that completes it (cfg.h, CH_MIN_RXBUF).
_Static_assert(CH_TRUST_MIN_RXBUF ==
                   CH_WEBPKI_FLIGHT_ENTRIES * (CH_WEBPKI_CERT_MAX + 5) + 8 + REC_OVERHEAD,
               "cfg.h's webpki receive floor is the flight formula over webpki.h's bounds");

// The anchor rule: 1 to CH_WEBPKI_ANCHOR_MAX anchors, each carrying a
// non-empty name and a non-empty spki. The chain walk reads through
// both pointers of every anchor it consults, so a NULL or empty entry
// is refused here, before the handshake sends a byte.
static int anchors_ok(const ch_cfg *cfg) {
    if (cfg->anchors == NULL || cfg->anchor_count == 0 ||
        cfg->anchor_count > CH_WEBPKI_ANCHOR_MAX) {
        return 0;
    }
    for (size_t i = 0; i < cfg->anchor_count; i++) {
        const ch_trust_anchor *a = &cfg->anchors[i];
        if (a->name == NULL || a->name_len == 0 || a->spki == NULL || a->spki_len == 0) {
            return 0;
        }
    }
    return 1;
}

// The hostname rule: the shape webpki_hostname_ok checks. That check
// reads hostname_len bytes through the pointer, so a NULL hostname is
// refused before it runs.
static int hostname_ok(const ch_cfg *cfg) {
    return cfg->hostname != NULL && webpki_hostname_ok(cfg->hostname, cfg->hostname_len);
}

// The clock rule: now_seconds 0 is the value a caller who never set the
// field leaves there, so it is refused as an unset clock. It names
// 1970-01-01T00:00:00Z, a moment no certificate the walk admits is
// valid at, so the refusal turns a certain CH_EAUTH mid-handshake into
// a CH_EINVAL that names the config.
static int clock_set(const ch_cfg *cfg) {
    return cfg->now_seconds != 0;
}

// The PSK rule: no psk, no psk_id, both lengths 0, and no resumption. A
// resumed handshake presents no certificate, so it would skip the
// hostname check, and nothing binds a ticket to the hostname it was
// issued for (docs/webpki.md, "No PSK, and no resumption"). A length
// set without its pointer is refused too: it is a PSK config with a
// field missing, not a chain config.
static int psk_unset(const ch_cfg *cfg) {
    return cfg->psk == NULL && cfg->psk_len == 0 && cfg->psk_id == NULL && cfg->psk_id_len == 0 &&
           cfg->resumption == 0;
}

// The pin rule: this mode reads neither server_pubkey slot, so a config
// that sets one, or only its length, is a provisioning mistake, not a
// second trust path.
static int pins_unset(const ch_cfg *cfg) {
    return cfg->server_pubkey == NULL && cfg->server_pubkey_len == 0 &&
           cfg->server_pubkey2 == NULL && cfg->server_pubkey2_len == 0;
}

// One offered ALPN protocol name: a non-NULL pointer and 1 to
// CH_ALPN_NAME_MAX bytes. RFC 7301 §3.1 makes a ProtocolName 1 to 255
// bytes; this mode's cap is shorter, and cfg.h says what it costs the
// ClientHello.
static int alpn_name_ok(const ch_alpn_protocol *protocol) {
    return protocol->name != NULL && protocol->name_len > 0 &&
           protocol->name_len <= CH_ALPN_NAME_MAX;
}

// Whether entry i repeats a name an earlier entry already offered. A
// repeat offers the server the same protocol twice, and its selection
// would name two indices, so ch_tls.alpn_selected could not report
// which one the caller meant.
static int alpn_name_repeats(const ch_cfg *cfg, size_t i) {
    for (size_t j = 0; j < i; j++) {
        if (cfg->alpn_protocols[i].name_len == cfg->alpn_protocols[j].name_len &&
            ct_memeq(cfg->alpn_protocols[i].name, cfg->alpn_protocols[j].name,
                     cfg->alpn_protocols[i].name_len)) {
            return 1;
        }
    }
    return 0;
}

// The ALPN rule: offering nothing is legal and sends no extension, so a
// NULL list with a count of 0 passes. An offer is 1 to CH_ALPN_MAX
// entries, each a name alpn_name_ok accepts and none repeating another.
// A count without a list, or a list without a count, is a config with a
// field missing, and is refused like a PSK length without its pointer.
static int alpn_ok(const ch_cfg *cfg) {
    if (cfg->alpn_protocols == NULL) {
        return cfg->alpn_count == 0;
    }
    if (cfg->alpn_count == 0 || cfg->alpn_count > CH_ALPN_MAX) {
        return 0;
    }
    for (size_t i = 0; i < cfg->alpn_count; i++) {
        if (!alpn_name_ok(&cfg->alpn_protocols[i]) || alpn_name_repeats(cfg, i)) {
            return 0;
        }
    }
    return 1;
}

// The one auth mode this build has, the chain: every rule above holds.
static int chain_config_ok(const ch_cfg *cfg) {
    return anchors_ok(cfg) && hostname_ok(cfg) && clock_set(cfg) && psk_unset(cfg) &&
           pins_unset(cfg) && alpn_ok(cfg);
}

// The chain rules plus the terms the raw and ca definition above checks.
// ch_record_init calls this and no ch_connect, so it too refuses a short
// receive buffer and require_pq in this mode
// (https://github.com/c4milo/chapulin/issues/171).
int tlsi_config_ok(const ch_cfg *cfg) {
    if (!chain_config_ok(cfg) || cfg->buf == NULL || cfg->buf_len < CH_MIN_RXBUF) {
        return 0;
    }
#ifndef CH_KEX_PQ
    // require_pq in a classic build: the raw and ca tlsi_config_ok above
    // says why no handshake this build runs can satisfy it.
    if (cfg->require_pq) {
        return 0;
    }
#endif
    return 1;
}

// Guarded as the raw and ca ch_connect above is: this transport filters
// handshake.c out, so a compiled ch_connect leaves ch_handshake
// undefined.
#ifndef CH_TRANSPORT_RECORD
int ch_connect(ch_tls *t, const ch_cfg *cfg) {
    memset(t, 0, sizeof *t);
    t->cfg = *cfg;
    if (!tlsi_config_ok(cfg) || cfg->send == NULL || cfg->recv == NULL) {
        t->state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    // No PSK is set, so psk_ok is 0; epoch_init refuses the epoch
    // callbacks, as it does in every build but a CA mode.
    int rc = tlsi_epoch_init(t, cfg, 0);
    if (rc != CH_OK) {
        t->state = CH_ST_FAILED;
        return rc;
    }
    return ch_handshake(t);
}
#endif // CH_TRANSPORT_RECORD
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
    ks_exporter(t->exp_master, label, context, context_len, out, out_len);
    return CH_OK;
}
#endif
