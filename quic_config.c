// The configuration rules ch_quic_init applies. Contract in
// quic_config.h.
#include "quic_config.h"

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#ifdef CH_TRUST_WEBPKI
#include "webpki.h"
#else
#include "ct.h"
#endif
#ifdef CH_PIN_ECDSA
#include "p256.h"
#else
#include "rsa.h"
#endif

#ifdef CH_TRUST_WEBPKI
// The ALPN rule under TRUST=webpki. webpki_cfg_ok, which trust_config_ok
// below calls, holds an offer to 0 to CH_ALPN_MAX names of 1 to
// CH_ALPN_NAME_MAX bytes, none repeating another, as it does over TCP.
// RFC 9001 §8.1 makes ALPN mandatory for QUIC (rfc9001.txt:1891-1895), so
// the one rule this transport adds is that the offer names a protocol.
static int alpn_ok(const ch_cfg *cfg) {
    return cfg->alpn_protocols != NULL && cfg->alpn_count > 0;
}
#else
// One offered ALPN protocol name: a non-NULL pointer and 1 to
// CH_ALPN_NAME_MAX bytes. RFC 7301 §3.1 makes a ProtocolName 1 to 255
// bytes; this mode's cap is shorter, and cfg.h says what it costs the
// ClientHello. The three rules here are tls.c's, which a QUIC object
// does not compile.
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

// The ALPN rule. It differs from tls.c's in one way: an offer of
// nothing is refused, because RFC 9001 §8.1 makes ALPN mandatory for
// QUIC (rfc9001.txt:1891-1895). Otherwise an offer is 1 to CH_ALPN_MAX
// entries, each a name alpn_name_ok accepts and none repeating another.
static int alpn_ok(const ch_cfg *cfg) {
    if (cfg->alpn_protocols == NULL || cfg->alpn_count == 0 || cfg->alpn_count > CH_ALPN_MAX) {
        return 0;
    }
    for (size_t i = 0; i < cfg->alpn_count; i++) {
        if (!alpn_name_ok(&cfg->alpn_protocols[i]) || alpn_name_repeats(cfg, i)) {
            return 0;
        }
    }
    return 1;
}
#endif

// The two rules this transport adds to its trust mode's: RFC 9001 §8.2
// makes an endpoint that sends no transport parameters a protocol
// violation (rfc9001.txt:1929-1936), and a caller that never learns a
// level is usable can protect no packet.
static int transport_config_ok(const ch_cfg *cfg) {
    return cfg->transport_params != NULL && cfg->transport_params_len > 0 &&
           cfg->transport_params_len <= CH_TRANSPORT_PARAMS_MAX && cfg->on_level_ready != NULL;
}

#ifdef CH_TRUST_WEBPKI
// The web PKI rules are webpki_cfg_ok's, the ones ch_connect applies
// over TCP (webpki_cfg.h), so a configuration means the same thing on
// both transports: anchors with a hostname and a clock, SPKI pins beside
// the anchors or alone, 0 to CH_SPKI_PIN_MAX pins, no pin slot, and PSK
// fields that are unset or present a ticket bound to this hostname,
// these anchors and these pins (webpki_ticket.h). Its ALPN rule admits
// an empty offer, which alpn_ok above refuses.
static int trust_config_ok(const ch_cfg *cfg) {
    return webpki_cfg_ok(cfg);
}
#else
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

// Exactly one auth mode, tls.c's rule: a config carrying both a PSK and
// a pin is a provisioning mistake and gets refused, not resolved. The
// optional second pin obeys every slot-A rule and never stands alone.
static int trust_config_ok(const ch_cfg *cfg) {
    int psk_ok =
        cfg->psk != NULL && cfg->psk_len > 0 && cfg->psk_id != NULL && cfg->server_pubkey == NULL;
    int pin_ok =
        cfg->psk == NULL && cfg->server_pubkey != NULL && pin_len_ok(cfg->server_pubkey_len);
    if (cfg->server_pubkey2 != NULL && (!pin_ok || !pin_len_ok(cfg->server_pubkey2_len))) {
        return 0;
    }
#ifndef CH_PIN_ECDSA
    // Every real modulus is odd, a product of odd primes, so an even pin
    // in either slot is provisioning corruption. tls.c refuses it here
    // for the same reason: inside the handshake it would surface as
    // CH_EAUTH and read like an attack.
    if ((pin_ok && (cfg->server_pubkey[cfg->server_pubkey_len - 1] & 1) == 0) ||
        (cfg->server_pubkey2 != NULL &&
         (cfg->server_pubkey2[cfg->server_pubkey2_len - 1] & 1) == 0)) {
        return 0;
    }
#endif
    return psk_ok || pin_ok;
}
#endif

// Loads the stored revocation epoch and checks a resuming ticket
// against it, the rule tls.c's epoch_init states (docs/ca.md, INV-21).
// Outside a CA-mode build nothing enforces an epoch, so a config that
// sets the callbacks is refused rather than silently ignored.
static int epoch_init(ch_tls *t, const ch_cfg *cfg) {
#ifdef CH_TRUST_CA
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
    if (cfg->psk == NULL || !cfg->resumption) {
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
    t->epoch_status = cfg->ticket_epoch > stored ? CH_EPOCH_AHEAD : CH_EPOCH_MATCHED;
    return CH_OK;
#else
    (void)t;
    return (cfg->epoch_load != NULL || cfg->epoch_store != NULL) ? CH_EINVAL : CH_OK;
#endif
}

int quic_config_ok(ch_tls *t, const ch_cfg *cfg) {
    if (!trust_config_ok(cfg) || !transport_config_ok(cfg) || !alpn_ok(cfg) || cfg->buf == NULL ||
        cfg->buf_len < CH_MIN_RXBUF) {
        return CH_EINVAL;
    }
#ifndef CH_KEX_HYBRID
    // require_pq asks that the key exchange be post-quantum, and this
    // build offers x25519 alone, so no handshake it runs can satisfy
    // the flag. tls.c refuses it before it sends a byte for the same
    // reason: a request the build cannot enforce is a provisioning
    // mistake, not a no-op. A TRUST=webpki build offers the hybrid in
    // every build (docs/decisions.md 53), so it admits the flag, which
    // drops x25519 from its hello as it does over TCP.
    if (cfg->require_pq) {
        return CH_EINVAL;
    }
#endif
    return epoch_init(t, cfg);
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
