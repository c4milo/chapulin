// The configuration rules of a TRUST=webpki build, which ch_connect and
// ch_record_init check through tlsi_config_ok, and ch_quic_init through
// quic_config_ok, before the handshake sends a byte. webpki_cfg.h states
// the fields; webpki.h declares webpki_cfg_ok. Every rule here reads the
// caller's configuration alone, never peer input.
#include "webpki.h"

// Only a TRUST=webpki build compiles this file (the Makefile's
// WEBPKI_SRCS), and the guard says so to a reader and to
// lint-quic-partition, which preprocesses every root file without the
// define: the ALPN caps below exist in that case only under
// CH_TRANSPORT_QUIC_NONBLOCKING.
#ifdef CH_TRUST_WEBPKI

#include "ct.h"
#include "webpki_ticket.h"

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

// The pin slot rule: this mode reads neither server_pubkey slot, so a
// config that sets one, or only its length, is a provisioning mistake,
// not a second trust path.
static int pin_slots_unset(const ch_cfg *cfg) {
    return cfg->server_pubkey == NULL && cfg->server_pubkey_len == 0 &&
           cfg->server_pubkey2 == NULL && cfg->server_pubkey2_len == 0;
}

// The SPKI pin rule: 0 to CH_SPKI_PIN_MAX pins. A count without a list,
// or a list without a count, is a config with a field missing.
static int spki_pins_ok(const ch_cfg *cfg) {
    if (cfg->spki_pins == NULL) {
        return cfg->spki_pin_count == 0;
    }
    return cfg->spki_pin_count > 0 && cfg->spki_pin_count <= CH_SPKI_PIN_MAX;
}

// Whether the config trusts SPKI pins alone: pins, and neither an
// anchor list nor a count. The client then offers raw public keys
// alone, and no certificate chain is verified.
static int pins_alone(const ch_cfg *cfg) {
    return cfg->spki_pin_count > 0 && cfg->anchors == NULL && cfg->anchor_count == 0;
}

// The trust rule. Anchors take a hostname for the leaf to name and a
// clock for the dates to meet. Pins alone take neither: nothing checks
// a name or a date on a raw public key, so the clock is not read, and a
// hostname, which is then only the server_name to send, may be unset.
// One that is set must still have the shape webpki_hostname_ok checks.
static int trust_ok(const ch_cfg *cfg) {
    if (pins_alone(cfg)) {
        return (cfg->hostname == NULL && cfg->hostname_len == 0) || hostname_ok(cfg);
    }
    return anchors_ok(cfg) && hostname_ok(cfg) && clock_set(cfg);
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

// Every rule above holds, and the PSK fields are unset or present a
// ticket bound to this configuration, which webpki_resumption_ok checks
// after the rules it needs (webpki_ticket.h).
int webpki_cfg_ok(const ch_cfg *cfg) {
    return spki_pins_ok(cfg) && trust_ok(cfg) && webpki_resumption_ok(cfg) &&
           pin_slots_unset(cfg) && alpn_ok(cfg);
}

#endif // CH_TRUST_WEBPKI
