// The two calls a ROLE=server object exports beyond ch_read, ch_write and
// ch_close. srv.h states both contracts; this file checks the caller's
// configuration and hands the session to srv_handshake.
//
// It is the mirror of tls.c's ch_connect, and it refuses the same way:
// every rule is a named predicate over ch_cfg, every refusal is
// CH_EINVAL before a byte goes out, and the session is left dead rather
// than half-live.
#include "srv.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "ct.h"
#include "handshake_message.h"
#include "srv_auth.h"
#include "srv_handshake.h"

// One offered ALPN protocol name: a non-NULL pointer and 1 to
// CH_ALPN_NAME_MAX bytes, which is the shape cfg.h states for the field.
//
// The three ALPN rules below repeat tls.c's, which a TRUST=webpki client
// compiles. A server object compiles neither that arm nor any other copy,
// so the rules are written once per object. Moving them to a file both
// roles compile is owed and is not this file's to make.
static int alpn_name_ok(const ch_alpn_protocol *protocol) {
    return protocol->name != NULL && protocol->name_len > 0 &&
           protocol->name_len <= CH_ALPN_NAME_MAX;
}

// Whether entry i repeats a name an earlier entry already offers. A
// repeat would let two indices name one protocol, so ch_tls.alpn_selected
// could not report which one the caller meant.
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

// The ALPN rule: offering nothing is legal and selects nothing, so a NULL
// list with a count of 0 passes. An offer is 1 to CH_ALPN_MAX entries,
// each a name alpn_name_ok accepts and none repeating another. A count
// without a list, or a list without a count, is a configuration with a
// field missing.
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

// The client-only fields, which all answer "do I trust this peer". A
// server that requests no client certificate never asks, so a
// configuration that sets one of them is a provisioning mistake and not a
// second trust path (srv_cfg.h). Each length is refused without its
// pointer too: that is a PSK or a pin with a field missing, and the same
// rule a TRUST=webpki client applies to the pin fields.
static int client_fields_unset(const ch_cfg *cfg) {
    return cfg->psk == NULL && cfg->psk_len == 0 && cfg->psk_id == NULL && cfg->psk_id_len == 0 &&
           cfg->resumption == 0 && cfg->server_pubkey == NULL && cfg->server_pubkey_len == 0 &&
           cfg->server_pubkey2 == NULL && cfg->server_pubkey2_len == 0 && cfg->require_pq == 0 &&
           cfg->epoch_load == NULL && cfg->epoch_store == NULL;
}

// The SNI rule: a name the server cannot report is a name it must not
// require, so require_server_name needs sni_buf. A capacity without a
// buffer is the same field missing, and leaving both at zero drops every
// name the clients send (srv_cfg.h).
static int sni_ok(const ch_srv_cfg *srv) {
    return srv->sni_buf != NULL || (srv->sni_cap == 0 && srv->require_server_name == 0);
}

#ifdef CH_SUITE_AES_GCM
// The suite order rule (srv_cfg.h): no list takes the default order, and
// a list is 1 to 3 code points, each one this build holds. A count
// without a list, or a list without a count, is a field missing.
static int suites_ok(const ch_srv_cfg *srv) {
    if (srv->cipher_suites == NULL) {
        return srv->cipher_suite_count == 0;
    }
    if (srv->cipher_suite_count == 0 || srv->cipher_suite_count > 3) {
        return 0;
    }
    for (size_t i = 0; i < srv->cipher_suite_count; i++) {
        if (suite_hash_len(srv->cipher_suites[i]) == 0) {
            return 0;
        }
    }
    return 1;
}
#endif

// The server's own fields: at least one provisioned identity to prove
// this endpoint with, and the key the HelloRetryRequest cookie is minted
// under. RFC 9846 §9.2 makes the cookie extension mandatory to implement
// and a stateless retry cannot be minted without that key, so a NULL
// cookie_key refuses the configuration rather than the first client that
// sends an empty client_shares list.
static int srv_fields_ok(const ch_cfg *cfg) {
#ifdef CH_SUITE_AES_GCM
    if (!suites_ok(&cfg->srv)) {
        return 0;
    }
#endif
    return srv_identity_live(cfg) != 0 && cfg->srv.cookie_key != NULL && sni_ok(&cfg->srv);
}

// The transport the caller supplies, and the buffer every message this
// server reads has to fit. CH_MIN_RXBUF is the floor this tree already
// declares; srv.h says the role's own floor waits on a bench/sram.sh
// measurement, and this file states no number of its own before then.
static int transport_ok(const ch_cfg *cfg) {
#ifdef CH_TRANSPORT_QUIC
    // A QUIC server drives no socket: the caller owns UDP and hands this
    // stack CRYPTO bytes, so send and recv are unset here rather than
    // required, and the sink those bytes leave through takes their place
    // (srv_cfg.h, on_crypto_out).
    return cfg->buf != NULL && cfg->buf_len >= CH_MIN_RXBUF && cfg->send == NULL &&
           cfg->recv == NULL && cfg->srv.on_crypto_out != NULL && cfg->on_level_ready != NULL;
#elif defined(CH_TRANSPORT_RECORD)
    // A record-mode server drives no socket while the handshake runs:
    // the caller owns it, and the flight leaves through on_record_out
    // (srv_cfg.h). send and recv stay required all the same, because
    // ch_read and ch_write call them once the session is connected, and
    // by then the caller holds the bytes and they never block (rec.h).
    return cfg->buf != NULL && cfg->send != NULL && cfg->recv != NULL &&
           cfg->buf_len >= CH_MIN_RXBUF && cfg->srv.on_record_out != NULL;
#else
    return cfg->buf != NULL && cfg->send != NULL && cfg->recv != NULL &&
           cfg->buf_len >= CH_MIN_RXBUF;
#endif
}

// A blocking build has one caller, ch_srv_accept below, so the linkage
// is internal there and clang-tidy's misc-use-internal-linkage is right
// to ask for it. The two non-blocking builds have their caller in
// another file -- srv_quic.c and srv_rec.c -- which is why srv_flight.h
// declares it at all.
#if defined(CH_TRANSPORT_QUIC) || defined(CH_TRANSPORT_RECORD)
int srv_config_ok(const ch_cfg *cfg) {
#else
static int srv_config_ok(const ch_cfg *cfg) {
#endif
    return srv_fields_ok(cfg) && client_fields_unset(cfg) && alpn_ok(cfg) && transport_ok(cfg);
}

// Only the blocking transport has an accept call: the other two return
// to their caller between messages, and srv_handshake.c is not in either
// object for this to call.
#if !defined(CH_TRANSPORT_QUIC) && !defined(CH_TRANSPORT_RECORD)
int ch_srv_accept(ch_tls *t, const ch_cfg *cfg) {
    memset(t, 0, sizeof *t);
    t->cfg = *cfg;
    if (!srv_config_ok(cfg)) {
        t->state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    return srv_handshake(t);
}
#endif

int ch_srv_check(const ch_cfg *cfg) {
    uint8_t live = srv_identity_live(cfg);
    if (live == 0) {
        return CH_EINVAL;
    }
    if ((live & SRV_IDENTITY_ECDSA_P256) != 0 &&
        srv_identity_check(cfg, SIGALG_ECDSA_P256_SHA256) != CH_OK) {
        return CH_EINVAL;
    }
    if ((live & SRV_IDENTITY_RSA_PSS) != 0 &&
        srv_identity_check(cfg, SIGALG_RSA_PSS_RSAE_SHA256) != CH_OK) {
        return CH_EINVAL;
    }
    return CH_OK;
}

#endif // CH_ROLE_SERVER
