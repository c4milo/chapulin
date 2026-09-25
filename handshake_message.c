#include "handshake_message.h"

#include "buf.h"

// A raw or ca client is a device image that pins the endpoint it talks
// to, and it offers ChaCha20 alone (docs/decisions.md entry 45), so it has
// no use for the AES suite; the Makefile refuses SUITE=aesgcm for it the
// same way. A build that carries the server role may take the define,
// because its server selects the suite whatever its client offers.
#if defined(CH_SUITE_AES_GCM) && !defined(CH_TRUST_WEBPKI) && !defined(CH_ROLE_SERVER)
#error "CH_SUITE_AES_GCM is refused for a raw or ca client: use TRUST=webpki or a server role"
#endif
#ifdef CH_TRUST_WEBPKI
#include "webpki_pin.h"
#endif

#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
// application_layer_protocol_negotiation (RFC 7301 §3.1): a
// ProtocolNameList of one or more ProtocolName, each an opaque vector
// with a one-byte length, in the order the caller listed them. A caller
// that offers nothing gets no extension, which is how RFC 7301 says a
// client asks for no protocol negotiation. ch_connect has already held
// alpn_count to CH_ALPN_MAX and every name to CH_ALPN_NAME_MAX bytes,
// so both length casts are in range.
static void write_alpn(wbuf *w, const ch_cfg *cfg) {
    if (cfg->alpn_count == 0) {
        return;
    }
    wb_u16(w, EXT_ALPN);
    size_t ext = wb_mark(w, 2);
    size_t list = wb_mark(w, 2);
    for (size_t i = 0; i < cfg->alpn_count; i++) {
        wb_u8(w, (uint8_t)cfg->alpn_protocols[i].name_len);
        wb_bytes(w, cfg->alpn_protocols[i].name, cfg->alpn_protocols[i].name_len);
    }
    wb_patch16(w, list);
    wb_patch16(w, ext);
}
#endif

#ifdef CH_TRUST_WEBPKI
// server_name (RFC 6066 §3): a ServerNameList holding one host_name
// entry. The chain walk matches the leaf's subjectAltName against the
// same cfg->hostname bytes. A configuration of SPKI pins alone may set
// no hostname, and then the hello names none (webpki_cfg.h).
static void write_server_name(wbuf *w, const ch_cfg *cfg) {
    if (cfg->hostname_len == 0) {
        return;
    }
    wb_u16(w, EXT_SERVER_NAME);
    wb_u16(w, (uint16_t)(2 + 1 + 2 + cfg->hostname_len));
    wb_u16(w, (uint16_t)(1 + 2 + cfg->hostname_len)); // server_name_list length
    wb_u8(w, 0);                                      // name_type: host_name
    wb_u16(w, (uint16_t)cfg->hostname_len);
    wb_bytes(w, cfg->hostname, cfg->hostname_len);
}

// signature_algorithms for a public chain: its links may be signed by any
// family, so offer every scheme the walk verifies (RFC 9846 §4.3.3). The
// first three may sign CertificateVerify; the two PKCS#1 v1.5 schemes are
// for certificate signatures only (§4.3.3).
static void write_webpki_signature_algorithms(wbuf *w) {
    wb_u16(w, EXT_SIGNATURE_ALGORITHMS);
    wb_u16(w, 2 + 5 * 2);
    wb_u16(w, 5 * 2);
    wb_u16(w, SIGALG_RSA_PSS_RSAE_SHA256);
    wb_u16(w, SIGALG_ECDSA_P256_SHA256);
    wb_u16(w, SIGALG_ECDSA_P384_SHA384);
    wb_u16(w, SIGALG_RSA_PKCS1_SHA256);
    wb_u16(w, SIGALG_RSA_PKCS1_SHA384);
}

// server_certificate_type (RFC 7250 §4.1): the certificate types this
// configuration can judge, the raw public key first because a
// configuration that offers it prefers it (webpki_pin.h). A
// configuration without SPKI pins sends no extension, and its server
// sends the X.509 type RFC 9846 §4.5.1 defaults to.
static void write_cert_types(wbuf *w, const ch_cfg *cfg) {
    uint8_t offered = webpki_cert_types_offered(cfg);
    if (offered == 0) {
        return;
    }
    uint8_t raw = (offered >> CH_CERT_TYPE_RAW_PUBLIC_KEY) & 1U;
    uint8_t x509 = (offered >> CH_CERT_TYPE_X509) & 1U;
    wb_u16(w, EXT_SERVER_CERTIFICATE_TYPE);
    wb_u16(w, (uint16_t)(1 + raw + x509));
    wb_u8(w, (uint8_t)(raw + x509)); // server_certificate_types length
    if (raw) {
        wb_u8(w, CH_CERT_TYPE_RAW_PUBLIC_KEY);
    }
    if (x509) {
        wb_u8(w, CH_CERT_TYPE_X509);
    }
}
#endif

// pre_shared_key (RFC 9846 §4.3.11): the one identity cfg presents and a
// zeroed binder as long as the PSK's hash, which hsf_build_client_hello
// computes once the rest of the hello is written. It is the last extension, which §4.3.11
// requires (rfc9846.txt:2564-2565), because the binder covers every byte
// before the binders list; the caller writes nothing after it.
static void write_pre_shared_key(wbuf *w, const ch_cfg *cfg) {
    wb_u16(w, EXT_PRE_SHARED_KEY);
    size_t psk = wb_mark(w, 2);
    size_t ids = wb_mark(w, 2);
    wb_u16(w, (uint16_t)cfg->psk_id_len);
    wb_bytes(w, cfg->psk_id, cfg->psk_id_len);
    uint32_t age = cfg->resumption ? cfg->obfuscated_age : 0;
    wb_u16(w, (uint16_t)(age >> 16));
    wb_u16(w, (uint16_t)age);
    wb_patch16(w, ids);
    size_t hash_len = hs_psk_hash_len(cfg);
    wb_u16(w, (uint16_t)(1 + hash_len)); // binders list: one binder
    wb_u8(w, (uint8_t)hash_len);
    size_t binder = wb_mark(w, hash_len);
    (void)binder;
    wb_patch16(w, psk);
}

#ifdef CH_KEX_TWO_GROUPS
// supported_groups and key_share for the build that offers two groups
// (docs/decisions.md entry 53). supported_groups lists the hybrid first,
// then x25519, and key_share carries an entry for each in the same order,
// which RFC 9846 §4.3.8 requires (rfc9846.txt:2161-2163). require_pq
// leaves x25519 off both lists.
//
// The x25519 entry's key_exchange is the x25519 half of the hybrid
// entry's, the same pub. RFC 9846 §4.3.8 asks for the key_exchange of
// each KeyShareEntry to be generated independently
// (rfc9846.txt:2182-2184), and RFC 9954 §3.2 relaxes that for a value of
// the same algorithm reused across the KeyShareEntry records of one
// ClientHello, which is what this is. The ML-KEM half has no second use.
static void write_two_groups(wbuf *w, const ch_cfg *cfg, const uint8_t ek[MLKEM_EK_LEN],
                             const uint8_t pub[32]) {
    size_t groups_len = cfg->require_pq ? 2 : 4;
    wb_u16(w, EXT_SUPPORTED_GROUPS);
    wb_u16(w, (uint16_t)(2 + groups_len));
    wb_u16(w, (uint16_t)groups_len);
    wb_u16(w, CH_GROUP_X25519MLKEM768);
    if (!cfg->require_pq) {
        wb_u16(w, CH_GROUP_X25519);
    }

    wb_u16(w, EXT_KEY_SHARE);
    size_t ext = wb_mark(w, 2);
    size_t shares = wb_mark(w, 2); // client_shares length
    wb_u16(w, CH_GROUP_X25519MLKEM768);
    wb_u16(w, CH_HYBRID_CLIENT_SHARE);
    wb_bytes(w, ek, MLKEM_EK_LEN); // ML-KEM first (RFC 10024)
    wb_bytes(w, pub, 32);
    if (!cfg->require_pq) {
        wb_u16(w, CH_GROUP_X25519);
        wb_u16(w, 32);
        wb_bytes(w, pub, 32);
    }
    wb_patch16(w, shares);
    wb_patch16(w, ext);
}
#endif

size_t hs_build_client_hello(uint8_t *out, size_t cap, const ch_cfg *cfg,
#ifdef CH_KEX_HYBRID
                             const uint8_t ek[MLKEM_EK_LEN],
#endif
                             const uint8_t pub[32], const uint8_t random32[32],
                             uint16_t record_size_limit, const uint8_t *cookie, size_t cookie_len) {
    wbuf w;
    wb_init(&w, out, cap);

    wb_u8(&w, HS_CLIENT_HELLO);
    size_t msg = wb_mark(&w, 3);
    wb_u16(&w, 0x0303); // legacy_version
    wb_bytes(&w, random32, 32);
    wb_u8(&w, 0); // empty legacy_session_id: no middlebox compat needed
#ifdef CH_CLIENT_AES_SUITES
    // ChaCha20 first, the order srv_select prefers for the reason it
    // states, then AES-128-GCM and AES-256-GCM (docs/decisions.md 45 and
    // 58).
    wb_u16(&w, 6);
    wb_u16(&w, SUITE_CHACHA20_POLY1305_SHA256);
    wb_u16(&w, SUITE_AES_128_GCM_SHA256);
    wb_u16(&w, SUITE_AES_256_GCM_SHA384);
#else
    wb_u16(&w, 2); // one suite
    wb_u16(&w, SUITE_CHACHA20_POLY1305_SHA256);
#endif
    wb_u8(&w, 1); // legacy_compression_methods = {null}
    wb_u8(&w, 0);

    size_t exts = wb_mark(&w, 2);

#ifdef CH_TRUST_WEBPKI
    // server_name first in the list, as clients conventionally send it.
    write_server_name(&w, cfg);
    write_alpn(&w, cfg);
#elif defined(CH_TRANSPORT_QUIC)
    // RFC 9001 §8.1 makes ALPN mandatory for a QUIC client
    // (rfc9001.txt:1891-1895), and ch_quic_init refuses a configuration
    // that offers no protocol, so this writes the extension in every
    // trust mode.
    write_alpn(&w, cfg);
#endif

    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 3);
    wb_u8(&w, 2);
    wb_u16(&w, TLS13);

#ifdef CH_KEX_TWO_GROUPS
    write_two_groups(&w, cfg, ek, pub);
#else
    wb_u16(&w, EXT_SUPPORTED_GROUPS);
    wb_u16(&w, 4);
    wb_u16(&w, 2);
    wb_u16(&w, CH_KEX_GROUP);

    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, 2 + 2 + 2 + CH_KEX_CLIENT_SHARE);
    wb_u16(&w, 2 + 2 + CH_KEX_CLIENT_SHARE); // client_shares length
    wb_u16(&w, CH_KEX_GROUP);
    wb_u16(&w, CH_KEX_CLIENT_SHARE);
#ifdef CH_KEX_HYBRID
    wb_bytes(&w, ek, MLKEM_EK_LEN); // ML-KEM first (RFC 10024)
#endif
    wb_bytes(&w, pub, 32);
#endif

    // Sent in both modes: without it a server (Go enforces this) will not
    // issue session tickets, and pinned mode relies on tickets to make
    // reconnects cheap.
    wb_u16(&w, EXT_PSK_MODES);
    wb_u16(&w, 2);
    wb_u8(&w, 1);
    wb_u8(&w, 1); // psk_dhe_ke only

#ifndef CH_TRANSPORT_QUIC
    wb_u16(&w, EXT_RECORD_SIZE_LIMIT);
    wb_u16(&w, 2);
    wb_u16(&w, record_size_limit);
#else
    // RFC 9001 §4.1.3 removes the record layer record_size_limit sizes
    // (rfc9001.txt:462-464), so a QUIC hello sends none and writes the
    // caller's encoded transport parameters in its place, unread (§8.2,
    // rfc9001.txt:1922-1924). ch_quic_init has already held the length
    // to CH_TRANSPORT_PARAMS_MAX, so the cast is in range.
    (void)record_size_limit;
    wb_u16(&w, EXT_QUIC_TRANSPORT_PARAMS);
    wb_u16(&w, (uint16_t)cfg->transport_params_len);
    wb_bytes(&w, cfg->transport_params, cfg->transport_params_len);
#endif

    if (cookie != NULL) {
        wb_u16(&w, EXT_COOKIE);
        wb_u16(&w, (uint16_t)(2 + cookie_len));
        wb_u16(&w, (uint16_t)cookie_len);
        wb_bytes(&w, cookie, cookie_len);
    }

#ifdef CH_TRUST_WEBPKI
    // Every webpki hello offers the certificate path, a resuming one too:
    // a server that declines the ticket then authenticates with a
    // certificate in the same connection (docs/decisions.md 55), and RFC
    // 9846 §4.3.3 requires signature_algorithms of a client that wants a
    // server to authenticate that way (rfc9846.txt:1811-1813).
    write_webpki_signature_algorithms(&w);
    write_cert_types(&w, cfg);
    if (cfg->psk != NULL) {
        write_pre_shared_key(&w, cfg);
    }
#else
    if (cfg->psk == NULL) {
        // Pinned-key mode: the server authenticates by signature, so
        // offer the one algorithm the pin can be.
        wb_u16(&w, EXT_SIGNATURE_ALGORITHMS);
        wb_u16(&w, 4);
        wb_u16(&w, 2);
        wb_u16(&w, CH_PIN_SIGALG);
    } else {
        // The ticket alone, with no signature scheme beside it: a raw or
        // ca server that declines it fails the handshake closed.
        write_pre_shared_key(&w, cfg);
    }
#endif

    wb_patch16(&w, exts);
    wb_patch24(&w, msg);
    return w.err ? 0 : w.len;
}
