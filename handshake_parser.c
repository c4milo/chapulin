// The two attacker-facing handshake message parsers, split out of
// handshake.c so proof, fuzz, and strictness-test builds compile them
// without the state machine. Contract in handshake_parser.h.
#include "handshake_parser.h"

#include <string.h>

#include "buf.h"
#include "cfg.h"
#include "handshake_message.h"

const uint8_t hsp_hrr_magic[32] = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
                                   0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
                                   0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

// The ServerHello's one allowed bit per extension type, or 0 for a
// type the message may not carry.
static uint8_t server_hello_ext_bit(uint16_t ext) {
    switch (ext) {
    case EXT_SUPPORTED_VERSIONS:
        return 1U << 0;
    case EXT_KEY_SHARE:
        return 1U << 1;
    case EXT_PRE_SHARED_KEY:
        return 1U << 2;
    case EXT_COOKIE:
        return 1U << 3;
    default:
        return 0; // ServerHello may carry nothing else
    }
}

// key_share: our one offered group, echoed with the server's public.
static int parse_key_share(rbuf *e, server_hello_info *info, int hrr) {
    if (hrr) {
        // The build offers one group, so an HRR can never legally ask
        // for a different share: selecting ours is redundant (illegal)
        // and selecting another group is unsupported. Both are fatal.
        return CH_EPROTO;
    }
    uint16_t group = rb_u16(e);
    if (group != CH_KEX_GROUP || rb_u16(e) != CH_KEX_SERVER_SHARE) {
        return CH_EPROTO;
    }
#ifdef CH_KEX_PQ
    const uint8_t *ct = rb_bytes(e, MLKEM_CT_LEN);
    if (ct == NULL) {
        return CH_EPROTO;
    }
    info->server_ct = ct;
#endif
    const uint8_t *pub = rb_bytes(e, X25519_LEN);
    if (pub == NULL) {
        return CH_EPROTO;
    }
    memcpy(info->server_pub, pub, X25519_LEN);
    info->group = group;
    info->have_share = 1;
    return CH_OK;
}

// cookie: legal only in an HRR, bounded by what a retry can echo.
static int parse_cookie(rbuf *e, server_hello_info *info, int hrr) {
    if (!hrr) {
        return CH_EPROTO;
    }
    info->cookie_len = rb_u16(e);
    info->cookie = rb_bytes(e, info->cookie_len);
    if (info->cookie == NULL || info->cookie_len > HSP_COOKIE_MAX) {
        return CH_EPROTO;
    }
    return CH_OK;
}

static int parse_server_hello_ext(rbuf *r, server_hello_info *info, int hrr, int psk_mode) {
    uint16_t ext = rb_u16(r);
    size_t ext_len = rb_u16(r);
    const uint8_t *ext_data = rb_bytes(r, ext_len);
    if (ext_data == NULL) {
        return CH_EPROTO;
    }
    if (ext == EXT_PRE_SHARED_KEY && (hrr || !psk_mode)) {
        // Selecting a PSK we never offered, or selecting one from a
        // HelloRetryRequest: RFC 9846 §4.2.4 does not list
        // pre_shared_key for a retry, and §4.3 makes a recognized
        // extension in a message it is not specified for fatal.
        return CH_EPROTO;
    }
    uint8_t bit = server_hello_ext_bit(ext);
    if (bit == 0) {
        return CH_EPROTO;
    }
    if (info->seen & bit) {
        return CH_EPROTO; // RFC 9846 §4.3: one extension of each type
    }
    info->seen |= bit;
    rbuf e;
    rb_init(&e, ext_data, ext_len);
    int rc = CH_OK;
    switch (ext) {
    case EXT_SUPPORTED_VERSIONS:
        info->version_ok = rb_u16(&e) == TLS13;
        break;
    case EXT_KEY_SHARE:
        rc = parse_key_share(&e, info, hrr);
        break;
    case EXT_PRE_SHARED_KEY:
        info->psk_ok = rb_u16(&e) == 0; // we offered exactly one identity
        break;
    default: // EXT_COOKIE: the bit map admits nothing else
        rc = parse_cookie(&e, info, hrr);
        break;
    }
    if (rc != CH_OK) {
        return rc;
    }
    // RFC 9846 §4.3: extension_data matches its struct exactly, so a
    // non-empty remainder is a decode error.
    return e.err || rb_left(&e) != 0 ? CH_EPROTO : CH_OK;
}

int hsp_parse_server_hello(const uint8_t *body, size_t n, server_hello_info *info, int psk_mode) {
    rbuf r;
    rb_init(&r, body, n);
    if (rb_u16(&r) != 0x0303) {
        return CH_EPROTO;
    }
    const uint8_t *random = rb_bytes(&r, 32);
    if (random == NULL) {
        return CH_EPROTO;
    }
    // Variable time on purpose: both sides are public (an RFC constant
    // against wire bytes). The inv-16 allowlist names this compare.
    info->hrr = memcmp(random, hsp_hrr_magic, 32) == 0;
    if (rb_u8(&r) != 0) {
        return CH_EPROTO; // we sent an empty legacy_session_id; the echo must match
    }
    if (rb_u16(&r) != SUITE_CHACHA20_POLY1305_SHA256 || rb_u8(&r) != 0) {
        return CH_EPROTO;
    }
    size_t exts_len = rb_u16(&r);
    if (r.err || exts_len != rb_left(&r)) {
        return CH_EPROTO;
    }
    while (rb_left(&r) > 0) {
        int rc = parse_server_hello_ext(&r, info, info->hrr, psk_mode);
        if (rc != CH_OK) {
            return rc;
        }
    }
    return info->version_ok ? CH_OK : CH_EPROTO;
}

// Certificate framing per RFC 9846 §4.5.1; the entries themselves
// are the trust mode's concern, not this parser's.
int hsp_parse_certificate(const uint8_t *body, size_t n, const uint8_t **list, size_t *list_len,
                          uint8_t *alert) {
    rbuf r;
    rb_init(&r, body, n);
    if (rb_u8(&r) != 0) {
        *alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
    size_t len = rb_u24(&r);
    if (r.err || len != rb_left(&r) || len == 0) {
        return CH_EPROTO;
    }
    *list = rb_bytes(&r, len);
    *list_len = len;
    return CH_OK;
}

#ifdef CH_TRUST_WEBPKI
// The CertificateVerify algorithms a TRUST=webpki build accepts, one per
// leaf key family the walk admits: rsa_pss_rsae_sha256,
// ecdsa_secp256r1_sha256 and ecdsa_secp384r1_sha384. The ClientHello
// also offered rsa_pkcs1_sha256 and rsa_pkcs1_sha384, for certificate
// signatures only, and RFC 9846 §4.3.3 forbids them here. Every scheme
// but the three gets the pinned builds' answer to a scheme they did not
// offer: CH_EAUTH with handshake_failure.
static int certificate_verify_scheme_ok(uint16_t algorithm) {
    return algorithm == SIGALG_RSA_PSS_RSAE_SHA256 || algorithm == SIGALG_ECDSA_P256_SHA256 ||
           algorithm == SIGALG_ECDSA_P384_SHA384;
}
#endif

// CertificateVerify per RFC 9846 §4.5.2: we offered exactly one
// signature algorithm, so the message may carry nothing else. A
// TRUST=webpki build offered several and admits the three
// certificate_verify_scheme_ok names, reporting which one in *scheme.
int hsp_parse_certificate_verify(const uint8_t *body, size_t n,
#ifdef CH_TRUST_WEBPKI
                                 uint16_t *scheme,
#endif
                                 const uint8_t **sig, size_t *sig_len, uint8_t *alert) {
    rbuf r;
    rb_init(&r, body, n);
#ifdef CH_TRUST_WEBPKI
    uint16_t algorithm = rb_u16(&r);
    if (!certificate_verify_scheme_ok(algorithm)) {
        *alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EAUTH;
    }
    *scheme = algorithm;
#else
    if (rb_u16(&r) != CH_PIN_SIGALG) {
        *alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EAUTH;
    }
#endif
    size_t len = rb_u16(&r);
    *sig = rb_bytes(&r, len);
    if (*sig == NULL || rb_left(&r) != 0) {
        return CH_EPROTO;
    }
    *sig_len = len;
    return CH_OK;
}

// record_size_limit: one u16, floored by RFC 8449, clamped into the
// session's send limit.
static int parse_record_size_limit(const uint8_t *ext_data, size_t ext_len, uint16_t *peer_limit) {
    rbuf e;
    rb_init(&e, ext_data, ext_len);
    uint16_t limit = rb_u16(&e);
    // §4.3: extension_data matches its struct exactly; the body is
    // one u16, so a non-empty remainder is a decode error.
    if (e.err || rb_left(&e) != 0 || limit < 64) {
        return CH_EPROTO;
    }
    // The limit covers content plus the inner type byte.
    uint16_t pt = limit - 1;
    if (pt < *peer_limit) {
        *peer_limit = pt;
    }
    return CH_OK;
}

#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
#ifdef CH_TRUST_WEBPKI
// A TRUST=webpki ClientHello sent server_name, and RFC 6066 §3 lets the
// server acknowledge it in EncryptedExtensions with empty
// extension_data. That empty acknowledgement is the one server_name the
// parser admits.
static int server_name_acknowledged(uint16_t ext, size_t ext_len) {
    return ext == EXT_SERVER_NAME && ext_len == 0;
}
#endif

// What the ALPN arm reads and writes: the protocol names the
// ClientHello offered, the index it reports, and the alert a refusal
// names. One struct so the two functions below take one pointer rather
// than four parameters.
typedef struct {
    const ch_alpn_protocol *offered;
    size_t offered_count;
    uint8_t *selected;
    uint8_t *alert;
} alpn_out;

// application_layer_protocol_negotiation in EncryptedExtensions
// (RFC 7301 §3.2). The body is a ProtocolNameList, and §3.2 says it
// "MUST contain exactly one ProtocolName"; a ProtocolName is
// `opaque ProtocolName<1..2^8-1>`, so it holds at least one byte. Two
// bodies fail that structure and get RFC 9846 §6's decode_error, the
// alert for a length that is incorrect or a field outside the specified
// range: a list that is not one whole name, which covers two names and
// trailing bytes, and a name of zero bytes.
//
// A name the client did not offer is a different fault. The body is
// well formed and its value is not acceptable, which RFC 9846 §6.2
// names illegal_parameter. RFC 7301 §3.2 gives the server no way to
// select outside the offer: a server that shares no protocol with the
// client sends a no_application_protocol alert instead. The compare is
// variable time on purpose, like the HRR-magic compare above: protocol
// names are public on both sides.
static int parse_alpn(const uint8_t *ext_data, size_t ext_len, const alpn_out *out) {
    rbuf e;
    rb_init(&e, ext_data, ext_len);
    size_t list_len = rb_u16(&e);
    size_t name_len = rb_u8(&e);
    const uint8_t *name = rb_bytes(&e, name_len);
    if (e.err || name_len == 0 || list_len != 1 + name_len || rb_left(&e) != 0) {
        *out->alert = ALERT_DECODE_ERROR;
        return CH_EPROTO;
    }
    for (size_t i = 0; i < out->offered_count; i++) {
        if (out->offered[i].name_len == name_len &&
            memcmp(out->offered[i].name, name, name_len) == 0) {
            *out->selected = (uint8_t)i;
            return CH_OK;
        }
    }
#ifdef CH_TRANSPORT_QUIC
    // RFC 9001 §8.1 makes a QUIC client terminate with error 0x0178
    // whenever ALPN negotiation fails (rfc9001.txt:1896-1902), which
    // §4.8's 0x0100 conversion produces from alert 120 and not from
    // alert 47.
    *out->alert = ALERT_NO_APPLICATION_PROTOCOL;
#else
    *out->alert = ALERT_ILLEGAL_PARAMETER;
#endif
    return CH_EPROTO;
}

// The bit that marks one of the extra extensions these two builds admit
// seen: the empty server_name acknowledgement a TRUST=webpki build
// sent, or an ALPN selection the client offered and parse_alpn
// accepted. ALPN is admitted only when the ClientHello offered
// protocols, so with no offer it falls through as an extension the
// client never requested. 0 says the loop does not admit this
// extension, and out->alert then holds the alert parse_alpn named, or
// the unsupported_extension the caller seeded it with.
static uint8_t extra_ext_bit(uint16_t ext, const uint8_t *ext_data, size_t ext_len,
                             const alpn_out *out) {
#ifdef CH_TRUST_WEBPKI
    if (server_name_acknowledged(ext, ext_len)) {
        return 1U << 2;
    }
#else
    (void)ext_len;
#endif
    if (ext == EXT_ALPN && out->offered_count > 0) {
        return parse_alpn(ext_data, ext_len, out) == CH_OK ? (uint8_t)(1U << 3) : 0;
    }
    return 0;
}

// The alert for an extension the loop does not admit. In a TRUST=webpki
// build a server_name there carries data, because
// server_name_acknowledged admits the empty one. That body has the
// wrong length for the empty extension_data RFC 6066 §3 requires, and
// RFC 9846 §6 names that fault decode_error. An ALPN extension the loop
// did not admit carries alpn_alert, which is the alert parse_alpn named
// or, when no offer let it run, unsupported_extension. Every other
// extension was never offered: unsupported_extension (RFC 9846 §4.3),
// and a server_name is one of those in a build that sent none.
static uint8_t unadmitted_extension_alert(uint16_t ext, uint8_t alpn_alert) {
#ifdef CH_TRUST_WEBPKI
    if (ext == EXT_SERVER_NAME) {
        return ALERT_DECODE_ERROR;
    }
#endif
    return ext == EXT_ALPN ? alpn_alert : ALERT_UNSUPPORTED_EXTENSION;
}
#endif

// Encrypted extensions: take the peer's record_size_limit, tolerate
// supported_groups (a server may volunteer it for later connections)
// and, in a TRUST=webpki build, one empty server_name acknowledgement
// and one ALPN selection; reject everything else — RFC 9846 §4.3
// requires unsupported_extension for anything the ClientHello did not
// offer.
int hsp_parse_encrypted_exts(const uint8_t *body, size_t n, uint16_t *peer_limit,
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
                             const ch_alpn_protocol *offered, size_t offered_count,
                             uint8_t *selected,
#endif
#ifdef CH_TRANSPORT_QUIC
                             const uint8_t **transport_params, size_t *transport_params_len,
#endif
                             uint8_t *alert) {
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
    // parse_alpn writes over this one, so an ALPN extension the loop
    // refuses carries its own alert and one it never reached carries
    // the answer for an extension the client did not offer.
    uint8_t alpn_alert = ALERT_UNSUPPORTED_EXTENSION;
    const alpn_out alpn = {offered, offered_count, selected, &alpn_alert};
#endif
    rbuf r;
    rb_init(&r, body, n);
    size_t exts_len = rb_u16(&r);
    if (r.err || exts_len != rb_left(&r)) {
        return CH_EPROTO;
    }
    // bit 0 record_size_limit, bit 1 supported_groups, bit 2 server_name,
    // bit 3 application_layer_protocol_negotiation, bit 4
    // quic_transport_parameters
    uint8_t seen = 0;
    while (rb_left(&r) > 0) {
        uint16_t ext = rb_u16(&r);
        size_t ext_len = rb_u16(&r);
        const uint8_t *ext_data = rb_bytes(&r, ext_len);
        if (ext_data == NULL) {
            return CH_EPROTO;
        }
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
        // Read before the chain rather than inside it, so this build's
        // extra extensions cost the chain one arm and not two.
        uint8_t extra_bit = extra_ext_bit(ext, ext_data, ext_len, &alpn);
#endif
        uint8_t bit;
        if (ext == EXT_RECORD_SIZE_LIMIT) {
            bit = 1U << 0;
            if (parse_record_size_limit(ext_data, ext_len, peer_limit) != CH_OK) {
                return CH_EPROTO;
            }
        } else if (ext == EXT_SUPPORTED_GROUPS) {
            bit = 1U << 1; // tolerated; its body is deliberately unread
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
        } else if (extra_bit != 0) {
            bit = extra_bit; // admitted once, like the other two
#endif
#ifdef CH_TRANSPORT_QUIC
        } else if (ext == EXT_QUIC_TRANSPORT_PARAMS) {
            // The body belongs to the QUIC version in use and is opaque
            // to TLS (RFC 9001 §8.2, rfc9001.txt:1926-1928), so it is
            // reported and not read. The pointer is into body.
            bit = 1U << 4;
            *transport_params = ext_data;
            *transport_params_len = ext_len;
#endif
        } else {
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
            *alert = unadmitted_extension_alert(ext, alpn_alert);
#else
            *alert = ALERT_UNSUPPORTED_EXTENSION;
#endif
            return CH_EPROTO;
        }
        if (seen & bit) {
            return CH_EPROTO; // RFC 9846 §4.3: one extension of each type
        }
        seen |= bit;
    }
#ifdef CH_TRANSPORT_QUIC
    // RFC 9001 §8.2 makes an EncryptedExtensions without the extension
    // an error of type 0x016d (rfc9001.txt:1930-1936), which §4.8
    // produces from missing_extension and no other description.
    if ((seen & (1U << 4)) == 0) {
        *alert = ALERT_MISSING_EXTENSION;
        return CH_EPROTO;
    }
#endif
    return CH_OK;
}
