// The EncryptedExtensions parser, split out of handshake_parser.c to
// keep each file under the 500-line limit. Like that file it is a pure
// parser over the caller's buffer, with no I/O and no session state.
// Contract in handshake_parser.h.
#include "handshake_parser.h"

#include <string.h>

#include "buf.h"
#include "cfg.h"
#include "handshake_message.h"

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
// variable time on purpose, like the HRR-magic compare in
// handshake_parser.c: protocol names are public on both sides.
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

// The bit that marks an ALPN selection seen, when the ClientHello
// offered protocols and parse_alpn accepted the one the server named. 0
// says the loop does not admit this extension: with no offer an ALPN
// extension falls through as one the client never requested, and after
// a refusal *out->alert holds the alert parse_alpn named.
static uint8_t alpn_ext_bit(uint16_t ext, const uint8_t *ext_data, size_t ext_len,
                            const alpn_out *out) {
    if (ext == EXT_ALPN && out->offered_count > 0) {
        return parse_alpn(ext_data, ext_len, out) == CH_OK ? (uint8_t)(1U << 3) : 0;
    }
    return 0;
}
#endif

#ifdef CH_TRUST_WEBPKI
// What the two arms only a TRUST=webpki build has read and write:
// whether the ClientHello sent server_name, the certificate types its
// server_certificate_type offered as webpki_cert_types_offered's bit set,
// the type the server selected, and the alert a refusal names.
typedef struct {
    int server_name_sent;
    uint8_t cert_types_offered;
    uint8_t *cert_type;
    uint8_t *alert;
} webpki_ext_out;

// RFC 6066 §3 lets a server acknowledge the server_name a ClientHello
// sent with empty extension_data. That empty acknowledgement is the one
// server_name the parser admits.
static int server_name_acknowledged(uint16_t ext, size_t ext_len) {
    return ext == EXT_SERVER_NAME && ext_len == 0;
}

// Whether type is one the ClientHello offered: its bit in offered, the
// bit set webpki_cert_types_offered returns. A value of 8 or more has no
// bit there, so no ClientHello offered it.
static int cert_type_offered(uint8_t offered, uint8_t type) {
    return type < 8 && ((offered >> type) & 1U) != 0;
}

// server_certificate_type in EncryptedExtensions. The server's
// ServerCertTypeExtension is one CertificateType (RFC 7250 §3,
// rfc7250.txt:317-324), and only a single value is permitted there
// (§4.2, rfc7250.txt:485-487). A body that is not one byte cannot be
// decoded as that struct, which RFC 9846 §6 names decode_error
// (rfc9846.txt:3784-3788). A type the ClientHello did not offer is well
// formed and not acceptable, illegal_parameter
// (rfc9846.txt:3789-3791): RFC 7250 §4.2 has a server with no type in
// common with the client end the handshake with unsupported_certificate
// (rfc7250.txt:435-438) rather than select one outside the offer.
static int parse_server_cert_type(const uint8_t *ext_data, size_t ext_len,
                                  const webpki_ext_out *out) {
    rbuf e;
    rb_init(&e, ext_data, ext_len);
    uint8_t type = rb_u8(&e);
    if (e.err || rb_left(&e) != 0) {
        *out->alert = ALERT_DECODE_ERROR;
        return CH_EPROTO;
    }
    if (!cert_type_offered(out->cert_types_offered, type)) {
        *out->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
    *out->cert_type = type;
    return CH_OK;
}

// The bit that marks one of the two extensions only a TRUST=webpki build
// admits seen, or 0 when the loop does not admit this one. Each is
// admitted only when the ClientHello asked for it, so with no request it
// falls through as an extension the client never requested:
//  - server_name, bit 2, when the ClientHello sent one. A server_name
//    that carries data has the wrong length for the empty
//    extension_data RFC 6066 §3 requires, and RFC 9846 §6 names that
//    fault decode_error.
//  - server_certificate_type, bit 5, when the ClientHello offered
//    certificate types and parse_server_cert_type accepted the one the
//    server named.
// After a refusal *out->alert holds the alert the arm named.
static uint8_t webpki_ext_bit(uint16_t ext, const uint8_t *ext_data, size_t ext_len,
                              const webpki_ext_out *out) {
    if (ext == EXT_SERVER_NAME && out->server_name_sent) {
        if (server_name_acknowledged(ext, ext_len)) {
            return 1U << 2;
        }
        *out->alert = ALERT_DECODE_ERROR;
        return 0;
    }
    if (ext == EXT_SERVER_CERTIFICATE_TYPE && out->cert_types_offered != 0) {
        return parse_server_cert_type(ext_data, ext_len, out) == CH_OK ? (uint8_t)(1U << 5) : 0;
    }
    return 0;
}
#endif

// Encrypted extensions: take the peer's record_size_limit, tolerate
// supported_groups (a server may volunteer it for later connections)
// and admit the extensions the ClientHello asked for: in a TRUST=webpki
// build one empty server_name acknowledgement, one ALPN selection and
// one server_certificate_type; in a TRANSPORT=quic build one ALPN
// selection and quic_transport_parameters. Reject everything else —
// RFC 9846 §4.3 requires unsupported_extension for anything the
// ClientHello did not offer.
int hsp_parse_encrypted_exts(const uint8_t *body, size_t n, uint16_t *peer_limit,
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
                             const ch_alpn_protocol *offered, size_t offered_count,
                             uint8_t *selected,
#endif
#ifdef CH_TRUST_WEBPKI
                             int server_name_sent, uint8_t cert_types_offered, uint8_t *cert_type,
#endif
#ifdef CH_TRANSPORT_QUIC
                             const uint8_t **transport_params, size_t *transport_params_len,
#endif
                             uint8_t *alert) {
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
    // An arm below writes over this one when it refuses the extension it
    // read, so a refused extension carries its arm's alert and one no
    // arm read carries the answer for an extension the client did not
    // offer.
    uint8_t arm_alert = ALERT_UNSUPPORTED_EXTENSION;
    const alpn_out alpn = {offered, offered_count, selected, &arm_alert};
#endif
#ifdef CH_TRUST_WEBPKI
    const webpki_ext_out webpki = {server_name_sent, cert_types_offered, cert_type, &arm_alert};
#endif
    rbuf r;
    rb_init(&r, body, n);
    size_t exts_len = rb_u16(&r);
    if (r.err || exts_len != rb_left(&r)) {
        return CH_EPROTO;
    }
    // bit 0 record_size_limit, bit 1 supported_groups, bit 2 server_name,
    // bit 3 application_layer_protocol_negotiation, bit 4
    // quic_transport_parameters, bit 5 server_certificate_type
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
        // extra extensions cost the chain one arm and not three.
        uint8_t extra_bit = alpn_ext_bit(ext, ext_data, ext_len, &alpn);
#endif
#ifdef CH_TRUST_WEBPKI
        extra_bit |= webpki_ext_bit(ext, ext_data, ext_len, &webpki);
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
            *alert = arm_alert;
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
