// One reader per ClientHello extension a ROLE=server build recognizes.
// srv_parser.c walks the message and calls srv_read_extension for each
// recognized type; this file is what that call reaches. The split is by
// size, not by concern: the two halves are one parser, and srv_parser.h
// states the contract both keep. webpki_ext.c stands in the same
// relation to webpki.c.
//
// Every reader takes the extension's own body as a reader bounded by
// the length the message gave it, so no reader can walk past its own
// extension whatever its lengths claim, and each returns CH_OK or
// writes its alert through srv_refuse. The caller holds each one to
// filling that body exactly (rfc9846.txt:1561-1565), so a reader that
// leaves bytes behind is refused without having to check for itself.
//
// Every byte here is public: it arrives before any key exists, so no
// reader takes a constant-time obligation. All reading goes through the
// rbuf reader (buf.h) and every multi-byte value moves byte by byte.
#include "srv_parser.h"

#ifdef CH_ROLE_SERVER

#include "buf.h"
#include "ct.h"

// The two psk_key_exchange_modes values as the wire spells them (RFC
// 9846 §4.3.9); SRV_PSK_KE and SRV_PSK_DHE_KE are the bits that report
// them.
#define PSK_KE 0
#define PSK_DHE_KE 1

// RFC 6066 §3: host_name, the one NameType the document defines.
#define SERVER_NAME_HOST_NAME 0

// RFC 8449 §4: the smallest record_size_limit a peer may send.
#define RECORD_SIZE_LIMIT_MIN 64

// The vector bounds of RFC 9846 §4.3.11's OfferedPsks: identities holds
// at least one PskIdentity of a one-byte identity and its four-byte
// obfuscated_ticket_age, and binders holds at least one PskBinderEntry
// of 32 bytes with its length byte.
#define PSK_IDENTITIES_MIN 7
#define PSK_BINDERS_MIN 33
#define PSK_BINDER_MIN 32
#define OBFUSCATED_AGE_LEN 4

// server_name (RFC 6066 §3): a ServerNameList holding one host_name.
// The list is one entry because host_name is the only NameType the
// document defines and §3 forbids two names of one type, so a body
// shaped any other way cannot be parsed against that syntax, which is
// decode_error (rfc9846.txt:3785-3788).
static int read_server_name(rbuf *e, hello_parse *p) {
    size_t list_len = rb_u16(e);
    uint8_t name_type = rb_u8(e);
    size_t name_len = rb_u16(e);
    const uint8_t *name = rb_bytes(e, name_len);
    if (name == NULL || name_type != SERVER_NAME_HOST_NAME || name_len == 0 ||
        list_len != 3 + name_len) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    p->ch->server_name = name;
    p->ch->server_name_len = name_len;
    return CH_OK;
}

// supported_groups (§4.3.7): NamedGroup named_group_list<2..2^16-1>.
static int read_supported_groups(rbuf *e, hello_parse *p) {
    size_t list_len = 0;
    if (!srv_open_code_point_list(e, &list_len)) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    if (srv_list_has(e, list_len, CH_KEX_GROUP)) {
        p->ch->groups |= SRV_GROUP_KEX;
    }
    return CH_OK;
}

// signature_algorithms (§4.3.3): SignatureScheme
// supported_signature_algorithms<2..2^16-2>. One walk sets both bits;
// a scheme outside the two is read and ignored.
static int read_signature_algorithms(rbuf *e, hello_parse *p) {
    size_t list_len = 0;
    if (!srv_open_code_point_list(e, &list_len)) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    for (size_t i = 0; i < list_len; i += 2) {
        uint16_t scheme = rb_u16(e);
        if (scheme == SIGALG_ECDSA_P256_SHA256) {
            p->ch->sigalgs |= SRV_SIGALG_ECDSA_P256;
        }
        if (scheme == SIGALG_RSA_PSS_RSAE_SHA256) {
            p->ch->sigalgs |= SRV_SIGALG_RSA_PSS;
        }
    }
    return CH_OK;
}

// Records one protocol name the client listed when the caller offers
// it: the lowest index in the offer seen so far, because the server's
// order decides. Names are public on both sides; ct_memeq is the
// compare INV-16 admits in a library source.
static void alpn_offered(hello_parse *p, const uint8_t *name, size_t name_len) {
    for (size_t j = 0; j < p->offered_count; j++) {
        if (p->offered[j].name_len == name_len && ct_memeq(p->offered[j].name, name, name_len)) {
            if (p->ch->alpn_selected == CH_ALPN_NONE || j < p->ch->alpn_selected) {
                p->ch->alpn_selected = (uint8_t)j;
            }
            return;
        }
    }
}

// application_layer_protocol_negotiation (RFC 7301 §3.1): a
// ProtocolNameList protocol_name_list<2..2^16-1> of ProtocolName
// <1..2^8-1>. The list fills the body and the names fill the list, or
// decode_error. A name the caller does not offer is read and passed
// over, and a list with no offered name leaves alpn_selected at
// CH_ALPN_NONE. Whether that ends the handshake is srv_select's verdict:
// RFC 7301 §3.2 makes it fatal for a server that offers protocols, and
// this parser reports the offer and reaches no verdict on it.
static int read_alpn(rbuf *e, hello_parse *p) {
    size_t list_len = rb_u16(e);
    if (e->err || list_len < 2 || list_len > rb_left(e)) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    size_t used = 0;
    while (used < list_len) {
        size_t name_len = rb_u8(e);
        const uint8_t *name = rb_bytes(e, name_len);
        if (name == NULL || name_len == 0) {
            return srv_refuse(p->alert, ALERT_DECODE_ERROR);
        }
        alpn_offered(p, name, name_len);
        used += 1 + name_len;
    }
    if (used != list_len) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    return CH_OK;
}

// record_size_limit (RFC 8449 §4): one two-byte value of at least 64.
// A smaller value is a fatal illegal_parameter there.
//
// The wire value counts the inner content-type byte, so what is stored
// is one less: client_hello.record_size_limit is the largest plaintext
// the server may put in one record, which is what srv_handshake.c
// compares against CH_TX_PT. handshake_parser_ee.c:25 is the client's
// matching step.
//
// No upper bound is checked. §4 forbids a server to enforce the
// protocol's maximum, because a client may advertise a limit that an
// extension the server does not know enables.
static int read_record_size_limit(rbuf *e, hello_parse *p) {
    uint16_t limit = rb_u16(e);
    if (e->err) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    if (limit < RECORD_SIZE_LIMIT_MIN) {
        return srv_refuse(p->alert, ALERT_ILLEGAL_PARAMETER);
    }
    p->ch->record_size_limit = (uint16_t)(limit - 1);
    return CH_OK;
}

// The identities list of pre_shared_key: PskIdentity
// identities<7..2^16-1>, each an opaque identity<1..2^16-1> and a
// four-byte obfuscated_ticket_age. It reports the list's length, which
// fixes where the binders start.
static int read_psk_identities(rbuf *e, hello_parse *p, size_t *identities_len) {
    *identities_len = rb_u16(e);
    if (e->err || *identities_len < PSK_IDENTITIES_MIN || *identities_len > rb_left(e)) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    size_t used = 0;
    while (used < *identities_len) {
        size_t identity_len = rb_u16(e);
        if (rb_bytes(e, identity_len) == NULL || identity_len == 0 ||
            rb_bytes(e, OBFUSCATED_AGE_LEN) == NULL) {
            return srv_refuse(p->alert, ALERT_DECODE_ERROR);
        }
        used += 2 + identity_len + OBFUSCATED_AGE_LEN;
    }
    if (used != *identities_len) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    return CH_OK;
}

// The binders list of pre_shared_key: PskBinderEntry
// binders<33..2^16-1>, each an opaque PskBinderEntry<32..255>.
static int read_psk_binders(rbuf *e, hello_parse *p) {
    size_t binders_len = rb_u16(e);
    if (e->err || binders_len < PSK_BINDERS_MIN || binders_len > rb_left(e)) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    size_t used = 0;
    while (used < binders_len) {
        size_t binder_len = rb_u8(e);
        if (rb_bytes(e, binder_len) == NULL || binder_len < PSK_BINDER_MIN) {
            return srv_refuse(p->alert, ALERT_DECODE_ERROR);
        }
        used += 1 + binder_len;
    }
    if (used != binders_len) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    return CH_OK;
}

// pre_shared_key (§4.3.11): OfferedPsks, the two lists above. This
// build selects no PSK and reads no identity, so the walk holds the
// syntax and records where the binders start, which is the one value
// a later binder check cannot recover (rfc9846.txt:2586 states the
// client's half of that rule). data_off is where this extension's body
// starts, counted from the start of the ClientHello body.
static int read_pre_shared_key(rbuf *e, size_t data_off, hello_parse *p) {
    size_t identities_len = 0;
    int rc = read_psk_identities(e, p, &identities_len);
    if (rc != CH_OK) {
        return rc;
    }
    p->ch->truncated_len = data_off + 2 + identities_len;
    return read_psk_binders(e, p);
}

// supported_versions (§4.3.1): ProtocolVersion versions<2..254>, with a
// one-byte length. The list must hold 0x0304, or the client is not
// negotiating this version: protocol_version (rfc9846.txt:1742-1744,
// rfc9846.txt:3972-3973). A version outside this build's one is read
// and ignored.
static int read_supported_versions(rbuf *e, hello_parse *p) {
    size_t list_len = rb_u8(e);
    if (e->err || list_len < 2 || (list_len & 1) != 0 || list_len > rb_left(e)) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    if (!srv_list_has(e, list_len, TLS13)) {
        return srv_refuse(p->alert, ALERT_PROTOCOL_VERSION);
    }
    return CH_OK;
}

// cookie (§4.3.2): opaque cookie<1..2^16-1>, the client's echo of what
// srv_send_hello_retry_request minted. srv_check_retry_hello opens it.
static int read_cookie(rbuf *e, hello_parse *p) {
    size_t cookie_len = rb_u16(e);
    const uint8_t *cookie = rb_bytes(e, cookie_len);
    if (cookie == NULL || cookie_len == 0) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    p->ch->cookie = cookie;
    p->ch->cookie_len = cookie_len;
    return CH_OK;
}

// psk_key_exchange_modes (§4.3.9): PskKeyExchangeMode ke_modes<1..255>.
// A mode outside the two the document defines is read and ignored.
static int read_psk_modes(rbuf *e, hello_parse *p) {
    size_t list_len = rb_u8(e);
    if (e->err || list_len == 0 || list_len > rb_left(e)) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    for (size_t i = 0; i < list_len; i++) {
        uint8_t mode = rb_u8(e);
        if (mode == PSK_KE) {
            p->ch->psk_modes |= SRV_PSK_KE;
        }
        if (mode == PSK_DHE_KE) {
            p->ch->psk_modes |= SRV_PSK_DHE_KE;
        }
    }
    return CH_OK;
}

// One KeyShareEntry for this build's group. Its key_exchange must be
// CH_KEX_CLIENT_SHARE bytes, or illegal_parameter, this design's choice
// under §6 (rfc9846.txt:3789-3791). The first such entry is the share;
// §4.3.8 forbids the client a second one for the same group and leaves
// checking that to the server's discretion, so a second is read and
// ignored.
static int take_share(hello_parse *p, const uint8_t *share, size_t share_len) {
    if (share_len != CH_KEX_CLIENT_SHARE) {
        return srv_refuse(p->alert, ALERT_ILLEGAL_PARAMETER);
    }
    if (p->ch->share == NULL) {
        p->ch->share = share;
        p->ch->share_len = share_len;
        p->ch->shares |= SRV_GROUP_KEX;
    }
    return CH_OK;
}

// key_share (§4.3.8): KeyShareEntry client_shares<0..2^16-1>, each a
// group and an opaque key_exchange<1..2^16-1>. An empty list is
// permitted (rfc9846.txt:4599-4601) and leaves shares at 0. An entry
// for a group this build does not hold is read and ignored.
static int read_key_share(rbuf *e, hello_parse *p) {
    size_t list_len = rb_u16(e);
    if (e->err || list_len > rb_left(e)) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    size_t used = 0;
    while (used < list_len) {
        uint16_t group = rb_u16(e);
        size_t share_len = rb_u16(e);
        const uint8_t *share = rb_bytes(e, share_len);
        if (share == NULL || share_len == 0) {
            return srv_refuse(p->alert, ALERT_DECODE_ERROR);
        }
        if (group == CH_KEX_GROUP) {
            int rc = take_share(p, share, share_len);
            if (rc != CH_OK) {
                return rc;
            }
        }
        used += 4 + share_len;
    }
    if (used != list_len) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    return CH_OK;
}

// One recognized extension's body. srv_parser.h states the contract.
int srv_read_extension(rbuf *e, uint16_t type, size_t data_off, hello_parse *p) {
    switch (type) {
    case EXT_SERVER_NAME:
        return read_server_name(e, p);
    case EXT_SUPPORTED_GROUPS:
        return read_supported_groups(e, p);
    case EXT_SIGNATURE_ALGORITHMS:
        return read_signature_algorithms(e, p);
    case EXT_ALPN:
        return read_alpn(e, p);
    case EXT_RECORD_SIZE_LIMIT:
        return read_record_size_limit(e, p);
    case EXT_PRE_SHARED_KEY:
        return read_pre_shared_key(e, data_off, p);
    case EXT_SUPPORTED_VERSIONS:
        return read_supported_versions(e, p);
    case EXT_COOKIE:
        return read_cookie(e, p);
    case EXT_PSK_MODES:
        return read_psk_modes(e, p);
    case EXT_KEY_SHARE:
        return read_key_share(e, p);
    case EXT_PADDING:
        // RFC 7685: a body the server reads nothing from, whose length
        // is the one thing about it a second hello may change.
        rb_skip(e, rb_left(e));
        return CH_OK;
    case EXT_EARLY_DATA:
        // An empty body, which the exact-fill check after this call
        // holds it to, and no other effect (rfc9846.txt:2385-2401).
        return CH_OK;
    case EXT_QUIC_TRANSPORT_PARAMS:
#ifdef CH_TRANSPORT_QUIC
        // A QUIC server keeps the body and reads none of it: its content
        // belongs to the QUIC version in use (rfc9001.txt:1926-1928), and
        // the driver hands these bytes to the caller. They point into
        // cfg.buf, which the next message overwrites.
        p->ch->transport_params_len = rb_left(e);
        p->ch->transport_params = rb_bytes(e, p->ch->transport_params_len);
        return CH_OK;
#else
        // Refused, and the one extension here that is recognized in
        // order to be refused. RFC 9001 §8.2 requires a fatal
        // unsupported_extension from an implementation that understands
        // the extension when the transport is not QUIC
        // (rfc9001.txt:1945-1949), and a build over TLS records is not
        // QUIC. The body goes unread either way.
        return srv_refuse(p->alert, ALERT_UNSUPPORTED_EXTENSION);
#endif
    default:
        // Unreachable: the caller asked srv_ext_known first, and every
        // type that answers 1 has a case above. It refuses anyway
        // rather than returning CH_OK, so a type added to srv_ext_known
        // and not to this switch fails the handshake instead of
        // quietly parsing as an empty extension and taking its bit. No
        // test reaches this arm, because no input reaches it.
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
}

#endif // CH_ROLE_SERVER
