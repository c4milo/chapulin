// The ClientHello parser's walk over one message. srv_parser.h states
// the contract; this file reads one body and reports what srv_flight.c
// decides on. The per-extension readers sit in srv_parser_ext.c, which
// this file reaches through srv_read_extension; the two are one parser
// split by size, and srv_parser_ext.h says so where it declares the call.
//
// Structure. srv_parse_client_hello reads the head (legacy_version
// through legacy_compression_methods) and the extension block's
// framing. srv_ext_over_max then counts the extensions, and
// srv_ext_duplicate compares their types. The count comes first
// because the duplicate check and the frozen digest's walk each cost
// the square of it, and the count is what bounds them
// (docs/decisions.md 59). Then parse_extension reads one extension at
// a time: an unrecognized type is skipped by its length (RFC 9846
// §4.2.2, rfc9846.txt:1299) and a recognized one goes to its reader and
// must fill its own body exactly (rfc9846.txt:1561-1565). The checks that
// need the whole message -- which required extension never arrived, and
// whether the key exchange halves agree -- run once after the loop,
// over the seen mask, in check_required.
//
// Every refusal names its alert where it happens: srv_refuse writes the
// description into *alert and returns CH_EPROTO, so a reader finds the
// section, the alert and the return on one line.
//
// The frozen digest takes one sha256_update over the head as the walk
// reads it. Once the walk has accepted every extension, add_frozen_extensions
// adds one sha256_update per extension the digest covers, over its type,
// length and body as they sit in the message, in ascending type order
// rather than in the order the client sent them. frozen_covers names the
// five extensions the digest leaves out, and docs/decisions.md 59 states
// why the order is the types' and not the wire's.
#include "srv_parser.h"
#include "srv_parser_ext.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "buf.h"

// The SRV_EXT_ bit of a recognized extension type, or 0.
static uint16_t ext_bit(uint16_t type) {
    switch (type) {
    case EXT_SERVER_NAME:
        return SRV_EXT_SERVER_NAME;
    case EXT_SUPPORTED_GROUPS:
        return SRV_EXT_SUPPORTED_GROUPS;
    case EXT_SIGNATURE_ALGORITHMS:
        return SRV_EXT_SIGNATURE_ALGORITHMS;
    case EXT_ALPN:
        return SRV_EXT_ALPN;
    case EXT_RECORD_SIZE_LIMIT:
        return SRV_EXT_RECORD_SIZE_LIMIT;
    case EXT_PRE_SHARED_KEY:
        return SRV_EXT_PRE_SHARED_KEY;
    case EXT_SUPPORTED_VERSIONS:
        return SRV_EXT_SUPPORTED_VERSIONS;
    case EXT_COOKIE:
        return SRV_EXT_COOKIE;
    case EXT_PSK_MODES:
        return SRV_EXT_PSK_MODES;
    case EXT_KEY_SHARE:
        return SRV_EXT_KEY_SHARE;
    case EXT_EARLY_DATA:
        return SRV_EXT_EARLY_DATA;
    case EXT_PADDING:
        return SRV_EXT_PADDING;
    case EXT_QUIC_TRANSPORT_PARAMS:
        return SRV_EXT_QUIC_TRANSPORT_PARAMS;
    default:
        return 0;
    }
}

int srv_ext_known(uint16_t type) {
    return ext_bit(type) != 0;
}

// Whether the frozen digest covers an extension of this type. RFC 9846
// §4.2.2 lets a second ClientHello change five extensions and nothing
// else (rfc9846.txt:1191-1213): the key_share it replaces, the
// early_data it removes, the cookie it adds, the pre_shared_key it
// updates and the padding whose length it may change. The digest leaves
// each of those out whole, so a second hello that changes anything else
// changes the digest.
static int frozen_covers(uint16_t type) {
    return type != EXT_KEY_SHARE && type != EXT_EARLY_DATA && type != EXT_COOKIE &&
           type != EXT_PRE_SHARED_KEY && type != EXT_PADDING;
}

// The fields before the extension block, §4.2.2's legacy_version
// through legacy_compression_methods, and the head's share of the
// frozen digest.
static int parse_head(rbuf *r, const uint8_t *body, hello_parse *p) {
    client_hello *ch = p->ch;
    // legacy_version is read and not judged. §4.2.2 has a server that
    // sees supported_versions ignore it (rfc9846.txt:1306-1313), and a
    // hello without supported_versions is refused for that absence in
    // check_required, so no value here changes a verdict.
    (void)rb_u16(r);
    const uint8_t *random_bytes = rb_bytes(r, SRV_RANDOM);
    if (random_bytes == NULL) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    memcpy(ch->random, random_bytes, SRV_RANDOM);
    // legacy_session_id<0..32>.
    size_t session_id_len = rb_u8(r);
    const uint8_t *session_id = rb_bytes(r, session_id_len);
    if (session_id == NULL || session_id_len > SRV_SESSION_ID_MAX) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    memcpy(ch->session_id, session_id, session_id_len);
    ch->session_id_len = (uint8_t)session_id_len;
    // cipher_suites<2..2^16-2>: every code point outside this build's
    // one suite is read and ignored (rfc9846.txt:4636-4637).
    size_t suites_len = 0;
    if (!srv_open_code_point_list(r, &suites_len)) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    if (srv_list_has(r, suites_len, SUITE_CHACHA20_POLY1305_SHA256)) {
        ch->suites |= SRV_SUITE_CHACHA20_POLY1305;
    }
#ifdef CH_SUITE_AES_GCM
    if (srv_list_has(r, suites_len, SUITE_AES_128_GCM_SHA256)) {
        ch->suites |= SRV_SUITE_AES_128_GCM;
    }
#endif
    // legacy_compression_methods: exactly one zero byte, or
    // illegal_parameter (rfc9846.txt:1284-1288).
    size_t compression_len = rb_u8(r);
    const uint8_t *compression = rb_bytes(r, compression_len);
    if (compression == NULL) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    if (compression_len != 1 || compression[0] != 0) {
        return srv_refuse(p->alert, ALERT_ILLEGAL_PARAMETER);
    }
    // Every byte read so far is frozen across a HelloRetryRequest.
    sha256_update(&p->frozen, body, p->n - rb_left(r));
    return CH_OK;
}

// Whether the first n bytes of exts, a prefix that ends on an extension
// boundary, hold an extension of this type.
static int type_before(const uint8_t *exts, size_t n, uint16_t type) {
    rbuf r;
    rb_init(&r, exts, n);
    while (rb_left(&r) > 0) {
        uint16_t seen = rb_u16(&r);
        rb_skip(&r, rb_u16(&r));
        if (r.err) {
            return 0;
        }
        if (seen == type) {
            return 1;
        }
    }
    return 0;
}

int srv_ext_over_max(const uint8_t *exts, size_t n) {
    rbuf r;
    rb_init(&r, exts, n);
    // How many whole extensions the walk has read. The walk stops at the
    // first one past SRV_CLIENT_HELLO_EXT_MAX, so this never exceeds
    // SRV_CLIENT_HELLO_EXT_MAX + 1.
    size_t count = 0;
    while (rb_left(&r) > 0) {
        (void)rb_u16(&r);
        rb_skip(&r, rb_u16(&r));
        if (r.err) {
            // Malformed framing before the count passed
            // SRV_CLIENT_HELLO_EXT_MAX: the caller's own walk answers
            // decode_error.
            return 0;
        }
        count++;
        if (count > SRV_CLIENT_HELLO_EXT_MAX) {
            return 1;
        }
    }
    return 0;
}

int srv_ext_duplicate(const uint8_t *exts, size_t n) {
    rbuf r;
    rb_init(&r, exts, n);
    // How many bytes of the block sit before the extension being read.
    size_t before = 0;
    while (rb_left(&r) > 0) {
        uint16_t type = rb_u16(&r);
        size_t len = rb_u16(&r);
        rb_skip(&r, len);
        if (r.err) {
            // Malformed framing: the caller's own walk answers
            // decode_error, and this predicate says nothing about it.
            return 0;
        }
        if (type_before(exts, before, type)) {
            return 1;
        }
        before += 4 + len;
    }
    return 0;
}

// The covered extension with the smallest type at or above lowest_type: a
// pointer to its first byte, with its type in *type and its body length
// in *len. Returns NULL when the block holds no covered extension of
// such a type, and NULL when the block's framing is malformed, which
// srv_parse_client_hello has refused before it calls add_frozen_extensions.
//
// Of two extensions with one type it reports the first, because only a
// strictly smaller type replaces the one it holds.
// add_frozen_extensions would then never add the second, which is why
// the parser refuses a duplicate before that call.
static const uint8_t *next_covered(const uint8_t *exts, size_t n, uint32_t lowest_type,
                                   uint16_t *type, size_t *len) {
    const uint8_t *found = NULL;
    rbuf r;
    rb_init(&r, exts, n);
    while (rb_left(&r) > 0) {
        // A zero-length read returns the current position and advances
        // nothing.
        const uint8_t *ext = rb_bytes(&r, 0);
        uint16_t ext_type = rb_u16(&r);
        size_t ext_len = rb_u16(&r);
        rb_skip(&r, ext_len);
        if (r.err) {
            return NULL;
        }
        if (frozen_covers(ext_type) && ext_type >= lowest_type &&
            (found == NULL || ext_type < *type)) {
            found = ext;
            *type = ext_type;
            *len = ext_len;
        }
    }
    return found;
}

// Adds every covered extension of the block to the frozen digest, whole
// and in ascending type order. The order is the types' rather than the
// wire's because RFC 9846 §4.3 lets extensions appear in any order
// (rfc9846.txt:1669-1670), and a second ClientHello that keeps each
// extension and changes the order changes nothing §4.2.2 freezes
// (docs/decisions.md 59).
//
// Requires a block srv_ext_duplicate cleared, so no two extensions share
// a type: each pass adds the extension of the smallest type above the
// last one added, so a second extension of one type would never be
// added. With distinct types the bytes hashed are one string per set of
// covered extensions, because each extension carries its own type and
// length.
//
// Each pass walks the whole block, and there is one pass per covered
// extension and one more, so a block of n extensions costs at most
// (n + 1) * n header reads. srv_parse_client_hello has refused a block
// of more than SRV_CLIENT_HELLO_EXT_MAX extensions before it calls this,
// and docs/decisions.md 59 gives the worst case that leaves.
static void add_frozen_extensions(sha256 *frozen, const uint8_t *exts, size_t n) {
    // The smallest type the next pass may add. It is 32 bits wide, so the
    // pass after type 0xffff looks above every type and finds none.
    uint32_t lowest_type = 0;
    for (;;) {
        uint16_t type = 0;
        size_t len = 0;
        const uint8_t *ext = next_covered(exts, n, lowest_type, &type, &len);
        if (ext == NULL) {
            return;
        }
        sha256_update(frozen, ext, 4 + len);
        lowest_type = (uint32_t)type + 1;
    }
}

// One extension: its framing and its reader. It runs on the message
// reader, whose remaining bytes are the block's, because the block ends
// the message.
static int parse_extension(rbuf *r, hello_parse *p) {
    client_hello *ch = p->ch;
    // pre_shared_key must be the last extension (rfc9846.txt:2564-2567),
    // so any extension after it is illegal_parameter.
    if ((ch->seen & SRV_EXT_PRE_SHARED_KEY) != 0) {
        return srv_refuse(p->alert, ALERT_ILLEGAL_PARAMETER);
    }
    // Where this extension's body starts, counted from the start of the
    // message: four header bytes past the current position.
    size_t data_off = p->n - rb_left(r) + 4;
    uint16_t type = rb_u16(r);
    size_t len = rb_u16(r);
    const uint8_t *data = rb_bytes(r, len);
    if (data == NULL) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    // §4.2.2: an unrecognized extension is skipped by its length and
    // reaches no check (rfc9846.txt:1299).
    if (!srv_ext_known(type)) {
        return CH_OK;
    }
    ch->seen |= ext_bit(type);
    rbuf e;
    rb_init(&e, data, len);
    int rc = srv_read_extension(&e, type, data_off, p);
    if (rc != CH_OK) {
        return rc;
    }
    // extension_data matches its struct exactly, so bytes left inside
    // the body are decode_error (rfc9846.txt:1561-1565).
    if (e.err || rb_left(&e) != 0) {
        return srv_refuse(p->alert, ALERT_DECODE_ERROR);
    }
    return CH_OK;
}

// The checks a single pass cannot make, over the seen mask.
static int check_required(const client_hello *ch, uint8_t *alert) {
    uint16_t seen = ch->seen;
    // No supported_versions: the client is not negotiating this version
    // (rfc9846.txt:1306-1313), which is protocol_version
    // (rfc9846.txt:3972-3973). A supported_versions without 0x0304 was
    // refused where it was read.
    if ((seen & SRV_EXT_SUPPORTED_VERSIONS) == 0) {
        return srv_refuse(alert, ALERT_PROTOCOL_VERSION);
    }
    // pre_shared_key without psk_key_exchange_modes: the server must
    // abort (rfc9846.txt:2306-2307), and illegal_parameter is this
    // design's choice under §6 (rfc9846.txt:3789-3791).
    if ((seen & SRV_EXT_PRE_SHARED_KEY) != 0 && (seen & SRV_EXT_PSK_MODES) == 0) {
        return srv_refuse(alert, ALERT_ILLEGAL_PARAMETER);
    }
    // §9.2 (rfc9846.txt:4595-4605): without pre_shared_key, both
    // signature_algorithms and supported_groups; and supported_groups
    // and key_share come together or not at all. missing_extension is
    // the alert §9.2 names. An empty client_shares list is a present
    // key_share (rfc9846.txt:4599-4601).
    uint16_t auth = SRV_EXT_SIGNATURE_ALGORITHMS | SRV_EXT_SUPPORTED_GROUPS;
    if ((seen & SRV_EXT_PRE_SHARED_KEY) == 0 && (seen & auth) != auth) {
        return srv_refuse(alert, ALERT_MISSING_EXTENSION);
    }
    if (((seen & SRV_EXT_SUPPORTED_GROUPS) == 0) != ((seen & SRV_EXT_KEY_SHARE) == 0)) {
        return srv_refuse(alert, ALERT_MISSING_EXTENSION);
    }
    // A KeyShareEntry for a group supported_groups did not list. §4.3.8
    // forbids the client to send one and names illegal_parameter for a
    // server that checks; a conformant client never sends it.
    if ((ch->shares & (uint8_t)~ch->groups) != 0) {
        return srv_refuse(alert, ALERT_ILLEGAL_PARAMETER);
    }
    return CH_OK;
}

int srv_parse_client_hello(const uint8_t *body, size_t n, client_hello *ch,
                           const ch_alpn_protocol *offered, size_t offered_count, uint8_t *alert) {
    hello_parse p;
    p.n = n;
    p.ch = ch;
    p.offered = offered;
    p.offered_count = offered_count;
    p.alert = alert;
    sha256_init(&p.frozen);
    // 0 is the first protocol in the caller's list, so the no-selection
    // value goes in before any reader can report one.
    ch->alpn_selected = CH_ALPN_NONE;

    rbuf r;
    rb_init(&r, body, n);
    int rc = parse_head(&r, body, &p);
    if (rc != CH_OK) {
        return rc;
    }
    // Nothing after the compression list is a ClientHello from before
    // this document, which §4.2.2's negotiation cannot bring to this
    // version: protocol_version (rfc9846.txt:1306-1313,
    // rfc9846.txt:3972-3973).
    if (rb_left(&r) == 0) {
        return srv_refuse(alert, ALERT_PROTOCOL_VERSION);
    }
    // The extension block ends the message. Its own lower bound,
    // extensions<8..2^16-1>, is not judged here: a shorter block is TLS
    // 1.2 syntax, and check_required answers such a hello with
    // protocol_version once no supported_versions has been read.
    size_t exts_len = rb_u16(&r);
    if (r.err || exts_len != rb_left(&r)) {
        return srv_refuse(alert, ALERT_DECODE_ERROR);
    }
    // The block's first byte, for the count, the duplicate check and the
    // frozen digest. A zero-length read returns the current position and
    // advances nothing.
    const uint8_t *exts = rb_bytes(&r, 0);
    // At most SRV_CLIENT_HELLO_EXT_MAX extensions, counted before the two
    // walks whose cost is the square of the count (docs/decisions.md
    // 59). RFC 9846 bounds the block's bytes and not its count
    // (rfc9846.txt:1237), so a block of more parses under the syntax and
    // the refusal is not decode_error (rfc9846.txt:3785-3788);
    // illegal_parameter is this design's choice under §6
    // (rfc9846.txt:3789-3791).
    if (srv_ext_over_max(exts, exts_len)) {
        return srv_refuse(alert, ALERT_ILLEGAL_PARAMETER);
    }
    // One extension of each type per block (rfc9846.txt:1673-1674);
    // illegal_parameter is this design's choice under §6
    // (rfc9846.txt:3789-3791). add_frozen_extensions needs it as well.
    if (srv_ext_duplicate(exts, exts_len)) {
        return srv_refuse(alert, ALERT_ILLEGAL_PARAMETER);
    }
    while (rb_left(&r) > 0) {
        rc = parse_extension(&r, &p);
        if (rc != CH_OK) {
            return rc;
        }
    }
    add_frozen_extensions(&p.frozen, exts, exts_len);
    sha256_final(&p.frozen, ch->frozen);
    return check_required(ch, alert);
}

#endif // CH_ROLE_SERVER
