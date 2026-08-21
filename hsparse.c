// The two attacker-facing handshake message parsers, split out of
// handshake.c so proof, fuzz, and strictness-test builds compile them
// without the state machine. Contract in hsparse.h.
#include "hsparse.h"

#include <string.h>

#include "buf.h"
#include "cfg.h"
#include "hsmsg.h"

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
        // We offer only x25519, so an HRR can never legally ask for a
        // different share: selecting ours is redundant (illegal) and
        // selecting another group is unsupported. Both are fatal.
        return CH_EPROTO;
    }
    if (rb_u16(e) != GROUP_X25519 || rb_u16(e) != X25519_LEN) {
        return CH_EPROTO;
    }
    const uint8_t *pub = rb_bytes(e, X25519_LEN);
    if (pub == NULL) {
        return CH_EPROTO;
    }
    memcpy(info->server_pub, pub, X25519_LEN);
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
    if (ext == EXT_PRE_SHARED_KEY && !psk_mode) {
        return CH_EPROTO; // selecting a PSK we never offered
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

// Encrypted extensions: take the peer's record_size_limit, tolerate
// supported_groups (a server may volunteer it for later connections),
// reject everything else — RFC 9846 §4.3 requires unsupported_extension
// for anything the ClientHello did not offer.
// Certificate framing per RFC 9846 §4.4.2; the entries themselves
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

// CertificateVerify per RFC 9846 §4.4.3: we offered exactly one
// signature algorithm, so the message may carry nothing else.
int hsp_parse_certificate_verify(const uint8_t *body, size_t n, const uint8_t **sig,
                                 size_t *sig_len, uint8_t *alert) {
    rbuf r;
    rb_init(&r, body, n);
    if (rb_u16(&r) != CH_PIN_SIGALG) {
        *alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EAUTH;
    }
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

int hsp_parse_encrypted_exts(const uint8_t *body, size_t n, uint16_t *peer_limit, uint8_t *alert) {
    rbuf r;
    rb_init(&r, body, n);
    size_t exts_len = rb_u16(&r);
    if (r.err || exts_len != rb_left(&r)) {
        return CH_EPROTO;
    }
    uint8_t seen = 0; // bit 0 record_size_limit, bit 1 supported_groups
    while (rb_left(&r) > 0) {
        uint16_t ext = rb_u16(&r);
        size_t ext_len = rb_u16(&r);
        const uint8_t *ext_data = rb_bytes(&r, ext_len);
        if (ext_data == NULL) {
            return CH_EPROTO;
        }
        uint8_t bit;
        if (ext == EXT_RECORD_SIZE_LIMIT) {
            bit = 1U << 0;
            if (parse_record_size_limit(ext_data, ext_len, peer_limit) != CH_OK) {
                return CH_EPROTO;
            }
        } else if (ext == EXT_SUPPORTED_GROUPS) {
            bit = 1U << 1; // tolerated; its body is deliberately unread
        } else {
            *alert = ALERT_UNSUPPORTED_EXTENSION;
            return CH_EPROTO;
        }
        if (seen & bit) {
            return CH_EPROTO; // RFC 9846 §4.3: one extension of each type
        }
        seen |= bit;
    }
    return CH_OK;
}
