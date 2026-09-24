// The ServerHello, Certificate and CertificateVerify parsers, split out
// of handshake.c so proof, fuzz, and strictness-test builds compile them
// without the state machine. The EncryptedExtensions parser is in
// handshake_parser_ee.c. Contract in handshake_parser.h.
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
        return HSP_SEEN_PRE_SHARED_KEY;
    case EXT_COOKIE:
        return 1U << 3;
    default:
        return 0; // ServerHello may carry nothing else
    }
}

#ifdef CH_KEX_TWO_GROUPS
// key_share in a ServerHello that selected x25519, whose share the hello
// of the build that offers two groups carried beside the hybrid one: the
// group, a 32-byte length and the server's public value.
static int parse_x25519_share(rbuf *e, server_hello_info *info) {
    if (rb_u16(e) != X25519_LEN) {
        return CH_EPROTO;
    }
    const uint8_t *pub = rb_bytes(e, X25519_LEN);
    if (pub == NULL) {
        return CH_EPROTO;
    }
    memcpy(info->server_pub, pub, X25519_LEN);
    info->group = CH_GROUP_X25519;
    info->have_share = 1;
    return CH_OK;
}
#endif

#ifdef CH_SUITE_AES_GCM
// Whether this client's ClientHello offered suite: ChaCha20 always, and
// AES-128-GCM from the client that offers both (CH_CLIENT_TWO_SUITES).
// RFC 9846 §4.2.3 makes any other suite an illegal_parameter abort
// (rfc9846.txt:1373-1376).
static int suite_offered(uint16_t suite) {
#ifdef CH_CLIENT_TWO_SUITES
    return suite == SUITE_CHACHA20_POLY1305_SHA256 || suite == SUITE_AES_128_GCM_SHA256;
#else
    return suite == SUITE_CHACHA20_POLY1305_SHA256;
#endif
}
#endif

// key_share: a group this client sent a share for, echoed with the
// server's share.
static int parse_key_share(rbuf *e, server_hello_info *info, int hrr) {
    if (hrr) {
        // Every group the hello lists in supported_groups also has a share
        // in its key_share: the build's one group, both groups in a
        // CH_KEX_TWO_GROUPS build, or the hybrid alone there under
        // require_pq, which lists the hybrid alone. So a retry that names
        // a group names one the hello already sent a share for or one it
        // never listed, and RFC 9846 §4.3.8 makes both an
        // illegal_parameter abort (rfc9846.txt:2205-2212).
        return CH_EPROTO;
    }
    uint16_t group = rb_u16(e);
#ifdef CH_KEX_TWO_GROUPS
    if (group == CH_GROUP_X25519) {
        return parse_x25519_share(e, info);
    }
    if (group != CH_GROUP_X25519MLKEM768 || rb_u16(e) != CH_HYBRID_SERVER_SHARE) {
        return CH_EPROTO;
    }
#else
    if (group != CH_KEX_GROUP || rb_u16(e) != CH_KEX_SERVER_SHARE) {
        return CH_EPROTO;
    }
#endif
#ifdef CH_KEX_HYBRID
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
#ifdef CH_SUITE_AES_GCM
    info->suite = rb_u16(&r);
    if (!suite_offered(info->suite) || rb_u8(&r) != 0) {
        return CH_EPROTO;
    }
#else
    if (rb_u16(&r) != SUITE_CHACHA20_POLY1305_SHA256 || rb_u8(&r) != 0) {
        return CH_EPROTO;
    }
#endif
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
