// Certificate extensions for the web PKI trust mode (TRUST=webpki): the
// walk over one certificate's extensions [3] field, which judges the
// four extensions the profile reads and skips or refuses the rest.
// Contract in webpki.h; the profile in docs/webpki.md ("The chain
// walk", steps 3 and 6c, and "What the mode does not check"). x509.c's
// parse_extensions is the ca mode's walk over the same grammar. That
// walk byte-compares each extension value against the one value the ca
// profile admits. Public CAs write several values for each extension,
// so this walk decodes keyUsage, extendedKeyUsage and basicConstraints.
// Every byte here is public, so variable time is fine and deliberate.
#include "webpki.h"

#include "buf.h"
#include "ct.h"
#include "handshake_message.h"
#include "x509_der.h"

// DER tags this file reads.
#define TAG_BOOLEAN 0x01
#define TAG_INTEGER 0x02
#define TAG_OBJECT_IDENTIFIER 0x06
#define TAG_SEQUENCE 0x30
#define TAG_EXTENSIONS 0xa3 // [3] EXPLICIT, constructed

// Extension OID contents, arc 2.5.29 (RFC 5280 §4.2.1).
static const uint8_t oid_key_usage[] = {0x55, 0x1d, 0x0f};
static const uint8_t oid_subject_alt_name[] = {0x55, 0x1d, 0x11};
static const uint8_t oid_basic_constraints[] = {0x55, 0x1d, 0x13};
static const uint8_t oid_ext_key_usage[] = {0x55, 0x1d, 0x25};

// id-kp-serverAuth, 1.3.6.1.5.5.7.3.1 (RFC 5280 §4.2.1.12), content octets.
static const uint8_t oid_server_auth[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};

// cA TRUE: the one DER encoding of a BOOLEAN TRUE. A FALSE cA is the
// DEFAULT, so DER leaves it absent (X.690 §11.5).
static const uint8_t ca_true[] = {TAG_BOOLEAN, 0x01, 0xff};

// The keyUsage bits each arm needs, in x509_read_keyusage's mask over
// the first named-bit octet (RFC 5280 §4.2.1.3).
#define KEY_USAGE_DIGITAL_SIGNATURE 0x80
#define KEY_USAGE_KEY_CERT_SIGN 0x04

// pathLenConstraint content octets: two hold every value up to 32767,
// far past CH_WEBPKI_CHAIN_MAX.
#define PATH_LEN_CONTENT_MAX 2

// The bits webpki_read_extensions requires in out->seen, per arm.
#define LEAF_REQUIRED (WEBPKI_EXT_KEY_USAGE | WEBPKI_EXT_EXT_KEY_USAGE | WEBPKI_EXT_SAN)
#define ISSUER_REQUIRED (WEBPKI_EXT_KEY_USAGE | WEBPKI_EXT_BASIC_CONSTRAINTS)

static int bytes_are(const uint8_t *got, size_t n, const uint8_t *want, size_t want_n) {
    return n == want_n && ct_memeq(got, want, want_n) != 0;
}

// The WEBPKI_EXT_* bit an extnID names, or 0 for an extnID this walk
// does not read.
static uint8_t extension_bit(const x509_extension *ext) {
    if (bytes_are(ext->oid, ext->oid_len, oid_key_usage, sizeof oid_key_usage)) {
        return WEBPKI_EXT_KEY_USAGE;
    }
    if (bytes_are(ext->oid, ext->oid_len, oid_ext_key_usage, sizeof oid_ext_key_usage)) {
        return WEBPKI_EXT_EXT_KEY_USAGE;
    }
    if (bytes_are(ext->oid, ext->oid_len, oid_basic_constraints, sizeof oid_basic_constraints)) {
        return WEBPKI_EXT_BASIC_CONSTRAINTS;
    }
    if (bytes_are(ext->oid, ext->oid_len, oid_subject_alt_name, sizeof oid_subject_alt_name)) {
        return WEBPKI_EXT_SAN;
    }
    return 0;
}

// Sets *alert to ALERT_UNSUPPORTED_CERTIFICATE and returns CH_EPROTO:
// the extension is well-formed and breaks the profile.
static int off_profile(uint8_t *alert) {
    *alert = ALERT_UNSUPPORTED_CERTIFICATE;
    return CH_EPROTO;
}

// One KeyPurposeId: an OBJECT IDENTIFIER with content. Sets *server_auth
// to 1 when it is id-kp-serverAuth, byte for byte, and leaves it alone
// otherwise; no other OID is interpreted. Returns 1, or 0 on malformed
// DER.
static int read_purpose(rbuf *v, int *server_auth) {
    size_t oid_len = 0;
    if (!x509_read_header(v, TAG_OBJECT_IDENTIFIER, &oid_len) || oid_len == 0) {
        return 0;
    }
    const uint8_t *oid = rb_bytes(v, oid_len);
    if (oid == NULL) {
        return 0;
    }
    if (bytes_are(oid, oid_len, oid_server_auth, sizeof oid_server_auth)) {
        *server_auth = 1;
    }
    return 1;
}

// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId, filling
// the extnValue exactly. Sets *server_auth to 1 when one KeyPurposeId
// is id-kp-serverAuth and to 0 otherwise. Returns 1, or 0 on malformed
// DER.
static int read_ext_key_usage(const uint8_t *value, size_t value_len, int *server_auth) {
    rbuf v;
    rb_init(&v, value, value_len);
    size_t list_len = 0;
    if (!x509_read_header(&v, TAG_SEQUENCE, &list_len) || list_len == 0 ||
        list_len != rb_left(&v)) {
        return 0;
    }
    *server_auth = 0;
    while (rb_left(&v) > 0) {
        if (!read_purpose(&v, server_auth)) {
            return 0;
        }
    }
    return !v.err;
}

// pathLenConstraint INTEGER (0..MAX) in canonical DER: one or two
// content octets, non-negative, and no 0x00 pad the value does not
// need. Returns 1 and sets *path_len, or 0.
static int read_path_len(rbuf *v, int *path_len) {
    size_t len = 0;
    if (!x509_read_header(v, TAG_INTEGER, &len) || len == 0 || len > PATH_LEN_CONTENT_MAX) {
        return 0;
    }
    const uint8_t *c = rb_bytes(v, len);
    if (c == NULL || (c[0] & 0x80) != 0) {
        return 0; // negative
    }
    if (len == 1) {
        *path_len = c[0];
        return 1;
    }
    if (c[0] == 0 && (c[1] & 0x80) == 0) {
        return 0; // a pad the value does not need
    }
    *path_len = (int)c[0] * 256 + (int)c[1];
    return 1;
}

// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
// pathLenConstraint INTEGER (0..MAX) OPTIONAL } (RFC 5280 §4.2.1.9),
// filling the extnValue exactly. Sets *ca to 1 when cA is present,
// which DER allows only as TRUE, and *path_len to the constraint or -1
// when absent. Returns 1, or 0 on malformed DER.
static int read_basic_constraints(const uint8_t *value, size_t value_len, int *ca, int *path_len) {
    rbuf v;
    rb_init(&v, value, value_len);
    size_t seq_len = 0;
    if (!x509_read_header(&v, TAG_SEQUENCE, &seq_len) || seq_len != rb_left(&v)) {
        return 0;
    }
    *ca = 0;
    *path_len = -1;
    rbuf next = v;
    if (rb_left(&v) > 0 && rb_u8(&next) == TAG_BOOLEAN) {
        if (!x509_read_exact(&v, ca_true, sizeof ca_true)) {
            return 0; // FALSE written out, or TRUE in a non-DER byte
        }
        *ca = 1;
    }
    if (rb_left(&v) > 0 && !read_path_len(&v, path_len)) {
        return 0;
    }
    return !v.err && rb_left(&v) == 0;
}

// basicConstraints against the arm. The leaf asserts no CA. An issuer
// marks the extension critical and asserts CA (RFC 5280 §4.2.1.9 makes
// both a MUST for a CA that signs certificates). A pathLenConstraint
// without cA TRUE breaks the same section on either arm. Records cA
// and the constraint in out.
static int judge_basic_constraints(const x509_extension *ext, int is_ca, webpki_cert *out,
                                   uint8_t *alert) {
    int ca = 0;
    int path_len = -1;
    if (!read_basic_constraints(ext->value, ext->value_len, &ca, &path_len)) {
        return CH_EPROTO;
    }
    if (ca != is_ca || (is_ca && !ext->critical) || (!ca && path_len >= 0)) {
        return off_profile(alert);
    }
    out->is_ca = (uint8_t)ca;
    out->path_len = path_len;
    return CH_OK;
}

// One recognized extension, its seen bit already recorded. keyUsage
// needs the arm's bit and admits others beside it: an RSA leaf often
// asserts keyEncipherment too, and an issuer cRLSign.
// extendedKeyUsage needs id-kp-serverAuth on the leaf and is not read
// on an issuer. subjectAltName is recorded for webpki_match_san and not
// read here.
static int judge_extension(const x509_extension *ext, uint8_t bit, int is_ca, webpki_cert *out,
                           uint8_t *alert) {
    if (bit == WEBPKI_EXT_KEY_USAGE) {
        uint8_t required = is_ca ? KEY_USAGE_KEY_CERT_SIGN : KEY_USAGE_DIGITAL_SIGNATURE;
        // x509_read_keyusage answers one 0 for malformed DER and for a
        // missing bit, so both report the off-profile alert, as x509.c's do.
        return x509_read_keyusage(ext->value, ext->value_len, required) ? CH_OK
                                                                        : off_profile(alert);
    }
    if (bit == WEBPKI_EXT_EXT_KEY_USAGE) {
        int server_auth = 0;
        if (is_ca) {
            return CH_OK;
        }
        if (!read_ext_key_usage(ext->value, ext->value_len, &server_auth)) {
            return CH_EPROTO;
        }
        return server_auth ? CH_OK : off_profile(alert);
    }
    if (bit == WEBPKI_EXT_BASIC_CONSTRAINTS) {
        return judge_basic_constraints(ext, is_ca, out, alert);
    }
    out->san = ext->value;
    out->san_len = ext->value_len;
    return CH_OK;
}

// One Extension TLV of at most CH_WEBPKI_EXT_TLV_MAX bytes.
static int read_one_extension(rbuf *list, int is_ca, webpki_cert *out, uint8_t *alert) {
    x509_extension ext;
    if (!x509_read_extension(list, CH_WEBPKI_EXT_TLV_MAX, &ext)) {
        return CH_EPROTO;
    }
    uint8_t bit = extension_bit(&ext);
    if (bit == 0) {
        // RFC 5280 §4.2: an unrecognized critical extension MUST be
        // refused. This is the rule that refuses nameConstraints, the
        // policy extensions and the CT poison extension.
        return ext.critical ? off_profile(alert) : CH_OK;
    }
    if ((out->seen & bit) != 0) {
        // RFC 5280 §4.2: a certificate MUST NOT carry one extension twice.
        return off_profile(alert);
    }
    out->seen |= bit;
    return judge_extension(&ext, bit, is_ca, out, alert);
}

int webpki_read_extensions(rbuf *t, int is_ca, webpki_cert *out, uint8_t *alert) {
    out->seen = 0;
    out->is_ca = 0;
    out->path_len = -1;
    out->san = NULL;
    out->san_len = 0;
    size_t wrap_len = 0;
    if (!x509_read_header(t, TAG_EXTENSIONS, &wrap_len)) {
        return CH_EPROTO;
    }
    const uint8_t *wrap = rb_bytes(t, wrap_len);
    if (wrap == NULL) {
        return CH_EPROTO;
    }
    rbuf list;
    rb_init(&list, wrap, wrap_len);
    size_t list_len = 0;
    if (!x509_read_header(&list, TAG_SEQUENCE, &list_len) || list_len == 0 ||
        list_len != rb_left(&list)) {
        return CH_EPROTO; // Extensions is SIZE (1..MAX) and fills its wrapper
    }
    size_t ext_count = 0;
    while (rb_left(&list) > 0) {
        ext_count++;
        if (ext_count > CH_WEBPKI_EXT_COUNT_MAX) {
            return CH_EPROTO; // a cap, so the caller's ALERT_BAD_CERTIFICATE (webpki.h)
        }
        int rc = read_one_extension(&list, is_ca != 0, out, alert);
        if (rc != CH_OK) {
            return rc;
        }
    }
    uint8_t required = is_ca != 0 ? ISSUER_REQUIRED : LEAF_REQUIRED;
    if ((out->seen & required) != required) {
        return off_profile(alert);
    }
    return CH_OK;
}
