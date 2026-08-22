// Canonical-DER primitives for the profiled certificate parser. The
// mechanism is a length-first strict decoder: every routine rejects a
// non-minimal or malformed encoding before any field is interpreted,
// so no value ever has a second accepted representation on the
// decoded spine. Contract in x509.h; profile in x509.c.
#include "x509.h"

#include "buf.h"
#include "cfg.h"
#include "ct.h"

// One DER length. Definite form only, and the shortest form that
// fits: short form under 0x80, long form 0x81 for 0x80..0xff, 0x82
// for 0x100 up. Three or more length octets cannot occur under
// CH_X509_MAX. The length must also fit the bytes that remain.
int x509_read_len(rbuf *r, size_t *out_len) {
    size_t len = rb_u8(r);
    if (len == 0x80 || len > 0x82) {
        return 0; // indefinite, or over the input cap
    }
    if (len == 0x81) {
        len = rb_u8(r);
        if (len < 0x80) {
            return 0; // short form would fit
        }
    } else if (len == 0x82) {
        size_t hi = rb_u8(r);
        size_t lo = rb_u8(r);
        len = (hi << 8) | lo;
        if (len < 0x100) {
            return 0; // one length octet would fit
        }
    }
    if (r->err || len > rb_left(r)) {
        return 0;
    }
    *out_len = len;
    return 1;
}

int x509_read_header(rbuf *r, uint8_t tag, size_t *out_len) {
    if (rb_u8(r) != tag || r->err) {
        return 0;
    }
    return x509_read_len(r, out_len);
}

// Literal compare against a pinned encoding. Certificate bytes are
// public; ct_memeq is INV-16's designated comparator either way.
int x509_read_exact(rbuf *r, const uint8_t *want, size_t n) {
    const uint8_t *got = rb_bytes(r, n);
    if (got == NULL) {
        return 0;
    }
    return ct_memeq(got, want, n) != 0;
}

int x509_skip(rbuf *r, uint8_t tag) {
    size_t len = 0;
    if (!x509_read_header(r, tag, &len)) {
        return 0;
    }
    rb_skip(r, len);
    return !r->err;
}

// serialNumber: INTEGER, positive, nonzero, minimal; value at most 20
// bytes (RFC 5280 §4.1.2.2 bounds the value, not the encoding), so
// content reaches 21 exactly when a top-bit-set value needs the 0x00
// pad. CAs that draw 20 random bytes stay admissible.
int x509_read_serial(rbuf *r) {
    size_t len = 0;
    if (!x509_read_header(r, 0x02, &len)) {
        return 0;
    }
    if (len == 0 || len > 21) {
        return 0;
    }
    const uint8_t *c = rb_bytes(r, len);
    if (c == NULL) {
        return 0;
    }
    if (c[0] & 0x80) {
        return 0; // negative
    }
    if (c[0] == 0 && (len == 1 || !(c[1] & 0x80))) {
        return 0; // zero, or a pad the value does not need
    }
    if (len == 21 && c[0] != 0) {
        return 0; // 21-byte value: over the RFC cap
    }
    return 1;
}

// One Time, shared by both readers: UTCTime "YYMMDDHHMMSSZ" (13
// bytes) or GeneralizedTime "YYYYMMDDHHMMSSZ" (15), the only shapes
// RFC 5280 §4.1.2.5 admits. Each ends in 'Z'; zulu is the only
// admitted zone. Yields the content bytes; x509_read_time ignores
// them because no clock exists to compare them against.
static int read_time_bytes(rbuf *r, const uint8_t **c, size_t *want) {
    uint8_t tag = rb_u8(r);
    if (tag == 0x17) {
        *want = 13;
    } else if (tag == 0x18) {
        *want = 15;
    } else {
        return 0;
    }
    if (rb_u8(r) != *want) {
        return 0;
    }
    *c = rb_bytes(r, *want);
    return *c != NULL && (*c)[*want - 1] == 0x5a;
}

int x509_read_time(rbuf *r) {
    const uint8_t *c = NULL;
    size_t want = 0;
    return read_time_bytes(r, &c, &want);
}

// keyUsage extnValue: a named-bit BIT STRING. Canonical DER strips
// trailing zero bits (X.690 §11.2.2), so digitalSignature-only is
// exactly 03 02 07 80. The unused-bit count must match the lowest
// set bit and the padding below it must be zero, or two encodings
// would name one bit set. required is the bit the caller demands in
// the first defined octet: 0x80 digitalSignature (leaf), 0x04
// keyCertSign (intermediate).
int x509_read_keyusage(const uint8_t *v, size_t n, uint8_t required) {
    rbuf r;
    rb_init(&r, v, n);
    size_t len = 0;
    if (!x509_read_header(&r, 0x03, &len)) {
        return 0;
    }
    if (len < 2 || len > 3) {
        return 0; // one unused-bits octet plus the 1..2 defined octets
    }
    const uint8_t *c = rb_bytes(&r, len);
    if (c == NULL || r.err || rb_left(&r) != 0) {
        return 0;
    }
    uint8_t unused = c[0];
    uint8_t last = c[len - 1];
    if (unused > 7 || last == 0) {
        return 0;
    }
    if ((last & (uint8_t)((1U << unused) - 1U)) != 0) {
        return 0; // padding bits must be zero
    }
    if (((last >> unused) & 1U) == 0) {
        return 0; // trailing zero bits must be absent
    }
    return (c[1] & required) != 0;
}

// A DER BIT STRING whose bits fill whole bytes: one zero
// unused-bits octet, then the bytes. Every BIT STRING this profile
// decodes — keys and signatures — has that shape.
int x509_read_bitstring(rbuf *r, const uint8_t **bytes, size_t *n) {
    size_t len = 0;
    if (!x509_read_header(r, 0x03, &len) || len < 1) {
        return 0;
    }
    if (rb_u8(r) != 0x00 || r->err) {
        return 0;
    }
    *bytes = rb_bytes(r, len - 1);
    if (*bytes == NULL) {
        return 0;
    }
    *n = len - 1;
    return 1;
}

// x509_read_time plus extraction. An epoch-shaped date — UTCTime,
// YY 00..49, DD 01..28, HHMMSS zero — yields its epoch number
// YY*336 + (MM-1)*28 + (DD-1) with ok = 1. Any other shape-valid Time
// passes with ok = 0; the driver decides whether to enforce.
int x509_read_time_epoch(rbuf *r, uint32_t *index, int *ok) {
    const uint8_t *c = NULL;
    size_t want = 0;
    *ok = 0;
    if (!read_time_bytes(r, &c, &want)) {
        return 0;
    }
    if (want != 13) {
        return 1; // GeneralizedTime is shape-valid, never epoch-shaped
    }
    uint32_t digit[12];
    for (int i = 0; i < 12; i++) {
        digit[i] = (uint32_t)c[i] - '0';
        if (digit[i] > 9) {
            return 1; // shape-valid Time, not all digits
        }
    }
    uint32_t yy = digit[0] * 10 + digit[1];
    uint32_t mm = digit[2] * 10 + digit[3];
    uint32_t dd = digit[4] * 10 + digit[5];
    uint32_t hms = digit[6] + digit[7] + digit[8] + digit[9] + digit[10] + digit[11];
    if (yy > 49 || mm < 1 || mm > 12 || dd < 1 || dd > 28 || hms != 0) {
        return 1; // a valid date, but not an allowed epoch
    }
    *index = yy * 336 + (mm - 1) * 28 + (dd - 1);
    *ok = 1;
    return 1;
}

// subjectPublicKeyInfo for the build's one algorithm. The
// AlgorithmIdentifier is byte-compared against its single canonical
// encoding; the key comes back as a pointer into the caller's
// buffer, valid only until that buffer is reused.
#ifdef CH_PIN_ECDSA
// id-ecPublicKey + prime256v1 (RFC 5480 §2.1.1).
static const uint8_t spki_algid[] = {0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                                     0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                                     0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

int x509_read_spki(rbuf *r, const uint8_t **key, size_t *key_len) {
    size_t len = 0;
    if (!x509_read_header(r, 0x30, &len)) {
        return 0;
    }
    const uint8_t *body = rb_bytes(r, len);
    if (body == NULL) {
        return 0;
    }
    rbuf s;
    rb_init(&s, body, len);
    if (!x509_read_exact(&s, spki_algid, sizeof spki_algid)) {
        return 0;
    }
    const uint8_t *bits = NULL;
    size_t bits_len = 0;
    if (!x509_read_bitstring(&s, &bits, &bits_len) || s.err || rb_left(&s) != 0) {
        return 0;
    }
    // The key itself: the uncompressed-point marker, then X||Y.
    rbuf pt;
    rb_init(&pt, bits, bits_len);
    if (rb_u8(&pt) != 0x04 || pt.err) {
        return 0;
    }
    *key = rb_bytes(&pt, 64);
    if (*key == NULL || rb_left(&pt) != 0) {
        return 0;
    }
    *key_len = 64;
    return 1;
}
#else
// rsaEncryption with its mandatory NULL parameters (RFC 3279 §2.3.1).
static const uint8_t spki_algid[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                     0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
// publicExponent: 65537 and nothing else.
static const uint8_t spki_exponent[] = {0x02, 0x03, 0x01, 0x00, 0x01};

// The modulus INTEGER, in value/content terms: every real modulus
// has its top bit set, so canonical DER demands exactly one 0x00 pad
// octet — a missing pad would read as negative, an unneeded pad is
// non-minimal. Yields the value bytes rsa_pss_verify consumes.
static int read_rsa_modulus(rbuf *k, const uint8_t **value, size_t *value_len) {
    size_t content_len = 0;
    if (!x509_read_header(k, 0x02, &content_len) || content_len < 2) {
        return 0;
    }
    if (rb_u8(k) != 0x00 || k->err) {
        return 0; // the pad octet
    }
    size_t n = content_len - 1;
    const uint8_t *v = rb_bytes(k, n);
    if (v == NULL) {
        return 0;
    }
    if (!(v[0] & 0x80)) {
        return 0; // a pad the value did not need
    }
    if (n < 256 || n > 384 || (n % 8) != 0) {
        return 0; // the verifier's own admitted range (rsa.h)
    }
    if ((v[n - 1] & 1U) == 0) {
        return 0; // rsa_mont's Montgomery arithmetic needs an odd modulus
    }
    *value = v;
    *value_len = n;
    return 1;
}

int x509_read_spki(rbuf *r, const uint8_t **key, size_t *key_len) {
    size_t len = 0;
    if (!x509_read_header(r, 0x30, &len)) {
        return 0;
    }
    const uint8_t *body = rb_bytes(r, len);
    if (body == NULL) {
        return 0;
    }
    rbuf s;
    rb_init(&s, body, len);
    if (!x509_read_exact(&s, spki_algid, sizeof spki_algid)) {
        return 0;
    }
    const uint8_t *bits = NULL;
    size_t bits_len = 0;
    if (!x509_read_bitstring(&s, &bits, &bits_len) || s.err || rb_left(&s) != 0) {
        return 0;
    }
    // RSAPublicKey ::= SEQUENCE { modulus, publicExponent }.
    rbuf k;
    rb_init(&k, bits, bits_len);
    size_t seq_len = 0;
    if (!x509_read_header(&k, 0x30, &seq_len) || seq_len != rb_left(&k)) {
        return 0;
    }
    if (!read_rsa_modulus(&k, key, key_len)) {
        return 0;
    }
    if (!x509_read_exact(&k, spki_exponent, sizeof spki_exponent)) {
        return 0;
    }
    return !k.err && rb_left(&k) == 0;
}
#endif

// X.690 §8.19: each OID subidentifier is base-128 with minimal
// octets — a subidentifier may not start with 0x80 — and the last
// octet completes one. Without this, one OID has many encodings and
// a duplicate could pose as an unknown extension.
static int oid_minimal(const uint8_t *oid, size_t n) {
    int at_subid_start = 1;
    for (size_t i = 0; i < n; i++) {
        if (at_subid_start && oid[i] == 0x80) {
            return 0;
        }
        at_subid_start = (oid[i] & 0x80) == 0;
    }
    return at_subid_start; // a set high bit on the last octet is a cut
}

// One Extension: SEQUENCE { extnID OBJECT IDENTIFIER, critical
// BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }. Canonical DER: a
// FALSE critical must be absent; TRUE is exactly 01 01 ff. The whole
// TLV must fit tlv_cap. Fills out with pointers into the caller's
// buffer.
int x509_read_extension(rbuf *e, size_t tlv_cap, x509_extension *out) {
    size_t xlen = 0;
    size_t before = rb_left(e);
    if (!x509_read_header(e, 0x30, &xlen) || before - rb_left(e) + xlen > tlv_cap) {
        return 0;
    }
    const uint8_t *body = rb_bytes(e, xlen);
    if (body == NULL) {
        return 0;
    }
    rbuf x;
    rb_init(&x, body, xlen);
    size_t oid_len = 0;
    if (!x509_read_header(&x, 0x06, &oid_len) || oid_len == 0 || oid_len > 16) {
        return 0;
    }
    out->oid = rb_bytes(&x, oid_len);
    out->oid_len = oid_len;
    if (out->oid == NULL || !oid_minimal(out->oid, oid_len)) {
        return 0;
    }
    uint8_t tag = rb_u8(&x);
    out->critical = 0;
    if (tag == 0x01) {
        uint8_t bool_len = rb_u8(&x);
        uint8_t bool_val = rb_u8(&x);
        if (bool_len != 0x01 || bool_val != 0xff || x.err) {
            return 0;
        }
        out->critical = 1;
        tag = rb_u8(&x);
    }
    if (tag != 0x04 || x.err) {
        return 0;
    }
    size_t vlen = 0;
    if (!x509_read_len(&x, &vlen)) {
        return 0;
    }
    out->value = rb_bytes(&x, vlen);
    out->value_len = vlen;
    return out->value != NULL && !x.err && rb_left(&x) == 0;
}

size_t x509_emit_header(uint8_t tag, size_t len, uint8_t out[4]) {
    out[0] = tag;
    if (len < 0x80) {
        out[1] = (uint8_t)len;
        return 2;
    }
    if (len < 0x100) {
        out[1] = 0x81;
        out[2] = (uint8_t)len;
        return 3;
    }
    out[1] = 0x82;
    out[2] = (uint8_t)(len >> 8);
    out[3] = (uint8_t)(len & 0xff);
    return 4;
}
