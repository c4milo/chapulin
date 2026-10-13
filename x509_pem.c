// The DER readers of the files an operator provisions. Contract in
// x509_pem.h.
//
// Every compare against a constant goes through x509_read_exact, which
// compares through ct_memeq. The key readers branch on a key's tags and
// lengths, which are the same for every P-256 key of one form. They copy
// the scalar with no branch and no index on its bytes.
#include "x509_pem.h"

#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "x509_der.h"

// DER tags this file reads.
#define TAG_INTEGER 0x02
#define TAG_BIT_STRING 0x03
#define TAG_OCTET_STRING 0x04
#define TAG_SEQUENCE 0x30
#define TAG_VERSION 0xa0           // [0] EXPLICIT Version, in a TBSCertificate
#define TAG_ISSUER_UNIQUE_ID 0x81  // [1] IMPLICIT UniqueIdentifier
#define TAG_SUBJECT_UNIQUE_ID 0x82 // [2] IMPLICIT UniqueIdentifier
#define TAG_EXTENSIONS 0xa3        // [3] EXPLICIT Extensions
#define TAG_CURVE 0xa0             // [0] ECParameters, in an ECPrivateKey
#define TAG_PUBLIC_KEY 0xa1        // [1] publicKey, in an ECPrivateKey

// id-ecPublicKey with the namedCurve prime256v1 (RFC 5480 section
// 2.1.1): the AlgorithmIdentifier SEQUENCE whole, as a P-256
// SubjectPublicKeyInfo and a P-256 PrivateKeyInfo both carry it.
static const uint8_t p256_algorithm[] = {0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                                         0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                                         0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
// A P-256 SubjectPublicKeyInfo around p256_algorithm. Before the
// algorithm is its SEQUENCE header of 89 bytes. After it is a BIT STRING
// of 66 bytes, the unused-bits octet 0 and the marker 0x04 of an
// uncompressed point.
static const uint8_t p256_spki_header[] = {0x30, 0x59};
static const uint8_t p256_spki_point_header[] = {0x03, 0x42, 0x00, 0x04};
// PrivateKeyInfo's version 0 (RFC 5958 section 2).
static const uint8_t pkcs8_version[] = {0x02, 0x01, 0x00};
// ECPrivateKey's version 1, and its privateKey OCTET STRING header for a
// 32-byte scalar (RFC 5915 section 3).
static const uint8_t ec_version[] = {0x02, 0x01, 0x01};
static const uint8_t ec_scalar_header[] = {0x04, 0x20};
// ECPrivateKey's parameters [0] that name prime256v1, and its publicKey
// [1] header for an uncompressed P-256 point. The header is a BIT STRING
// of 66 bytes, the unused-bits octet 0 and the marker 0x04.
static const uint8_t ec_curve[] = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                   0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
// ECParameters' namedCurve prime256v1 alone, an EC PARAMETERS block's
// whole DER: the OBJECT IDENTIFIER ec_curve holds inside its [0].
static const uint8_t p256_parameters[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                                          0xce, 0x3d, 0x03, 0x01, 0x07};
static const uint8_t ec_point_header[] = {0xa1, 0x44, 0x03, 0x42, 0x00, 0x04};

#define P256_SCALAR_BYTES 32
#define P256_XY_BYTES 64

// Whether an ECPrivateKey must name its curve. Inside a PKCS #8
// PrivateKeyInfo the AlgorithmIdentifier names it. Outside one, RFC 5915
// section 3 requires the field.
#define CURVE_OPTIONAL 0
#define CURVE_REQUIRED 1

// Whether the next byte is tag. r is not advanced.
static int tag_follows(const rbuf *r, uint8_t tag) {
    rbuf next = *r;
    uint8_t got = rb_u8(&next);
    return !next.err && got == tag;
}

// One TLV of tag, whole. Points *tlv at its bytes, header included,
// through a copy of the reader made before the read. webpki_cert.c's
// read_name does the same.
static int read_tlv(rbuf *r, uint8_t tag, const uint8_t **tlv, size_t *tlv_len) {
    rbuf start = *r;
    if (!x509_skip(r, tag)) {
        return 0;
    }
    *tlv_len = rb_left(&start) - rb_left(r);
    *tlv = rb_bytes(&start, *tlv_len);
    return *tlv != NULL;
}

// A field that may be absent: when the next byte is tag, one TLV of it.
static int skip_optional(rbuf *r, uint8_t tag) {
    return !tag_follows(r, tag) || x509_skip(r, tag);
}

// The TBSCertificate's fields in RFC 5280 section 4.1's order, each read
// for its outer fields alone, with the subject and the key kept whole.
static int read_tbs(const uint8_t *tbs, size_t tbs_len, const uint8_t **name, size_t *name_len,
                    const uint8_t **spki, size_t *spki_len) {
    rbuf t;
    rb_init(&t, tbs, tbs_len);
    if (!skip_optional(&t, TAG_VERSION) || !x509_skip(&t, TAG_INTEGER) ||
        !x509_skip(&t, TAG_SEQUENCE) || !x509_skip(&t, TAG_SEQUENCE) ||
        !x509_skip(&t, TAG_SEQUENCE)) {
        return 0; // version, serialNumber, signature, issuer, validity
    }
    if (!read_tlv(&t, TAG_SEQUENCE, name, name_len) ||
        !read_tlv(&t, TAG_SEQUENCE, spki, spki_len)) {
        return 0;
    }
    if (!skip_optional(&t, TAG_ISSUER_UNIQUE_ID) || !skip_optional(&t, TAG_SUBJECT_UNIQUE_ID) ||
        !skip_optional(&t, TAG_EXTENSIONS)) {
        return 0;
    }
    return !t.err && rb_left(&t) == 0;
}

int x509_pem_read_subject_key(const uint8_t *cert, size_t cert_len, const uint8_t **name,
                              size_t *name_len, const uint8_t **spki, size_t *spki_len) {
    CH_ASSERT(name != NULL && name_len != NULL && spki != NULL && spki_len != NULL);
    CH_ASSERT(cert != NULL || cert_len == 0);
    rbuf r;
    rb_init(&r, cert, cert_len);
    size_t body_len = 0;
    if (!x509_read_header(&r, TAG_SEQUENCE, &body_len) || body_len != rb_left(&r)) {
        return 0;
    }
    size_t tbs_len = 0;
    if (!x509_read_header(&r, TAG_SEQUENCE, &tbs_len)) {
        return 0;
    }
    const uint8_t *tbs = rb_bytes(&r, tbs_len);
    // signatureAlgorithm and signatureValue: their outer fields, and
    // nothing after them.
    if (tbs == NULL || !x509_skip(&r, TAG_SEQUENCE) || !x509_skip(&r, TAG_BIT_STRING) || r.err ||
        rb_left(&r) != 0) {
        return 0;
    }
    return read_tbs(tbs, tbs_len, name, name_len, spki, spki_len);
}

int x509_pem_spki_is_p256(const uint8_t *spki, size_t spki_len, const uint8_t point[64]) {
    CH_ASSERT(point != NULL);
    CH_ASSERT(spki != NULL || spki_len == 0);
    rbuf s;
    rb_init(&s, spki, spki_len);
    return x509_read_exact(&s, p256_spki_header, sizeof p256_spki_header) &&
           x509_read_exact(&s, p256_algorithm, sizeof p256_algorithm) &&
           x509_read_exact(&s, p256_spki_point_header, sizeof p256_spki_point_header) &&
           x509_read_exact(&s, point, P256_XY_BYTES) && rb_left(&s) == 0;
}

// ECPrivateKey's two optional fields, the curve and the point, after the
// scalar. Points *point at X||Y when the publicKey field is there, and
// leaves it as it was, NULL, when it is not.
static int read_ec_optional(rbuf *r, int curve_required, const uint8_t **point) {
    int has_curve = tag_follows(r, TAG_CURVE);
    if (curve_required && !has_curve) {
        return 0;
    }
    if (has_curve && !x509_read_exact(r, ec_curve, sizeof ec_curve)) {
        return 0;
    }
    if (tag_follows(r, TAG_PUBLIC_KEY)) {
        if (!x509_read_exact(r, ec_point_header, sizeof ec_point_header)) {
            return 0;
        }
        *point = rb_bytes(r, P256_XY_BYTES);
        if (*point == NULL) {
            return 0;
        }
    }
    return 1;
}

// ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING,
// parameters [0] OPTIONAL, publicKey [1] OPTIONAL }, which fills der.
// The call copies the scalar out only once every field has read.
static int read_ec_private_key(const uint8_t *der, size_t der_len, int curve_required,
                               uint8_t scalar[32], const uint8_t **point) {
    rbuf r;
    rb_init(&r, der, der_len);
    size_t len = 0;
    if (!x509_read_header(&r, TAG_SEQUENCE, &len) || len != rb_left(&r)) {
        return 0;
    }
    if (!x509_read_exact(&r, ec_version, sizeof ec_version) ||
        !x509_read_exact(&r, ec_scalar_header, sizeof ec_scalar_header)) {
        return 0;
    }
    const uint8_t *bytes = rb_bytes(&r, P256_SCALAR_BYTES);
    const uint8_t *xy = NULL;
    if (bytes == NULL || !read_ec_optional(&r, curve_required, &xy) || r.err || rb_left(&r) != 0) {
        return 0;
    }
    memcpy(scalar, bytes, P256_SCALAR_BYTES);
    *point = xy;
    return 1;
}

int x509_pem_read_pkcs8(const uint8_t *der, size_t der_len, uint8_t scalar[32],
                        const uint8_t **point) {
    CH_ASSERT(scalar != NULL && point != NULL);
    CH_ASSERT(der != NULL || der_len == 0);
    rbuf r;
    rb_init(&r, der, der_len);
    size_t len = 0;
    if (!x509_read_header(&r, TAG_SEQUENCE, &len) || len != rb_left(&r)) {
        return 0;
    }
    if (!x509_read_exact(&r, pkcs8_version, sizeof pkcs8_version) ||
        !x509_read_exact(&r, p256_algorithm, sizeof p256_algorithm)) {
        return 0;
    }
    // privateKey fills the rest: no attributes [0], no publicKey [1].
    size_t key_len = 0;
    if (!x509_read_header(&r, TAG_OCTET_STRING, &key_len) || key_len != rb_left(&r)) {
        return 0;
    }
    const uint8_t *key = rb_bytes(&r, key_len);
    return key != NULL && read_ec_private_key(key, key_len, CURVE_OPTIONAL, scalar, point);
}

int x509_pem_read_sec1(const uint8_t *der, size_t der_len, uint8_t scalar[32],
                       const uint8_t **point) {
    CH_ASSERT(scalar != NULL && point != NULL);
    CH_ASSERT(der != NULL || der_len == 0);
    return read_ec_private_key(der, der_len, CURVE_REQUIRED, scalar, point);
}

int x509_pem_parameters_are_p256(const uint8_t *der, size_t der_len) {
    CH_ASSERT(der != NULL || der_len == 0);
    rbuf r;
    rb_init(&r, der, der_len);
    return x509_read_exact(&r, p256_parameters, sizeof p256_parameters) && rb_left(&r) == 0;
}
