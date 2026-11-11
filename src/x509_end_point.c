// The tls-server-end-point channel binding (RFC 5929 section 4.1):
// scram.h's ch_tls_server_end_point, which states the contract. It is a
// certificate file (INV-5): it reads a certificate's outer fields through
// x509_der.c's canonical readers, finds the hash its signatureAlgorithm
// names, and hashes the certificate with it. It returns no verdict about
// the certificate, and no session calls it. Outside a SCRAM build it
// holds nothing, and scram.h's includes keep the unit from being empty.
#include "scram.h"

#ifdef CH_SCRAM

#include "buf.h"
#include "ct.h"
#include "sha256.h"
#include "sha512.h"
#include "x509_der.h"

_Static_assert(CH_TLS_SERVER_END_POINT_LEN_MAX == SHA512_LEN,
               "scram.h states the longest end-point value");

#define TAG_OBJECT_IDENTIFIER 0x06
#define TAG_NULL 0x05
#define TAG_BIT_STRING 0x03
#define TAG_SEQUENCE 0x30
// RSASSA-PSS-params' four fields, each [n] EXPLICIT (RFC 4055 section
// 3.1): hashAlgorithm, maskGenAlgorithm, saltLength and trailerField.
#define TAG_PSS_HASH 0xa0
#define TAG_PSS_MASK 0xa1
#define TAG_PSS_SALT 0xa2
#define TAG_PSS_TRAILER 0xa3

// One row: the bytes of an OBJECT IDENTIFIER's value, and the length of
// the digest RFC 5929 section 4.1 takes for it. SHA-256 stands in for
// MD5 and SHA-1 there, so those rows give 32 too.
typedef struct {
    const uint8_t *oid;
    size_t oid_len;
    size_t digest_len;
} hash_row;

// 1.2.840.113549.1.1.n: PKCS #1's signature algorithms (RFC 8017
// appendix C). n is the last byte.
#define PKCS1(n) {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, (n)}
static const uint8_t md5_with_rsa[] = PKCS1(0x04);
static const uint8_t sha1_with_rsa[] = PKCS1(0x05);
static const uint8_t rsassa_pss[] = PKCS1(0x0a);
static const uint8_t sha256_with_rsa[] = PKCS1(0x0b);
static const uint8_t sha384_with_rsa[] = PKCS1(0x0c);
static const uint8_t sha512_with_rsa[] = PKCS1(0x0d);
// 1.2.840.10045.4.1, and 1.2.840.10045.4.3.n: ECDSA's (RFC 5758 section
// 3.2).
static const uint8_t ecdsa_with_sha1[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01};
static const uint8_t ecdsa_with_sha256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
static const uint8_t ecdsa_with_sha384[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03};
static const uint8_t ecdsa_with_sha512[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04};
// 1.3.14.3.2.26, and 2.16.840.1.101.3.4.2.n: the hashes RSASSA-PSS's
// parameters name (RFC 4055 section 2.1).
static const uint8_t id_sha1[] = {0x2b, 0x0e, 0x03, 0x02, 0x1a};
static const uint8_t id_sha256[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
static const uint8_t id_sha384[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
static const uint8_t id_sha512[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};

#define ROW(oid, digest_len) {(oid), sizeof(oid), (digest_len)}
// A signature algorithm that names one hash. RSA's take NULL parameters
// (RFC 4055 section 5), and ECDSA's take none (RFC 5758 section 3.2).
static const hash_row rsa_algorithms[] = {
    ROW(md5_with_rsa, SHA256_LEN),    ROW(sha1_with_rsa, SHA256_LEN),
    ROW(sha256_with_rsa, SHA256_LEN), ROW(sha384_with_rsa, SHA384_LEN),
    ROW(sha512_with_rsa, SHA512_LEN),
};
static const hash_row ecdsa_algorithms[] = {
    ROW(ecdsa_with_sha1, SHA256_LEN),
    ROW(ecdsa_with_sha256, SHA256_LEN),
    ROW(ecdsa_with_sha384, SHA384_LEN),
    ROW(ecdsa_with_sha512, SHA512_LEN),
};
static const hash_row pss_hashes[] = {
    ROW(id_sha1, SHA256_LEN),
    ROW(id_sha256, SHA256_LEN),
    ROW(id_sha384, SHA384_LEN),
    ROW(id_sha512, SHA512_LEN),
};

// Whether the oid_len bytes at oid are the want_len bytes at want. The
// certificate is public; ct_memeq is INV-16's comparator either way, as
// in x509_read_exact.
static int oid_is(const uint8_t *oid, size_t oid_len, const uint8_t *want, size_t want_len) {
    return oid_len == want_len && ct_memeq(oid, want, oid_len) != 0;
}

// The digest length of the row whose OID is the oid_len bytes at oid, or
// 0 when no row of the count has it.
static size_t row_digest_len(const hash_row *rows, size_t count, const uint8_t *oid,
                             size_t oid_len) {
    for (size_t i = 0; i < count; i++) {
        if (oid_is(oid, oid_len, rows[i].oid, rows[i].oid_len)) {
            return rows[i].digest_len;
        }
    }
    return 0;
}

// Reads one OBJECT IDENTIFIER and points *oid at its value. Returns 1,
// or 0 for anything else.
static int read_oid(rbuf *r, const uint8_t **oid, size_t *oid_len) {
    if (!x509_read_header(r, TAG_OBJECT_IDENTIFIER, oid_len)) {
        return 0;
    }
    *oid = rb_bytes(r, *oid_len);
    return *oid != NULL;
}

// Whether the next byte is tag. r is not advanced.
static int tag_follows(const rbuf *r, uint8_t tag) {
    rbuf next = *r;
    uint8_t got = rb_u8(&next);
    return !next.err && got == tag;
}

// A field that may be absent: when the next byte is tag, one TLV of it.
static int skip_optional(rbuf *r, uint8_t tag) {
    return !tag_follows(r, tag) || x509_skip(r, tag);
}

// The digest length for the hash an RSASSA-PSS hashAlgorithm field
// names: the n bytes at p are the field's content, one AlgorithmIdentifier
// with the hash's OID, and NULL parameters or none (RFC 4055 section 2.1
// takes both). Returns 0 for content that does not read, or for a hash
// outside pss_hashes.
static size_t pss_hash_digest_len(const uint8_t *p, size_t n) {
    rbuf field;
    rb_init(&field, p, n);
    size_t body_len = 0;
    const uint8_t *oid = NULL;
    size_t oid_len = 0;
    if (!x509_read_header(&field, TAG_SEQUENCE, &body_len) || body_len != rb_left(&field) ||
        !read_oid(&field, &oid, &oid_len) || !skip_optional(&field, TAG_NULL) || field.err ||
        rb_left(&field) != 0) {
        return 0;
    }
    return row_digest_len(pss_hashes, sizeof pss_hashes / sizeof pss_hashes[0], oid, oid_len);
}

// The digest length for RSASSA-PSS-params, the n bytes at p, or 0 for
// parameters that do not read or that name a hash outside pss_hashes.
// Each of the four fields may be absent, and an absent hashAlgorithm is
// SHA-1 (RFC 4055 section 3.1), which takes SHA-256 here. The three
// fields after the hash go unjudged: the mask function, the salt length
// and the trailer field pick nothing that RFC 5929 reads.
static size_t pss_digest_len(const uint8_t *p, size_t n) {
    rbuf params;
    rb_init(&params, p, n);
    size_t body_len = 0;
    if (!x509_read_header(&params, TAG_SEQUENCE, &body_len) || body_len != rb_left(&params)) {
        return 0;
    }
    size_t digest_len = SHA256_LEN;
    if (tag_follows(&params, TAG_PSS_HASH)) {
        size_t field_len = 0;
        if (!x509_read_header(&params, TAG_PSS_HASH, &field_len)) {
            return 0;
        }
        const uint8_t *field = rb_bytes(&params, field_len);
        if (field == NULL) {
            return 0;
        }
        digest_len = pss_hash_digest_len(field, field_len);
    }
    if (!skip_optional(&params, TAG_PSS_MASK) || !skip_optional(&params, TAG_PSS_SALT) ||
        !skip_optional(&params, TAG_PSS_TRAILER) || params.err || rb_left(&params) != 0) {
        return 0;
    }
    return digest_len;
}

// The digest length for an AlgorithmIdentifier's content, the n bytes at
// p: an OID, and the parameters its family takes. Returns 0 for content
// that does not read, or that names no hash the rule takes.
static size_t algorithm_digest_len(const uint8_t *p, size_t n) {
    rbuf body;
    rb_init(&body, p, n);
    const uint8_t *oid = NULL;
    size_t oid_len = 0;
    if (!read_oid(&body, &oid, &oid_len)) {
        return 0;
    }
    size_t rsa = row_digest_len(rsa_algorithms, sizeof rsa_algorithms / sizeof rsa_algorithms[0],
                                oid, oid_len);
    if (rsa != 0) {
        return x509_skip(&body, TAG_NULL) && rb_left(&body) == 0 ? rsa : 0;
    }
    size_t ecdsa = row_digest_len(
        ecdsa_algorithms, sizeof ecdsa_algorithms / sizeof ecdsa_algorithms[0], oid, oid_len);
    if (ecdsa != 0) {
        return rb_left(&body) == 0 ? ecdsa : 0;
    }
    if (!oid_is(oid, oid_len, rsassa_pss, sizeof rsassa_pss)) {
        return 0;
    }
    // Absent parameters are every default, so SHA-1, which takes SHA-256.
    size_t params_len = rb_left(&body);
    if (params_len == 0) {
        return SHA256_LEN;
    }
    const uint8_t *params = rb_bytes(&body, params_len);
    return params == NULL ? 0 : pss_digest_len(params, params_len);
}

// The digest length for cert, or 0 for bytes that are not the outer
// fields of one certificate: a Certificate SEQUENCE that fills cert, and
// in it a TBSCertificate SEQUENCE, a signatureAlgorithm SEQUENCE and a
// signature BIT STRING, with nothing after them (RFC 5280 section 4.1).
static size_t certificate_digest_len(const uint8_t *cert, size_t cert_len) {
    rbuf r;
    rb_init(&r, cert, cert_len);
    size_t body_len = 0;
    if (!x509_read_header(&r, TAG_SEQUENCE, &body_len) || body_len != rb_left(&r) ||
        !x509_skip(&r, TAG_SEQUENCE)) {
        return 0;
    }
    size_t algorithm_len = 0;
    if (!x509_read_header(&r, TAG_SEQUENCE, &algorithm_len)) {
        return 0;
    }
    const uint8_t *algorithm = rb_bytes(&r, algorithm_len);
    if (algorithm == NULL || !x509_skip(&r, TAG_BIT_STRING) || r.err || rb_left(&r) != 0) {
        return 0;
    }
    return algorithm_digest_len(algorithm, algorithm_len);
}

int ch_tls_server_end_point(const uint8_t *cert, size_t cert_len,
                            uint8_t out[CH_TLS_SERVER_END_POINT_LEN_MAX], size_t *out_len) {
    size_t digest_len = certificate_digest_len(cert, cert_len);
    switch (digest_len) {
    case SHA256_LEN:
        sha256_of(cert, cert_len, out);
        break;
    case SHA384_LEN:
        sha384_of(cert, cert_len, out);
        break;
    case SHA512_LEN:
        sha512_of(cert, cert_len, out);
        break;
    default:
        return CH_EINVAL;
    }
    *out_len = digest_len;
    return CH_OK;
}

#endif // CH_SCRAM
