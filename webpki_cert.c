// One certificate for the web PKI trust mode (TRUST=webpki): the
// Certificate SEQUENCE and its TBSCertificate, field by field, with
// each field handed to the reader that owns it. Contract in webpki.h;
// the profile in docs/webpki.md ("The chain walk", steps 2, 3 and 6c).
// x509.c's parse_certificate and parse_tbs are the ca mode's parser
// over the same grammar, and this file keeps their order and their
// exact-fill checks. The walk, the clock and the hostname are the
// caller's; this file decides none of them. Every byte here is public,
// so variable time is fine and deliberate.
#include "webpki.h"

#include "buf.h"
#include "handshake_message.h"
#include "x509_der.h"

// DER tags this file reads.
#define TAG_SEQUENCE 0x30
#define TAG_ISSUER_UNIQUE_ID 0x81  // [1] IMPLICIT UniqueIdentifier, a BIT STRING
#define TAG_SUBJECT_UNIQUE_ID 0x82 // [2] IMPLICIT UniqueIdentifier, a BIT STRING

// version [0] EXPLICIT INTEGER 2: the one admitted v3 encoding
// (RFC 5280 §4.1.2.1).
static const uint8_t version_v3[] = {0xa0, 0x03, 0x02, 0x01, 0x02};

// x509_read_serial admits a positive INTEGER in minimal form of at most
// 21 content octets, the 21st only as the 0x00 pad a top-bit-set value
// needs: at most 20 value octets, the RFC 5280 §4.1.2.2 cap webpki.h
// names. This file states the cap and never enforces it, so the
// assertion fails if CH_WEBPKI_SERIAL_MAX moves off the 20 that reader
// admits. A change inside x509_read_serial itself fails
// test/webpki_cert_test.c's serial boundary instead.
_Static_assert(CH_WEBPKI_SERIAL_MAX == 20, "x509_read_serial admits at most 20 value octets");

// Name: one SEQUENCE TLV, left unread inside. Points *tlv at its bytes,
// header included, through a copy of the reader made before the read,
// because the walk and the anchors compare whole Names byte for byte.
static int read_name(rbuf *r, const uint8_t **tlv, size_t *tlv_len) {
    rbuf start = *r;
    if (!x509_skip(r, TAG_SEQUENCE)) {
        return 0;
    }
    *tlv_len = rb_left(&start) - rb_left(r);
    *tlv = rb_bytes(&start, *tlv_len);
    return *tlv != NULL;
}

// signature AlgorithmIdentifier: webpki_read_sigalg, and the bytes it
// consumed, so the outer signatureAlgorithm can be compared against
// them byte for byte.
static int read_sigalg_tlv(rbuf *r, uint8_t *sigalg, const uint8_t **tlv, size_t *tlv_len) {
    rbuf start = *r;
    if (!webpki_read_sigalg(r, sigalg)) {
        return 0;
    }
    *tlv_len = rb_left(&start) - rb_left(r);
    *tlv = rb_bytes(&start, *tlv_len);
    return *tlv != NULL;
}

// Validity ::= SEQUENCE { notBefore Time, notAfter Time }, filling its
// length exactly, with notBefore no later than notAfter. Whether the
// caller's clock falls inside is the walk's check.
static int read_validity(rbuf *t, webpki_cert *out) {
    size_t validity_len = 0;
    if (!x509_read_header(t, TAG_SEQUENCE, &validity_len)) {
        return 0;
    }
    const uint8_t *validity = rb_bytes(t, validity_len);
    if (validity == NULL) {
        return 0;
    }
    rbuf v;
    rb_init(&v, validity, validity_len);
    if (!webpki_read_time(&v, &out->not_before) || !webpki_read_time(&v, &out->not_after)) {
        return 0;
    }
    return !v.err && rb_left(&v) == 0 && out->not_before <= out->not_after;
}

// The TBSCertificate fields through the subject: version, serialNumber,
// signature, issuer, validity, subject. Leaves the signature
// AlgorithmIdentifier's bytes in *sigalg_tlv for the outer compare.
static int read_tbs_names(rbuf *t, webpki_cert *out, const uint8_t **sigalg_tlv,
                          size_t *sigalg_tlv_len, uint8_t *alert) {
    if (!x509_read_exact(t, version_v3, sizeof version_v3) || !x509_read_serial(t)) {
        return CH_EPROTO;
    }
    if (!read_sigalg_tlv(t, &out->sigalg, sigalg_tlv, sigalg_tlv_len)) {
        // SHA-1, RSA-PSS, any other algorithm, or a malformed field:
        // webpki_read_sigalg compares whole encodings, so one verdict
        // covers all of them (webpki.h's alert exception).
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    if (!read_name(t, &out->issuer, &out->issuer_len) || !read_validity(t, out) ||
        !read_name(t, &out->subject, &out->subject_len)) {
        return CH_EPROTO;
    }
    return CH_OK;
}

// 1 when the next field is issuerUniqueID or subjectUniqueID
// (RFC 5280 §4.1.2.8). t is not advanced.
static int unique_id_follows(const rbuf *t) {
    rbuf next = *t;
    uint8_t tag = rb_u8(&next);
    return !next.err && (tag == TAG_ISSUER_UNIQUE_ID || tag == TAG_SUBJECT_UNIQUE_ID);
}

// The TBSCertificate body, first byte to last, exact-fill.
static int read_tbs(const uint8_t *tbs, size_t tbs_len, int is_ca, webpki_cert *out,
                    const uint8_t **sigalg_tlv, size_t *sigalg_tlv_len, uint8_t *alert) {
    rbuf t;
    rb_init(&t, tbs, tbs_len);
    int rc = read_tbs_names(&t, out, sigalg_tlv, sigalg_tlv_len, alert);
    if (rc != CH_OK) {
        return rc;
    }
    if (!webpki_read_spki(&t, &out->spki)) {
        // A key algorithm or size the mode refuses, or malformed DER:
        // webpki_read_spki answers one 0 for both (webpki.h's alert
        // exception).
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    if (unique_id_follows(&t)) {
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    rc = webpki_read_extensions(&t, is_ca, out, alert);
    if (rc != CH_OK) {
        return rc;
    }
    if (t.err || rb_left(&t) != 0) {
        return CH_EPROTO; // nothing follows extensions in a v3 TBSCertificate
    }
    return CH_OK;
}

int webpki_parse_certificate(const uint8_t *cert, size_t cert_len, int is_ca, webpki_cert *out,
                             uint8_t *alert) {
    if (cert_len > CH_WEBPKI_CERT_MAX) {
        return CH_EPROTO;
    }
    rbuf r;
    rb_init(&r, cert, cert_len);
    size_t body_len = 0;
    if (!x509_read_header(&r, TAG_SEQUENCE, &body_len) || body_len != rb_left(&r)) {
        return CH_EPROTO;
    }
    size_t tbs_len = 0;
    if (!x509_read_header(&r, TAG_SEQUENCE, &tbs_len)) {
        return CH_EPROTO;
    }
    out->tbs = rb_bytes(&r, tbs_len);
    out->tbs_len = tbs_len;
    if (out->tbs == NULL) {
        return CH_EPROTO;
    }
    const uint8_t *sigalg_tlv = NULL;
    size_t sigalg_tlv_len = 0;
    int rc = read_tbs(out->tbs, tbs_len, is_ca != 0, out, &sigalg_tlv, &sigalg_tlv_len, alert);
    if (rc != CH_OK) {
        return rc;
    }
    if (!x509_read_exact(&r, sigalg_tlv, sigalg_tlv_len)) {
        // RFC 5280 §4.1.1.2: signatureAlgorithm MUST equal the TBS
        // signature field. A byte compare answers one verdict for a
        // different algorithm and for a malformed or missing field
        // (webpki.h's alert exception).
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    if (!x509_read_bitstring(&r, &out->sig, &out->sig_len) || out->sig_len == 0) {
        return CH_EPROTO;
    }
    if (r.err || rb_left(&r) != 0) {
        return CH_EPROTO;
    }
    return CH_OK;
}
