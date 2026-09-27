// Proves: webpki_read_certificate_key (webpki_cert.c) reads no byte
// outside cert[0..n) and is UB-free for every n up to one past
// CH_WEBPKI_LEAF_PIN_CERT_MAX and every byte cert holds, and its result
// contract holds. It is the reader a leaf pinned with no anchor goes
// through (webpki_pin.h, docs/decisions.md 65), which reads a certificate
// only as far as its key. It returns CH_OK or CH_EPROTO. A refusal leaves
// the alert at the caller's ALERT_BAD_CERTIFICATE or sets
// ALERT_UNSUPPORTED_CERTIFICATE. On CH_OK the alert is untouched, the
// length is at most CH_WEBPKI_LEAF_PIN_CERT_MAX, and:
//
//   - tbs lies inside the certificate; issuer, subject and the
//     SubjectPublicKeyInfo TLV lie inside tbs; the key lies inside that
//     TLV, which is at most SPKI_MAX bytes, the bytes an SPKI pin hashes
//   - issuer and subject are whole TLVs of two bytes or more
//   - notBefore is no later than notAfter
//   - sigalg is one of the four WEBPKI_SIG_* values and spki.alg one of
//     the three WEBPKI_KEY_* values
//
// And on every return: the extensions reader never ran, and the fields
// the call does not write, san, seen, is_ca, path_len and sig, hold what
// the caller left.
//
// Layered as webpki_cert is, over the same four reader stubs
// (proof/webpki_cert_stubs.h). The DER primitives in x509_der.c, rbuf
// (buf.c) and ct_memeq (ct.c) are real, x509_skip among them, which frames
// the extensions, the outer signatureAlgorithm and the signature the
// reader skips unread.
//
// cert is a heap object of exactly n bytes, so a read at cert[n] is a
// bounds failure whatever n is, as in record_whole_len. The heap is the
// harness's, not the library's: CBMC gives the object n unconstrained
// bytes. cbmc 6.11 gives each read at a symbolic offset into a fixed-size
// array clauses in proportion to the array's length, with
// --arrays-uf-always or without it, so a fixed array of
// CH_WEBPKI_LEAF_PIN_CERT_MAX + 1 bytes made a formula of 78 million
// clauses, about 4,700 a byte. The heap object's formula has 0.8
// million.
#include "harness.h"

#include <stdlib.h>

#include "buf.h"
#include "handshake_message.h"
#include "webpki.h"

#include "webpki_cert_stubs.h"

#include "webpki_cert.c"

// 1 when [inner, inner + inner_len) lies inside [outer, outer + outer_len).
static int inside(const uint8_t *outer, size_t outer_len, const uint8_t *inner, size_t inner_len) {
    return inner != NULL && inner >= outer && inner_len <= outer_len &&
           (size_t)(inner - outer) <= outer_len - inner_len;
}

// The fields webpki_read_certificate_key does not write.
static int unwritten_equal(const webpki_cert *a, const webpki_cert *b) {
    return a->san == b->san && a->san_len == b->san_len && a->seen == b->seen &&
           a->is_ca == b->is_ca && a->path_len == b->path_len && a->sig == b->sig &&
           a->sig_len == b->sig_len;
}

int main(void) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= CH_WEBPKI_LEAF_PIN_CERT_MAX + 1);
    uint8_t *cert = malloc(n);
    __CPROVER_assume(cert != NULL);
    webpki_cert out;
    __CPROVER_havoc_object(&out);
    const webpki_cert before = out;
    uint8_t alert = ALERT_BAD_CERTIFICATE;

    int rc = webpki_read_certificate_key(cert, n, &out, &alert);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "key: CH_OK or CH_EPROTO");
    __CPROVER_assert(extensions_reads == 0, "key: the extensions are never read");
    __CPROVER_assert(unwritten_equal(&out, &before), "key: the unwritten fields are untouched");
    if (rc != CH_OK) {
        __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE || alert == ALERT_UNSUPPORTED_CERTIFICATE,
                         "key: a refusal names one of the two alerts");
        free(cert);
        return 0;
    }
    __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE, "key: success keeps the alert");
    __CPROVER_assert(n <= CH_WEBPKI_LEAF_PIN_CERT_MAX,
                     "key: success is at most CH_WEBPKI_LEAF_PIN_CERT_MAX");
    __CPROVER_assert(inside(cert, n, out.tbs, out.tbs_len), "key: tbs inside the certificate");
    __CPROVER_assert(inside(out.tbs, out.tbs_len, out.issuer, out.issuer_len) &&
                         out.issuer_len >= 2,
                     "key: issuer is a TLV inside tbs");
    __CPROVER_assert(inside(out.tbs, out.tbs_len, out.subject, out.subject_len) &&
                         out.subject_len >= 2,
                     "key: subject is a TLV inside tbs");
    __CPROVER_assert(inside(out.tbs, out.tbs_len, out.spki_tlv, out.spki_tlv_len) &&
                         out.spki_tlv_len <= SPKI_MAX,
                     "key: the SubjectPublicKeyInfo TLV inside tbs");
    __CPROVER_assert(inside(out.spki_tlv, out.spki_tlv_len, out.spki.key, out.spki.key_len),
                     "key: the key inside its SubjectPublicKeyInfo TLV");
    __CPROVER_assert(out.not_before <= out.not_after, "key: notBefore no later than notAfter");
    __CPROVER_assert(out.sigalg >= WEBPKI_SIG_RSA_SHA256 && out.sigalg <= WEBPKI_SIG_ECDSA_SHA384,
                     "key: sigalg is one of the four");
    __CPROVER_assert(out.spki.alg >= WEBPKI_KEY_RSA && out.spki.alg <= WEBPKI_KEY_P384,
                     "key: the key algorithm is one of the three");
    free(cert);
    return 0;
}
