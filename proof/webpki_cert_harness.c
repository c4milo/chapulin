// Proves: webpki_parse_certificate (webpki_cert.c) is memory-safe and
// UB-free over any bytes up to one past CH_WEBPKI_CERT_MAX and any arm
// value, and its result contract holds. It returns CH_OK or CH_EPROTO.
// A refusal leaves the alert at the caller's ALERT_BAD_CERTIFICATE or
// sets ALERT_UNSUPPORTED_CERTIFICATE. On CH_OK the alert is untouched,
// the length is at most CH_WEBPKI_CERT_MAX, and every pointer webpki.h
// says points into the caller's buffer does:
//
//   - tbs lies inside the certificate; issuer, subject, the
//     SubjectPublicKeyInfo TLV and san (when not NULL) lie inside tbs; the
//     key lies inside that TLV, which is at most SPKI_MAX bytes, the bytes
//     an SPKI pin hashes; sig lies inside the certificate after tbs and is
//     not empty
//   - issuer and subject are whole TLVs of two bytes or more
//   - notBefore is no later than notAfter
//   - sigalg is one of the four WEBPKI_SIG_* values and spki.alg one of
//     the three WEBPKI_KEY_* values
//   - is_ca is the arm the caller asked for, normalized to 0 or 1, and
//     the seen bits hold that arm's required extensions
//
// Layered, the x509parse pattern. The four readers the parser hands
// fields to are stubs (proof/webpki_cert_stubs.h, which
// webpki_cert_key shares) that assert what the parser passes them and
// havoc their outputs within exactly what their own harnesses prove:
// webpki_read_sigalg (webpki_sigalg: 15 or 12 bytes, one of four
// values), webpki_read_time (webpki_time: 15 or 17 bytes, a packed date
// in range), webpki_read_spki (webpki_spki: at most 550 bytes, the key
// inside them, one of three algorithms) and webpki_read_extensions
// (webpki_ext: the arm's bits, is_ca equal to the arm, path_len from -1
// to 32767, san NULL or inside the bytes consumed). Each stub may fail
// at any point, consuming any prefix and setting err, as the real
// readers may. The DER primitives in x509_der.c, rbuf (buf.c) and
// ct_memeq (ct.c) are real: the object under proof is the parser's own
// field order, its exact-fill checks and its pointer arithmetic.
#include "harness.h"

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

int main(void) {
    static uint8_t cert[CH_WEBPKI_CERT_MAX + 1];
    fill_nondet(cert, sizeof cert);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof cert);
    int is_ca = nondet_int();
    webpki_cert out;
    uint8_t alert = ALERT_BAD_CERTIFICATE;

    int rc = webpki_parse_certificate(cert, n, is_ca, &out, &alert);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "parse: CH_OK or CH_EPROTO");
    if (rc != CH_OK) {
        __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE || alert == ALERT_UNSUPPORTED_CERTIFICATE,
                         "parse: a refusal names one of the two alerts");
        return 0;
    }
    __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE, "parse: success keeps the alert");
    __CPROVER_assert(n <= CH_WEBPKI_CERT_MAX, "parse: success is at most CH_WEBPKI_CERT_MAX");
    __CPROVER_assert(inside(cert, n, out.tbs, out.tbs_len), "parse: tbs inside the certificate");
    __CPROVER_assert(inside(out.tbs, out.tbs_len, out.issuer, out.issuer_len) &&
                         out.issuer_len >= 2,
                     "parse: issuer is a TLV inside tbs");
    __CPROVER_assert(inside(out.tbs, out.tbs_len, out.subject, out.subject_len) &&
                         out.subject_len >= 2,
                     "parse: subject is a TLV inside tbs");
    __CPROVER_assert(inside(out.tbs, out.tbs_len, out.spki.key, out.spki.key_len),
                     "parse: the key inside tbs");
    __CPROVER_assert(inside(out.tbs, out.tbs_len, out.spki_tlv, out.spki_tlv_len) &&
                         out.spki_tlv_len <= SPKI_MAX,
                     "parse: the SubjectPublicKeyInfo TLV inside tbs");
    __CPROVER_assert(inside(out.spki_tlv, out.spki_tlv_len, out.spki.key, out.spki.key_len),
                     "parse: the key inside its SubjectPublicKeyInfo TLV");
    __CPROVER_assert(inside(cert, n, out.sig, out.sig_len) && out.sig_len >= 1,
                     "parse: a non-empty signature inside the certificate");
    __CPROVER_assert(out.sig >= out.tbs + out.tbs_len, "parse: the signature follows tbs");
    __CPROVER_assert(out.san == NULL || inside(out.tbs, out.tbs_len, out.san, out.san_len),
                     "parse: san is NULL or inside tbs");
    __CPROVER_assert(out.not_before <= out.not_after, "parse: notBefore no later than notAfter");
    __CPROVER_assert(out.sigalg >= WEBPKI_SIG_RSA_SHA256 && out.sigalg <= WEBPKI_SIG_ECDSA_SHA384,
                     "parse: sigalg is one of the four");
    __CPROVER_assert(out.spki.alg >= WEBPKI_KEY_RSA && out.spki.alg <= WEBPKI_KEY_P384,
                     "parse: the key algorithm is one of the three");
    __CPROVER_assert(out.is_ca == (is_ca != 0), "parse: is_ca is the normalized arm");
    uint8_t required = is_ca != 0
                           ? (WEBPKI_EXT_KEY_USAGE | WEBPKI_EXT_BASIC_CONSTRAINTS)
                           : (WEBPKI_EXT_KEY_USAGE | WEBPKI_EXT_EXT_KEY_USAGE | WEBPKI_EXT_SAN);
    __CPROVER_assert((out.seen & required) == required, "parse: the arm's extensions were seen");
    return 0;
}
