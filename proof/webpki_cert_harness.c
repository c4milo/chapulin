// Proves: webpki_parse_certificate (webpki_cert.c) is memory-safe and
// UB-free over any bytes up to one past CH_WEBPKI_CERT_MAX and any arm
// value, and its result contract holds. It returns CH_OK or CH_EPROTO.
// A refusal leaves the alert at the caller's ALERT_BAD_CERTIFICATE or
// sets ALERT_UNSUPPORTED_CERTIFICATE. On CH_OK the alert is untouched,
// the length is at most CH_WEBPKI_CERT_MAX, and every pointer webpki.h
// says points into the caller's buffer does:
//
//   - tbs lies inside the certificate; issuer, subject, the key and san
//     (when not NULL) lie inside tbs; sig lies inside the certificate
//     after tbs and is not empty
//   - issuer and subject are whole TLVs of two bytes or more
//   - notBefore is no later than notAfter
//   - sigalg is one of the four WEBPKI_SIG_* values and spki.alg one of
//     the three WEBPKI_KEY_* values
//   - is_ca is the arm the caller asked for, normalized to 0 or 1, and
//     the seen bits hold that arm's required extensions
//
// Layered, the x509parse pattern. The four readers the parser hands
// fields to are stubs that assert what the parser passes them and
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

int nondet_int(void);
uint64_t nondet_u64(void);

// webpki_spki's proven bound on an accepted SubjectPublicKeyInfo.
#define SPKI_MAX 550
#define PACKED_MIN UINT64_C(19500101000000)
#define PACKED_MAX UINT64_C(99991231235959)

// A reader failure: any prefix of what remains consumed, err maybe set.
static int havoc_failure(rbuf *r) {
    size_t take = nondet_size_t();
    __CPROVER_assume(take <= rb_left(r));
    rb_skip(r, take);
    if (nondet_u8() & 1) {
        r->err = 1;
    }
    return 0;
}

// The start of a successful read of exactly take bytes, which a reader
// can only reach with err clear and take bytes left. Returns a pointer
// to the bytes the read consumes, the base the stub's outputs point into.
static const uint8_t *consume(rbuf *r, size_t take) {
    __CPROVER_assume(!r->err && take <= rb_left(r));
    const uint8_t *start = rb_bytes(r, take);
    __CPROVER_assert(start != NULL, "stub: the consumed bytes are readable");
    return start;
}

int webpki_read_sigalg(rbuf *r, uint8_t *sigalg) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "sigalg stub: rbuf writable");
    __CPROVER_assert(__CPROVER_w_ok(sigalg, sizeof *sigalg), "sigalg stub: out writable");
    if (nondet_u8() & 1) {
        return havoc_failure(r);
    }
    uint8_t value = nondet_u8();
    __CPROVER_assume(value >= WEBPKI_SIG_RSA_SHA256 && value <= WEBPKI_SIG_ECDSA_SHA384);
    (void)consume(r, value <= WEBPKI_SIG_RSA_SHA384 ? 15U : 12U);
    *sigalg = value;
    return 1;
}

int webpki_read_time(rbuf *r, uint64_t *packed) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "time stub: rbuf writable");
    __CPROVER_assert(__CPROVER_w_ok(packed, sizeof *packed), "time stub: out writable");
    if (nondet_u8() & 1) {
        return havoc_failure(r);
    }
    uint64_t value = nondet_u64();
    __CPROVER_assume(value >= PACKED_MIN && value <= PACKED_MAX);
    (void)consume(r, (nondet_u8() & 1) ? 15U : 17U);
    *packed = value;
    return 1;
}

int webpki_read_spki(rbuf *r, webpki_spki *out) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "spki stub: rbuf writable");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "spki stub: out writable");
    if (nondet_u8() & 1) {
        return havoc_failure(r);
    }
    size_t take = nondet_size_t();
    __CPROVER_assume(take <= SPKI_MAX);
    const uint8_t *start = consume(r, take);
    size_t key_off = nondet_size_t();
    size_t key_len = nondet_size_t();
    __CPROVER_assume(key_len <= take && key_off <= take - key_len);
    uint8_t alg = nondet_u8();
    __CPROVER_assume(alg >= WEBPKI_KEY_RSA && alg <= WEBPKI_KEY_P384);
    out->alg = alg;
    out->key = start + key_off;
    out->key_len = key_len;
    return 1;
}

int webpki_read_extensions(rbuf *t, int is_ca, webpki_cert *out, uint8_t *alert) {
    __CPROVER_assert(__CPROVER_w_ok(t, sizeof *t), "extensions stub: rbuf writable");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "extensions stub: out writable");
    __CPROVER_assert(__CPROVER_w_ok(alert, sizeof *alert), "extensions stub: alert writable");
    __CPROVER_assert(is_ca == 0 || is_ca == 1, "extensions stub: the arm is 0 or 1");
    out->seen = nondet_u8();
    out->is_ca = nondet_u8();
    out->path_len = nondet_int();
    out->san = NULL;
    out->san_len = 0;
    if (nondet_u8() & 1) {
        if (nondet_u8() & 1) {
            *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        }
        (void)havoc_failure(t);
        return CH_EPROTO;
    }
    size_t take = nondet_size_t();
    const uint8_t *start = consume(t, take);
    uint8_t required = is_ca ? (WEBPKI_EXT_KEY_USAGE | WEBPKI_EXT_BASIC_CONSTRAINTS)
                             : (WEBPKI_EXT_KEY_USAGE | WEBPKI_EXT_EXT_KEY_USAGE | WEBPKI_EXT_SAN);
    __CPROVER_assume((out->seen & required) == required);
    out->is_ca = (uint8_t)is_ca;
    __CPROVER_assume(out->path_len >= -1 && out->path_len <= 32767);
    __CPROVER_assume(is_ca || out->path_len == -1);
    if (!is_ca || (nondet_u8() & 1)) {
        size_t san_off = nondet_size_t();
        size_t san_len = nondet_size_t();
        __CPROVER_assume(san_len <= take && san_off <= take - san_len);
        out->san = start + san_off;
        out->san_len = san_len;
    }
    return CH_OK;
}

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
