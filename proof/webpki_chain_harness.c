// Proves: webpki_verify_chain (webpki.c) is memory-safe and UB-free
// over any CertificateEntry list of up to CH_PROOF_LIST_LEN bytes, any
// anchor array of up to CH_PROOF_ANCHORS entries with unconstrained
// bytes, any hostname and any clock, and its result contract holds. It
// returns CH_OK, CH_EPROTO or CH_EAUTH; a refusal names one of the four
// alerts webpki.h's table lists; and CH_OK leaves a leaf key the
// message buffer's reuse cannot disturb — copied into out, at most
// CH_WEBPKI_KEY_MAX bytes, under one of the three key algorithms.
//
// Layered, the webpki_cert pattern. The five calls the walk makes are
// stubs that assert what the walk passes them and havoc their outputs
// within exactly what their own harnesses prove:
//
//   - webpki_parse_certificate (webpki_cert): CH_OK or CH_EPROTO, the
//     alert left or set to unsupported_certificate, and on CH_OK every
//     pointer inside the certificate, the dates ordered and in range,
//     sigalg and spki.alg in range, the key at most CH_WEBPKI_KEY_MAX
//     bytes (webpki_spki proves a modulus at most CH_RSA_MODULUS_MAX
//     and the two EC keys at 64 and 96), is_ca the arm asked for, and
//     path_len from -1 to 32767
//   - webpki_read_spki (webpki_spki): at most 550 bytes consumed, the
//     key inside them, one of three algorithms
//   - webpki_verify and webpki_match_san (webpki_sigalg, webpki_name):
//     a nondet verdict over inputs the stub asserts are readable
//   - webpki_pack_seconds (webpki_time): a packed date in range
//
// So the object under proof is the walk itself: the entry framing, the
// anchor loop, the depth accounting, the pathLenConstraint arithmetic
// and the memcpy of the leaf key.
//
// Not proved here: that the walk accepts only a chain whose signatures
// verify. The stubs answer a nondet verdict, so the formula says
// nothing about which chains reach CH_OK. spec/Spec/Webpki.lean states
// that property and test/webpki_chain_test.c tests it over the corpus.
#include "harness.h"

#include "buf.h"
#include "handshake_message.h"
#include "webpki.h"

int nondet_int(void);
uint64_t nondet_u64(void);

// The list this harness drives the walk over. Three entries of a few
// bytes each fit, which is one more than the two the walk reads before
// CH_WEBPKI_CHAIN_MAX stops it.
#ifndef CH_PROOF_LIST_LEN
#define CH_PROOF_LIST_LEN 24
#endif
// Anchors the configuration carries.
#ifndef CH_PROOF_ANCHORS
#define CH_PROOF_ANCHORS 2
#endif
// The caller's anchor bytes and hostname, unconstrained.
#define CH_PROOF_ANCHOR_LEN 8
#define CH_PROOF_HOST_LEN 8

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

int webpki_read_spki(rbuf *r, webpki_spki *out) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "spki stub: rbuf writable");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "spki stub: out writable");
    if (nondet_u8() & 1) {
        return havoc_failure(r);
    }
    size_t take = nondet_size_t();
    __CPROVER_assume(take <= SPKI_MAX && !r->err && take <= rb_left(r));
    const uint8_t *start = rb_bytes(r, take);
    __CPROVER_assert(start != NULL, "spki stub: the consumed bytes are readable");
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

int webpki_parse_certificate(const uint8_t *cert, size_t cert_len, int is_ca, webpki_cert *out,
                             uint8_t *alert) {
    __CPROVER_assert(cert_len == 0 || __CPROVER_r_ok(cert, cert_len),
                     "parse stub: the certificate is readable");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "parse stub: out writable");
    __CPROVER_assert(__CPROVER_w_ok(alert, sizeof *alert), "parse stub: alert writable");
    __CPROVER_assert(is_ca == 0 || is_ca == 1, "parse stub: the arm is 0 or 1");
    if (nondet_u8() & 1) {
        if (nondet_u8() & 1) {
            *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        }
        return CH_EPROTO;
    }
    __CPROVER_assume(cert_len <= CH_WEBPKI_CERT_MAX && cert_len > 0);
    // Every pointer webpki.h says points into the certificate does, and
    // the walk reads the Names, the key and the dates through them.
    size_t tbs_off = nondet_size_t();
    size_t tbs_len = nondet_size_t();
    __CPROVER_assume(tbs_len <= cert_len && tbs_off <= cert_len - tbs_len);
    size_t issuer_off = nondet_size_t();
    size_t issuer_len = nondet_size_t();
    __CPROVER_assume(issuer_len <= cert_len && issuer_off <= cert_len - issuer_len);
    size_t subject_off = nondet_size_t();
    size_t subject_len = nondet_size_t();
    __CPROVER_assume(subject_len <= cert_len && subject_off <= cert_len - subject_len);
    size_t key_off = nondet_size_t();
    size_t key_len = nondet_size_t();
    __CPROVER_assume(key_len <= CH_WEBPKI_KEY_MAX && key_len <= cert_len &&
                     key_off <= cert_len - key_len);
    size_t san_off = nondet_size_t();
    size_t san_len = nondet_size_t();
    __CPROVER_assume(san_len <= cert_len && san_off <= cert_len - san_len);
    uint64_t not_before = nondet_u64();
    uint64_t not_after = nondet_u64();
    __CPROVER_assume(not_before >= PACKED_MIN && not_after <= PACKED_MAX &&
                     not_before <= not_after);
    uint8_t sigalg = nondet_u8();
    __CPROVER_assume(sigalg >= WEBPKI_SIG_RSA_SHA256 && sigalg <= WEBPKI_SIG_ECDSA_SHA384);
    uint8_t alg = nondet_u8();
    __CPROVER_assume(alg >= WEBPKI_KEY_RSA && alg <= WEBPKI_KEY_P384);
    int path_len = nondet_int();
    __CPROVER_assume(path_len >= -1 && path_len <= 32767);
    __CPROVER_assume(is_ca || path_len == -1);
    out->tbs = cert + tbs_off;
    out->tbs_len = tbs_len;
    out->issuer = cert + issuer_off;
    out->issuer_len = issuer_len;
    out->subject = cert + subject_off;
    out->subject_len = subject_len;
    out->not_before = not_before;
    out->not_after = not_after;
    out->spki.alg = alg;
    out->spki.key = cert + key_off;
    out->spki.key_len = key_len;
    out->sigalg = sigalg;
    out->sig = cert;
    out->sig_len = cert_len;
    out->san = (nondet_u8() & 1) ? cert + san_off : NULL;
    out->san_len = out->san == NULL ? 0 : san_len;
    out->seen = nondet_u8();
    out->is_ca = (uint8_t)is_ca;
    out->path_len = path_len;
    return CH_OK;
}

int webpki_verify(const webpki_cert *cert, const webpki_spki *signer) {
    __CPROVER_assert(__CPROVER_r_ok(cert, sizeof *cert), "verify stub: certificate readable");
    __CPROVER_assert(__CPROVER_r_ok(signer, sizeof *signer), "verify stub: signer readable");
    __CPROVER_assert(signer->key_len == 0 || __CPROVER_r_ok(signer->key, signer->key_len),
                     "verify stub: the signer key is readable");
    return (int)(nondet_u8() & 1);
}

int webpki_match_san(const uint8_t *san, size_t san_len, const uint8_t *host, size_t host_len) {
    __CPROVER_assert(san == NULL || san_len == 0 || __CPROVER_r_ok(san, san_len),
                     "san stub: the GeneralNames is readable");
    __CPROVER_assert(host_len == 0 || __CPROVER_r_ok(host, host_len),
                     "san stub: the hostname is readable");
    return (int)(nondet_u8() & 1);
}

uint64_t webpki_pack_seconds(uint64_t now_seconds) {
    (void)now_seconds;
    uint64_t packed = nondet_u64();
    __CPROVER_assume(packed >= PACKED_MIN && packed <= PACKED_MAX);
    return packed;
}

#include "webpki.c"

int main(void) {
    static uint8_t list[CH_PROOF_LIST_LEN];
    static uint8_t anchor_bytes[CH_PROOF_ANCHORS][CH_PROOF_ANCHOR_LEN];
    static uint8_t spki_bytes[CH_PROOF_ANCHORS][CH_PROOF_ANCHOR_LEN];
    static uint8_t host[CH_PROOF_HOST_LEN];
    static ch_trust_anchor anchors[CH_PROOF_ANCHORS];
    fill_nondet(list, sizeof list);
    fill_nondet(host, sizeof host);
    for (size_t i = 0; i < CH_PROOF_ANCHORS; i++) {
        fill_nondet(anchor_bytes[i], CH_PROOF_ANCHOR_LEN);
        fill_nondet(spki_bytes[i], CH_PROOF_ANCHOR_LEN);
        size_t name_len = nondet_size_t();
        size_t spki_len = nondet_size_t();
        __CPROVER_assume(name_len <= CH_PROOF_ANCHOR_LEN && spki_len <= CH_PROOF_ANCHOR_LEN);
        anchors[i].name = anchor_bytes[i];
        anchors[i].name_len = name_len;
        anchors[i].spki = spki_bytes[i];
        anchors[i].spki_len = spki_len;
    }
    size_t list_len = nondet_size_t();
    __CPROVER_assume(list_len <= sizeof list);
    size_t anchor_count = nondet_size_t();
    __CPROVER_assume(anchor_count <= CH_PROOF_ANCHORS);
    size_t host_len = nondet_size_t();
    __CPROVER_assume(host_len <= sizeof host);

    ch_cfg cfg;
    __CPROVER_havoc_object(&cfg);
    cfg.anchors = anchors;
    cfg.anchor_count = anchor_count;
    cfg.hostname = host;
    cfg.hostname_len = host_len;
    webpki_leaf_info out;
    // hsa_server_auth seeds bad_certificate, and so does this. The walk
    // writes its own alert on every refusal, including the entry
    // framing one, so the assert below reads what the walk wrote rather
    // than what this line left.
    uint8_t alert = ALERT_BAD_CERTIFICATE;

    int rc = webpki_verify_chain(list, list_len, &cfg, &out, &alert);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO || rc == CH_EAUTH,
                     "walk: CH_OK, CH_EPROTO or CH_EAUTH");
    if (rc != CH_OK) {
        __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE || alert == ALERT_UNSUPPORTED_CERTIFICATE ||
                             alert == ALERT_CERTIFICATE_EXPIRED || alert == ALERT_UNKNOWN_CA,
                         "walk: a refusal names one of the four alerts");
        return 0;
    }
    __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE, "walk: success keeps the alert");
    __CPROVER_assert(out.alg >= WEBPKI_KEY_RSA && out.alg <= WEBPKI_KEY_P384,
                     "walk: the leaf key algorithm is one of the three");
    __CPROVER_assert(out.key_len <= CH_WEBPKI_KEY_MAX,
                     "walk: the leaf key fits webpki_leaf_info.key");
    return 0;
}
