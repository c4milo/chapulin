// The Certificate and CertificateVerify rows of the handshake message
// differential, over the framing and build tokens
// test/diff_handshake_parser.h defines. Included by test/diff_test.c after
// that header (single translation unit).
#ifndef CH_DIFF_HANDSHAKE_CERTIFICATE_H
#define CH_DIFF_HANDSHAKE_CERTIFICATE_H

#include "diff_handshake_parser.h"

// The certificate_request_context and the CertificateEntry list
// (§4.4.2), with the row's one deviation written into them.
static void hspd_cert_build(wbuf *w, size_t mut, size_t entries, const uint8_t *leaf,
                            size_t leaf_len) {
    if (mut == 1) { // §4.4.2: the client's context is empty
        wb_u8(w, 2);
        wb_u16(w, 0);
    } else {
        wb_u8(w, 0);
    }
    size_t list = wb_mark(w, 3);
    for (size_t e = 0; e < entries; e++) {
        size_t n = e == 0 ? leaf_len : 1 + rng_below(64);
        wb_u24(w, (uint32_t)n);
        wb_bytes(w, leaf, n);
        if (mut == 2) { // a per-entry extension the profile never offers
            wb_u16(w, 4);
            wb_u16(w, HSPD_RECORD_SIZE_LIMIT);
            wb_u16(w, 2);
        } else {
            wb_u16(w, 0);
        }
    }
    wb_patch24(w, list);
    if (mut == 3) {
        wb_u8(w, 0); // trailing octet past the exact-fill list
    }
}

static void diff_hs_certificate(void) {
    for (int i = 0; i < 400; i++) {
        size_t mut = rng_below(6);
        size_t entries = mut == 0 ? 0 : 1 + rng_below(3);

        uint8_t leaf[200];
        size_t leaf_len = 1 + rng_below(sizeof leaf);
        rng_fill(leaf, leaf_len);

        uint8_t body[HSPD_BODY_MAX];
        wbuf w;
        wb_init(&w, body, sizeof body);
        hspd_cert_build(&w, mut, entries, leaf, leaf_len);
        if (w.err) {
            die("handshake_parser: Certificate buffer too small");
        }

        const uint8_t *clist = NULL;
        size_t clist_len = 0;
        uint8_t alert = 0;
        int rc = hsp_parse_certificate(body, w.len, &clist, &clist_len, &alert);
        char want[2 * sizeof leaf + 64];
        if (mut <= 3) {
            // Framing the C parser decides for itself — an empty list,
            // a nonempty certificate_request_context, a trailing octet
            // — plus mut 2, an entry extension the client never
            // offered: §4.4.2 makes it an unsupported_extension, but
            // hsp_parse_certificate hands the list on without reading
            // the entries, so that one refusal lives a layer up. The CA
            // build makes it in x509_verify_leaf (empty per-entry
            // extensions required); the pinned build never parses the
            // entries at all — it hashes the certificate into the
            // transcript and authenticates by the signature, so the
            // unread extension changes nothing an attacker can use. The
            // model refuses it either way; see CONTRACT.md's split
            // table.
            (void)snprintf(want, sizeof want, "ERR hs_certificate reject");
            CH_ASSERT(mut == 2 || rc != CH_OK);
        } else {
            char leaf_hex[2 * sizeof leaf + 1];
            (void)hex_encode(leaf_hex, leaf, leaf_len);
            (void)snprintf(want, sizeof want, "ok %zu %s", entries, leaf_hex);
            CH_ASSERT(rc == CH_OK && clist_len == w.len - 4);
        }
        char cmd[2 * (HSPD_BODY_MAX + 4) + 64];
        hspd_request(cmd, sizeof cmd, "hs_certificate", "", HSPD_CERTIFICATE, body, w.len);
        expect(cmd, want);
    }
}

// The algorithm a row writes. mut 0 and 3 to 7 each name one scheme:
// the two PKCS#1 v1.5 schemes the webpki build offers for certificates
// only; rsa_pkcs1_sha512 and rsa_pss_rsae_sha384, which no build offers;
// and ecdsa_secp384r1_sha384 and the other pinned build's scheme, which
// a pinned build refuses and the webpki build admits. Every other row
// names one the build admits: its pinned scheme, or one of the webpki
// build's three.
static uint16_t hspd_cv_algorithm(size_t mut) {
    switch (mut) {
    case 0:
        return SIGALG_RSA_PKCS1_SHA256;
    case 3:
        return SIGALG_RSA_PKCS1_SHA384;
    case 4:
        return 0x0601; // rsa_pkcs1_sha512
    case 5:
        return 0x0805; // rsa_pss_rsae_sha384
    case 6:
        return SIGALG_ECDSA_P384_SHA384;
    case 7:
        return CH_PIN_SIGALG == SIGALG_RSA_PSS_RSAE_SHA256 ? SIGALG_ECDSA_P256_SHA256
                                                           : SIGALG_RSA_PSS_RSAE_SHA256;
    default:
        break;
    }
#ifdef CH_TRUST_WEBPKI
    static const uint16_t admitted[] = {SIGALG_RSA_PSS_RSAE_SHA256, SIGALG_ECDSA_P256_SHA256,
                                        SIGALG_ECDSA_P384_SHA384};
    return admitted[rng_below(3)];
#else
    return CH_PIN_SIGALG;
#endif
}

static void diff_hs_certificate_verify(void) {
    // The build's offer: the model takes its name so both narrow the same
    // way (RFC 9846 §4.4.3) — the pinned build's one scheme, or webpki.
#ifdef CH_TRUST_WEBPKI
    const char *scheme = "webpki";
#elif CH_PIN_SIGALG == SIGALG_ECDSA_P256_SHA256
    const char *scheme = "p256";
#else
    const char *scheme = "rsa";
#endif
    for (int i = 0; i < 400; i++) {
        size_t mut = rng_below(10);
        uint8_t sig[300];
        size_t sig_len = 1 + rng_below(sizeof sig);
        rng_fill(sig, sig_len);

        uint8_t body[HSPD_BODY_MAX];
        wbuf w;
        wb_init(&w, body, sizeof body);
        uint16_t algorithm = hspd_cv_algorithm(mut);
        wb_u16(&w, algorithm);
        wb_u16(&w, (uint16_t)(mut == 1 ? sig_len + 1 : sig_len));
        wb_bytes(&w, sig, sig_len);
        if (mut == 2) {
            wb_u8(&w, 0); // trailing octet past the exact-fill signature
        }
        if (w.err) {
            die("handshake_parser: CertificateVerify buffer too small");
        }

        const uint8_t *csig = NULL;
        size_t csig_len = 0;
        uint8_t alert = 0;
#ifdef CH_TRUST_WEBPKI
        uint16_t reported = 0;
        int rc = hsp_parse_certificate_verify(body, w.len, &reported, &csig, &csig_len, &alert);
#else
        uint16_t reported = CH_PIN_SIGALG;
        int rc = hsp_parse_certificate_verify(body, w.len, &csig, &csig_len, &alert);
#endif
        char want[2 * sizeof sig + 64];
        if (rc != CH_OK) {
            (void)snprintf(want, sizeof want, "ERR hs_certificate_verify reject");
        } else {
            // The C reports the scheme it read (webpki) or accepted only
            // its pinned one; either way it must be what the row wrote.
            CH_ASSERT(reported == algorithm);
            char sig_hex[2 * sizeof sig + 1];
            (void)hex_encode(sig_hex, csig, csig_len);
            (void)snprintf(want, sizeof want, "ok %u %s", (unsigned)reported, sig_hex);
        }
        char cmd[2 * (HSPD_BODY_MAX + 4) + 64];
        hspd_request(cmd, sizeof cmd, "hs_certificate_verify", scheme, HSPD_CERTIFICATE_VERIFY,
                     body, w.len);
        expect(cmd, want);
    }
}

#endif
