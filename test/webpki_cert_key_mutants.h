// The key reader's rows for test/webpki_cert_test.c:
// webpki_read_certificate_key, which reads a leaf pinned with no anchor
// only as far as its key (docs/decisions.md 65), over the r2 leaf and the
// mutants test/webpki_cert_mutants.h builds.
//
// What it reads, it reads as webpki_parse_certificate does, so the base
// leaf gives both the same SubjectPublicKeyInfo. What it skips, it does
// not judge: a leaf the full parser refuses for an unknown critical
// extension, a missing subjectAltName, an outer signatureAlgorithm that
// differs from the TBS one or a signature it could not read is taken.
// What it skips it still frames, so each container ends where its fields
// end (INV-25): one byte past the extensions inside the TBSCertificate,
// or past the signature inside the Certificate, is refused, and so is a
// TBSCertificate with no extensions field. CH_WEBPKI_CERT_MAX holds as for
// the full parser.
//
// Included by test/webpki_cert_test.c after webpki_cert_mutants.h, whose
// base leaf and splice helpers it reads.
#ifndef CH_TEST_WEBPKI_CERT_KEY_MUTANTS_H
#define CH_TEST_WEBPKI_CERT_KEY_MUTANTS_H

// Reads cert as far as its key and requires rc and the alert it leaves.
static void expect_key(const uint8_t *cert, size_t n, int want_rc, uint8_t want_alert,
                       const char *file, int line) {
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    webpki_cert key;
    int rc = webpki_read_certificate_key(cert, n, &key, &alert);
    if (rc != want_rc || alert != want_alert) {
        (void)fprintf(stderr, "FAIL %s:%d: rc %d alert %u, want rc %d alert %u\n", file, line, rc,
                      alert, want_rc, want_alert);
        failures++;
    }
}
#define KEY_OK(cert, n) expect_key(cert, n, CH_OK, ALERT_BAD_CERTIFICATE, __FILE__, __LINE__)
#define KEY_BAD(cert, n) expect_key(cert, n, CH_EPROTO, ALERT_BAD_CERTIFICATE, __FILE__, __LINE__)
#define KEY_UNSUPPORTED(cert, n)                                                                   \
    expect_key(cert, n, CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE, __FILE__, __LINE__)

// The TLV at off in cert with one zero byte appended after it, inside the
// same container.
static size_t with_byte_after(const uint8_t *cert, size_t n, size_t off) {
    static uint8_t grown[X509MUT_CAP];
    size_t len = tlv_total(cert, n, off);
    memcpy(grown, cert + off, len);
    grown[len] = 0;
    return splice(mutant, cert, n, off, len, grown, len + 1);
}

// The base leaf: the same key, at the same bytes, as the full parser.
static void test_key_matches_parser(void) {
    webpki_cert full;
    webpki_cert key;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    CHECK(webpki_parse_certificate(base_leaf, base_leaf_len, 0, &full, &alert) == CH_OK);
    CHECK(webpki_read_certificate_key(base_leaf, base_leaf_len, &key, &alert) == CH_OK);
    CHECK(key.spki_tlv == full.spki_tlv && key.spki_tlv_len == full.spki_tlv_len);
    CHECK(key.spki.alg == full.spki.alg && key.spki.key == full.spki.key &&
          key.spki.key_len == full.spki.key_len);
    CHECK(key.tbs == full.tbs && key.tbs_len == full.tbs_len);
}

// Fields after the key are not judged.
static void test_key_skips(void) {
    // An unknown critical extension, 2.5.29.9, which the full parser
    // refuses.
    static const uint8_t critical[] = {0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d,
                                       0x09, 0x01, 0x01, 0xff, 0x04, 0x00};
    size_t n = with_first_extension(base_leaf, base_leaf_len, critical, sizeof critical);
    EXPECT_UNSUPPORTED(mutant, n, 0);
    KEY_OK(mutant, n);
    n = with_extension(base_leaf, base_leaf_len, oid_san, NULL, 0);
    EXPECT_UNSUPPORTED(mutant, n, 0);
    KEY_OK(mutant, n);
    // The outer signatureAlgorithm changed, so it no longer equals the
    // TBS one, and the signature emptied.
    static const uint8_t ecdsa_sha384[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                           0x48, 0xce, 0x3d, 0x04, 0x03, 0x03};
    size_t outer = nth_child(base_leaf, base_leaf_len, 0, 1);
    n = splice(mutant, base_leaf, base_leaf_len, outer, tlv_total(base_leaf, base_leaf_len, outer),
               ecdsa_sha384, sizeof ecdsa_sha384);
    EXPECT_UNSUPPORTED(mutant, n, 0);
    KEY_OK(mutant, n);
    static const uint8_t empty_signature[] = {0x03, 0x01, 0x00};
    size_t sig = nth_child(base_leaf, base_leaf_len, 0, 2);
    n = splice(mutant, base_leaf, base_leaf_len, sig, tlv_total(base_leaf, base_leaf_len, sig),
               empty_signature, sizeof empty_signature);
    EXPECT_BAD(mutant, n, 0);
    KEY_OK(mutant, n);
}

// What it skips it frames, and what it reads it judges.
static void test_key_frames(void) {
    size_t extensions = tbs_field(base_leaf, base_leaf_len, 7);
    KEY_BAD(mutant, with_byte_after(base_leaf, base_leaf_len, extensions));
    size_t sig = nth_child(base_leaf, base_leaf_len, 0, 2);
    KEY_BAD(mutant, with_byte_after(base_leaf, base_leaf_len, sig));
    size_t n = splice(mutant, base_leaf, base_leaf_len, extensions,
                      tlv_total(base_leaf, base_leaf_len, extensions), NULL, 0);
    KEY_BAD(mutant, n);
    // A key on a curve the mode refuses: secp256k1 in place of P-256.
    size_t spki = tbs_field(base_leaf, base_leaf_len, 6);
    static uint8_t other_curve[X509MUT_CAP];
    size_t spki_len = tlv_total(base_leaf, base_leaf_len, spki);
    memcpy(other_curve, base_leaf + spki, spki_len);
    static const uint8_t prime256v1[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    static const uint8_t secp256k1[] = {0x2b, 0x81, 0x04, 0x00, 0x0a};
    const uint8_t *at = NULL;
    for (size_t i = 0; i + sizeof prime256v1 <= spki_len && at == NULL; i++) {
        if (memcmp(other_curve + i, prime256v1, sizeof prime256v1) == 0) {
            at = other_curve + i;
        }
    }
    CHECK(at != NULL);
    if (at == NULL) {
        return;
    }
    size_t oid_at = (size_t)(at - other_curve);
    static uint8_t replaced[X509MUT_CAP];
    memcpy(replaced, other_curve, oid_at - 1);
    replaced[oid_at - 1] = sizeof secp256k1;
    memcpy(replaced + oid_at, secp256k1, sizeof secp256k1);
    memcpy(replaced + oid_at + sizeof secp256k1, other_curve + oid_at + sizeof prime256v1,
           spki_len - oid_at - sizeof prime256v1);
    size_t replaced_len = spki_len - sizeof prime256v1 + sizeof secp256k1;
    // The AlgorithmIdentifier SEQUENCE and the SPKI SEQUENCE shrink by 3.
    replaced[1] = (uint8_t)(replaced[1] - 3);
    replaced[3] = (uint8_t)(replaced[3] - 3);
    n = splice(mutant, base_leaf, base_leaf_len, spki, spki_len, replaced, replaced_len);
    EXPECT_UNSUPPORTED(mutant, n, 0);
    KEY_UNSUPPORTED(mutant, n);
}

// CH_WEBPKI_CERT_MAX: 3072 bytes read, 3073 refused.
static void test_key_size_bound(void) {
    static uint8_t big[CH_WEBPKI_CERT_MAX + 1];
    size_t n = padded_leaf(big, CH_WEBPKI_CERT_MAX);
    KEY_OK(big, n);
    n = padded_leaf(big, CH_WEBPKI_CERT_MAX + 1);
    KEY_BAD(big, n);
}

static void test_key_mutants(void) {
    test_key_matches_parser();
    test_key_skips();
    test_key_frames();
    test_key_size_bound();
}

#endif
