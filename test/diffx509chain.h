// List-shape rows for the certificate differential: framing mutants
// around one good certificate, and the two-entry chain the Lean spec
// mints (x509mintchain) — the leaf signed by an intermediate, the
// intermediate signed by the CA — which the C parser must accept
// with the same leaf key. The chain reject rows: swapped entries, a
// third entry, four off-profile intermediates each genuinely
// CA-signed so the profile check alone rejects them, a leaf the pin
// signed instead of the intermediate, and truncations. Included by
// diffx509.h only, after certd_row and certd_mint; test/diff.c is
// the one translation unit.
#ifndef CH_DIFFX509CHAIN_H
#define CH_DIFFX509CHAIN_H

// List-level mutants around one good certificate: truncations,
// trailing bytes, and a second entry too broken to be a chain.
static void certd_list_mutants(const char *alg, const char *ca_hex, const uint8_t *ca_key,
                               size_t ca_len, const uint8_t *cert, size_t cert_len) {
    static uint8_t list[CERTD_CERT_MAX + 24];
    size_t n = certd_wrap(list, cert, cert_len);
    // A byte short: the entry's framing overruns the input.
    certd_row(alg, ca_hex, ca_key, ca_len, list, n - 1, NULL);
    // A byte long: data after the one entry.
    list[n] = 0;
    certd_row(alg, ca_hex, ca_key, ca_len, list, n + 1, NULL);
    // A 1-byte second cert with empty extensions: two entries are the
    // chain grammar, but this one dies in the intermediate's parser.
    memcpy(list + n, (const uint8_t[]){0x00, 0x00, 0x01, 0x30, 0x00, 0x00}, 6);
    certd_row(alg, ca_hex, ca_key, ca_len, list, n + 6, NULL);
    // Truncated certificate with the framing patched to match: the
    // outer SEQUENCE now overruns the entry.
    n = certd_wrap(list, cert, cert_len - 1);
    certd_row(alg, ca_hex, ca_key, ca_len, list, n, NULL);
}

// P-256 intermediate: its own private scalar (the chain's middle
// signer; its point becomes the intermediate's SPKI) and signing
// nonce. The RSA chain reuses the diffrsa.h 3072-bit key as the
// intermediate and the 2048-bit key as the CA.
static const char *const certd_p256_int_d_hex =
    "2e9f0c2b1d4a68355c7e01f2a9b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5";
static const char *const certd_p256_int_k_hex =
    "619b8f0a7c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f506172839405161b";

// The intermediate's extension arm: keyUsage(keyCertSign) critical
// plus basicConstraints(CA=TRUE, pathLen 0) critical — and the four
// off-profile variants the chain rows reject.
static const char *const certd_int_exts_hex =
    "300e0603551d0f0101ff04040302020430120603551d130101ff040830060101ff020100";
// basicConstraints CA=TRUE with pathLenConstraint absent.
static const char *const certd_int_exts_no_pathlen_hex =
    "300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff";
// basicConstraints CA=FALSE (the empty SEQUENCE).
static const char *const certd_int_exts_not_ca_hex =
    "300e0603551d0f0101ff040403020204300c0603551d130101ff04023000";
// extendedKeyUsage(serverAuth) added: purpose fields belong to end
// entities.
static const char *const certd_int_exts_eku_hex =
    "300e0603551d0f0101ff04040302020430120603551d130101ff040830060101ff020100"
    "30130603551d25040c300a06082b06010505070301";
// keyUsage digitalSignature instead of keyCertSign.
static const char *const certd_int_exts_no_certsign_hex =
    "300e0603551d0f0101ff04040302078030120603551d130101ff040830060101ff020100";

// Mints one chained pair through the spec: the leaf (the profile's
// leaf extensions) signed by the intermediate, then the intermediate
// carrying int_exts_hex signed by the CA. Returns the two-entry
// CertificateEntry-list bytes.
static size_t certd_mint_chain(const char *alg, const char *leaf_hex, const char *int_exts_hex,
                               uint8_t *list) {
    static char cmd[8192];
    static char list_hex[2 * CERTD_LIST_MAX + 1];
    if (strcmp(alg, "rsa") == 0) {
        (void)snprintf(cmd, sizeof cmd, "x509mintchain rsa %s %s %s %s %s %s %s %s %s %s %s %s",
                       diff_rsa_n2048, diff_rsa_d2048, diff_rsa_n3072, diff_rsa_d3072,
                       certd_salt_hex, certd_serial_hex, certd_name_hex, certd_validity_hex,
                       certd_name_hex, leaf_hex, certd_exts_hex, int_exts_hex);
    } else {
        (void)snprintf(cmd, sizeof cmd, "x509mintchain p256 %s %s %s %s %s %s %s %s %s %s %s",
                       certd_p256_ca_d_hex, certd_p256_ca_k_hex, certd_p256_int_d_hex,
                       certd_p256_int_k_hex, certd_serial_hex, certd_name_hex, certd_validity_hex,
                       certd_name_hex, leaf_hex, certd_exts_hex, int_exts_hex);
    }
    query(cmd, list_hex, sizeof list_hex);
    size_t n = strlen(list_hex);
    if (n % 2 != 0 || n / 2 < 16 || n / 2 > CERTD_LIST_MAX || !hex_decode(list, list_hex, n / 2)) {
        die("x509mintchain: malformed spec response");
    }
    return n / 2;
}

// Appends one CertificateEntry (u24 length, the certificate, empty
// u16 extensions) at len; returns the new list length.
static size_t certd_append_entry(uint8_t *list, size_t len, const uint8_t *cert, size_t cert_len) {
    return len + certd_wrap(list + len, cert, cert_len);
}

// Splits a spec-minted two-entry list into its certificates. The
// framing came from the spec, so a bad split is a test bug.
static void certd_split_chain(const uint8_t *list, size_t list_len, const uint8_t **leaf,
                              size_t *leaf_len, const uint8_t **inter, size_t *inter_len) {
    size_t n1 = ((size_t)list[0] << 16) | ((size_t)list[1] << 8) | list[2];
    if (n1 + 5 + 5 > list_len) {
        die("x509mintchain: first entry overruns the list");
    }
    *leaf = list + 3;
    *leaf_len = n1;
    const uint8_t *p = list + n1 + 5;
    size_t n2 = ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2];
    if (n1 + 5 + n2 + 5 != list_len) {
        die("x509mintchain: second entry does not fill the list");
    }
    *inter = p + 3;
    *inter_len = n2;
}

// One C-only alert check: in the build's algorithm, the list must
// fail with exactly this return code and alert against pin slot A.
static void certd_alert(const char *alg, const uint8_t *ca_key, size_t ca_len, const uint8_t *list,
                        size_t list_len, int want_rc, uint8_t seed, uint8_t want_alert,
                        const char *why) {
    if (strcmp(alg, certd_build_alg) != 0) {
        return;
    }
    x509_leaf_info info;
    uint8_t alert = seed;
    if (x509_verify_leaf(list, list_len, ca_key, ca_len, NULL, 0, &info, &alert) != want_rc ||
        alert != want_alert) {
        die(why);
    }
    comparisons++;
}

// The slot pair, C-only: slot B anchors when slot A holds the wrong
// key, and a head off both pins fails as unknown_ca.
static void certd_slot_checks(const char *alg, const uint8_t *list, size_t list_len,
                              const uint8_t *wrong_ca, size_t wrong_len, const uint8_t *ca_key,
                              size_t ca_len, const char *why_b, const char *why_unknown) {
    if (strcmp(alg, certd_build_alg) != 0) {
        return;
    }
    x509_leaf_info info;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    if (x509_verify_leaf(list, list_len, wrong_ca, wrong_len, ca_key, ca_len, &info, &alert) !=
            CH_OK ||
        info.ca_slot != 2) {
        die(why_b);
    }
    alert = ALERT_BAD_CERTIFICATE;
    if (x509_verify_leaf(list, list_len, wrong_ca, wrong_len, NULL, 0, &info, &alert) != CH_EAUTH ||
        alert != ALERT_UNKNOWN_CA) {
        die(why_unknown);
    }
    comparisons += 2;
}

// One algorithm's chain pass: mint the two-entry chain and accept it,
// then reject the swapped order, a third entry, four off-profile
// intermediates, a pin-signed leaf, and truncations — same verdict on
// both sides, with the C build's alerts checked exactly. leaf_hex is
// the chain's leaf key; wrong_ca_hex is a well-formed key of the same
// algorithm that never signed the intermediate.
static void diff_x509_chain(const char *alg, const char *ca_hex, const char *leaf_hex,
                            const char *wrong_ca_hex) {
    static uint8_t ca_key[384];
    static uint8_t wrong_ca[384];
    static uint8_t list[CERTD_LIST_MAX];
    static uint8_t mut[CERTD_LIST_MAX];
    static uint8_t single[CERTD_CERT_MAX + 16];
    size_t ca_len = strlen(ca_hex) / 2;
    size_t wrong_len = strlen(wrong_ca_hex) / 2;
    if (ca_len > sizeof ca_key || !hex_decode(ca_key, ca_hex, ca_len) ||
        wrong_len > sizeof wrong_ca || !hex_decode(wrong_ca, wrong_ca_hex, wrong_len)) {
        die("cert: malformed CA key constant");
    }
    size_t list_len = certd_mint_chain(alg, leaf_hex, certd_int_exts_hex, list);
    const uint8_t *leaf = NULL;
    size_t leaf_len = 0;
    const uint8_t *inter = NULL;
    size_t inter_len = 0;
    certd_split_chain(list, list_len, &leaf, &leaf_len, &inter, &inter_len);

    // The accept row: the chain yields the same leaf key on both
    // sides. Then the chain head against pins that never signed the
    // intermediate — for RSA, the intermediate's own key among them.
    certd_row(alg, ca_hex, ca_key, ca_len, list, list_len, leaf_hex);
    certd_row(alg, wrong_ca_hex, wrong_ca, wrong_len, list, list_len, NULL);
    if (strcmp(alg, certd_build_alg) == 0) {
        certd_slot_checks(alg, list, list_len, wrong_ca, wrong_len, ca_key, ca_len,
                          "cert: slot B did not anchor the chain",
                          "cert: a chain head off both pins must fail as unknown_ca");
    }

    // Leaf and intermediate swapped: the first entry faces the leaf
    // arm, where keyCertSign keyUsage is off-profile.
    size_t n = certd_append_entry(mut, 0, inter, inter_len);
    n = certd_append_entry(mut, n, leaf, leaf_len);
    certd_row(alg, ca_hex, ca_key, ca_len, mut, n, NULL);
    // A third entry — the root, played by the intermediate again,
    // never travels.
    memcpy(mut, list, list_len);
    n = certd_append_entry(mut, list_len, inter, inter_len);
    certd_row(alg, ca_hex, ca_key, ca_len, mut, n, NULL);
    certd_alert(alg, ca_key, ca_len, mut, n, CH_EPROTO, ALERT_BAD_CERTIFICATE,
                ALERT_UNSUPPORTED_CERTIFICATE,
                "cert: a third entry must fail as unsupported_certificate");

    // Off-profile intermediates, each genuinely CA-signed so the
    // profile arm alone rejects: basicConstraints without pathLen,
    // CA=FALSE, EKU present, keyUsage without keyCertSign.
    const char *const bad_int_exts[4] = {certd_int_exts_no_pathlen_hex, certd_int_exts_not_ca_hex,
                                         certd_int_exts_eku_hex, certd_int_exts_no_certsign_hex};
    for (size_t i = 0; i < 4; i++) {
        n = certd_mint_chain(alg, leaf_hex, bad_int_exts[i], mut);
        certd_row(alg, ca_hex, ca_key, ca_len, mut, n, NULL);
        certd_alert(alg, ca_key, ca_len, mut, n, CH_EPROTO, ALERT_BAD_CERTIFICATE,
                    ALERT_UNSUPPORTED_CERTIFICATE,
                    "cert: an off-profile intermediate must fail as unsupported_certificate");
    }

    // A leaf the pin signed instead of the intermediate: the chain
    // head verifies, the leaf does not check out under the
    // intermediate's key — both sides reject at the signature step,
    // and the C names the corrupt chain, not an unknown CA. The zero
    // alert seed proves the parser sets this path's alert itself.
    size_t single_len =
        certd_mint(alg, certd_serial_hex, certd_name_hex, leaf_hex, certd_exts_hex, single);
    n = certd_append_entry(mut, 0, single + 3, single_len - 5);
    n = certd_append_entry(mut, n, inter, inter_len);
    certd_row(alg, ca_hex, ca_key, ca_len, mut, n, NULL);
    certd_alert(alg, ca_key, ca_len, mut, n, CH_EAUTH, 0, ALERT_BAD_CERTIFICATE,
                "cert: a pin-signed leaf under an intermediate must fail as bad_certificate");

    // Truncations, each its own verdict row: one byte short; three
    // bytes short (into the intermediate's body); cut to exactly the
    // first entry — a well-framed list whose leaf then faces the pins
    // directly and fails at the signature; cut into the second
    // entry's u24 length; and a trailing byte.
    certd_row(alg, ca_hex, ca_key, ca_len, list, list_len - 1, NULL);
    certd_row(alg, ca_hex, ca_key, ca_len, list, list_len - 3, NULL);
    certd_row(alg, ca_hex, ca_key, ca_len, list, leaf_len + 5, NULL);
    certd_row(alg, ca_hex, ca_key, ca_len, list, leaf_len + 5 + 2, NULL);
    memcpy(mut, list, list_len);
    mut[list_len] = 0;
    certd_row(alg, ca_hex, ca_key, ca_len, mut, list_len + 1, NULL);
}

#endif
