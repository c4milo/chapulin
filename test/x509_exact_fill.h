// INV-25 for the ca mode's certificate reader: every container the
// parser decodes must be filled by the fields it decodes. One case per
// container, each the good leaf with one 0x00 byte added inside that
// container and every enclosing length re-encoded, so the byte is
// counted by the container that holds it and by nothing else. The
// unmutated leaf is the valid side of all of them. Included by
// x509_strict_test.c after its vectors and helpers, the
// session_tests.h pattern; not a standalone translation unit.
#ifndef CH_X509_EXACT_FILL_H
#define CH_X509_EXACT_FILL_H

// The TLV at off, rebuilt one byte longer, spliced back into the
// certificate. Its own length counts the added byte, so the fields
// inside it stop short of its end. The mutant is written to mutant_a.
static size_t with_trailing_byte(const uint8_t *cert, size_t n, size_t off) {
    static uint8_t tlv[X509MUT_CAP];
    tlv_shape s;
    tlv_read(cert + off, n - off, &s);
    size_t header = put_header(tlv, cert[off], s.content_len + 1);
    memcpy(tlv + header, cert + off + s.header_len, s.content_len);
    tlv[header + s.content_len] = 0x00;
    return splice(mutant_a, cert, n, off, s.header_len + s.content_len, tlv,
                  header + s.content_len + 1);
}

// The TLV at off with its declared length shortened by cut bytes and
// its content left where it is, spliced back into the certificate. The
// fields now run past the container that declared them while the
// enclosing container still covers them, which is what the length
// equalities at the container headers refuse. The mutant is written
// to mutant_a.
static size_t with_short_length(const uint8_t *cert, size_t n, size_t off, size_t cut) {
    static uint8_t tlv[X509MUT_CAP];
    tlv_shape s;
    tlv_read(cert + off, n - off, &s);
    size_t header = put_header(tlv, cert[off], s.content_len - cut);
    memcpy(tlv + header, cert + off + s.header_len, s.content_len);
    return splice(mutant_a, cert, n, off, s.header_len + s.content_len, tlv,
                  header + s.content_len);
}

// Every container the leaf's parse walks into, one byte too long.
static void test_exact_fill(void) {
    size_t tbs = nth_child(good_cert, good_cert_len, 0, 0);
    size_t spki = tbs_field(good_cert, good_cert_len, 6);
    size_t spki_bits = nth_child(good_cert, good_cert_len, spki, 1);
    size_t wrap = tbs_field(good_cert, good_cert_len, 7);
    size_t list = nth_child(good_cert, good_cert_len, wrap, 0);
    size_t key_usage = find_ext(good_cert, good_cert_len, oid_ku);
    size_t key_usage_value = ext_child(good_cert, good_cert_len, key_usage, 0x04);

    // The valid side: the leaf as issued fills every one of them.
    CHECK(run_cert(good_cert, good_cert_len) == CH_OK);

    // validity: a byte after notAfter (x509.c read_validity).
    CHECK(rejected(
        mutant_a,
        with_trailing_byte(good_cert, good_cert_len, tbs_field(good_cert, good_cert_len, 4)),
        ALERT_BAD_CERTIFICATE));

    // subjectPublicKeyInfo: a byte after the BIT STRING, and a byte
    // after the key inside the BIT STRING (x509_der.c x509_read_spki).
    CHECK(rejected(mutant_a, with_trailing_byte(good_cert, good_cert_len, spki),
                   ALERT_UNSUPPORTED_CERTIFICATE));
    CHECK(rejected(mutant_a, with_trailing_byte(good_cert, good_cert_len, spki_bits),
                   ALERT_UNSUPPORTED_CERTIFICATE));
#ifndef CH_PIN_ECDSA
    // RSAPublicKey: a byte after the publicExponent, inside the
    // SEQUENCE the BIT STRING carries.
    CHECK(rejected(mutant_a,
                   with_trailing_byte(good_cert, good_cert_len,
                                      nth_child(good_cert, good_cert_len, spki_bits, 0)),
                   ALERT_UNSUPPORTED_CERTIFICATE));
#endif

    // extensions [3]: a byte after the Extensions SEQUENCE, and a byte
    // after the last Extension inside it (x509.c parse_extensions).
    CHECK(rejected(mutant_a, with_trailing_byte(good_cert, good_cert_len, wrap),
                   ALERT_BAD_CERTIFICATE));
    CHECK(rejected(mutant_a, with_trailing_byte(good_cert, good_cert_len, list),
                   ALERT_BAD_CERTIFICATE));

    // One Extension: a byte after its extnValue (x509_der.c
    // x509_read_extension), and a byte after the BIT STRING inside the
    // keyUsage extnValue (x509_der.c x509_read_keyusage).
    CHECK(rejected(mutant_a, with_trailing_byte(good_cert, good_cert_len, key_usage),
                   ALERT_BAD_CERTIFICATE));
    CHECK(rejected(mutant_a, with_trailing_byte(good_cert, good_cert_len, key_usage_value),
                   ALERT_UNSUPPORTED_CERTIFICATE));

    // TBSCertificate: a byte after the extensions field (x509.c
    // parse_tbs).
    CHECK(rejected(mutant_a, with_trailing_byte(good_cert, good_cert_len, tbs),
                   ALERT_BAD_CERTIFICATE));

    // The Certificate SEQUENCE: a byte after the signature BIT STRING.
    // No container encloses it, so this one is built by hand.
    tlv_shape outer;
    tlv_read(good_cert, good_cert_len, &outer);
    size_t header = put_header(mutant_b, 0x30, outer.content_len + 1);
    memcpy(mutant_b + header, good_cert + outer.header_len, outer.content_len);
    mutant_b[header + outer.content_len] = 0x00;
    CHECK(rejected(mutant_b, header + outer.content_len + 1, ALERT_BAD_CERTIFICATE));

    // The CertificateEntry: a byte the outer SEQUENCE does not cover,
    // so the Certificate stops short of its entry (x509.c
    // parse_certificate's body_len compare).
    memcpy(mutant_b, good_cert, good_cert_len);
    mutant_b[good_cert_len] = 0x00;
    CHECK(rejected(mutant_b, good_cert_len + 1, ALERT_BAD_CERTIFICATE));

    // The other half of each length equality: a container whose length
    // stops before its own fields do. The bytes stay where they are,
    // so a reader that took the enclosing container's end for the
    // field's end would read straight past the short length and accept.

    // The Extensions SEQUENCE ends before its last Extension, which
    // stays inside the [3] wrapper (x509.c parse_extensions).
    size_t last_ext =
        nth_child(good_cert, good_cert_len, list, ext_count(good_cert, good_cert_len) - 1);
    CHECK(rejected(mutant_a,
                   with_short_length(good_cert, good_cert_len, list,
                                     tlv_total(good_cert, good_cert_len, last_ext)),
                   ALERT_BAD_CERTIFICATE));

#ifndef CH_PIN_ECDSA
    // The RSAPublicKey SEQUENCE ends before the publicExponent, which
    // stays inside the BIT STRING (x509_der.c x509_read_spki).
    size_t rsa_key = nth_child(good_cert, good_cert_len, spki_bits, 0);
    size_t exponent = nth_child(good_cert, good_cert_len, rsa_key, 1);
    CHECK(rejected(mutant_a,
                   with_short_length(good_cert, good_cert_len, rsa_key,
                                     tlv_total(good_cert, good_cert_len, exponent)),
                   ALERT_UNSUPPORTED_CERTIFICATE));
#endif

    // The Certificate SEQUENCE ends before the signature BIT STRING,
    // which stays inside the entry (x509.c parse_certificate).
    size_t signature = nth_child(good_cert, good_cert_len, 0, 2);
    size_t signature_len = tlv_total(good_cert, good_cert_len, signature);
    header = put_header(mutant_b, 0x30, outer.content_len - signature_len);
    memcpy(mutant_b + header, good_cert + outer.header_len, outer.content_len);
    CHECK(rejected(mutant_b, header + outer.content_len, ALERT_BAD_CERTIFICATE));
}

#endif
