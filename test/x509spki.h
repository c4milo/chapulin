// SubjectPublicKeyInfo cases for the certificate grammar suite: the
// encoding rules the parser holds the build's pinned key algorithm
// to — the AlgorithmIdentifier OID, and then the P-256 point or the
// RSA modulus and exponent inside the BIT STRING. Included by
// x509strict_test.c after its vectors and helpers, the
// x509chain_tests.h pattern; not a standalone translation unit.
#ifndef CH_X509SPKI_H
#define CH_X509SPKI_H

static void test_spki(void) {
    size_t spki = tbs_field(good_cert, good_cert_len, 6);
    size_t algid = nth_child(good_cert, good_cert_len, spki, 0);
    size_t bits = nth_child(good_cert, good_cert_len, spki, 1);
    size_t n;

    // One OID byte off the build's SPKI AlgorithmIdentifier.
    n = patch2(mutant_a, algid + 4, good_cert[algid + 4] ^ 1U, good_cert[algid + 5]);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

#ifdef CH_PIN_ECDSA
    tlv_shape bs;
    tlv_read(good_cert + bits, good_cert_len - bits, &bs);
    // A compressed point marker in place of uncompressed 0x04, then a
    // nonzero unused-bits octet.
    n = patch2(mutant_a, bits + bs.header_len, 0x00, 0x02);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));
    n = patch2(mutant_a, bits + bs.header_len, 0x01, 0x04);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

    // BIT STRING content one under and one over the exact 66 (the
    // unused-bits octet, the 0x04 marker, then X||Y): 65 truncates Y
    // and 67 trails a byte. 66 is the accept in test_accept.
    uint8_t repl[70] = {0x03, 65};
    memcpy(repl + 2, good_cert + bits + bs.header_len, 65);
    n = mutate(bits, bs.header_len + bs.content_len, repl, 67);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));
    repl[1] = 67;
    memcpy(repl + 2, good_cert + bits + bs.header_len, 66);
    repl[68] = 0x00;
    n = mutate(bits, bs.header_len + bs.content_len, repl, 69);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));
#else
    size_t rsapub = nth_child(good_cert, good_cert_len, bits, 0);
    size_t modulus = nth_child(good_cert, good_cert_len, rsapub, 0);
    size_t exponent = nth_child(good_cert, good_cert_len, rsapub, 1);
    size_t modulus_size = tlv_total(good_cert, good_cert_len, modulus);
    tlv_shape m;
    tlv_read(good_cert + modulus, good_cert_len - modulus, &m);
    const uint8_t *value = good_cert + modulus + m.header_len + 1;
    size_t value_len = m.content_len - 1;
    uint8_t repl[392];
    size_t repl_len;

    // publicExponent 3 in place of 65537.
    n = mutate(exponent, tlv_total(good_cert, good_cert_len, exponent),
               (const uint8_t[]){0x02, 0x01, 0x03}, 3);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

    // Pad missing: the top-bit-set value alone reads as negative.
    repl_len = put_header(repl, 0x02, value_len);
    memcpy(repl + repl_len, value, value_len);
    n = mutate(modulus, modulus_size, repl, repl_len + value_len);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

    // Pad unneeded: a second 0x00 octet the value does not require.
    repl_len = put_header(repl, 0x02, value_len + 2);
    repl[repl_len] = 0x00;
    repl[repl_len + 1] = 0x00;
    memcpy(repl + repl_len + 2, value, value_len);
    n = mutate(modulus, modulus_size, repl, repl_len + value_len + 2);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

    // The modulus with its low bit flipped: even, so rsa_mont's
    // Montgomery arithmetic cannot run. The parse rejects it —
    // CH_EPROTO, never CH_EAUTH — so no signature check is reached.
    size_t mod_last = modulus + m.header_len + m.content_len - 1;
    n = patch2(mutant_a, mod_last - 1, good_cert[mod_last - 1], good_cert[mod_last] ^ 1U);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

    // Modulus length: 255 (under), 385 (over), and 260 (inside the
    // range but not a multiple of 8) all reject. The accept sides
    // already exist: 384 is this build's good leaf in test_accept,
    // and 256 verifies in the differential chain driver — diff_x509
    // in test/diffx509.h mints the RSA chain leaf with the 2048-bit
    // key via test/diffx509chain.h.
    static const size_t bad_modulus_lens[3] = {255, 385, 260};
    for (size_t i = 0; i < 3; i++) {
        size_t vlen = bad_modulus_lens[i];
        repl_len = put_header(repl, 0x02, vlen + 1);
        repl[repl_len] = 0x00; // the pad octet
        memset(repl + repl_len + 1, 0x11, vlen);
        repl[repl_len + 1] = 0x80;    // top bit set: the pad is needed
        repl[repl_len + vlen] = 0x11; // odd: only the length is off
        n = mutate(modulus, modulus_size, repl, repl_len + 1 + vlen);
        CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));
    }
#endif
}

#endif
