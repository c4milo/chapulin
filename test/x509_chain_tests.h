// Chain (two-entry) cases for the certificate grammar suite: the
// helpers and tests for leaf-plus-intermediate lists. Included by
// x509_strict_test.c after its vectors and helpers, the
// session_tests.h pattern; not a standalone translation unit.

// Builds a two-entry list — the first argument in the leaf slot,
// the second in the intermediate slot — and runs it against CA
// slot A only.
static int run_pair(const uint8_t *leaf, size_t leaf_len, const uint8_t *inter, size_t inter_len) {
    size_t n = put_entry(chain_list, leaf, leaf_len);
    n += put_entry(chain_list + n, inter, inter_len);
    return run_list_slots(chain_list, n, ca_key, ca_key_len, NULL, 0);
}

// A mutant that only broke the CA signature proves the grammar still
// accepts it: the parse completed and only unknown_ca stopped it.
static int grammar_ok(const uint8_t *cert, size_t n) {
    return run_cert(cert, n) == CH_EAUTH && last_alert == ALERT_UNKNOWN_CA;
}

static int rejected(const uint8_t *cert, size_t n, uint8_t alert) {
    return run_cert(cert, n) == CH_EPROTO && last_alert == alert;
}

// Splices the good leaf; the mutant lands in mutant_a.
static size_t mutate(size_t target_off, size_t target_len, const uint8_t *repl, size_t repl_len) {
    return splice(mutant_a, good_cert, good_cert_len, target_off, target_len, repl, repl_len);
}

// Copies the good leaf and overwrites two bytes at off (lengths intact).
static size_t patch2(uint8_t *out, size_t off, uint8_t b0, uint8_t b1) {
    memcpy(out, good_cert, good_cert_len);
    out[off] = b0;
    out[off + 1] = b1;
    return good_cert_len;
}

// Splices the chain's intermediate; the mutant lands in mutant_a.
static size_t mutate_int(size_t target_off, size_t target_len, const uint8_t *repl,
                         size_t repl_len) {
    return splice(mutant_a, chain_int, chain_int_len, target_off, target_len, repl, repl_len);
}

// Runs the mutant intermediate behind the good chain leaf. Every
// intermediate-profile reject fires during the parse, before any
// signature check, so the broken CA signature never masks it.
static int int_rejected(size_t mut_len, uint8_t alert) {
    return run_pair(chain_leaf, chain_leaf_len, mutant_a, mut_len) == CH_EPROTO &&
           last_alert == alert;
}

static void test_accept(void) {
    // The good leaf verifies: right slot, right length, exact key.
    CHECK(run_cert(good_cert, good_cert_len) == CH_OK);
    CHECK(last_info.ca_slot == 1 && last_info.key_len == good_key_len);
    CHECK(memcmp(last_info.key, good_key, good_key_len) == 0);

    // Slot B fallback: a wrong key in slot A, the CA in slot B. A
    // wrong CA in every populated slot fails authentication.
    CHECK(run_slots(good_cert, good_cert_len, wrong_ca, ca_key_len, ca_key, ca_key_len) == CH_OK);
    CHECK(last_info.ca_slot == 2);
    CHECK(run_slots(good_cert, good_cert_len, wrong_ca, ca_key_len, NULL, 0) == CH_EAUTH);
    CHECK(last_alert == ALERT_UNKNOWN_CA);
    CHECK(run_slots(good_cert, good_cert_len, wrong_ca, ca_key_len, wrong_ca, ca_key_len) ==
          CH_EAUTH);
    CHECK(last_alert == ALERT_UNKNOWN_CA);

    // The other build's leaf carries the other algorithm end to end.
    // The RSA build reads the smaller P-256 leaf and rejects its
    // AlgorithmIdentifier; the ECDSA build's cap is 768 and the RSA
    // leaf exceeds it, so the size gate rejects it first.
#ifdef CH_PIN_ECDSA
    {
        static uint8_t big_list[sizeof certv_leaf_rsa + 8];
        size_t bn = put_entry(big_list, other_build_cert, other_build_cert_len);
        CHECK(run_list_slots(big_list, bn, ca_key, ca_key_len, NULL, 0) == CH_EPROTO);
        CHECK(last_alert == ALERT_BAD_CERTIFICATE);
    }
#else
    CHECK(rejected(other_build_cert, other_build_cert_len, ALERT_UNSUPPORTED_CERTIFICATE));
#endif

    // The leaf without extendedKeyUsage never authenticates a server.
    // The ECDSA build reaches the extension walk and rejects the
    // missing EKU; the RSA build stops earlier, on the ECDSA sigalg.
    CHECK(rejected(certv_leaf_p256_no_eku, sizeof certv_leaf_p256_no_eku,
                   ALERT_UNSUPPORTED_CERTIFICATE));
}

static void test_list(void) {
    static uint8_t list[2 * CH_X509_MAX + 16];
    size_t n = put_entry(list, good_cert, good_cert_len);

    // Per-entry extensions: empty accepts (every other case here); a
    // two-byte extension block is off-profile.
    list[n - 1] = 2;
    list[n] = 0;
    list[n + 1] = 0;
    CHECK(run_list_slots(list, n + 2, ca_key, ca_key_len, NULL, 0) == CH_EPROTO);
    CHECK(last_alert == ALERT_BAD_CERTIFICATE);
    list[n - 1] = 0;

    // One trailing (zero) byte after the single entry: a truncated
    // second entry, malformed rather than off-profile. Then a second
    // whole CertificateEntry holding a leaf: a leaf in the
    // intermediate's slot has no CA extensions, off-profile.
    CHECK(run_list_slots(list, n + 1, ca_key, ca_key_len, NULL, 0) == CH_EPROTO);
    CHECK(last_alert == ALERT_BAD_CERTIFICATE);
    memcpy(list + n, list, n);
    CHECK(run_list_slots(list, 2 * n, ca_key, ca_key_len, NULL, 0) == CH_EPROTO);
    CHECK(last_alert == ALERT_UNSUPPORTED_CERTIFICATE);

    // An empty certificate entry: malformed framing, so the caller's
    // seeded alert stands.
    memset(list, 0, 5);
    CHECK(run_list_slots(list, 5, ca_key, ca_key_len, NULL, 0) == CH_EPROTO);
    CHECK(last_alert == ALERT_BAD_CERTIFICATE);

    // A certificate over the CH_X509_MAX cap dies before any parsing.
    size_t over = CH_X509_MAX + 1;
    list[0] = (uint8_t)(over >> 16);
    list[1] = (uint8_t)(over >> 8);
    list[2] = (uint8_t)over;
    memset(list + 3, 0x30, over + 2); // filler bytes, never parsed
    CHECK(run_list_slots(list, over + 5, ca_key, ca_key_len, NULL, 0) == CH_EPROTO);
    CHECK(last_alert == ALERT_BAD_CERTIFICATE);

    // Every strict prefix of the good list fails closed with the
    // caller's seeded alert.
    n = put_entry(list, good_cert, good_cert_len);
    int all_prefixes_fail = 1;
    for (size_t k = 0; k < n; k++) {
        if (run_list_slots(list, k, ca_key, ca_key_len, NULL, 0) != CH_EPROTO ||
            last_alert != ALERT_BAD_CERTIFICATE) {
            all_prefixes_fail = 0;
            (void)fprintf(stderr, "truncation prefix %zu did not fail closed\n", k);
        }
    }
    CHECK(all_prefixes_fail);
}

static void test_chain(void) {
    size_t n = put_entry(chain_list, chain_leaf, chain_leaf_len);
    n += put_entry(chain_list + n, chain_int, chain_int_len);

    // Two entries accept: the leaf, then the intermediate that signed
    // it; the pin vouches for the intermediate. Exact key out.
    CHECK(run_list_slots(chain_list, n, ca_key, ca_key_len, NULL, 0) == CH_OK);
    CHECK(last_info.ca_slot == 1 && last_info.key_len == chain_leaf_key_len);
    CHECK(memcmp(last_info.key, chain_leaf_key, chain_leaf_key_len) == 0);

    // Slot-B fallback anchors the chain head; a wrong CA in every
    // populated slot is a pin mismatch on the head.
    CHECK(run_list_slots(chain_list, n, wrong_ca, ca_key_len, ca_key, ca_key_len) == CH_OK);
    CHECK(last_info.ca_slot == 2);
    CHECK(run_list_slots(chain_list, n, wrong_ca, ca_key_len, wrong_ca, ca_key_len) == CH_EAUTH);
    CHECK(last_alert == ALERT_UNKNOWN_CA);

    // Boundary pair for the two-entry list length: the exact length
    // is the accept above; one more byte starts a third entry, and a
    // third certificate is off-profile — the root never travels.
    chain_list[n] = 0;
    CHECK(run_list_slots(chain_list, n + 1, ca_key, ca_key_len, NULL, 0) == CH_EPROTO);
    CHECK(last_alert == ALERT_UNSUPPORTED_CERTIFICATE);

    // Three whole entries fail the same way.
    size_t n3 = n + put_entry(chain_list + n, chain_int, chain_int_len);
    CHECK(run_list_slots(chain_list, n3, ca_key, ca_key_len, NULL, 0) == CH_EPROTO);
    CHECK(last_alert == ALERT_UNSUPPORTED_CERTIFICATE);

    // Truncation sweep over the two-entry list. The prefix that is
    // exactly the leaf entry is a well-formed one-entry list whose
    // head the pins reject — the leaf's issuer is the intermediate,
    // not the CA. Every other prefix is malformed and keeps the
    // caller's seeded alert.
    size_t leaf_entry_len = chain_leaf_len + 5;
    int all_prefixes_fail = 1;
    for (size_t k = 0; k < n; k++) {
        int rc = run_list_slots(chain_list, k, ca_key, ca_key_len, NULL, 0);
        int ok = k == leaf_entry_len ? (rc == CH_EAUTH && last_alert == ALERT_UNKNOWN_CA)
                                     : (rc == CH_EPROTO && last_alert == ALERT_BAD_CERTIFICATE);
        if (!ok) {
            all_prefixes_fail = 0;
            (void)fprintf(stderr, "chain truncation prefix %zu did not fail closed\n", k);
        }
    }
    CHECK(all_prefixes_fail);

    // Mismatched chain: the direct leaf, then the intermediate. The
    // pins vouch for the intermediate, but the leaf does not check
    // out under it — a corrupt chain, not an unknown CA.
    CHECK(run_pair(good_cert, good_cert_len, chain_int, chain_int_len) == CH_EAUTH);
    CHECK(last_alert == ALERT_BAD_CERTIFICATE);

    // Wrong order: the intermediate in the leaf slot fails the leaf
    // profile arm (CA extensions where the leaf's belong); a leaf in
    // the intermediate slot fails the CA arm the same way. Built
    // explicitly rather than through run_pair: the deliberate swap
    // would trip clang-tidy's swapped-argument heuristic there.
    size_t swapped = put_entry(chain_list, chain_int, chain_int_len);
    swapped += put_entry(chain_list + swapped, chain_leaf, chain_leaf_len);
    CHECK(run_list_slots(chain_list, swapped, ca_key, ca_key_len, NULL, 0) == CH_EPROTO);
    CHECK(last_alert == ALERT_UNSUPPORTED_CERTIFICATE);
    CHECK(run_pair(chain_leaf, chain_leaf_len, chain_leaf, chain_leaf_len) == CH_EPROTO);
    CHECK(last_alert == ALERT_UNSUPPORTED_CERTIFICATE);
}

static void test_chain_intermediate(void) {
    // basicConstraints must be exactly CA=TRUE with pathLen 0:
    // pathLen stripped, then CA=FALSE spelled as the empty SEQUENCE.
    size_t bc_value =
        ext_child(chain_int, chain_int_len, find_ext(chain_int, chain_int_len, oid_bc), 0x04);
    tlv_shape v;
    tlv_read(chain_int + bc_value, chain_int_len - bc_value, &v);
    size_t n = mutate_int(bc_value + v.header_len, v.content_len,
                          (const uint8_t[]){0x30, 0x03, 0x01, 0x01, 0xff}, 5);
    CHECK(int_rejected(n, ALERT_UNSUPPORTED_CERTIFICATE));
    n = mutate_int(bc_value + v.header_len, v.content_len, (const uint8_t[]){0x30, 0x00}, 2);
    CHECK(int_rejected(n, ALERT_UNSUPPORTED_CERTIFICATE));

    // pathLen 1: canonical DER, but one more depth level than the
    // profile pins (pathLen 0 is the accept above via the good chain).
    n = mutate_int(bc_value + v.header_len, v.content_len,
                   (const uint8_t[]){0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01}, 8);
    CHECK(int_rejected(n, ALERT_UNSUPPORTED_CERTIFICATE));

    // extendedKeyUsage on a CA certificate is off-profile: purpose
    // fields belong to end entities. Insert serverAuth.
    static const uint8_t eku_ext[] = {0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25,
                                      0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b,
                                      0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
    n = mutate_int(first_ext(chain_int, chain_int_len), 0, eku_ext, sizeof eku_ext);
    CHECK(int_rejected(n, ALERT_UNSUPPORTED_CERTIFICATE));

    // keyUsage without keyCertSign: digitalSignature-only is
    // canonical named-bit DER, but the wrong bit for a CA.
    size_t ku_value =
        ext_child(chain_int, chain_int_len, find_ext(chain_int, chain_int_len, oid_ku), 0x04);
    tlv_read(chain_int + ku_value, chain_int_len - ku_value, &v);
    n = mutate_int(ku_value + v.header_len, v.content_len,
                   (const uint8_t[]){0x03, 0x02, 0x07, 0x80}, 4);
    CHECK(int_rejected(n, ALERT_UNSUPPORTED_CERTIFICATE));
}

// Replaces the serialNumber TLV: header, then pad_len 0x00 octets,
// then value_len filler bytes whose first byte is `first`.
static size_t serial_case(size_t pad_len, uint8_t first, size_t value_len) {
    size_t serial = tbs_field(good_cert, good_cert_len, 1);
    uint8_t repl[26];
    repl[0] = 0x02;
    repl[1] = (uint8_t)(pad_len + value_len);
    memset(repl + 2, 0x00, pad_len);
    memset(repl + 2 + pad_len, 0x11, value_len);
    repl[2 + pad_len] = first;
    return mutate(serial, tlv_total(good_cert, good_cert_len, serial), repl,
                  2 + pad_len + value_len);
}
