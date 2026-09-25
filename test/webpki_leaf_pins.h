// SPKI pins alone against an X.509 chain (docs/decisions.md 65): a
// configuration with pins and no anchors accepts a chain only when a pin
// names the leaf's SubjectPublicKeyInfo, and then verifies
// CertificateVerify under the leaf's key. The chain above the leaf, the
// dates and the names are not read, because there is no anchor, clock or
// hostname to check them against.
//
// Through hsa_server_auth: every CertificateVerify row of
// test/webpki_auth_vectors.h under a pin on its leaf gets the row's
// verdict, so a signature the leaf key did not make is refused with
// decrypt_error; a pin on the intermediate, on the row's anchor key or on
// nothing is refused with bad_certificate. Through webpki_verify_leaf_pin
// directly: leaves the walk refuses for a name, an extension or a date
// are accepted, a key or a signature algorithm the reader refuses is not,
// only entry 0 counts, and the framing refuses what the walk refuses.
//
// Included by test/webpki_auth_test.c after webpki_auth_pins.h, whose
// helpers it reads.
#ifndef CH_TEST_WEBPKI_LEAF_PINS_H
#define CH_TEST_WEBPKI_LEAF_PINS_H

// A row's chain with no anchor, as pins alone configure it.
static webpki_corpus_chain unanchored(const webpki_corpus_chain *row) {
    webpki_corpus_chain bare = *row;
    bare.anchor_count = 0;
    return bare;
}

// One CertificateVerify row under pins alone: a pin on the leaf gives the
// row's own verdict, and a pin on the intermediate, on the anchor's key or
// on nothing gives bad_certificate before any signature is checked.
static void test_leaf_pin_flight(const webpki_auth_vector *v) {
    const webpki_corpus_chain *row = chain_named(v->chain);
    if (row == NULL) {
        return;
    }
    webpki_corpus_chain bare = unanchored(row);
    const verdict *want = verdict_for(v->expected);
    pin_set pins;
    handshake_state h;
    pin_of_nothing(pins[0]);
    CHECK(entry_pin(row->message, row->message_len, 0, pins[1]));
    int rc = chain_flight(v, &bare, row->message, row->message_len, pins, 2, &h);
    check_refusal(v->name, rc, rc == CH_OK ? 0 : h.alert, want->rc, want->alert);
    if (rc == CH_OK) {
        CHECK(h.leaf.alg == scheme_family(v->scheme));
        CHECK(h.leaf.path_entries == 1 && h.leaf.anchor_index == 0);
    }
    CHECK(entry_pin(row->message, row->message_len, 1, pins[0]));
    rc = chain_flight(v, &bare, row->message, row->message_len, pins, 1, &h);
    check_refusal("intermediate pin without anchors", rc, h.alert, CH_EAUTH, ALERT_BAD_CERTIFICATE);
    sha256_of(row->anchors[0].spki, row->anchors[0].spki_len, pins[0]);
    rc = chain_flight(v, &bare, row->message, row->message_len, pins, 1, &h);
    check_refusal("anchor pin without anchors", rc, h.alert, CH_EAUTH, ALERT_BAD_CERTIFICATE);
    pin_of_nothing(pins[0]);
    rc = chain_flight(v, &bare, row->message, row->message_len, pins, 1, &h);
    check_refusal("no pin without anchors", rc, h.alert, CH_EAUTH, ALERT_BAD_CERTIFICATE);
}

// webpki_verify_leaf_pin over one Certificate message's list, under one
// pin, with the caller's bad_certificate seeded. Returns the code and
// leaves the alert in *alert.
static int leaf_pin_call(const uint8_t *message, size_t message_len, const uint8_t *pin,
                         uint8_t *alert) {
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.spki_pins = pin;
    cfg.spki_pin_count = 1;
    webpki_leaf_info leaf;
    *alert = ALERT_BAD_CERTIFICATE;
    rbuf list;
    message_list(message, message_len, &list);
    size_t list_len = rb_left(&list);
    return webpki_verify_leaf_pin(rb_bytes(&list, list_len), list_len, &cfg, &leaf, alert);
}

// The verdict under a pin on a corpus row's leaf, read by the same reader
// the call uses, or on nothing when that reader refuses the leaf.
static int corpus_leaf_pin(const char *name, uint8_t *alert) {
    const webpki_corpus_chain *row = chain_named(name);
    if (row == NULL) {
        return CH_EINVAL;
    }
    uint8_t pin[SHA256_LEN];
    pin_of_nothing(pin);
    const uint8_t *cert = NULL;
    size_t cert_len = 0;
    webpki_cert parsed;
    uint8_t ignored = ALERT_BAD_CERTIFICATE;
    if (message_entry(row->message, row->message_len, 0, &cert, &cert_len) &&
        webpki_read_certificate_key(cert, cert_len, &parsed, &ignored) == CH_OK) {
        sha256_of(parsed.spki_tlv, parsed.spki_tlv_len, pin);
    }
    return leaf_pin_call(row->message, row->message_len, pin, alert);
}

// The leaf is read only as far as its key. Rows the walk refuses for the
// leaf's name, extensions or dates pass under a pin on its key; a row
// whose leaf key the reader refuses does not, and its alert is the
// reader's.
static void test_leaf_read_as_far_as_its_key(void) {
    static const char *const accepted[] = {
        "no_subject_alt_name",
        "key_usage_no_digital_signature",
        "no_server_auth_eku",
        "leaf_asserts_ca",
        "expired",
        "not_yet_valid",
        "hostname_mismatch",
        "intermediate_not_ca",
    };
    uint8_t alert = 0;
    for (size_t i = 0; i < sizeof accepted / sizeof accepted[0]; i++) {
        int rc = corpus_leaf_pin(accepted[i], &alert);
        check_refusal(accepted[i], rc, alert, CH_OK, ALERT_BAD_CERTIFICATE);
    }
    int rc = corpus_leaf_pin("rsa_1024_leaf", &alert);
    check_refusal("rsa_1024_leaf without anchors", rc, alert, CH_EPROTO,
                  ALERT_UNSUPPORTED_CERTIFICATE);
}

// Only entry 0 counts. The r2 chain with its entries swapped puts the
// intermediate first: a pin on the leaf, now entry 1, names nothing, and
// a pin on the intermediate names the key of a certificate the reader
// takes as the leaf.
static void test_leaf_is_entry_zero(void) {
    const webpki_corpus_chain *r2 = chain_named("r2");
    if (r2 == NULL) {
        return;
    }
    const uint8_t *leaf = NULL;
    size_t leaf_len = 0;
    const uint8_t *issuer = NULL;
    size_t issuer_len = 0;
    CHECK(message_entry(r2->message, r2->message_len, 0, &leaf, &leaf_len));
    CHECK(message_entry(r2->message, r2->message_len, 1, &issuer, &issuer_len));
    static uint8_t list[PIN_MESSAGE_MAX];
    static uint8_t message[PIN_MESSAGE_MAX];
    wbuf w;
    wb_init(&w, list, sizeof list);
    put_entry(&w, issuer, issuer_len, 0);
    put_entry(&w, leaf, leaf_len, 0);
    size_t message_len = certificate_message(message, list, w.len);
    uint8_t pin[SHA256_LEN];
    uint8_t alert = 0;
    CHECK(entry_pin(r2->message, r2->message_len, 0, pin));
    int rc = leaf_pin_call(message, message_len, pin, &alert);
    check_refusal("leaf pin on entry 1", rc, alert, CH_EAUTH, ALERT_BAD_CERTIFICATE);
    CHECK(entry_pin(r2->message, r2->message_len, 1, pin));
    CHECK(leaf_pin_call(message, message_len, pin, &alert) == CH_OK);
}

// The framing refuses what the walk's framing refuses: an extensions
// vector on an entry after the leaf, one entry past
// CH_WEBPKI_FLIGHT_ENTRIES, and a leaf one byte short.
static void test_leaf_pin_framing(void) {
    const webpki_corpus_chain *r2 = chain_named("r2");
    if (r2 == NULL) {
        return;
    }
    const uint8_t *leaf = NULL;
    size_t leaf_len = 0;
    CHECK(message_entry(r2->message, r2->message_len, 0, &leaf, &leaf_len));
    uint8_t pin[SHA256_LEN];
    CHECK(entry_pin(r2->message, r2->message_len, 0, pin));
    static uint8_t list[PIN_MESSAGE_MAX];
    static uint8_t message[PIN_MESSAGE_MAX];
    uint8_t alert = 0;
    wbuf w;
    wb_init(&w, list, sizeof list);
    put_entry(&w, leaf, leaf_len, 0);
    put_entry(&w, leaf, leaf_len, 1);
    size_t message_len = certificate_message(message, list, w.len);
    int rc = leaf_pin_call(message, message_len, pin, &alert);
    check_refusal("extension after the leaf", rc, alert, CH_EPROTO, ALERT_UNSUPPORTED_EXTENSION);
    wb_init(&w, list, sizeof list);
    for (size_t i = 0; i < CH_WEBPKI_FLIGHT_ENTRIES; i++) {
        put_entry(&w, leaf, leaf_len, 0);
    }
    message_len = certificate_message(message, list, w.len);
    CHECK(leaf_pin_call(message, message_len, pin, &alert) == CH_OK);
    put_entry(&w, leaf, leaf_len, 0);
    message_len = certificate_message(message, list, w.len);
    rc = leaf_pin_call(message, message_len, pin, &alert);
    check_refusal("one entry too many", rc, alert, CH_EPROTO, ALERT_BAD_CERTIFICATE);
    wb_init(&w, list, sizeof list);
    put_entry(&w, leaf, leaf_len - 1, 0);
    message_len = certificate_message(message, list, w.len);
    rc = leaf_pin_call(message, message_len, pin, &alert);
    check_refusal("leaf one byte short", rc, alert, CH_EPROTO, ALERT_BAD_CERTIFICATE);
}

static void test_leaf_pins(void) {
    for (size_t i = 0; i < sizeof webpki_auth_vectors / sizeof webpki_auth_vectors[0]; i++) {
        test_leaf_pin_flight(&webpki_auth_vectors[i]);
    }
    test_leaf_read_as_far_as_its_key();
    test_leaf_is_entry_zero();
    test_leaf_pin_framing();
}

#endif
