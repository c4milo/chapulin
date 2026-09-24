// SPKI pins through hsa_server_auth (webpki_pin.h, and the dispatch in
// handshake_auth.c's webpki_server_key). A pin is SHA-256 of a whole DER
// SubjectPublicKeyInfo (RFC 7858 §4.2); this file computes each one from
// the key bytes the fixtures carry.
//
// Two halves. Under the RFC 7250 RawPublicKey type, the flights in
// test/webpki_auth_vectors.h's webpki_raw_vectors are accepted when a pin
// names the key, first or second of two, and refused when none does; the
// same key reframed with a second entry, an extensions vector or a
// trailing byte is refused by the framing, and a malformed or refused key
// by the reader. Under the X.509 type with anchors, each accepted chain
// row is accepted with a pin on its leaf, its intermediate or its anchor,
// and refused with a pin only on a certificate beyond the path, on an
// anchor that did not verify, or on nothing.
//
// Included by test/webpki_auth_test.c after run_flight and its helpers.
#ifndef CH_TEST_WEBPKI_AUTH_PINS_H
#define CH_TEST_WEBPKI_AUTH_PINS_H

#include "webpki_pin.h"

// The largest Certificate message this file builds, the aws chain with
// the r2 intermediate appended, fits the record reader's CH_MIN_RXBUF.
#define PIN_MESSAGE_MAX CH_MIN_RXBUF
// A Certificate message's bytes before its first CertificateEntry: the
// msg_type, the u24 length, the empty certificate_request_context and the
// u24 list length.
#define MESSAGE_HEADER_LEN 8

// Two pins: the slots a configuration here fills.
typedef uint8_t pin_set[2][SHA256_LEN];

// A pin no corpus key hashes to.
static void pin_of_nothing(uint8_t pin[SHA256_LEN]) {
    memset(pin, 0x5a, SHA256_LEN);
}

// A raw public key row by name.
static const webpki_raw_vector *raw_vector_named(const char *name) {
    for (size_t i = 0; i < sizeof webpki_raw_vectors / sizeof webpki_raw_vectors[0]; i++) {
        if (strcmp(webpki_raw_vectors[i].name, name) == 0) {
            return &webpki_raw_vectors[i];
        }
    }
    (void)fprintf(stderr, "FAIL no raw public key row named %s\n", name);
    failures++;
    return &webpki_raw_vectors[0];
}

// A CertificateVerify row by name.
static const webpki_auth_vector *auth_vector_named(const char *name) {
    for (size_t i = 0; i < sizeof webpki_auth_vectors / sizeof webpki_auth_vectors[0]; i++) {
        if (strcmp(webpki_auth_vectors[i].name, name) == 0) {
            return &webpki_auth_vectors[i];
        }
    }
    (void)fprintf(stderr, "FAIL no CertificateVerify row named %s\n", name);
    failures++;
    return &webpki_auth_vectors[0];
}

// Checks one refusal: the code and the alert hsa_server_auth left.
static void check_refusal(const char *what, int rc, uint8_t alert, int want_rc,
                          uint8_t want_alert) {
    if (rc != want_rc || alert != want_alert) {
        (void)fprintf(stderr, "FAIL %s: rc %d alert %u, want rc %d alert %u\n", what, rc, alert,
                      want_rc, want_alert);
        failures++;
    }
}

// A Certificate message around list.
static size_t certificate_message(uint8_t *out, const uint8_t *list, size_t list_len) {
    wbuf w;
    wb_init(&w, out, PIN_MESSAGE_MAX);
    wb_u8(&w, HS_CERTIFICATE);
    size_t body = wb_mark(&w, 3);
    wb_u8(&w, 0);
    wb_u24(&w, (uint32_t)list_len);
    wb_bytes(&w, list, list_len);
    wb_patch24(&w, body);
    CHECK(!w.err);
    return w.len;
}

// Appends one CertificateEntry: a u24 length, the bytes, and a u16
// extensions length followed by that many zero bytes.
static void put_entry(wbuf *w, const uint8_t *data, size_t data_len, size_t extensions_len) {
    wb_u24(w, (uint32_t)data_len);
    wb_bytes(w, data, data_len);
    wb_u16(w, (uint16_t)extensions_len);
    for (size_t i = 0; i < extensions_len; i++) {
        wb_u8(w, 0);
    }
}

// The CertificateEntry list of a Certificate message, as a reader.
static void message_list(const uint8_t *message, size_t message_len, rbuf *list) {
    rb_init(list, message, message_len);
    rb_skip(list, MESSAGE_HEADER_LEN);
    CHECK(!list->err);
}

// Entry index of a Certificate message, framed as the walk frames it.
static int message_entry(const uint8_t *message, size_t message_len, size_t index,
                         const uint8_t **cert, size_t *cert_len) {
    rbuf r;
    message_list(message, message_len, &r);
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    for (size_t i = 0; i <= index; i++) {
        if (webpki_read_entry(&r, CH_WEBPKI_CERT_MAX, cert, cert_len, &alert) != CH_OK) {
            return 0;
        }
    }
    return 1;
}

// The pin on entry index's SubjectPublicKeyInfo, the certificate parsed
// under the arm the walk reads it under.
static int entry_pin(const uint8_t *message, size_t message_len, size_t index,
                     uint8_t pin[SHA256_LEN]) {
    const uint8_t *cert = NULL;
    size_t cert_len = 0;
    webpki_cert parsed;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    if (!message_entry(message, message_len, index, &cert, &cert_len) ||
        webpki_parse_certificate(cert, cert_len, index != 0, &parsed, &alert) != CH_OK) {
        return 0;
    }
    sha256_of(parsed.spki_tlv, parsed.spki_tlv_len, pin);
    return 1;
}

// A session that selected cert_type and carries pins, and anchors only
// when row is not NULL.
static void pinned_session(ch_tls *t, ch_trust_anchor *anchors, const webpki_corpus_chain *row,
                           uint8_t cert_type, pin_set pins, size_t pin_count) {
    memset(t, 0, sizeof *t);
    if (row != NULL) {
        row_cfg(row, anchors, &t->cfg);
    }
    // ISO C has no implicit conversion that adds const to an array's
    // element type, so the pins take the field's type by cast.
    t->cfg.spki_pins = (const uint8_t *)pins;
    t->cfg.spki_pin_count = pin_count;
    t->server_cert_type = cert_type;
}

// One flight under pins: a CertificateVerify under scheme carrying sig,
// and the anchors of row when it is not NULL. An accepted flight's
// transcript is checked. Returns the code and leaves the alert and the
// key in h.
static int pinned_flight(uint8_t cert_type, const webpki_corpus_chain *row, uint16_t scheme,
                         const uint8_t *sig, size_t sig_len, const uint8_t *message,
                         size_t message_len, pin_set pins, size_t pin_count, handshake_state *h) {
    ch_trust_anchor anchors[CH_WEBPKI_ANCHOR_MAX];
    ch_tls t;
    pinned_session(&t, anchors, row, cert_type, pins, pin_count);
    uint8_t verify_msg[VERIFY_MSG_MAX];
    size_t verify_len = 0;
    int rc = run_flight(&t, h, message, message_len, scheme, sig, sig_len, verify_msg, &verify_len);
    if (rc == CH_OK) {
        check_transcript(&t, message, message_len, verify_msg, verify_len);
    }
    return rc;
}

static int raw_flight(const webpki_raw_vector *v, const uint8_t *message, size_t message_len,
                      pin_set pins, size_t pin_count, handshake_state *h) {
    return pinned_flight(CH_CERT_TYPE_RAW_PUBLIC_KEY, NULL, v->scheme, v->sig, v->sig_len, message,
                         message_len, pins, pin_count, h);
}

static int chain_flight(const webpki_auth_vector *v, const webpki_corpus_chain *row,
                        const uint8_t *message, size_t message_len, pin_set pins, size_t pin_count,
                        handshake_state *h) {
    return pinned_flight(CH_CERT_TYPE_X509, row, v->scheme, v->sig, v->sig_len, message,
                         message_len, pins, pin_count, h);
}

// Each key family's raw key: accepted with its pin first, accepted with
// its pin second of two (a rotation), and refused with bad_certificate
// when no pin names it. An accepted raw key has no path, so the walk's
// two path fields stay 0.
static void test_raw_keys(void) {
    for (size_t i = 0; i < sizeof webpki_raw_vectors / sizeof webpki_raw_vectors[0]; i++) {
        const webpki_raw_vector *v = &webpki_raw_vectors[i];
        uint8_t transcript[SHA256_LEN];
        sha256_of(v->message, v->message_len, transcript);
        CHECK(memcmp(transcript, v->transcript, SHA256_LEN) == 0);
        pin_set pins;
        handshake_state h;
        sha256_of(v->spki, v->spki_len, pins[0]);
        pin_of_nothing(pins[1]);
        CHECK(raw_flight(v, v->message, v->message_len, pins, 2, &h) == CH_OK);
        CHECK(h.leaf.alg == scheme_family(v->scheme));
        CHECK(h.leaf.path_entries == 0 && h.leaf.anchor_index == 0);
        pin_of_nothing(pins[0]);
        sha256_of(v->spki, v->spki_len, pins[1]);
        CHECK(raw_flight(v, v->message, v->message_len, pins, 2, &h) == CH_OK);
        int rc = raw_flight(v, v->message, v->message_len, pins, 1, &h);
        check_refusal(v->name, rc, h.alert, CH_EAUTH, ALERT_BAD_CERTIFICATE);
    }
}

// One reframed raw key list, refused before any pin is read: the P-256
// key is pinned, so the refusal is the framing's or the reader's.
static void check_raw_list(const char *what, const wbuf *list, int want_rc, uint8_t want_alert) {
    static uint8_t message[PIN_MESSAGE_MAX];
    const webpki_raw_vector *v = raw_vector_named("p256");
    pin_set pins;
    sha256_of(v->spki, v->spki_len, pins[0]);
    pin_of_nothing(pins[1]);
    CHECK(!list->err);
    size_t message_len = certificate_message(message, list->p, list->len);
    handshake_state h;
    int rc = raw_flight(v, message, message_len, pins, 2, &h);
    check_refusal(what, rc, h.alert, want_rc, want_alert);
}

// RFC 7250 §3: the list holds exactly one entry, whose data is one
// SubjectPublicKeyInfo and whose extensions vector is empty. The P-256
// key reframed each way this client refuses.
static void test_raw_key_framing(void) {
    const webpki_raw_vector *v = raw_vector_named("p256");
    uint8_t list[2 * (CH_WEBPKI_SPKI_MAX + 5) + 8];
    uint8_t spki[CH_WEBPKI_SPKI_MAX + 1] = {0};
    CHECK(v->spki_len < sizeof spki);
    wbuf w;
    wb_init(&w, list, sizeof list);
    put_entry(&w, v->spki, v->spki_len, 0);
    put_entry(&w, v->spki, v->spki_len, 0);
    check_raw_list("two entries", &w, CH_EPROTO, ALERT_BAD_CERTIFICATE);
    wb_init(&w, list, sizeof list);
    put_entry(&w, v->spki, v->spki_len, 4);
    check_raw_list("entry extensions", &w, CH_EPROTO, ALERT_UNSUPPORTED_EXTENSION);
    wb_init(&w, list, sizeof list);
    put_entry(&w, v->spki, v->spki_len, 0);
    wb_u8(&w, 0);
    check_raw_list("trailing byte", &w, CH_EPROTO, ALERT_BAD_CERTIFICATE);
    // The key and one more byte inside the entry: the reader must fill
    // the entry exactly.
    memcpy(spki, v->spki, v->spki_len);
    wb_init(&w, list, sizeof list);
    put_entry(&w, spki, v->spki_len + 1, 0);
    check_raw_list("byte after the key", &w, CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE);
    // A SubjectPublicKeyInfo whose SEQUENCE tag is a SET: malformed.
    spki[0] = 0x31;
    wb_init(&w, list, sizeof list);
    put_entry(&w, spki, v->spki_len, 0);
    check_raw_list("malformed key", &w, CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE);
    // The last byte of prime256v1's OID, 22 bytes in, moved: a curve the
    // mode refuses in a key that is otherwise well formed.
    spki[0] = 0x30;
    spki[22] ^= 0x01;
    wb_init(&w, list, sizeof list);
    put_entry(&w, spki, v->spki_len, 0);
    check_raw_list("refused curve", &w, CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE);
}

// CH_WEBPKI_SPKI_MAX bounds the raw entry at the largest key the reader
// accepts: the RSA-4096 root's 550-byte SubjectPublicKeyInfo is
// accepted, and the same key with one byte more inside the entry is
// refused by the framing with bad_certificate, where the reader would
// have answered unsupported_certificate. Called directly, since no
// fixture signs with that key.
static void test_raw_key_bound(void) {
    const uint8_t *spki = webpki_corpus_spki_root_gcs_rsa4096;
    size_t spki_len = sizeof webpki_corpus_spki_root_gcs_rsa4096;
    CHECK(spki_len == CH_WEBPKI_SPKI_MAX);
    uint8_t list[CH_WEBPKI_SPKI_MAX + 6];
    uint8_t padded[CH_WEBPKI_SPKI_MAX + 1] = {0};
    memcpy(padded, spki, spki_len);
    pin_set pins;
    sha256_of(spki, spki_len, pins[0]);
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.spki_pins = (const uint8_t *)pins;
    cfg.spki_pin_count = 1;
    webpki_leaf_info leaf;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    wbuf w;
    wb_init(&w, list, sizeof list);
    put_entry(&w, spki, spki_len, 0);
    CHECK(webpki_verify_raw_key(list, w.len, &cfg, &leaf, &alert) == CH_OK);
    CHECK(leaf.alg == WEBPKI_KEY_RSA && leaf.key_len == 512);
    CHECK(alert == ALERT_BAD_CERTIFICATE);
    wb_init(&w, list, sizeof list);
    put_entry(&w, padded, sizeof padded, 0);
    CHECK(webpki_verify_raw_key(list, w.len, &cfg, &leaf, &alert) == CH_EPROTO);
    CHECK(alert == ALERT_BAD_CERTIFICATE);
    cfg.spki_pin_count = 0;
    CHECK(!webpki_spki_pinned(&cfg, spki, spki_len));
}

// RFC 7858 §4.2 pins the validated chain: each accepted chain row passes
// with a pin, the second of two, on its leaf, its intermediate or its
// anchor, and a pin on nothing refuses it with bad_certificate.
static void test_chain_path_pins(const webpki_auth_vector *v) {
    const webpki_corpus_chain *row = chain_named(v->chain);
    if (row == NULL) {
        return;
    }
    pin_set pins;
    handshake_state h;
    pin_of_nothing(pins[0]);
    for (size_t index = 0; index < 2; index++) {
        CHECK(entry_pin(row->message, row->message_len, index, pins[1]));
        CHECK(chain_flight(v, row, row->message, row->message_len, pins, 2, &h) == CH_OK);
    }
    sha256_of(row->anchors[0].spki, row->anchors[0].spki_len, pins[1]);
    CHECK(chain_flight(v, row, row->message, row->message_len, pins, 2, &h) == CH_OK);
    int rc = chain_flight(v, row, row->message, row->message_len, pins, 1, &h);
    check_refusal(v->name, rc, h.alert, CH_EAUTH, ALERT_BAD_CERTIFICATE);
}

// A pinned certificate appended to a chain another CA signed does not
// pass: the aws walk stops at entry 1, so the r2 intermediate appended as
// entry 3 is beyond the path and its pin names nothing on it. It is a CA
// certificate, so it parses under the issuer arm, and a pin check that
// read past the path would count it. Pinned on the aws leaf instead, the
// same message passes the pins and fails only at CertificateVerify, whose
// signature covers the message without the fourth entry.
static void test_pin_beyond_path(void) {
    const webpki_auth_vector *v = auth_vector_named("rsa_pss");
    const webpki_corpus_chain *aws = chain_named("aws");
    const webpki_corpus_chain *r2 = chain_named("r2");
    if (aws == NULL || r2 == NULL) {
        return;
    }
    static uint8_t list[PIN_MESSAGE_MAX];
    static uint8_t message[PIN_MESSAGE_MAX];
    rbuf aws_list;
    message_list(aws->message, aws->message_len, &aws_list);
    const uint8_t *r2_issuer = NULL;
    size_t r2_issuer_len = 0;
    CHECK(message_entry(r2->message, r2->message_len, 1, &r2_issuer, &r2_issuer_len));
    wbuf w;
    wb_init(&w, list, sizeof list);
    size_t aws_list_len = rb_left(&aws_list);
    wb_bytes(&w, rb_bytes(&aws_list, aws_list_len), aws_list_len);
    put_entry(&w, r2_issuer, r2_issuer_len, 0);
    CHECK(!w.err);
    size_t message_len = certificate_message(message, list, w.len);
    pin_set pins;
    handshake_state h;
    CHECK(entry_pin(r2->message, r2->message_len, 1, pins[0]));
    CHECK(entry_pin(message, message_len, 3, pins[1])); // the issuer arm parses it
    CHECK(memcmp(pins[0], pins[1], SHA256_LEN) == 0);
    int rc = chain_flight(v, aws, message, message_len, pins, 1, &h);
    check_refusal("pin beyond the path", rc, h.alert, CH_EAUTH, ALERT_BAD_CERTIFICATE);
    CHECK(entry_pin(aws->message, aws->message_len, 0, pins[0]));
    rc = chain_flight(v, aws, message, message_len, pins, 1, &h);
    check_refusal("leaf pin, appended entry", rc, h.alert, CH_EAUTH, ALERT_DECRYPT_ERROR);
}

// The anchor the pins may name is the one that verified. The r2 chain
// under the impostor anchor, which carries the P-384 root's Name over
// another key, then the real root ends at anchor 1: a pin on the real
// root passes, and a pin on the impostor, which named the issuer and
// verified nothing, is refused.
static void test_pin_anchor_index(void) {
    const webpki_auth_vector *v = auth_vector_named("p256_sha256");
    const webpki_corpus_chain *r2 = chain_named("r2");
    const webpki_corpus_chain *impostor = chain_named("anchor_key_mismatch");
    if (r2 == NULL || impostor == NULL) {
        return;
    }
    webpki_corpus_anchor anchors[2] = {impostor->anchors[0], r2->anchors[0]};
    webpki_corpus_chain row = *r2;
    row.anchors = anchors;
    row.anchor_count = 2;
    pin_set pins;
    handshake_state h;
    sha256_of(r2->anchors[0].spki, r2->anchors[0].spki_len, pins[0]);
    CHECK(chain_flight(v, &row, r2->message, r2->message_len, pins, 1, &h) == CH_OK);
    CHECK(h.leaf.path_entries == 2 && h.leaf.anchor_index == 1);
    sha256_of(impostor->anchors[0].spki, impostor->anchors[0].spki_len, pins[0]);
    int rc = chain_flight(v, &row, r2->message, r2->message_len, pins, 1, &h);
    check_refusal("pin on the anchor that did not verify", rc, h.alert, CH_EAUTH,
                  ALERT_BAD_CERTIFICATE);
}

// Pins without anchors offer the raw key alone, so an X.509 answer is
// refused with unsupported_certificate before any chain is read, even
// one whose leaf a pin names (RFC 7250 §4.2).
static void test_pins_without_anchors(void) {
    const webpki_auth_vector *v = auth_vector_named("rsa_pss");
    const webpki_corpus_chain *row = chain_named(v->chain);
    if (row == NULL) {
        return;
    }
    pin_set pins;
    handshake_state h;
    CHECK(entry_pin(row->message, row->message_len, 0, pins[0]));
    webpki_corpus_chain bare = *row;
    bare.anchor_count = 0;
    int rc = chain_flight(v, &bare, row->message, row->message_len, pins, 1, &h);
    check_refusal("x509 answer without anchors", rc, h.alert, CH_EAUTH,
                  ALERT_UNSUPPORTED_CERTIFICATE);
}

static void test_chain_pins(void) {
    for (size_t i = 0; i < sizeof webpki_auth_vectors / sizeof webpki_auth_vectors[0]; i++) {
        const webpki_auth_vector *v = &webpki_auth_vectors[i];
        if (strcmp(v->expected, "ok") == 0) {
            test_chain_path_pins(v);
        }
    }
    test_pin_beyond_path();
    test_pin_anchor_index();
    test_pins_without_anchors();
}

#endif
