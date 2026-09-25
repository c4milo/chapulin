// The SPKI pin half of the TRUST=webpki QUIC loop: ch_cfg.spki_pins over
// QUIC, with the meaning they have over TCP (docs/webpki.md, "Raw public
// keys and SPKI pins", and docs/decisions.md 64). Included by
// test/quic_loop_test.c after quic_loop_webpki.h, whose helpers it reads.
//
// The three configurations, against this tree's QUIC server, which
// presents the r2 chain and never sends a raw public key (docs/webpki.md,
// "Not here"):
//  1. A hostname and anchors alone: test_webpki_resumption in
//     quic_loop_webpki.h.
//  2. Pins alone, with no hostname, anchor or clock: the hello offers the
//     raw public key and X.509 and names no server. This server answers
//     with its chain, which passes when a pin names its leaf's key and no
//     other (docs/decisions.md 65), as over TCP.
//  3. A hostname, anchors and pins: the walk and the name check pass, and
//     a pin must name a key on the path the walk verified.
//
// Tickets bind the pins beside the hostname and the anchors
// (webpki_ticket.h), so a pinned session's ticket resumes under the same
// pins and ch_quic_init refuses it under any other set.
#ifndef CH_TEST_QUIC_LOOP_PINS_H
#define CH_TEST_QUIC_LOOP_PINS_H

#include "hello_exts.h"

// The pin list every pinned client below points at, filled per case. One
// slot more than CH_SPKI_PIN_MAX, so the refused count has its pins too.
static uint8_t pins[CH_SPKI_PIN_MAX + 1][SHA256_LEN];

// A pin that names no key anywhere in this test.
static void pin_of_nothing(uint8_t pin[SHA256_LEN]) {
    memset(pin, 0x5a, SHA256_LEN);
}

// The pin of entry index of the r2 chain the server presents: the leaf at
// 0, the intermediate at 1. r2_identity must have split the chain first.
static int r2_pin(size_t index, uint8_t pin[SHA256_LEN]) {
    webpki_cert parsed;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    if (webpki_parse_certificate(r2_chain[index].der, r2_chain[index].len, index != 0, &parsed,
                                 &alert) != CH_OK) {
        return 0;
    }
    sha256_of(parsed.spki_tlv, parsed.spki_tlv_len, pin);
    return 1;
}

static void anchor_pin(const webpki_corpus_anchor *anchor, uint8_t pin[SHA256_LEN]) {
    sha256_of(anchor->spki, anchor->spki_len, pin);
}

// The client of configuration 3: webpki_client's anchors, hostname and
// clock, and the first count entries of pins.
static void pinned_client(ch_cfg *cfg, const webpki_corpus_anchor *root, size_t count) {
    webpki_client(cfg, root, "s3.example.test");
    cfg->spki_pins = (const uint8_t *)pins;
    cfg->spki_pin_count = count;
}

// The client of configuration 2: the first count entries of pins and no
// hostname, anchor or clock.
static void pins_alone_client(ch_cfg *cfg, size_t count) {
    client_config(cfg, &server_alpn[0]);
    cfg->spki_pins = (const uint8_t *)pins;
    cfg->spki_pin_count = count;
}

// The ClientHello ch_quic_init stages for cfg, copied into out, or 0 when
// ch_quic_init refuses cfg.
static size_t staged_hello(const ch_cfg *cfg, uint8_t *out, size_t cap) {
    static ch_quic probe;
    size_t n = 0;
    if (ch_quic_init(&probe, cfg) != CH_OK ||
        ch_quic_crypto_out(&probe, CH_LEVEL_INITIAL, out, cap, &n) != CH_OK) {
        return 0;
    }
    return n;
}

// The server_certificate_type list a staged hello offers, written to
// types, or -1 when the hello carries no such extension.
static int offered_cert_types(const uint8_t *hello, size_t n, uint8_t types[2]) {
    size_t len = 0;
    const uint8_t *ext = hello_ext(hello, n, EXT_SERVER_CERTIFICATE_TYPE, &len);
    if (ext == NULL || len < 2 || len > 3 || ext[0] != len - 1) {
        return -1;
    }
    memcpy(types, ext + 1, len - 1);
    return (int)(len - 1);
}

// A handshake the client refuses at the server's Certificate with alert,
// which RFC 9001 §4.8 carries as 0x0100 plus the alert.
static void check_refused_at_certificate(const ch_cfg *ccfg, const ch_cfg *scfg, uint8_t alert) {
    CHECK(!run_quic(ccfg, scfg));
    CHECK(ch_quic_state(&client) == CH_ST_FAILED);
    CHECK(ch_quic_alert(&client) == alert);
    CHECK(ch_quic_error_code(&client) == 0x0100U + alert);
}

// Configuration 3's offer: the raw public key first, then X.509, beside
// the name, the five signature schemes and the hybrid and x25519 shares
// every webpki hello carries.
static void test_pins_with_anchors_offer(void) {
    static uint8_t hello[CH_HELLO_MAX];
    ch_cfg ccfg;
    uint8_t types[2];
    uint16_t schemes[8] = {0};
    size_t share_len = 0;
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    size_t n = staged_hello(&ccfg, hello, sizeof hello);
    CHECK(n > 0);
    CHECK(offered_cert_types(hello, n, types) == 2 && types[0] == CH_CERT_TYPE_RAW_PUBLIC_KEY &&
          types[1] == CH_CERT_TYPE_X509);
    CHECK(hello_first_ext(hello, n) == EXT_SERVER_NAME);
    CHECK(hello_sigalgs(hello, n, schemes, 8) == 5);
    CHECK(hello_key_share(hello, n, CH_GROUP_X25519, &share_len) != NULL && share_len == 32);
}

// Configuration 3 end to end. A pin on each key of the path the walk
// verified passes: the leaf, the intermediate, and the anchor. A pin on
// nothing the server sent is refused with bad_certificate, after a chain
// and a name that pass without pins.
static void test_pins_with_anchors(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    webpki_server(&scfg, ticket_key);
    for (size_t index = 0; index < 2; index++) {
        CHECK(r2_pin(index, pins[0]));
        pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
        CHECK(run_quic(&ccfg, &scfg));
        CHECK(client.t.server_cert_type == CH_CERT_TYPE_X509 && handshake_messages() == 4);
        check_keys_agree();
    }
    anchor_pin(webpki_corpus_anchors_root_p384, pins[0]);
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    CHECK(run_quic(&ccfg, &scfg));
    pin_of_nothing(pins[0]);
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    check_refused_at_certificate(&ccfg, &scfg, ALERT_BAD_CERTIFICATE);
}

// The CH_SPKI_PIN_MAX boundary: the last pin of CH_SPKI_PIN_MAX names the
// leaf and the handshake completes, and one pin more is refused by
// ch_quic_init with nothing sent. A count without a list, and a list
// without a count, are refused as over TCP.
static void test_pin_count_boundary(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    static ch_quic probe;
    webpki_server(&scfg, ticket_key);
    for (size_t i = 0; i < CH_SPKI_PIN_MAX + 1; i++) {
        pin_of_nothing(pins[i]);
    }
    CHECK(r2_pin(0, pins[CH_SPKI_PIN_MAX - 1]));
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, CH_SPKI_PIN_MAX);
    CHECK(run_quic(&ccfg, &scfg));
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, CH_SPKI_PIN_MAX + 1);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    pins_alone_client(&ccfg, CH_SPKI_PIN_MAX);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_OK);
    pins_alone_client(&ccfg, CH_SPKI_PIN_MAX + 1);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 0);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    ccfg.spki_pins = NULL;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
}

// The CH_WEBPKI_ANCHOR_MAX boundary beside a pin, which quic_config.c
// now takes from webpki_cfg_ok: the root last of CH_WEBPKI_ANCHOR_MAX
// anchors verifies the chain, and one anchor more is refused.
static void test_anchor_count_boundary(void) {
    static ch_trust_anchor many[CH_WEBPKI_ANCHOR_MAX + 1];
    static ch_quic probe;
    ch_cfg scfg;
    ch_cfg ccfg;
    const webpki_corpus_anchor *impostor = webpki_corpus_anchors_impostor_p384;
    const webpki_corpus_anchor *root = webpki_corpus_anchors_root_p384;
    for (size_t i = 0; i < CH_WEBPKI_ANCHOR_MAX; i++) {
        many[i] = (ch_trust_anchor){impostor->name, impostor->name_len, impostor->spki,
                                    impostor->spki_len};
    }
    many[CH_WEBPKI_ANCHOR_MAX - 1] =
        (ch_trust_anchor){root->name, root->name_len, root->spki, root->spki_len};
    many[CH_WEBPKI_ANCHOR_MAX] = many[CH_WEBPKI_ANCHOR_MAX - 1];
    webpki_server(&scfg, ticket_key);
    CHECK(r2_pin(0, pins[0]));
    pinned_client(&ccfg, root, 1);
    ccfg.anchors = many;
    ccfg.anchor_count = CH_WEBPKI_ANCHOR_MAX;
    CHECK(run_quic(&ccfg, &scfg));
    pinned_client(&ccfg, root, 1);
    ccfg.anchors = many;
    ccfg.anchor_count = CH_WEBPKI_ANCHOR_MAX + 1;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
}

// A pin on a key the walk did not verify is refused with bad_certificate.
// Under the impostor anchor, which carries the root's Name over another
// key, then the root, the chain ends at the root: a pin on the root
// passes and a pin on the impostor, which named the issuer and verified
// nothing, does not.
static void test_pin_on_unused_anchor(void) {
    static ch_trust_anchor both[2];
    ch_cfg scfg;
    ch_cfg ccfg;
    const webpki_corpus_anchor *impostor = webpki_corpus_anchors_impostor_p384;
    const webpki_corpus_anchor *root = webpki_corpus_anchors_root_p384;
    both[0] =
        (ch_trust_anchor){impostor->name, impostor->name_len, impostor->spki, impostor->spki_len};
    both[1] = (ch_trust_anchor){root->name, root->name_len, root->spki, root->spki_len};
    webpki_server(&scfg, ticket_key);
    anchor_pin(root, pins[0]);
    pinned_client(&ccfg, root, 1);
    ccfg.anchors = both;
    ccfg.anchor_count = 2;
    CHECK(run_quic(&ccfg, &scfg));
    anchor_pin(impostor, pins[0]);
    pinned_client(&ccfg, root, 1);
    ccfg.anchors = both;
    ccfg.anchor_count = 2;
    check_refused_at_certificate(&ccfg, &scfg, ALERT_BAD_CERTIFICATE);
}

// The server's chain with one more CA certificate after the path: the
// aws intermediate, which neither signs the r2 leaf nor is signed by the
// r2 root. Returns 0 when the aws message does not frame it.
static ch_cert appended_chain[3];

static int append_unused_issuer(ch_cfg *scfg) {
    rbuf r;
    rb_init(&r, webpki_corpus_message_aws, sizeof webpki_corpus_message_aws);
    (void)rb_bytes(&r, 4 + 1 + 3);  // header, empty context, list length
    (void)rb_bytes(&r, rb_u24(&r)); // the aws leaf
    (void)rb_bytes(&r, rb_u16(&r));
    size_t len = rb_u24(&r);
    const uint8_t *issuer = rb_bytes(&r, len);
    if (r.err || issuer == NULL) {
        return 0;
    }
    appended_chain[0] = r2_chain[0];
    appended_chain[1] = r2_chain[1];
    appended_chain[2] = (ch_cert){issuer, len};
    scfg->srv.ecdsa_p256.chain = appended_chain;
    scfg->srv.ecdsa_p256.chain_count = 3;
    return 1;
}

// A pin on a certificate the server sent after the path does not count,
// as RFC 7858 §4.2 pins the validated chain. It is a CA certificate, so
// a pin check that read past the path would parse it and pass. The same
// chain passes under a pin on its leaf, so the refusal is the pin's.
static void test_pin_beyond_path(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    webpki_server(&scfg, ticket_key);
    CHECK(append_unused_issuer(&scfg));
    webpki_cert parsed;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    CHECK(webpki_parse_certificate(appended_chain[2].der, appended_chain[2].len, 1, &parsed,
                                   &alert) == CH_OK);
    sha256_of(parsed.spki_tlv, parsed.spki_tlv_len, pins[0]);
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    check_refused_at_certificate(&ccfg, &scfg, ALERT_BAD_CERTIFICATE);
    CHECK(r2_pin(0, pins[0]));
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(handshake_messages() == 4);
}

// Configuration 2: pins alone need no hostname, anchor or clock, and the
// hello offers the raw public key, then X.509, and names no server. This
// server ignores the offer and sends its chain. A pin on the leaf's key
// passes, and CertificateVerify is checked under that key; a pin on the
// intermediate, on the root or on nothing is refused with
// bad_certificate, because under pins alone only the leaf's key counts.
static void test_pins_alone(void) {
    static uint8_t hello[CH_HELLO_MAX];
    ch_cfg scfg;
    ch_cfg ccfg;
    uint8_t types[2];
    uint16_t schemes[8] = {0};
    size_t len = 0;
    webpki_server(&scfg, ticket_key);
    CHECK(r2_pin(0, pins[0]));
    pins_alone_client(&ccfg, 1);
    size_t n = staged_hello(&ccfg, hello, sizeof hello);
    CHECK(n > 0);
    CHECK(offered_cert_types(hello, n, types) == 2 && types[0] == CH_CERT_TYPE_RAW_PUBLIC_KEY &&
          types[1] == CH_CERT_TYPE_X509);
    CHECK(hello_ext(hello, n, EXT_SERVER_NAME, &len) == NULL);
    CHECK(hello_first_ext(hello, n) == EXT_ALPN);
    // The key the pins accept verifies CertificateVerify, so the hello
    // offers the signature schemes.
    CHECK(hello_sigalgs(hello, n, schemes, 8) == 5);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.server_cert_type == CH_CERT_TYPE_X509 && handshake_messages() == 4);
    check_keys_agree();
    // A hostname beside the pins goes out as server_name and is checked
    // against nothing: the leaf does not name other.example.test.
    pins_alone_client(&ccfg, 1);
    ccfg.hostname = (const uint8_t *)"other.example.test";
    ccfg.hostname_len = strlen("other.example.test");
    n = staged_hello(&ccfg, hello, sizeof hello);
    CHECK(n > 0 && hello_first_ext(hello, n) == EXT_SERVER_NAME);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(r2_pin(1, pins[0]));
    pins_alone_client(&ccfg, 1);
    check_refused_at_certificate(&ccfg, &scfg, ALERT_BAD_CERTIFICATE);
    anchor_pin(webpki_corpus_anchors_root_p384, pins[0]);
    pins_alone_client(&ccfg, 1);
    check_refused_at_certificate(&ccfg, &scfg, ALERT_BAD_CERTIFICATE);
    pin_of_nothing(pins[0]);
    pins_alone_client(&ccfg, 1);
    check_refused_at_certificate(&ccfg, &scfg, ALERT_BAD_CERTIFICATE);
}

// What ch_quic_init refuses in configuration 2, with the webpki_cfg.c
// rules: a hostname must still have its shape, at the CH_HOSTNAME_MAX
// boundary, a hostname pointer needs its length, and half an anchor list
// is not pins alone.
static void test_pins_alone_refusals(void) {
    static uint8_t name[CH_HOSTNAME_MAX + 1];
    static ch_quic probe;
    ch_cfg ccfg;
    for (size_t i = 0; i < sizeof name; i++) {
        name[i] = (i % 64 == 63) ? '.' : 'a';
    }
    pins_alone_client(&ccfg, 1);
    ccfg.hostname = name;
    ccfg.hostname_len = CH_HOSTNAME_MAX;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_OK);
    ccfg.hostname_len = CH_HOSTNAME_MAX + 1;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    ccfg.hostname_len = 0;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    pins_alone_client(&ccfg, 1);
    ccfg.anchor_count = 1;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    pins_alone_client(&ccfg, 1);
    ccfg.anchors = r2_anchors;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
}

// Rewrites the kept ticket's binding to the one cfg's configuration gives
// its PSK, the binding a caller holds for a ticket that session received.
static void bind_kept_ticket(const ch_cfg *cfg) {
    uint8_t config_hash[SHA256_LEN];
    webpki_ticket_config_hash(cfg, config_hash);
    webpki_ticket_binding(kept.psk, kept.psk_len, config_hash, kept.binding);
}

// A pinned session's ticket resumes under the same pins, and the resuming
// hello offers both certificate types ahead of pre_shared_key, the last
// extension. Under any other pin set, or none, ch_quic_init refuses it.
static void test_pinned_resumption(void) {
    static uint8_t hello[CH_HELLO_MAX];
    static ch_quic probe;
    ch_cfg scfg;
    ch_cfg ccfg;
    uint8_t types[2];
    webpki_server(&scfg, ticket_key);
    CHECK(r2_pin(0, pins[0]));
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    size_t count = kept.count;
    CHECK(run_quic(&ccfg, &scfg));
    take_ticket();
    CHECK(kept.count == count + 1 && kept_ticket_bound(&ccfg));

    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    present_ticket(&ccfg);
    size_t n = staged_hello(&ccfg, hello, sizeof hello);
    int ext_count = 0;
    int psk_index = hello_ext_index(hello, n, EXT_PRE_SHARED_KEY, &ext_count);
    CHECK(offered_cert_types(hello, n, types) == 2 && psk_index == ext_count - 1);
    CHECK(hello_ext_index(hello, n, EXT_SERVER_CERTIFICATE_TYPE, NULL) < psk_index);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 1 && handshake_messages() == 2);
    take_ticket();
    CHECK(kept_ticket_bound(&ccfg));

    // Another pin set: the intermediate's pin in place of the leaf's, the
    // same pin twice, and no pin at all.
    CHECK(r2_pin(1, pins[0]));
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    CHECK(r2_pin(0, pins[0]));
    CHECK(r2_pin(0, pins[1]));
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 2);
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    // The binding the pinned session gave the ticket still resumes it.
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_OK);
}

// A server that declines a pinned ticket gets a full handshake in the
// same connection, and the pins judge its chain as in a handshake with no
// ticket: a pin on the leaf passes, and a pin on nothing is refused. The
// second client's binding is recomputed under its own pins, so
// ch_quic_init takes the ticket and the refusal comes from the chain.
static void test_pinned_decline(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    uint8_t binding[SHA256_LEN];
    memcpy(binding, kept.binding, sizeof binding);
    webpki_server(&scfg, other_ticket_key);
    CHECK(r2_pin(0, pins[0]));
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    present_ticket(&ccfg);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 0 && handshake_messages() == 4);
    pin_of_nothing(pins[0]);
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    present_ticket(&ccfg);
    bind_kept_ticket(&ccfg);
    check_refused_at_certificate(&ccfg, &scfg, ALERT_BAD_CERTIFICATE);
    CHECK(client.t.psk_selected == 0);
    memcpy(kept.binding, binding, sizeof binding);
}

// A pins-alone session's ticket stays bound to its pins: it resumes under
// the same pin with no Certificate, and ch_quic_init refuses it under
// another pin, under the same pin beside anchors, and under anchors with
// no pin.
static void test_pins_alone_resumption(void) {
    static ch_quic probe;
    ch_cfg scfg;
    ch_cfg ccfg;
    webpki_server(&scfg, ticket_key);
    CHECK(r2_pin(0, pins[0]));
    pins_alone_client(&ccfg, 1);
    size_t count = kept.count;
    CHECK(run_quic(&ccfg, &scfg));
    take_ticket();
    CHECK(kept.count == count + 1 && kept_ticket_bound(&ccfg));
    pins_alone_client(&ccfg, 1);
    present_ticket(&ccfg);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 1 && handshake_messages() == 2);
    take_ticket();
    CHECK(kept_ticket_bound(&ccfg));
    CHECK(r2_pin(1, pins[0]));
    pins_alone_client(&ccfg, 1);
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    CHECK(r2_pin(0, pins[0]));
    pinned_client(&ccfg, webpki_corpus_anchors_root_p384, 1);
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
}

static void test_webpki_pins(void) {
    test_pins_with_anchors_offer();
    test_pins_with_anchors();
    test_pin_count_boundary();
    test_anchor_count_boundary();
    test_pin_on_unused_anchor();
    test_pin_beyond_path();
    test_pins_alone();
    test_pins_alone_refusals();
    test_pinned_resumption();
    test_pinned_decline();
    test_pins_alone_resumption();
}

#endif
