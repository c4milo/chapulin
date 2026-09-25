// The SPKI pin rows of test/webpki_session_test.c: the configuration
// rules webpki_cfg.c adds for pins, and the server_certificate_type offer
// the ClientHello carries (RFC 7250 §4.1). Included after the session
// test's valid_cfg, refused and sends_client_hello.
#ifndef CH_TEST_WEBPKI_PINS_CASES_H
#define CH_TEST_WEBPKI_PINS_CASES_H

static const uint8_t test_pins[CH_SPKI_PIN_MAX + 1][SHA256_LEN] = {{1}, {2}, {3}, {4}, {5}};

// The server_certificate_type list the captured hello offers, written to
// out, or -1 when the hello carries no such extension.
static int offered_cert_types(const mock_server *s, uint8_t out[2]) {
    size_t len = 0;
    const uint8_t *ext = hello_ext(s->hello, s->hello_len, EXT_SERVER_CERTIFICATE_TYPE, &len);
    if (ext == NULL || len < 2 || len > 3 || ext[0] != len - 1) {
        return -1;
    }
    memcpy(out, ext + 1, len - 1);
    return (int)(len - 1);
}

// A configuration of SPKI pins alone: no anchors, no hostname and no clock.
static ch_cfg pins_alone_cfg(mock_server *s) {
    ch_cfg cfg = valid_cfg(s);
    cfg.anchors = NULL;
    cfg.anchor_count = 0;
    cfg.hostname = NULL;
    cfg.hostname_len = 0;
    cfg.now_seconds = 0;
    cfg.spki_pins = (const uint8_t *)test_pins;
    cfg.spki_pin_count = 1;
    return cfg;
}

static void test_webpki_pin_count(void) {
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    cfg.spki_pins = (const uint8_t *)test_pins;
    cfg.spki_pin_count = CH_SPKI_PIN_MAX;
    CHECK(sends_client_hello(&cfg));
    cfg = valid_cfg(&s);
    cfg.spki_pins = (const uint8_t *)test_pins;
    cfg.spki_pin_count = CH_SPKI_PIN_MAX + 1;
    CHECK(refused(&cfg));
    cfg.spki_pin_count = 0; // a list without a count
    CHECK(refused(&cfg));
    cfg.spki_pins = NULL; // a count without a list
    cfg.spki_pin_count = 1;
    CHECK(refused(&cfg));
}

static void test_webpki_pins_alone(void) {
    mock_server s;
    uint8_t types[2];
    // Pins alone need no anchor, hostname or clock, and the hello offers
    // the raw public key and then X.509, whose leaf a pin must name
    // (docs/decisions.md 65), and names no server.
    ch_cfg cfg = pins_alone_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    CHECK(offered_cert_types(&s, types) == 2 && types[0] == CH_CERT_TYPE_RAW_PUBLIC_KEY &&
          types[1] == CH_CERT_TYPE_X509);
    size_t len = 0;
    CHECK(hello_ext(s.hello, s.hello_len, EXT_SERVER_NAME, &len) == NULL);
    // A hostname beside the pins is sent, and must still have its shape.
    cfg = pins_alone_cfg(&s);
    cfg.hostname = host;
    cfg.hostname_len = sizeof host;
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_ext(s.hello, s.hello_len, EXT_SERVER_NAME, &len) != NULL);
    cfg = pins_alone_cfg(&s);
    cfg.hostname = host;
    cfg.hostname_len = 0; // a pointer without a length
    CHECK(refused(&cfg));
    static const uint8_t bad_host[] = {'a', '.', '.', 'b'};
    cfg.hostname = bad_host;
    cfg.hostname_len = sizeof bad_host;
    CHECK(refused(&cfg));
    // Half an anchor list is not pins alone, and anchors want their rules.
    cfg = pins_alone_cfg(&s);
    cfg.anchor_count = 1;
    CHECK(refused(&cfg));
    cfg = pins_alone_cfg(&s);
    cfg.anchors = anchors;
    CHECK(refused(&cfg));
}

static void test_webpki_pins_with_anchors(void) {
    mock_server s;
    uint8_t types[2];
    // Anchors and pins: the raw key first, then X.509, and the anchors
    // still want a hostname and a clock.
    ch_cfg cfg = valid_cfg(&s);
    cfg.spki_pins = (const uint8_t *)test_pins;
    cfg.spki_pin_count = 2;
    CHECK(sends_client_hello(&cfg));
    CHECK(offered_cert_types(&s, types) == 2 && types[0] == CH_CERT_TYPE_RAW_PUBLIC_KEY &&
          types[1] == CH_CERT_TYPE_X509);
    cfg = valid_cfg(&s);
    cfg.spki_pins = (const uint8_t *)test_pins;
    cfg.spki_pin_count = 1;
    cfg.now_seconds = 0;
    CHECK(refused(&cfg));
    cfg.now_seconds = 1789000000U;
    cfg.hostname = NULL;
    cfg.hostname_len = 0;
    CHECK(refused(&cfg));
    // No pins: no extension, and the server sends the X.509 default.
    cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    CHECK(offered_cert_types(&s, types) == -1);
}

static void test_webpki_pins(void) {
    test_webpki_pin_count();
    test_webpki_pins_alone();
    test_webpki_pins_with_anchors();
}

#endif
