// The two EncryptedExtensions arms that turn on what a TRUST=webpki
// ClientHello asked for, split out of test/handshake_strict_test.c to
// keep that file inside the 500-line limit: the server_name
// acknowledgement, which the parser admits only when the hello sent
// server_name, and server_certificate_type (RFC 7250 §4.2), which it
// admits only when the hello offered certificate types. Every other
// build sends neither, so both are responses to a request that never
// went out. Included by that file alone, after make_encrypted_exts and
// the alpn_offer table exist.
#ifndef CH_TEST_HANDSHAKE_STRICT_CERT_TYPE_H
#define CH_TEST_HANDSHAKE_STRICT_CERT_TYPE_H

#ifdef CH_TRUST_WEBPKI
// The three offers webpki_cert_types_offered makes: none, the raw key
// alone (SPKI pins without anchors), and the raw key and X.509 (pins
// and anchors).
#define OFFER_NONE 0U
#define OFFER_RAW (1U << CH_CERT_TYPE_RAW_PUBLIC_KEY)
#define OFFER_RAW_X509 (OFFER_RAW | (1U << CH_CERT_TYPE_X509))

// A seed the parser never writes: it writes only an offered type, and
// every offered type is below 8. A row that reads it back knows the
// parser left *cert_type alone.
#define CERT_TYPE_UNWRITTEN 0xff

// Parses an EncryptedExtensions holding exts, from a ClientHello that
// sent server_name when server_name_sent is set and offered the
// certificate types in offered, with the full ALPN offer. *cert_type is
// the caller's seed and the parser's selection. The alert is seeded with
// 0, which no refusal writes, so a row that reads 0 back after a refusal
// knows the parser kept the seed.
static int cert_type_row(const uint8_t *exts, size_t n, int server_name_sent, uint8_t offered,
                         uint8_t *cert_type, uint8_t *alert) {
    uint8_t body[64];
    size_t len = make_encrypted_exts(body, exts, n);
    uint16_t peer_limit = CH_TX_PT;
    uint8_t selected = CH_ALPN_NONE;
    *alert = 0;
    return hsp_parse_encrypted_exts(body, len, &peer_limit, alpn_offer, ALPN_OFFER_COUNT, &selected,
                                    server_name_sent, offered, cert_type, alert);
}

// One server_certificate_type extension whose body is the len bytes at
// value, in out.
static size_t cert_type_ext(uint8_t *out, const uint8_t *value, size_t len) {
    wbuf w;
    wb_init(&w, out, 16);
    wb_u16(&w, EXT_SERVER_CERTIFICATE_TYPE);
    wb_u16(&w, (uint16_t)len);
    wb_bytes(&w, value, len);
    CHECK(!w.err);
    return w.len;
}

// Runs one extension whose body is the one byte type, against offered,
// and returns the result with the selection and the alert.
static int cert_type_value_row(uint8_t type, uint8_t offered, uint8_t *cert_type, uint8_t *alert) {
    uint8_t ext[16];
    size_t n = cert_type_ext(ext, &type, 1);
    *cert_type = CERT_TYPE_UNWRITTEN;
    return cert_type_row(ext, n, 1, offered, cert_type, alert);
}

// The server_name acknowledgement admitted only when the ClientHello
// sent server_name. A pins-only configuration may leave the hostname
// unset, and its hello then sends none, so RFC 6066 §3 gives the server
// nothing to acknowledge: the empty acknowledgement is an unrequested
// response, unsupported_extension (110), and so is one with data, which
// a hello that sent server_name would answer with decode_error (50).
static void test_server_name_sent(void) {
    static const uint8_t empty[] = {0x00, 0x00, 0x00, 0x00};
    static const uint8_t data[] = {0x00, 0x00, 0x00, 0x01, 0x78};
    uint8_t cert_type = CH_CERT_TYPE_X509;
    uint8_t alert = 0;
    CHECK(cert_type_row(empty, sizeof empty, 1, OFFER_NONE, &cert_type, &alert) == CH_OK);
    CHECK(cert_type_row(empty, sizeof empty, 0, OFFER_NONE, &cert_type, &alert) == CH_EPROTO);
    CHECK(alert == ALERT_UNSUPPORTED_EXTENSION);
    CHECK(cert_type_row(data, sizeof data, 1, OFFER_NONE, &cert_type, &alert) == CH_EPROTO);
    CHECK(alert == ALERT_DECODE_ERROR);
    CHECK(cert_type_row(data, sizeof data, 0, OFFER_NONE, &cert_type, &alert) == CH_EPROTO);
    CHECK(alert == ALERT_UNSUPPORTED_EXTENSION);
}

// The value the server selects, against each offer. An offered type is
// accepted and written; the type the offer lacks and every value no
// offer can hold are illegal_parameter (47), and the selection is left
// alone.
static void test_cert_type_values(void) {
    uint8_t cert_type = 0;
    uint8_t alert = 0;
    CHECK(cert_type_value_row(CH_CERT_TYPE_RAW_PUBLIC_KEY, OFFER_RAW, &cert_type, &alert) == CH_OK);
    CHECK(cert_type == CH_CERT_TYPE_RAW_PUBLIC_KEY && alert == 0);
    CHECK(cert_type_value_row(CH_CERT_TYPE_X509, OFFER_RAW, &cert_type, &alert) == CH_EPROTO);
    CHECK(cert_type == CERT_TYPE_UNWRITTEN && alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(cert_type_value_row(CH_CERT_TYPE_RAW_PUBLIC_KEY, OFFER_RAW_X509, &cert_type, &alert) ==
          CH_OK);
    CHECK(cert_type == CH_CERT_TYPE_RAW_PUBLIC_KEY);
    CHECK(cert_type_value_row(CH_CERT_TYPE_X509, OFFER_RAW_X509, &cert_type, &alert) == CH_OK);
    CHECK(cert_type == CH_CERT_TYPE_X509);
    // 1 is OpenPGP, which RFC 9846 §4.5.1 forbids in TLS 1.3; 3 is the
    // first value past the two this client knows; 7 is the last bit of
    // the offer's bit set, and 8 the first value past it; 255 is the
    // largest CertificateType.
    static const uint8_t unoffered[] = {1, 3, 7, 8, 255};
    for (size_t i = 0; i < sizeof unoffered; i++) {
        CHECK(cert_type_value_row(unoffered[i], OFFER_RAW_X509, &cert_type, &alert) == CH_EPROTO);
        CHECK(cert_type == CERT_TYPE_UNWRITTEN && alert == ALERT_ILLEGAL_PARAMETER);
    }
    // No offer: the ClientHello sent no server_certificate_type, so any
    // selection answers a request that never went out (110).
    CHECK(cert_type_value_row(CH_CERT_TYPE_RAW_PUBLIC_KEY, OFFER_NONE, &cert_type, &alert) ==
          CH_EPROTO);
    CHECK(cert_type == CERT_TYPE_UNWRITTEN && alert == ALERT_UNSUPPORTED_EXTENSION);
    CHECK(cert_type_value_row(CH_CERT_TYPE_X509, OFFER_NONE, &cert_type, &alert) == CH_EPROTO);
    CHECK(alert == ALERT_UNSUPPORTED_EXTENSION);
}

// The body is one CertificateType (RFC 7250 §3). One byte is the only
// valid length; 0 and 2 are decode_error (50).
static void test_cert_type_lengths(void) {
    static const uint8_t two[] = {CH_CERT_TYPE_RAW_PUBLIC_KEY, 0x00};
    uint8_t ext[16];
    uint8_t cert_type = CERT_TYPE_UNWRITTEN;
    uint8_t alert = 0;
    size_t n = cert_type_ext(ext, two, 0);
    CHECK(cert_type_row(ext, n, 1, OFFER_RAW_X509, &cert_type, &alert) == CH_EPROTO);
    CHECK(cert_type == CERT_TYPE_UNWRITTEN && alert == ALERT_DECODE_ERROR);
    n = cert_type_ext(ext, two, 1);
    CHECK(cert_type_row(ext, n, 1, OFFER_RAW_X509, &cert_type, &alert) == CH_OK);
    CHECK(cert_type == CH_CERT_TYPE_RAW_PUBLIC_KEY);
    cert_type = CERT_TYPE_UNWRITTEN;
    n = cert_type_ext(ext, two, 2);
    CHECK(cert_type_row(ext, n, 1, OFFER_RAW_X509, &cert_type, &alert) == CH_EPROTO);
    CHECK(cert_type == CERT_TYPE_UNWRITTEN && alert == ALERT_DECODE_ERROR);
}

// The rest of the block around one server_certificate_type: it may sit
// beside the four other admitted extensions, it may not repeat, and a
// message without it is accepted and leaves the caller's seed, the
// X.509 type a server that sends none uses (RFC 9846 §4.5.1).
static void test_cert_type_in_block(void) {
    static const uint8_t beside[] = {0x00, 0x1c, 0x00, 0x02, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d, 0x00, 0x10, 0x00, 0x05,
                                     0x00, 0x03, 0x02, 'h',  '2',  0x00, 0x14, 0x00, 0x01, 0x02};
    static const uint8_t twice[] = {0x00, 0x14, 0x00, 0x01, 0x02, 0x00, 0x14, 0x00, 0x01, 0x02};
    static const uint8_t absent[] = {0x00, 0x1c, 0x00, 0x02, 0x04, 0x01};
    uint8_t cert_type = CERT_TYPE_UNWRITTEN;
    uint8_t alert = 0;
    CHECK(cert_type_row(beside, sizeof beside, 1, OFFER_RAW, &cert_type, &alert) == CH_OK);
    CHECK(cert_type == CH_CERT_TYPE_RAW_PUBLIC_KEY);
    CHECK(cert_type_row(twice, sizeof twice, 1, OFFER_RAW, &cert_type, &alert) == CH_EPROTO);
    CHECK(alert == 0); // the repeat rule keeps the caller's seed
    cert_type = CERT_TYPE_UNWRITTEN;
    CHECK(cert_type_row(absent, sizeof absent, 1, OFFER_RAW_X509, &cert_type, &alert) == CH_OK);
    CHECK(cert_type == CERT_TYPE_UNWRITTEN);
}

static void test_server_cert_type(void) {
    test_cert_type_values();
    test_cert_type_lengths();
    test_cert_type_in_block();
}
#else
// A raw or ca ClientHello sends neither server_name nor
// server_certificate_type, so both are unrequested responses (RFC 9846
// §4.3). test_server_name_acknowledgement holds this build's server_name
// rows, so this one has nothing to add.
static void test_server_name_sent(void) {
}

static void test_server_cert_type(void) {
    static const uint8_t cert_type[] = {0x00, 0x14, 0x00, 0x01, 0x02};
    CHECK(encrypted_exts_case(cert_type, sizeof cert_type) == CH_EPROTO);
    CHECK(encrypted_exts_alert_case(cert_type, sizeof cert_type, 47) ==
          ALERT_UNSUPPORTED_EXTENSION);
}
#endif

#endif
