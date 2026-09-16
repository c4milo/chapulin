// The EncryptedExtensions ALPN arm (RFC 7301 §3.2), split out of
// test/handshake_strict_test.c to keep that file inside the 500-line
// limit. A TRUST=webpki ClientHello offers protocol names, so the reply
// may carry exactly one of them and the parser reports which; every
// other build offers none, so any ALPN extension is a response to a
// request that never went out. Included by that file alone, after
// make_encrypted_exts and the alpn_offer table exist.
#ifndef CH_TEST_HANDSHAKE_STRICT_ALPN_H
#define CH_TEST_HANDSHAKE_STRICT_ALPN_H

// Holds the longest extension a row builds: the 4 header bytes, the 2
// list-length bytes, and a name of CH_ALPN_NAME_MAX + 1 bytes with its
// length byte.
#define ALPN_CASE_CAP 96

#ifdef CH_TRUST_WEBPKI
// An ALPN extension around the given ProtocolNameList bytes, with the
// list length field set to claimed. A row that passes the true length
// is well framed; one that passes another value claims a list the names
// do not fill.
static size_t alpn_ext(uint8_t *out, const uint8_t *names, size_t n, size_t claimed) {
    wbuf w;
    wb_init(&w, out, ALPN_CASE_CAP);
    wb_u16(&w, EXT_ALPN);
    wb_u16(&w, (uint16_t)(2 + n));
    wb_u16(&w, (uint16_t)claimed);
    wb_bytes(&w, names, n);
    CHECK(!w.err);
    return w.len;
}

// Parses an EncryptedExtensions holding that one extension, against an
// offer of the first offer_count names of alpn_offer. Reports the
// parser's selection in *selected and its alert in *alert, seeded with
// the illegal_parameter handshake.c seeds.
static int alpn_row(const uint8_t *names, size_t n, size_t claimed, size_t offer_count,
                    uint8_t *selected, uint8_t *alert) {
    uint8_t ext[ALPN_CASE_CAP];
    size_t ext_len = alpn_ext(ext, names, n, claimed);
    uint8_t body[ALPN_CASE_CAP + 8];
    size_t len = make_encrypted_exts(body, ext, ext_len);
    uint16_t peer_limit = CH_TX_PT;
    *selected = CH_ALPN_NONE;
    *alert = ALERT_ILLEGAL_PARAMETER;
    return hsp_parse_encrypted_exts(body, len, &peer_limit, alpn_offer, offer_count, selected,
                                    alert);
}

// One ProtocolName with its length byte, per row. alpn_offer's four
// entries are "h2", "http/1.1", "x" and CH_ALPN_NAME_MAX bytes of 'a'.
static const uint8_t alpn_h2_name[] = {2, 'h', '2'};
static const uint8_t alpn_http11_name[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
static const uint8_t alpn_shortest_name[] = {1, 'x'};
static const uint8_t alpn_empty_name[] = {0};
static const uint8_t alpn_two_names[] = {2, 'h', '2', 1, 'x'};
static const uint8_t alpn_unoffered_name[] = {2, 'h', '3'};
static const uint8_t alpn_prefix_name[] = {1, 'h'};
static const uint8_t alpn_h2_trailing[] = {2, 'h', '2', 0x00};

// A ProtocolName of len bytes of 'a' with its length byte, the shape
// the two CH_ALPN_NAME_MAX rows need: the offered name at the cap, and
// one byte past it, which no offer can hold.
static size_t alpn_name_of(uint8_t *out, size_t len) {
    out[0] = (uint8_t)len;
    memset(out + 1, 'a', len);
    return 1 + len;
}

// The names the server may select, and the framing and membership rules
// the parser holds them to.
static void test_alpn_selection(void) {
    uint8_t selected = 0;
    uint8_t alert = 0;
    memset(alpn_longest, 'a', sizeof alpn_longest);
    // Each offered name selects its own index, in the caller's order.
    CHECK(alpn_row(alpn_h2_name, sizeof alpn_h2_name, 3, ALPN_OFFER_COUNT, &selected, &alert) ==
          CH_OK);
    CHECK(selected == 0 && alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(alpn_row(alpn_http11_name, sizeof alpn_http11_name, 9, ALPN_OFFER_COUNT, &selected,
                   &alert) == CH_OK);
    CHECK(selected == 1);
    // The length boundary, both ends. One byte is the shortest
    // ProtocolName RFC 7301 §3.1 admits, and it selects the offer's
    // third name; zero bytes is outside that range, a decode_error (50).
    CHECK(alpn_row(alpn_shortest_name, sizeof alpn_shortest_name, 2, ALPN_OFFER_COUNT, &selected,
                   &alert) == CH_OK);
    CHECK(selected == 2);
    CHECK(alpn_row(alpn_empty_name, sizeof alpn_empty_name, 1, ALPN_OFFER_COUNT, &selected,
                   &alert) == CH_EPROTO);
    CHECK(selected == CH_ALPN_NONE && alert == ALERT_DECODE_ERROR);
    // The other boundary: CH_ALPN_NAME_MAX bytes is the longest name
    // ch_connect lets a caller offer, so it selects; one byte more can
    // match no offer, so it is illegal_parameter (47).
    uint8_t name[ALPN_CASE_CAP];
    size_t n = alpn_name_of(name, CH_ALPN_NAME_MAX);
    CHECK(alpn_row(name, n, n, ALPN_OFFER_COUNT, &selected, &alert) == CH_OK);
    CHECK(selected == 3);
    n = alpn_name_of(name, CH_ALPN_NAME_MAX + 1);
    CHECK(alpn_row(name, n, n, ALPN_OFFER_COUNT, &selected, &alert) == CH_EPROTO);
    CHECK(selected == CH_ALPN_NONE && alert == ALERT_ILLEGAL_PARAMETER);
    // §3.2 says the list holds exactly one name, so two names, a list
    // length the names do not fill, and a byte past the one name are
    // each a body of the wrong length: decode_error.
    CHECK(alpn_row(alpn_two_names, sizeof alpn_two_names, 5, ALPN_OFFER_COUNT, &selected, &alert) ==
          CH_EPROTO);
    CHECK(alert == ALERT_DECODE_ERROR);
    CHECK(alpn_row(alpn_h2_name, sizeof alpn_h2_name, 4, ALPN_OFFER_COUNT, &selected, &alert) ==
          CH_EPROTO);
    CHECK(alert == ALERT_DECODE_ERROR);
    CHECK(alpn_row(alpn_h2_trailing, sizeof alpn_h2_trailing, 3, ALPN_OFFER_COUNT, &selected,
                   &alert) == CH_EPROTO);
    CHECK(alert == ALERT_DECODE_ERROR);
    // A name the client never offered, and a prefix of one it did: both
    // are well formed and unacceptable, so both are illegal_parameter.
    CHECK(alpn_row(alpn_unoffered_name, sizeof alpn_unoffered_name, 3, ALPN_OFFER_COUNT, &selected,
                   &alert) == CH_EPROTO);
    CHECK(selected == CH_ALPN_NONE && alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(alpn_row(alpn_prefix_name, sizeof alpn_prefix_name, 2, ALPN_OFFER_COUNT, &selected,
                   &alert) == CH_EPROTO);
    CHECK(alert == ALERT_ILLEGAL_PARAMETER);
    // An offer of one name reaches only that name: the second offered
    // name is unoffered there.
    CHECK(alpn_row(alpn_h2_name, sizeof alpn_h2_name, 3, 1, &selected, &alert) == CH_OK);
    CHECK(selected == 0);
    CHECK(alpn_row(alpn_http11_name, sizeof alpn_http11_name, 9, 1, &selected, &alert) ==
          CH_EPROTO);
    CHECK(alert == ALERT_ILLEGAL_PARAMETER);
    // No offer at all: the extension answers a request that never went
    // out, which RFC 9846 §4.3 calls unsupported_extension (110).
    CHECK(alpn_row(alpn_h2_name, sizeof alpn_h2_name, 3, 0, &selected, &alert) == CH_EPROTO);
    CHECK(selected == CH_ALPN_NONE && alert == ALERT_UNSUPPORTED_EXTENSION);
}

// The rest of the block around one ALPN extension: it may sit beside
// the other three admitted extensions, it may not repeat, and a message
// without it is accepted with no selection — RFC 7301 §3.2 lets a
// server that does not support ALPN send none.
static void test_alpn_in_block(void) {
    static const uint8_t beside[] = {0x00, 0x1c, 0x00, 0x02, 0x04, 0x01, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d,
                                     0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h',  '2'};
    static const uint8_t twice[] = {0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2',
                                    0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'};
    static const uint8_t absent[] = {0x00, 0x1c, 0x00, 0x02, 0x04, 0x01};
    uint8_t body[64];
    uint16_t peer_limit = CH_TX_PT;
    uint8_t alert = ALERT_ILLEGAL_PARAMETER;
    uint8_t selected = CH_ALPN_NONE;
    size_t len = make_encrypted_exts(body, beside, sizeof beside);
    CHECK(hsp_parse_encrypted_exts(body, len, &peer_limit, alpn_offer, ALPN_OFFER_COUNT, &selected,
                                   &alert) == CH_OK);
    CHECK(selected == 0);
    CHECK(encrypted_exts_case(twice, sizeof twice) == CH_EPROTO);
    CHECK(encrypted_exts_alert_case(twice, sizeof twice, 47) == 47);
    selected = CH_ALPN_NONE;
    len = make_encrypted_exts(body, absent, sizeof absent);
    CHECK(hsp_parse_encrypted_exts(body, len, &peer_limit, alpn_offer, ALPN_OFFER_COUNT, &selected,
                                   &alert) == CH_OK);
    CHECK(selected == CH_ALPN_NONE);
}
#else
// A raw or ca ClientHello sends no ALPN extension, so an ALPN reply is
// an unrequested response whatever it carries (RFC 9846 §4.3).
static void test_alpn_selection(void) {
    static const uint8_t alpn[] = {0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'};
    CHECK(encrypted_exts_case(alpn, sizeof alpn) == CH_EPROTO);
    CHECK(encrypted_exts_alert_case(alpn, sizeof alpn, 47) == ALERT_UNSUPPORTED_EXTENSION);
}

static void test_alpn_in_block(void) {
    static const uint8_t empty_alpn[] = {0x00, 0x10, 0x00, 0x00};
    CHECK(encrypted_exts_case(empty_alpn, sizeof empty_alpn) == CH_EPROTO);
    CHECK(encrypted_exts_alert_case(empty_alpn, sizeof empty_alpn, 47) ==
          ALERT_UNSUPPORTED_EXTENSION);
}
#endif

#endif
