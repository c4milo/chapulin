// The per-extension readers of srv_parser_ext.c, the frozen-field digest and
// the two predicates, split out of test/srv_parser_tests.h because that file
// passed the 500-line limit. It is included from there, after the helpers and
// the golden hello it reads.
#ifndef CH_SRV_PARSER_READER_TESTS_H
#define CH_SRV_PARSER_READER_TESTS_H

// The readers with a rule of their own: server_name, record_size_limit,
// psk_key_exchange_modes, supported_groups and the cookie.
static void test_readers(void) {
    uint8_t buf[HELLO_CAP];
    // RFC 6066 §3: a NameType other than host_name, an empty name, and a
    // list length that does not fit its one entry.
    static const uint8_t other_type[] = {0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x01, 0x00, 0x01, 'x'};
    static const uint8_t empty_name[] = {0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00};
    static const uint8_t long_list[] = {0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 0x00, 0x00, 0x01, 'x'};
    size_t n = replaced(buf, AT_SERVER_NAME, other_type, sizeof other_type);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = replaced(buf, AT_SERVER_NAME, empty_name, sizeof empty_name);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = replaced(buf, AT_SERVER_NAME, long_list, sizeof long_list);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // RFC 8449 §4: 64 is the smallest limit, 63 is illegal_parameter, and
    // a limit above the protocol's maximum is stored as sent.
    static const uint8_t limit_64[] = {0x00, 0x1c, 0x00, 0x02, 0x00, 0x40};
    static const uint8_t limit_63[] = {0x00, 0x1c, 0x00, 0x02, 0x00, 0x3f};
    static const uint8_t limit_max[] = {0x00, 0x1c, 0x00, 0x02, 0xff, 0xff};
    static const uint8_t limit_short[] = {0x00, 0x1c, 0x00, 0x01, 0x40};
    n = replaced(buf, AT_RECORD_SIZE_LIMIT, limit_64, sizeof limit_64);
    CHECK(parse(buf, n) == CH_OK && parsed.record_size_limit == 63);
    n = replaced(buf, AT_RECORD_SIZE_LIMIT, limit_63, sizeof limit_63);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
    // 0xffff is accepted whole: RFC 8449 §4 forbids a server to enforce
    // the protocol's maximum. The stored value is one less, the plaintext
    // it allows.
    n = replaced(buf, AT_RECORD_SIZE_LIMIT, limit_max, sizeof limit_max);
    CHECK(parse(buf, n) == CH_OK && parsed.record_size_limit == 0xfffe);
    n = replaced(buf, AT_RECORD_SIZE_LIMIT, limit_short, sizeof limit_short);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = dropped(buf, AT_RECORD_SIZE_LIMIT);
    CHECK(parse(buf, n) == CH_OK && parsed.record_size_limit == 0);
    // §4.2.9: an empty ke_modes list is decode_error; psk_ke reports its
    // bit, and a mode the document does not define is ignored.
    static const uint8_t no_modes[] = {0x00, 0x2d, 0x00, 0x01, 0x00};
    static const uint8_t ke_and_unknown[] = {0x00, 0x2d, 0x00, 0x03, 0x02, 0x00, 0x07};
    n = replaced(buf, AT_PSK_MODES, no_modes, sizeof no_modes);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = replaced(buf, AT_PSK_MODES, ke_and_unknown, sizeof ke_and_unknown);
    CHECK(parse(buf, n) == CH_OK && parsed.psk_modes == SRV_PSK_KE);
    // §4.2.7: an empty named_group_list is decode_error, and a list of
    // groups this build does not hold parses with groups at 0 when the
    // key_share carries no share for this build's group either.
    static const uint8_t no_groups[] = {0x00, 0x0a, 0x00, 0x02, 0x00, 0x00};
    static const uint8_t p256_only[] = {0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17};
    static const uint8_t no_shares[] = {0x00, 0x33, 0x00, 0x02, 0x00, 0x00};
    n = replaced(buf, AT_GROUPS, no_groups, sizeof no_groups);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    extension exts[GOLDEN_EXT_COUNT];
    memcpy(exts, golden_exts, sizeof exts);
    exts[AT_GROUPS] = (extension)EXTENSION(p256_only);
    exts[AT_KEY_SHARE] = (extension)EXTENSION(no_shares);
    n = assemble(buf, hello_head, sizeof hello_head, exts, GOLDEN_EXT_COUNT);
    CHECK(parse(buf, n) == CH_OK && parsed.groups == 0 && parsed.shares == 0);
    // §4.2.2: cookie<1..2^16-1>, so an empty cookie is decode_error.
    static const uint8_t no_cookie[] = {0x00, 0x2c, 0x00, 0x02, 0x00, 0x00};
    n = appended(buf, no_cookie, sizeof no_cookie);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
}

// SHA-256 over the fields §4.1.2 freezes across a HelloRetryRequest: the
// head and every extension but key_share, early_data, cookie,
// pre_shared_key and padding, each with its type and length words.
static void test_frozen_digest(void) {
    uint8_t buf[HELLO_CAP];
    uint8_t covered[HELLO_CAP];
    size_t m = sizeof hello_head;
    memcpy(covered, hello_head, m);
    for (size_t at = 0; at < GOLDEN_EXT_COUNT; at++) {
        if (at != AT_KEY_SHARE && at != AT_PADDING) {
            memcpy(covered + m, golden_exts[at].bytes, golden_exts[at].len);
            m += golden_exts[at].len;
        }
    }
    uint8_t want[SHA256_LEN];
    sha256_of(covered, m, want);
    size_t n = appended(buf, ext_early_data, sizeof ext_early_data);
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, want, SHA256_LEN) == 0);
    // A second hello that changes only what §4.1.2 permits keeps the
    // digest: another share, no early_data, no padding, a cookie and a
    // pre_shared_key added.
    uint8_t other_share[sizeof ext_key_share];
    memcpy(other_share, ext_key_share, sizeof ext_key_share);
    other_share[KEY_SHARE_KEY_AT] ^= 0xff;
    extension share = {other_share, sizeof other_share};
    extension cookie = EXTENSION(ext_cookie);
    extension psk = EXTENSION(ext_psk);
    extension exts[GOLDEN_EXT_COUNT + 2];
    size_t count = 0;
    for (size_t at = 0; at < GOLDEN_EXT_COUNT; at++) {
        if (at == AT_KEY_SHARE) {
            exts[count++] = share;
        } else if (at != AT_PADDING) {
            exts[count++] = golden_exts[at];
        }
    }
    exts[count++] = cookie;
    exts[count++] = psk;
    n = assemble(buf, hello_head, sizeof hello_head, exts, count);
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, want, SHA256_LEN) == 0);
    // A change to a frozen field moves it: one random byte, one
    // supported_groups byte, and the order of two frozen extensions.
    n = golden(buf);
    buf[HEAD_RANDOM_AT] ^= 0x01;
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, want, SHA256_LEN) != 0);
    static const uint8_t groups_reordered[] = {0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
                                               0x00, 0x1d, 0x0a, 0x0a, 0x00, 0x17};
    n = replaced(buf, AT_GROUPS, groups_reordered, sizeof groups_reordered);
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, want, SHA256_LEN) != 0);
    extension swapped[GOLDEN_EXT_COUNT];
    memcpy(swapped, golden_exts, sizeof swapped);
    swapped[AT_GROUPS] = golden_exts[AT_SIGALGS];
    swapped[AT_SIGALGS] = golden_exts[AT_GROUPS];
    n = assemble(buf, hello_head, sizeof hello_head, swapped, GOLDEN_EXT_COUNT);
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, want, SHA256_LEN) != 0);
}

// The two predicates srv_parser.h exports beside the parser.
static void test_predicates(void) {
    static const uint16_t known[] = {
        EXT_SERVER_NAME,       EXT_SUPPORTED_GROUPS, EXT_SIGNATURE_ALGORITHMS, EXT_ALPN,
        EXT_RECORD_SIZE_LIMIT, EXT_PRE_SHARED_KEY,   EXT_SUPPORTED_VERSIONS,   EXT_COOKIE,
        EXT_PSK_MODES,         EXT_KEY_SHARE,        EXT_EARLY_DATA,           EXT_PADDING};
    for (size_t i = 0; i < sizeof known / sizeof known[0]; i++) {
        CHECK(srv_ext_known(known[i]) == 1);
    }
    // GREASE, status_request, post_handshake_auth, quic_transport_parameters.
    static const uint16_t unknown[] = {0x1a1a, 5, 49, EXT_QUIC_TRANSPORT_PARAMS, 0xffff};
    for (size_t i = 0; i < sizeof unknown / sizeof unknown[0]; i++) {
        CHECK(srv_ext_known(unknown[i]) == 0);
    }
    // srv_ext_duplicate over a block: no duplicate, a duplicate of an
    // unknown type, and malformed framing, which is not its verdict.
    static const uint8_t distinct[] = {0x1a, 0x1a, 0x00, 0x00, 0x2a, 0x2a, 0x00, 0x01, 0x00};
    static const uint8_t twice[] = {0x1a, 0x1a, 0x00, 0x00, 0x2a, 0x2a, 0x00,
                                    0x00, 0x1a, 0x1a, 0x00, 0x01, 0x00};
    static const uint8_t malformed[] = {0x1a, 0x1a, 0x00, 0x00, 0x1a, 0x1a, 0x00, 0x09, 0x00};
    CHECK(srv_ext_duplicate(distinct, sizeof distinct) == 0);
    CHECK(srv_ext_duplicate(twice, sizeof twice) == 1);
    CHECK(srv_ext_duplicate(malformed, sizeof malformed) == 0);
    CHECK(srv_ext_duplicate(distinct, 0) == 0);
}

#endif
