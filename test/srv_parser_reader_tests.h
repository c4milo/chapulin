// The per-extension readers of srv_parser_ext.c, the frozen-field digest, the
// bound on the extension count and the three predicates, split out of
// test/srv_parser_tests.h because that file passed the 500-line limit. It is
// included from there, after the helpers and the golden hello it reads.
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

// The golden hello's covered extensions in ascending type order, written
// out rather than sorted, so the order the digest takes is stated here:
// server_name (0x0000), supported_groups (0x000a), signature_algorithms
// (0x000d), ALPN (0x0010), record_size_limit (0x001c), supported_versions
// (0x002b), psk_key_exchange_modes (0x002d) and GREASE (0x1a1a).
static const size_t covered_ascending[] = {
    AT_SERVER_NAME,       AT_GROUPS,   AT_SIGALGS,   AT_ALPN,
    AT_RECORD_SIZE_LIMIT, AT_VERSIONS, AT_PSK_MODES, AT_GREASE};
#define COVERED_COUNT (sizeof covered_ascending / sizeof covered_ascending[0])

// Where one byte of each covered golden extension can change and leave a
// hello that parses: the last byte, except in supported_versions, whose
// last two bytes are the 0x0304 the parser requires, so the draft version
// before them changes instead.
static size_t changed_at(size_t at) {
    return at == AT_VERSIONS ? 5 : golden_exts[at].len - 1;
}

// SHA-256 over the fields §4.1.2 freezes across a HelloRetryRequest: the
// head, then every extension but key_share, early_data, cookie,
// pre_shared_key and padding, each with its type and length words, in
// ascending type order (docs/decisions.md 59).
static void test_frozen_digest(void) {
    uint8_t buf[HELLO_CAP];
    uint8_t covered[HELLO_CAP];
    size_t m = sizeof hello_head;
    memcpy(covered, hello_head, m);
    for (size_t i = 0; i < COVERED_COUNT; i++) {
        const extension *e = &golden_exts[covered_ascending[i]];
        memcpy(covered + m, e->bytes, e->len);
        m += e->len;
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
    // The order of the extensions is not frozen (rfc9846.txt:1669-1670):
    // two swapped, and all ten reversed, keep the digest.
    extension swapped[GOLDEN_EXT_COUNT];
    memcpy(swapped, golden_exts, sizeof swapped);
    swapped[AT_GROUPS] = golden_exts[AT_SIGALGS];
    swapped[AT_SIGALGS] = golden_exts[AT_GROUPS];
    n = assemble(buf, hello_head, sizeof hello_head, swapped, GOLDEN_EXT_COUNT);
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, want, SHA256_LEN) == 0);
    for (size_t i = 0; i < GOLDEN_EXT_COUNT; i++) {
        swapped[i] = golden_exts[GOLDEN_EXT_COUNT - 1 - i];
    }
    n = assemble(buf, hello_head, sizeof hello_head, swapped, GOLDEN_EXT_COUNT);
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, want, SHA256_LEN) == 0);
    // A change to a frozen field moves the digest away from the golden
    // hello's own, as this parser computes it, so each case below holds
    // the walk and not only the vector above: one random byte, the order
    // of the groups inside supported_groups, one byte of each covered
    // extension in turn, one covered extension dropped and one unknown
    // extension added.
    n = golden(buf);
    CHECK(parse(buf, n) == CH_OK);
    uint8_t kept[SHA256_LEN];
    memcpy(kept, parsed.frozen, sizeof kept);
    buf[HEAD_RANDOM_AT] ^= 0x01;
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, kept, SHA256_LEN) != 0);
    static const uint8_t groups_reordered[] = {0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
                                               0x00, 0x1d, 0x0a, 0x0a, 0x00, 0x17};
    n = replaced(buf, AT_GROUPS, groups_reordered, sizeof groups_reordered);
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, kept, SHA256_LEN) != 0);
    uint8_t ext[HELLO_CAP];
    for (size_t i = 0; i < COVERED_COUNT; i++) {
        size_t at = covered_ascending[i];
        memcpy(ext, golden_exts[at].bytes, golden_exts[at].len);
        ext[changed_at(at)] ^= 0x01;
        n = replaced(buf, at, ext, golden_exts[at].len);
        CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, kept, SHA256_LEN) != 0);
    }
    n = dropped(buf, AT_ALPN);
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, kept, SHA256_LEN) != 0);
    static const uint8_t unknown[] = {0x2a, 0x2a, 0x00, 0x00};
    n = appended(buf, unknown, sizeof unknown);
    CHECK(parse(buf, n) == CH_OK && memcmp(parsed.frozen, kept, SHA256_LEN) != 0);
}

// The first of the distinct unknown types that fill a hello out to a count.
// 0x1000 through 0x10ff is no type this parser recognizes and none the
// golden hello carries, and every one of them sorts between
// psk_key_exchange_modes (0x002d) and GREASE (0x1a1a).
#define PAD_TYPE 0x1000

// A ClientHello body over the golden head: the first `given` extensions of
// exts, then empty extensions of types PAD_TYPE + given upward until the
// block holds `count` in all, then `tail_len` bytes of tail.
static size_t padded(uint8_t *dst, const extension *exts, size_t given, size_t count,
                     const uint8_t *tail, size_t tail_len) {
    wbuf w;
    wb_init(&w, dst, HELLO_CAP);
    wb_bytes(&w, hello_head, sizeof hello_head);
    size_t mark = wb_mark(&w, 2);
    for (size_t i = 0; i < given; i++) {
        wb_bytes(&w, exts[i].bytes, exts[i].len);
    }
    for (size_t i = given; i < count; i++) {
        wb_u16(&w, (uint16_t)(PAD_TYPE + i));
        wb_u16(&w, 0);
    }
    wb_bytes(&w, tail, tail_len);
    wb_patch16(&w, mark);
    CHECK(!w.err);
    return w.len;
}

// SRV_CLIENT_HELLO_EXT_MAX at its edge (docs/decisions.md 59). The golden
// hello filled out to exactly the bound parses, and its digest still covers
// every covered extension, the filler included; one more is illegal_parameter.
// The bound is checked before any rule on the extensions themselves: a
// supported_versions with a trailing byte is decode_error at the bound and
// illegal_parameter one past it, and so is a block that ends in half a
// header after the bound's extensions and after one more.
static void test_extension_count(void) {
    static uint8_t buf[HELLO_CAP];
    size_t n = padded(buf, golden_exts, GOLDEN_EXT_COUNT, SRV_CLIENT_HELLO_EXT_MAX, NULL, 0);
    CHECK(parse(buf, n) == CH_OK && parsed.seen == GOLDEN_SEEN);
    // The digest: the head, the covered golden extensions below the filler
    // in ascending order, the filler, then GREASE, the one covered golden
    // type above it (covered_ascending ends with it).
    static uint8_t covered[HELLO_CAP];
    size_t m = sizeof hello_head;
    memcpy(covered, hello_head, m);
    for (size_t i = 0; i + 1 < COVERED_COUNT; i++) {
        const extension *e = &golden_exts[covered_ascending[i]];
        memcpy(covered + m, e->bytes, e->len);
        m += e->len;
    }
    for (size_t i = GOLDEN_EXT_COUNT; i < SRV_CLIENT_HELLO_EXT_MAX; i++) {
        covered[m++] = (uint8_t)((PAD_TYPE + i) >> 8);
        covered[m++] = (uint8_t)(PAD_TYPE + i);
        covered[m++] = 0;
        covered[m++] = 0;
    }
    memcpy(covered + m, ext_grease, sizeof ext_grease);
    m += sizeof ext_grease;
    uint8_t want[SHA256_LEN];
    sha256_of(covered, m, want);
    CHECK(memcmp(parsed.frozen, want, SHA256_LEN) == 0);
    n = padded(buf, golden_exts, GOLDEN_EXT_COUNT, SRV_CLIENT_HELLO_EXT_MAX + 1, NULL, 0);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));

    extension exts[GOLDEN_EXT_COUNT];
    memcpy(exts, golden_exts, sizeof exts);
    uint8_t trailing[sizeof ext_versions + 1];
    exts[AT_VERSIONS].bytes = trailing;
    exts[AT_VERSIONS].len = trailed(trailing, ext_versions, sizeof ext_versions);
    n = padded(buf, exts, GOLDEN_EXT_COUNT, SRV_CLIENT_HELLO_EXT_MAX, NULL, 0);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = padded(buf, exts, GOLDEN_EXT_COUNT, SRV_CLIENT_HELLO_EXT_MAX + 1, NULL, 0);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));

    static const uint8_t half_header[] = {0x2a, 0x2a};
    n = padded(buf, golden_exts, GOLDEN_EXT_COUNT, SRV_CLIENT_HELLO_EXT_MAX, half_header,
               sizeof half_header);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = padded(buf, golden_exts, GOLDEN_EXT_COUNT, SRV_CLIENT_HELLO_EXT_MAX + 1, half_header,
               sizeof half_header);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
}

// quic_transport_parameters, the one extension this parser recognizes in
// order to refuse. RFC 9001 §8.2 requires a fatal unsupported_extension
// from an implementation that understands it when the transport is not
// QUIC (rfc9001.txt:1945-1949), and every build here runs over TLS
// records. The hello is the golden one with the extension appended, so
// the refusal is that extension's and no other field's.
static void test_quic_transport_params(void) {
    uint8_t buf[HELLO_CAP];
    size_t n = appended(buf, ext_quic_transport_params, sizeof ext_quic_transport_params);
    CHECK(refused(buf, n, ALERT_UNSUPPORTED_EXTENSION));
    // An empty body is refused the same way: the answer is about the
    // type and never about what the body holds.
    static const uint8_t empty_body[] = {0x00, 0x39, 0x00, 0x00};
    n = appended(buf, empty_body, sizeof empty_body);
    CHECK(refused(buf, n, ALERT_UNSUPPORTED_EXTENSION));
    // Recognition is what reaches that refusal. Without the bit, §4.2.2
    // would skip the extension by its length and the hello would parse,
    // which is what the golden hello's GREASE extension does.
    CHECK(srv_ext_known(EXT_QUIC_TRANSPORT_PARAMS) == 1);
    n = golden(buf);
    CHECK(parse(buf, n) == CH_OK);
}

// The three predicates srv_parser.h exports beside the parser.
static void test_predicates(void) {
    static const uint16_t known[] = {EXT_SERVER_NAME,
                                     EXT_SUPPORTED_GROUPS,
                                     EXT_SIGNATURE_ALGORITHMS,
                                     EXT_ALPN,
                                     EXT_RECORD_SIZE_LIMIT,
                                     EXT_PRE_SHARED_KEY,
                                     EXT_SUPPORTED_VERSIONS,
                                     EXT_COOKIE,
                                     EXT_PSK_MODES,
                                     EXT_KEY_SHARE,
                                     EXT_EARLY_DATA,
                                     EXT_PADDING,
                                     EXT_QUIC_TRANSPORT_PARAMS};
    for (size_t i = 0; i < sizeof known / sizeof known[0]; i++) {
        CHECK(srv_ext_known(known[i]) == 1);
    }
    // GREASE, status_request, post_handshake_auth. quic_transport_parameters
    // left this list when the parser gained the bit it refuses on.
    static const uint16_t unknown[] = {0x1a1a, 5, 49, 0xffff};
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
    // srv_ext_over_max over blocks of empty extensions: the bound, one
    // more, the most a 64 KiB block holds, and none. A block whose framing
    // breaks at the extension one past the bound is not its verdict.
    static uint8_t block[0xffff];
    size_t most = sizeof block / 4;
    for (size_t i = 0; i < most; i++) {
        block[4 * i] = (uint8_t)((PAD_TYPE + i) >> 8);
        block[4 * i + 1] = (uint8_t)(PAD_TYPE + i);
    }
    size_t bound = SRV_CLIENT_HELLO_EXT_MAX;
    CHECK(srv_ext_over_max(block, 4 * bound) == 0);
    CHECK(srv_ext_over_max(block, 4 * (bound + 1)) == 1);
    CHECK(srv_ext_over_max(block, 4 * most) == 1);
    CHECK(srv_ext_over_max(block, 0) == 0);
    CHECK(srv_ext_over_max(block, 4 * bound + 3) == 0);
}

#endif
