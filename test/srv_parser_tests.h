// srv_parser.c against the ClientHello of RFC 9846 §4.1.2: one hello
// written out by hand that parses, one mutant per refusal srv_parser.h
// lists, and the exact boundary pair of every length rule, the shape
// test/handshake_strict_test.c gives the client's parsers. The hello
// and the helpers that vary it are test/srv_parser_hello.h's; this
// header is included after it and after test/srv_test.c's CHECK.
#ifndef CH_SRV_PARSER_TESTS_H
#define CH_SRV_PARSER_TESTS_H

static void test_golden_hello(void) {
    uint8_t buf[HELLO_CAP];
    size_t n = golden(buf);
    CHECK(n == 216);
    CHECK(parse(buf, n) == CH_OK);
    CHECK(parsed_alert == ALERT_SEED);
    CHECK(memcmp(parsed.random, hello_head + HEAD_RANDOM_AT, SRV_RANDOM) == 0);
    CHECK(parsed.session_id_len == SRV_SESSION_ID_MAX);
    CHECK(memcmp(parsed.session_id, hello_head + HEAD_SESSION_ID_AT, SRV_SESSION_ID_MAX) == 0);
    CHECK(parsed.suites == SRV_SUITE_CHACHA20_POLY1305);
    CHECK(parsed.groups == SRV_GROUP_KEX && parsed.shares == SRV_GROUP_KEX);
    CHECK(parsed.sigalgs == (SRV_SIGALG_ECDSA_P256 | SRV_SIGALG_RSA_PSS));
    // The share is the key_exchange bytes where they sit in the message.
    CHECK(inside(buf, n, parsed.share, parsed.share_len));
    CHECK(parsed.share_len == CH_KEX_CLIENT_SHARE);
    CHECK(memcmp(parsed.share, ext_key_share + KEY_SHARE_KEY_AT, CH_KEX_CLIENT_SHARE) == 0);
    CHECK(inside(buf, n, parsed.server_name, parsed.server_name_len));
    CHECK(parsed.server_name_len == 9 && memcmp(parsed.server_name, "localhost", 9) == 0);
    // The hello advertises 0x4000. The stored value is the plaintext it
    // allows, one less, because RFC 8449 §4 counts the content-type byte.
    CHECK(parsed.record_size_limit == 16383);
    CHECK(parsed.psk_modes == SRV_PSK_DHE_KE);
    CHECK(parsed.alpn_selected == CH_ALPN_NONE);
    CHECK(parsed.cookie == NULL && parsed.cookie_len == 0);
    CHECK(parsed.truncated_len == 0);
    CHECK(parsed.seen == GOLDEN_SEEN);
    // The hand-written head and the head builder agree, so every head
    // case below varies the golden and nothing else.
    uint8_t head[HEAD_CAP];
    size_t head_len = make_head(head, SRV_SESSION_ID_MAX, HEAD_SUITES, HEAD_SUITES_LEN,
                                compression_null, sizeof compression_null);
    CHECK(head_len == sizeof hello_head && memcmp(head, hello_head, head_len) == 0);
}

static void test_head(void) {
    uint8_t buf[HELLO_CAP];
    size_t n = golden(buf);
    // legacy_version is read and not judged (§4.2.1): a hello that says
    // TLS 1.0 there negotiates on supported_versions.
    buf[1] = 0x01;
    CHECK(parse(buf, n) == CH_OK);
    // A body that ends inside the random, and one that ends right after
    // the compression list, which is a hello from before this version.
    CHECK(refused(buf, 20, ALERT_DECODE_ERROR));
    CHECK(refused(buf, sizeof hello_head, ALERT_PROTOCOL_VERSION));
    // legacy_session_id<0..32>: 32 is the golden's, 33 is the first
    // length refused, and 0 parses and reports 0.
    static const uint8_t chacha[] = {0x13, 0x03};
    CHECK(head_case(33, chacha, sizeof chacha, compression_null, 1) == CH_EPROTO);
    CHECK(parsed_alert == ALERT_DECODE_ERROR);
    CHECK(head_case(0, chacha, sizeof chacha, compression_null, 1) == CH_OK);
    CHECK(parsed.session_id_len == 0);
    // cipher_suites<2..2^16-2>: one suite is the shortest list, an empty
    // list and an odd length are decode_error, and a list without this
    // build's suite parses with suites at 0 for srv_select to refuse.
    static const uint8_t odd[] = {0x13, 0x03, 0x13};
    static const uint8_t others[] = {0x13, 0x01, 0x13, 0x02};
    CHECK(head_case(0, chacha, 0, compression_null, 1) == CH_EPROTO);
    CHECK(parsed_alert == ALERT_DECODE_ERROR);
    CHECK(head_case(0, odd, sizeof odd, compression_null, 1) == CH_EPROTO);
    CHECK(parsed_alert == ALERT_DECODE_ERROR);
    CHECK(head_case(0, others, sizeof others, compression_null, 1) == CH_OK);
    CHECK(parsed.suites == 0);
    // legacy_compression_methods: exactly one zero byte, or
    // illegal_parameter (§4.1.2), for a nonzero byte, two bytes and none.
    static const uint8_t deflate[] = {0x01};
    static const uint8_t two[] = {0x00, 0x01};
    CHECK(head_case(0, chacha, sizeof chacha, deflate, sizeof deflate) == CH_EPROTO);
    CHECK(parsed_alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(head_case(0, chacha, sizeof chacha, two, sizeof two) == CH_EPROTO);
    CHECK(parsed_alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(head_case(0, chacha, sizeof chacha, compression_null, 0) == CH_EPROTO);
    CHECK(parsed_alert == ALERT_ILLEGAL_PARAMETER);
}

static void test_extension_block(void) {
    uint8_t buf[HELLO_CAP];
    size_t n = golden(buf);
    // The block's length fills the message: one more or one less is
    // decode_error.
    buf[sizeof hello_head + 1] += 1;
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    buf[sizeof hello_head + 1] -= 2;
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // An empty block, or a block holding one unknown extension: TLS 1.2
    // syntax with no supported_versions, which is protocol_version.
    n = assemble(buf, hello_head, sizeof hello_head, NULL, 0);
    CHECK(refused(buf, n, ALERT_PROTOCOL_VERSION));
    n = assemble(buf, hello_head, sizeof hello_head, &golden_exts[AT_GREASE], 1);
    CHECK(refused(buf, n, ALERT_PROTOCOL_VERSION));
    // An extension whose length runs past the block, and a block that
    // ends inside an extension's header.
    static const uint8_t overrun[] = {0x1a, 0x1a, 0x00, 0x05, 0x00};
    static const uint8_t half_header[] = {0x1a, 0x1a};
    n = appended(buf, overrun, sizeof overrun);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = appended(buf, half_header, sizeof half_header);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // One extension of each type (§4.2): a second supported_versions, and
    // a second unknown type, which a seen mask alone would not see.
    n = appended(buf, ext_versions, sizeof ext_versions);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
    n = appended(buf, ext_grease, sizeof ext_grease);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
    // §4.2.2's ignore rule: an unknown extension with a large body, and
    // one with a byte more than the golden's, both skip by their length.
    static uint8_t wide[4 + 200];
    memset(wide, 0, sizeof wide);
    wide[0] = 0x2a;
    wide[1] = 0x2a;
    wide[3] = 200;
    n = appended(buf, wide, sizeof wide);
    CHECK(parse(buf, n) == CH_OK && parsed.seen == GOLDEN_SEEN);
    uint8_t scratch[HELLO_CAP];
    size_t m = trailed(scratch, ext_grease, sizeof ext_grease);
    n = replaced(buf, AT_GREASE, scratch, m);
    CHECK(parse(buf, n) == CH_OK);
}

// Every recognized extension must fill its body exactly (§4.2): the
// golden's parses, and the same extension with one trailing byte is
// decode_error. padding is the one recognized type whose body is read
// whole, so a longer padding is a longer padding.
static void test_exact_fill(void) {
    uint8_t buf[HELLO_CAP];
    uint8_t scratch[HELLO_CAP];
    for (size_t at = 0; at < GOLDEN_EXT_COUNT; at++) {
        if (at == AT_GREASE || at == AT_PADDING) {
            continue;
        }
        size_t m = trailed(scratch, golden_exts[at].bytes, golden_exts[at].len);
        size_t n = replaced(buf, at, scratch, m);
        CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    }
    size_t m = trailed(scratch, ext_padding, sizeof ext_padding);
    size_t n = replaced(buf, AT_PADDING, scratch, m);
    CHECK(parse(buf, n) == CH_OK);
    // The three extensions the golden does not carry, exact and trailed.
    n = appended(buf, ext_early_data, sizeof ext_early_data);
    CHECK(parse(buf, n) == CH_OK && parsed.seen == (GOLDEN_SEEN | SRV_EXT_EARLY_DATA));
    m = trailed(scratch, ext_early_data, sizeof ext_early_data);
    n = appended(buf, scratch, m);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = appended(buf, ext_cookie, sizeof ext_cookie);
    CHECK(parse(buf, n) == CH_OK && parsed.seen == (GOLDEN_SEEN | SRV_EXT_COOKIE));
    CHECK(inside(buf, n, parsed.cookie, parsed.cookie_len) && parsed.cookie_len == 4);
    CHECK(memcmp(parsed.cookie, ext_cookie + 6, 4) == 0);
    m = trailed(scratch, ext_cookie, sizeof ext_cookie);
    n = appended(buf, scratch, m);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    m = trailed(scratch, ext_psk, sizeof ext_psk);
    n = appended(buf, scratch, m);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
}

// §9.2's required extensions, and §4.2.1's supported_versions.
static void test_required_extensions(void) {
    uint8_t buf[HELLO_CAP];
    size_t n = dropped(buf, AT_VERSIONS);
    CHECK(refused(buf, n, ALERT_PROTOCOL_VERSION));
    // A supported_versions without 0x0304, one with 0x0304 alone, an
    // empty list and an odd one.
    static const uint8_t only_12[] = {0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03};
    static const uint8_t only_13[] = {0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04};
    static const uint8_t no_version[] = {0x00, 0x2b, 0x00, 0x01, 0x00};
    static const uint8_t odd_version[] = {0x00, 0x2b, 0x00, 0x04, 0x03, 0x03, 0x04, 0x00};
    n = replaced(buf, AT_VERSIONS, only_12, sizeof only_12);
    CHECK(refused(buf, n, ALERT_PROTOCOL_VERSION));
    n = replaced(buf, AT_VERSIONS, only_13, sizeof only_13);
    CHECK(parse(buf, n) == CH_OK);
    n = replaced(buf, AT_VERSIONS, no_version, sizeof no_version);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = replaced(buf, AT_VERSIONS, odd_version, sizeof odd_version);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // An odd list whose versions fill the body: the case above runs out
    // of bytes mid-version, so the odd length itself goes unread.
    static const uint8_t odd_fills[] = {0x00, 0x2b, 0x00, 0x05, 0x03, 0x03, 0x04, 0x00, 0x00};
    n = replaced(buf, AT_VERSIONS, odd_fills, sizeof odd_fills);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // Without pre_shared_key, signature_algorithms and supported_groups
    // are both required; supported_groups and key_share come together.
    n = dropped(buf, AT_SIGALGS);
    CHECK(refused(buf, n, ALERT_MISSING_EXTENSION));
    n = dropped(buf, AT_GROUPS);
    CHECK(refused(buf, n, ALERT_MISSING_EXTENSION));
    n = dropped(buf, AT_KEY_SHARE);
    CHECK(refused(buf, n, ALERT_MISSING_EXTENSION));
    // An empty client_shares list is a present key_share (§9.2): it
    // parses, sets the bit, and reports no share, the HelloRetryRequest
    // input.
    static const uint8_t no_shares[] = {0x00, 0x33, 0x00, 0x02, 0x00, 0x00};
    n = replaced(buf, AT_KEY_SHARE, no_shares, sizeof no_shares);
    CHECK(parse(buf, n) == CH_OK && parsed.seen == GOLDEN_SEEN);
    CHECK(parsed.shares == 0 && parsed.share == NULL && parsed.share_len == 0);
}

static void test_key_share(void) {
    uint8_t buf[HELLO_CAP];
    uint8_t ext[HELLO_CAP];
    // A key_exchange for this build's group is CH_KEX_CLIENT_SHARE bytes:
    // one fewer and one more are illegal_parameter, and an empty one is
    // outside the vector's syntax.
    size_t m = make_key_share(ext, CH_KEX_GROUP, CH_KEX_CLIENT_SHARE);
    size_t n = replaced(buf, AT_KEY_SHARE, ext, m);
    CHECK(parse(buf, n) == CH_OK && parsed.share_len == CH_KEX_CLIENT_SHARE);
    m = make_key_share(ext, CH_KEX_GROUP, CH_KEX_CLIENT_SHARE - 1);
    n = replaced(buf, AT_KEY_SHARE, ext, m);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
    m = make_key_share(ext, CH_KEX_GROUP, CH_KEX_CLIENT_SHARE + 1);
    n = replaced(buf, AT_KEY_SHARE, ext, m);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
    m = make_key_share(ext, CH_KEX_GROUP, 0);
    n = replaced(buf, AT_KEY_SHARE, ext, m);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // An entry for a group this build does not hold is read and ignored,
    // whatever its length: no share, and no refusal.
    m = make_key_share(ext, 0x0017, 65); // secp256r1
    n = replaced(buf, AT_KEY_SHARE, ext, m);
    CHECK(parse(buf, n) == CH_OK && parsed.shares == 0 && parsed.share == NULL);
    // Two entries for this build's group: the first is the share.
    static const uint8_t twice[] = {
        0x00, 0x33, 0x00, 0x4a, 0x00, 0x48, 0x00, 0x1d, 0x00, 0x20, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x00, 0x1d, 0x00, 0x20, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
    n = replaced(buf, AT_KEY_SHARE, twice, sizeof twice);
    CHECK(parse(buf, n) == CH_OK && parsed.share != NULL && parsed.share[0] == 0x01);
    // The entries fill client_shares: a list length one past them is
    // decode_error.
    memcpy(ext, ext_key_share, sizeof ext_key_share);
    ext[5] += 1;
    n = replaced(buf, AT_KEY_SHARE, ext, sizeof ext_key_share);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // A list length that names fewer bytes than its one entry spans.
    // The longer length above is refused before the walk, by the list
    // running past the body, so only this one reads the exact fill.
    memcpy(ext, ext_key_share, sizeof ext_key_share);
    ext[5] = 4;
    n = replaced(buf, AT_KEY_SHARE, ext, sizeof ext_key_share);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // A share for this build's group when supported_groups does not list
    // it (§4.2.8): illegal_parameter.
    static const uint8_t p256_only[] = {0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17};
    n = replaced(buf, AT_GROUPS, p256_only, sizeof p256_only);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
}

static void test_pre_shared_key(void) {
    uint8_t buf[HELLO_CAP];
    uint8_t ext[HELLO_CAP];
    // The golden with pre_shared_key last: it parses, and truncated_len
    // is where the binders start, counted from the start of the body.
    size_t n = appended(buf, ext_psk, sizeof ext_psk);
    CHECK(parse(buf, n) == CH_OK && parsed.seen == (GOLDEN_SEEN | SRV_EXT_PRE_SHARED_KEY));
    CHECK(parsed.truncated_len == n - PSK_BINDERS_FIELD_LEN);
    // pre_shared_key relaxes §9.2's signature_algorithms rule and not
    // the supported_groups pairing.
    extension psk = EXTENSION(ext_psk);
    n = variant(buf, AT_SIGALGS, NULL, &psk);
    CHECK(parse(buf, n) == CH_OK);
    n = variant(buf, AT_GROUPS, NULL, &psk);
    CHECK(refused(buf, n, ALERT_MISSING_EXTENSION));
    // Not last (§4.2.11), and without psk_key_exchange_modes (§4.2.9).
    n = variant(buf, AT_PADDING, &psk, &golden_exts[AT_PADDING]);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
    n = variant(buf, AT_PSK_MODES, NULL, &psk);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
    // identities<7..2^16-1>: the golden's 7 is the shortest; 6 is refused.
    memcpy(ext, ext_psk, sizeof ext_psk);
    ext[5] = 6;
    n = appended(buf, ext, sizeof ext_psk);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // An empty identity, and an identity that overruns the list.
    memcpy(ext, ext_psk, sizeof ext_psk);
    ext[7] = 0;
    n = appended(buf, ext, sizeof ext_psk);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    memcpy(ext, ext_psk, sizeof ext_psk);
    ext[7] = 2;
    n = appended(buf, ext, sizeof ext_psk);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // binders<33..2^16-1> of PskBinderEntry<32..255>: 33 is the shortest
    // list and 32 the shortest entry; one under each is refused.
    memcpy(ext, ext_psk, sizeof ext_psk);
    ext[14] = 32;
    n = appended(buf, ext, sizeof ext_psk);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    memcpy(ext, ext_psk, sizeof ext_psk);
    ext[15] = 31;
    n = appended(buf, ext, sizeof ext_psk);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    // The same bounds again, over lists that fill the extension exactly.
    // The four cases above are refused by the walk running out of bytes
    // rather than by the bound, so the bound itself goes unread; these
    // reach it, and an empty list runs no walk at all. The bodies are
    // the golden's own, so the accepted case offers what the golden does.
    const uint8_t *ids = ext_psk + PSK_IDENTITIES_AT;
    const uint8_t *binders = ext_psk + PSK_BINDERS_AT;
    // Two binders of 15 and 16 bytes fill binders<33..> exactly, and
    // each is under PskBinderEntry's own floor of 32.
    uint8_t two_short[PSK_BINDERS_LEN];
    memset(two_short, 0x5a, sizeof two_short);
    two_short[0] = 15;
    two_short[16] = 16;
    CHECK(psk_case(ids, PSK_IDENTITIES_LEN, binders, PSK_BINDERS_LEN) == CH_OK);
    CHECK(psk_case(NULL, 0, binders, PSK_BINDERS_LEN) == CH_EPROTO);
    CHECK(parsed_alert == ALERT_DECODE_ERROR);
    CHECK(psk_case(ids, PSK_IDENTITIES_LEN, NULL, 0) == CH_EPROTO);
    CHECK(parsed_alert == ALERT_DECODE_ERROR);
    CHECK(psk_case(ids, PSK_IDENTITIES_LEN, two_short, sizeof two_short) == CH_EPROTO);
    CHECK(parsed_alert == ALERT_DECODE_ERROR);
}

static void test_alpn(void) {
    // The server's order decides (RFC 7301 §3.2): the client lists h2
    // first, and the offer's first name the client also listed wins.
    static const ch_alpn_protocol http_first[] = {
        {name_http11, sizeof name_http11},
        {name_h2,     sizeof name_h2    }
    };
    static const ch_alpn_protocol h2_first[] = {
        {name_h2,     sizeof name_h2    },
        {name_http11, sizeof name_http11}
    };
    static const ch_alpn_protocol spdy_then_h2[] = {
        {name_spdy, sizeof name_spdy},
        {name_h2,   sizeof name_h2  }
    };
    CHECK(alpn_case(http_first, 2) == 0);
    CHECK(alpn_case(h2_first, 2) == 0);
    CHECK(alpn_case(spdy_then_h2, 2) == 1);
    CHECK(alpn_case(spdy_then_h2, 1) == CH_ALPN_NONE);
    CHECK(alpn_case(NULL, 0) == CH_ALPN_NONE);
    // The list's syntax: an empty list, an empty name, and names that
    // do not fill the list are decode_error.
    uint8_t buf[HELLO_CAP];
    static const uint8_t empty_list[] = {0x00, 0x10, 0x00, 0x02, 0x00, 0x00};
    static const uint8_t empty_name[] = {0x00, 0x10, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00};
    static const uint8_t short_list[] = {0x00, 0x10, 0x00, 0x05, 0x00, 0x02, 0x02, 'h', '2'};
    size_t n = replaced(buf, AT_ALPN, empty_list, sizeof empty_list);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = replaced(buf, AT_ALPN, empty_name, sizeof empty_name);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
    n = replaced(buf, AT_ALPN, short_list, sizeof short_list);
    CHECK(refused(buf, n, ALERT_DECODE_ERROR));
}

#include "srv_parser_reader_tests.h"

#endif
