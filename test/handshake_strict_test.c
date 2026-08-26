// Encoding strictness for the ServerHello and EncryptedExtensions
// parsers (issue #10): every extension body must match its struct
// exactly (RFC 9846 §4.3 makes trailing bytes a decode error) and no
// extension type may repeat. Each behavior gets a boundary pair: the
// exact-length body parses, the same body plus one byte fails. The
// parsers live in handshake_parse.c and depend only on buf.c, so those two files
// are the whole link line. Its own binary with a private main, like the
// other standalone test mains.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "buf.h"
#include "cfg.h"
#include "handshake_message.h"
#include "handshake_parse.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// Golden ServerHello body (no handshake header): version 1.3 via
// supported_versions plus an x25519 key_share, both exact-length.
static const uint8_t server_hello_golden[] = {
    0x03, 0x03,                                     // legacy_version: 0x0303
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, // random, 32 bytes,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, // any value that is
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, // not the HRR
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, // sentinel
    0x00,       // legacy_session_id_echo: empty, matching our offer
    0x13, 0x03, // cipher_suite: TLS_CHACHA20_POLY1305_SHA256
    0x00,       // legacy_compression_method: null
    0x00, 0x2e, // extensions length: 46
    0x00, 0x2b, // extension_type: supported_versions (43)
    0x00, 0x02, // extension length: 2
    0x03, 0x04, // selected_version: TLS 1.3
    0x00, 0x33, // extension_type: key_share (51)
    0x00, 0x24, // extension length: 36
    0x00, 0x1d, // group: x25519
    0x00, 0x20, // key_exchange length: 32
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, // key_exchange: 32
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, // public-key bytes
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, // (any value; the
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, // parser copies them)
};

// Golden EncryptedExtensions body: one exact-length record_size_limit.
static const uint8_t encrypted_exts_golden[] = {
    0x00, 0x06, // extensions length: 6
    0x00, 0x1c, // extension_type: record_size_limit (28)
    0x00, 0x02, // extension length: 2
    0x04, 0x01, // limit: 1025
};

// Assembles a ServerHello body around the given extension bytes: the
// golden message's fixed fields, then the extension block. hrr swaps
// the random for the HRR sentinel.
static size_t make_server_hello(uint8_t *out, int hrr, const uint8_t *exts, size_t n) {
    size_t fixed = 2 + 32 + 1 + 2 + 1;
    memcpy(out, server_hello_golden, fixed);
    if (hrr) {
        memcpy(out + 2, hsp_hrr_magic, 32);
    }
    out[fixed] = (uint8_t)(n >> 8);
    out[fixed + 1] = (uint8_t)n;
    memcpy(out + fixed + 2, exts, n);
    return fixed + 2 + n;
}

static size_t make_encrypted_exts(uint8_t *out, const uint8_t *exts, size_t n) {
    out[0] = (uint8_t)(n >> 8);
    out[1] = (uint8_t)n;
    if (n > 0) {
        memcpy(out + 2, exts, n);
    }
    return 2 + n;
}

static int try_server_hello(const uint8_t *body, size_t n, int psk_mode) {
    server_hello_info info;
    memset(&info, 0, sizeof info);
    return hsp_parse_server_hello(body, n, &info, psk_mode);
}

static int try_encrypted_exts(const uint8_t *body, size_t n) {
    uint16_t peer_limit = CH_TX_PT;
    uint8_t alert = 0;
    return hsp_parse_encrypted_exts(body, n, &peer_limit, &alert);
}

// Extension blobs for the ServerHello cases, named by extension.
static const uint8_t versions_exact[] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
static const uint8_t versions_trail[] = {0x00, 0x2b, 0x00, 0x03, 0x03, 0x04, 0x00};
// The issue's lenient input: 4 junk bytes after a valid selected_version.
static const uint8_t versions_junk[] = {0x00, 0x2b, 0x00, 0x06, 0x03, 0x04, 0xde, 0xad, 0xbe, 0xef};
static const uint8_t versions_dup[] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
                                       0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
#ifdef CH_KEX_PQ
// The hybrid key_share body is 2 + 2 + 1120 bytes, too large for a
// literal: main fills these through build_key_share_cases below, with
// the same shapes as the classic literals in the other build — the
// exact-length extension, then the same extension with its length one
// larger and one trailing byte.
static uint8_t key_share_exact[2 + 2 + 2 + 2 + CH_KEX_SERVER_SHARE];
static uint8_t key_share_trail[sizeof key_share_exact + 1];

// Fills key_share_exact and key_share_trail for the hybrid build. The
// share bytes are arbitrary: the parser stores them, never checks them.
static void build_key_share_cases(void) {
    wbuf w;
    wb_init(&w, key_share_exact, sizeof key_share_exact);
    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, 2 + 2 + CH_KEX_SERVER_SHARE);
    wb_u16(&w, CH_KEX_GROUP);
    wb_u16(&w, CH_KEX_SERVER_SHARE);
    for (size_t i = 0; i < CH_KEX_SERVER_SHARE; i++) {
        wb_u8(&w, 0x09);
    }
    CHECK(!w.err && w.len == sizeof key_share_exact);
    // The trailing-byte case: the extension length grows by one and one
    // zero byte follows the share.
    memcpy(key_share_trail, key_share_exact, sizeof key_share_exact);
    size_t trail_body = 2 + 2 + CH_KEX_SERVER_SHARE + 1;
    key_share_trail[2] = (uint8_t)(trail_body >> 8);
    key_share_trail[3] = (uint8_t)trail_body;
    key_share_trail[sizeof key_share_trail - 1] = 0x00;
}
#else
static const uint8_t key_share_exact[] = {
    0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09};
static const uint8_t key_share_trail[] = {
    0x00, 0x33, 0x00, 0x25, 0x00, 0x1d, 0x00, 0x20, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x00};
#endif

static const uint8_t psk_exact[] = {0x00, 0x29, 0x00, 0x02, 0x00, 0x00};
static const uint8_t psk_trail[] = {0x00, 0x29, 0x00, 0x03, 0x00, 0x00, 0x00};
static const uint8_t cookie_exact[] = {0x00, 0x2c, 0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb};
static const uint8_t cookie_trail[] = {0x00, 0x2c, 0x00, 0x05, 0x00, 0x02, 0xaa, 0xbb, 0x00};

// Extension blobs for the EncryptedExtensions cases: record_size_limit
// and supported_groups.
static const uint8_t record_limit_exact[] = {0x00, 0x1c, 0x00, 0x02, 0x04, 0x01};
static const uint8_t record_limit_trail[] = {0x00, 0x1c, 0x00, 0x03, 0x04, 0x01, 0x00};
static const uint8_t record_limit_dup[] = {0x00, 0x1c, 0x00, 0x02, 0x04, 0x01,
                                           0x00, 0x1c, 0x00, 0x02, 0x04, 0x01};
static const uint8_t groups_tolerated[] = {0x00, 0x0a, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef};
static const uint8_t groups_dup[] = {0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d,
                                     0x00, 0x0a, 0x00, 0x02, 0x00, 0x17};

// The assembled cases hold the 38 fixed bytes, the 2-byte extensions
// length, and at most supported_versions (6) plus one key_share in its
// trailing-byte shape (9 + CH_KEX_SERVER_SHARE); the caps round up.
#ifdef CH_KEX_PQ
#define SH_CASE_CAP (64 + CH_KEX_SERVER_SHARE)
#define SH_EXTS_CAP (24 + CH_KEX_SERVER_SHARE)
#else
#define SH_CASE_CAP 192
#define SH_EXTS_CAP 96
#endif

// Parses a ServerHello assembled around the given extension bytes.
static int server_hello_case(const uint8_t *exts, size_t n, int hrr, int psk_mode) {
    uint8_t buf[SH_CASE_CAP];
    size_t len = make_server_hello(buf, hrr, exts, n);
    return try_server_hello(buf, len, psk_mode);
}

// Parses an EncryptedExtensions assembled from the given extension bytes.
static int encrypted_exts_case(const uint8_t *exts, size_t n) {
    uint8_t buf[64];
    size_t len = make_encrypted_exts(buf, exts, n);
    return try_encrypted_exts(buf, len);
}

// The alert contract: callers seed a default, and the parser overwrites
// it only when it knows better. Returns the alert after the parse.
static uint8_t encrypted_exts_alert_case(const uint8_t *exts, size_t n, uint8_t seed) {
    uint8_t buf[64];
    size_t len = make_encrypted_exts(buf, exts, n);
    uint16_t peer_limit = CH_TX_PT;
    uint8_t alert = seed;
    (void)hsp_parse_encrypted_exts(buf, len, &peer_limit, &alert);
    return alert;
}

// Same, with supported_versions prepended: CH_OK requires a selected
// version, so this isolates the extension under test.
static int server_hello_case2(const uint8_t *ext2, size_t n, int hrr, int psk_mode) {
    uint8_t exts[SH_EXTS_CAP];
    memcpy(exts, versions_exact, sizeof versions_exact);
    memcpy(exts + sizeof versions_exact, ext2, n);
    return server_hello_case(exts, sizeof versions_exact + n, hrr, psk_mode);
}

int main(void) {
#ifdef CH_KEX_PQ
    build_key_share_cases();
    // The golden ServerHello offers an x25519 key_share, so the hybrid
    // build must refuse it; the key_share_exact case below is this
    // build's clean-parse anchor.
    CHECK(try_server_hello(server_hello_golden, sizeof server_hello_golden, 0) == CH_EPROTO);
#else
    // The golden ServerHello parses clean.
    CHECK(try_server_hello(server_hello_golden, sizeof server_hello_golden, 0) == CH_OK);
#endif
    CHECK(try_encrypted_exts(encrypted_exts_golden, sizeof encrypted_exts_golden) == CH_OK);

    // Boundary pairs, ServerHello: each extension's exact-length body
    // parses; the same body plus one trailing byte is a decode error.
    CHECK(server_hello_case(versions_exact, sizeof versions_exact, 0, 0) == CH_OK);
    CHECK(server_hello_case(versions_trail, sizeof versions_trail, 0, 0) == CH_EPROTO);
    CHECK(server_hello_case2(key_share_exact, sizeof key_share_exact, 0, 0) == CH_OK);
    CHECK(server_hello_case2(key_share_trail, sizeof key_share_trail, 0, 0) == CH_EPROTO);
    CHECK(server_hello_case2(psk_exact, sizeof psk_exact, 0, 1) == CH_OK);
    CHECK(server_hello_case2(psk_trail, sizeof psk_trail, 0, 1) == CH_EPROTO);
    CHECK(server_hello_case2(cookie_exact, sizeof cookie_exact, 1, 0) == CH_OK);
    CHECK(server_hello_case2(cookie_trail, sizeof cookie_trail, 1, 0) == CH_EPROTO);
    // §4.1.4 lists no pre_shared_key for a HelloRetryRequest: the same
    // body a final ServerHello accepts (the psk_exact pair above) is
    // fatal from a retry, even with a PSK offered.
    CHECK(server_hello_case2(psk_exact, sizeof psk_exact, 1, 1) == CH_EPROTO);

    // Regression, issue #10: junk after a valid selected_version once
    // parsed as valid TLS 1.3.
    CHECK(server_hello_case(versions_junk, sizeof versions_junk, 0, 0) == CH_EPROTO);

    // Duplicate extensions are illegal (§4.3), even byte-identical ones.
    CHECK(server_hello_case(versions_dup, sizeof versions_dup, 0, 0) == CH_EPROTO);

    // Boundary pair, EncryptedExtensions: record_size_limit exact
    // (the golden message) versus one trailing byte.
    CHECK(encrypted_exts_case(record_limit_exact, sizeof record_limit_exact) == CH_OK);
    CHECK(encrypted_exts_case(record_limit_trail, sizeof record_limit_trail) == CH_EPROTO);
    CHECK(encrypted_exts_case(record_limit_dup, sizeof record_limit_dup) == CH_EPROTO);
    // supported_groups stays tolerated with an unread body...
    CHECK(encrypted_exts_case(groups_tolerated, sizeof groups_tolerated) == CH_OK);
    // Alert contract: an extension we never offered upgrades the caller's
    // seeded default to unsupported_extension (RFC 9846 §4.3, wire value
    // 110); a plain decode failure leaves the seed untouched.
    static const uint8_t unknown_ext[] = {0x00, 0x2b, 0x00, 0x00};
    CHECK(encrypted_exts_case(unknown_ext, sizeof unknown_ext) == CH_EPROTO);
    CHECK(encrypted_exts_alert_case(unknown_ext, sizeof unknown_ext, 47) == 110);
    CHECK(encrypted_exts_alert_case(record_limit_trail, sizeof record_limit_trail, 47) == 47);
    // ...but may not repeat either.
    CHECK(encrypted_exts_case(groups_dup, sizeof groups_dup) == CH_EPROTO);
    // An empty extension block is a legal EncryptedExtensions.
    CHECK(encrypted_exts_case(NULL, 0) == CH_OK);

    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("handshake_strict_test: all checks passed\n");
    return 0;
}
