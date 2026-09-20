// The ClientHello test/srv_parser_tests.h reads, and the helpers that
// assemble its variants: a head and ten extension blobs, each written
// out by hand from the field list of the section it names, so a field
// written at the wrong offset shows as the wrong verdict rather than as
// a byte that matches by luck. The blobs carry what a browser's hello
// carries and this build does not hold -- a GREASE suite, a GREASE
// group, an unknown extension, a draft version, a third signature
// scheme -- because the rule is that every conformant client parses:
// §4.2.2 and §9.3 tell a server to ignore those values, and the cases
// hold the parser to that. It uses CHECK from test/srv_test.c and is
// included after it.
#ifndef CH_SRV_PARSER_HELLO_H
#define CH_SRV_PARSER_HELLO_H

// The alert every parse is seeded with. It is none of the descriptions
// the parser writes, so a case can tell a kept seed from a written one.
#define ALERT_SEED 0xa5

// Room for the hello and the largest mutant: the golden hello is 216 bytes.
#define HELLO_CAP 512
#define HEAD_CAP 128

// §4.1.2's fields before the extension block: legacy_version, a counting
// random, the longest legacy_session_id the field admits, three cipher
// suites of which the last is this build's, and the one zero
// compression byte.
static const uint8_t hello_head[] = {
    0x03, 0x03,                                     // legacy_version
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // random
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, //
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, //
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, //
    0x20,                                           // legacy_session_id length
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, // legacy_session_id
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, //
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, //
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, //
    0x00, 0x06,                                     // cipher_suites, 6 bytes:
    0x0a, 0x0a, 0x13, 0x01, 0x13, 0x03,             // GREASE, AES-128-GCM, ChaCha20-Poly1305
    0x01, 0x00};                                    // legacy_compression_methods: null
#define HEAD_RANDOM_AT 2
#define HEAD_SESSION_ID_AT 35
#define HEAD_SUITES ((const uint8_t *)hello_head + 69)
#define HEAD_SUITES_LEN 6
static const uint8_t compression_null[] = {0x00};

// The extensions, each as its type, length and body sit on the wire.
// RFC 6066 §3: one host_name, "localhost".
static const uint8_t ext_server_name[] = {0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09,
                                          'l',  'o',  'c',  'a',  'l',  'h',  'o',  's',  't'};
// A GREASE type with a two-byte body, which §4.2.2 has the server skip.
static const uint8_t ext_grease[] = {0x1a, 0x1a, 0x00, 0x02, 0x00, 0x00};
// §4.2.7: a GREASE group, x25519 and secp256r1.
static const uint8_t ext_groups[] = {0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
                                     0x0a, 0x0a, 0x00, 0x1d, 0x00, 0x17};
// §4.2.3: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256.
static const uint8_t ext_sigalgs[] = {0x00, 0x0d, 0x00, 0x08, 0x00, 0x06,
                                      0x04, 0x03, 0x08, 0x04, 0x04, 0x01};
// RFC 7301 §3.1: "h2" then "http/1.1".
static const uint8_t ext_alpn[] = {0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 'h', '2',
                                   0x08, 'h',  't',  't',  'p',  '/',  '1',  '.', '1'};
// RFC 8449 §4: 16384.
static const uint8_t ext_record_size_limit[] = {0x00, 0x1c, 0x00, 0x02, 0x40, 0x00};
// §4.2.1: draft 28's 0x7f1c, which the server ignores, then TLS 1.3.
static const uint8_t ext_versions[] = {0x00, 0x2b, 0x00, 0x05, 0x04, 0x7f, 0x1c, 0x03, 0x04};
// §4.2.9: psk_dhe_ke alone.
static const uint8_t ext_psk_modes[] = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x01};
// §4.2.8: one x25519 entry, its key_exchange counting from 0x40.
static const uint8_t ext_key_share[] = {
    0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, // client_shares, x25519, 32 bytes
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};
#define KEY_SHARE_KEY_AT 10
// RFC 7685: four zero bytes.
static const uint8_t ext_padding[] = {0x00, 0x15, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
// The four extensions the golden hello does not carry. §4.2.10's
// early_data is empty; §4.2.2's cookie echoes four bytes; §4.2.11's
// pre_shared_key offers one one-byte identity and one 32-byte binder,
// the smallest OfferedPsks the vector bounds admit; RFC 9001 §8.2's
// quic_transport_parameters carries three bytes, which stand for a body
// no build here reads.
static const uint8_t ext_quic_transport_params[] = {0x00, 0x39, 0x00, 0x03, 0xc0, 0xc1, 0xc2};
static const uint8_t ext_early_data[] = {0x00, 0x2a, 0x00, 0x00};
static const uint8_t ext_cookie[] = {0x00, 0x2c, 0x00, 0x06, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef};
static const uint8_t ext_psk[] = {
    0x00, 0x29, 0x00, 0x2c,                               // pre_shared_key, 44 bytes
    0x00, 0x07, 0x00, 0x01, 0x5a, 0x00, 0x00, 0x00, 0x00, // identities: one identity, age 0
    0x00, 0x21, 0x20,                                     // binders: one 32-byte binder
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f};
// Where each of the two OfferedPsks list bodies starts inside ext_psk,
// and how long that body is. PSK_BINDERS_FIELD_LEN counts the binders
// body plus the two-byte length in front of it, which is the distance
// truncated_len sits back from the end of the extension.
#define PSK_IDENTITIES_AT 6
#define PSK_IDENTITIES_LEN 7
#define PSK_BINDERS_AT 15
#define PSK_BINDERS_LEN 33
#define PSK_BINDERS_FIELD_LEN (2 + PSK_BINDERS_LEN)

typedef struct {
    const uint8_t *bytes;
    size_t len;
} extension;
#define EXTENSION(x) {(x), sizeof(x)}

// The golden hello's extensions, in the order a browser sends them.
static const extension golden_exts[] = {
    EXTENSION(ext_server_name), EXTENSION(ext_grease),    EXTENSION(ext_groups),
    EXTENSION(ext_sigalgs),     EXTENSION(ext_alpn),      EXTENSION(ext_record_size_limit),
    EXTENSION(ext_versions),    EXTENSION(ext_psk_modes), EXTENSION(ext_key_share),
    EXTENSION(ext_padding)};
#define GOLDEN_EXT_COUNT (sizeof golden_exts / sizeof golden_exts[0])
// Positions in golden_exts, for the cases that replace or drop one.
enum {
    AT_SERVER_NAME,
    AT_GREASE,
    AT_GROUPS,
    AT_SIGALGS,
    AT_ALPN,
    AT_RECORD_SIZE_LIMIT,
    AT_VERSIONS,
    AT_PSK_MODES,
    AT_KEY_SHARE,
    AT_PADDING,
    AT_NONE
};
#define GOLDEN_SEEN                                                                                \
    (SRV_EXT_SERVER_NAME | SRV_EXT_SUPPORTED_GROUPS | SRV_EXT_SIGNATURE_ALGORITHMS |               \
     SRV_EXT_ALPN | SRV_EXT_RECORD_SIZE_LIMIT | SRV_EXT_SUPPORTED_VERSIONS | SRV_EXT_PSK_MODES |   \
     SRV_EXT_KEY_SHARE | SRV_EXT_PADDING)

// Assembles a ClientHello body: head_len bytes of head, then the
// extension block's length over the extensions. Returns the body length.
static size_t assemble(uint8_t *dst, const uint8_t *head, size_t head_len, const extension *exts,
                       size_t count) {
    wbuf w;
    wb_init(&w, dst, HELLO_CAP);
    wb_bytes(&w, head, head_len);
    size_t mark = wb_mark(&w, 2);
    for (size_t i = 0; i < count; i++) {
        wb_bytes(&w, exts[i].bytes, exts[i].len);
    }
    wb_patch16(&w, mark);
    CHECK(!w.err);
    return w.len;
}

// The golden hello.
static size_t golden(uint8_t *dst) {
    return assemble(dst, hello_head, sizeof hello_head, golden_exts, GOLDEN_EXT_COUNT);
}

// The golden hello with the extension at `at` replaced by `ext`, or
// dropped when ext is NULL, and with `tail` appended after the last one
// when it is not NULL. AT_NONE replaces nothing.
static size_t variant(uint8_t *dst, size_t at, const extension *ext, const extension *tail) {
    extension exts[GOLDEN_EXT_COUNT + 1];
    size_t count = 0;
    for (size_t i = 0; i < GOLDEN_EXT_COUNT; i++) {
        if (i != at) {
            exts[count++] = golden_exts[i];
        } else if (ext != NULL) {
            exts[count++] = *ext;
        }
    }
    if (tail != NULL) {
        exts[count++] = *tail;
    }
    return assemble(dst, hello_head, sizeof hello_head, exts, count);
}

static size_t replaced(uint8_t *dst, size_t at, const uint8_t *ext, size_t n) {
    extension e = {ext, n};
    return variant(dst, at, &e, NULL);
}

static size_t dropped(uint8_t *dst, size_t at) {
    return variant(dst, at, NULL, NULL);
}

static size_t appended(uint8_t *dst, const uint8_t *ext, size_t n) {
    extension e = {ext, n};
    return variant(dst, AT_NONE, NULL, &e);
}

// A head whose session id length, cipher_suites and compression list the
// case chooses; the session id bytes count up from 0x20 as the golden's do.
static size_t make_head(uint8_t *dst, size_t session_id_len, const uint8_t *suites,
                        size_t suites_len, const uint8_t *compression, size_t compression_len) {
    wbuf w;
    wb_init(&w, dst, HEAD_CAP);
    wb_bytes(&w, hello_head, 2 + SRV_RANDOM);
    wb_u8(&w, (uint8_t)session_id_len);
    for (size_t i = 0; i < session_id_len; i++) {
        wb_u8(&w, (uint8_t)(0x20 + i));
    }
    wb_u16(&w, (uint16_t)suites_len);
    wb_bytes(&w, suites, suites_len);
    wb_u8(&w, (uint8_t)compression_len);
    wb_bytes(&w, compression, compression_len);
    CHECK(!w.err);
    return w.len;
}

// Copies ext with its length one larger and one zero byte after its
// body: the exact-fill mutant of every recognized extension.
static size_t trailed(uint8_t *dst, const uint8_t *ext, size_t n) {
    memcpy(dst, ext, n);
    size_t body = n - 4 + 1;
    dst[2] = (uint8_t)(body >> 8);
    dst[3] = (uint8_t)body;
    dst[n] = 0;
    return n + 1;
}

// The result of the last parse.
static client_hello parsed;
static uint8_t parsed_alert;

static int parse_with(const uint8_t *body, size_t n, const ch_alpn_protocol *offered,
                      size_t count) {
    memset(&parsed, 0, sizeof parsed);
    parsed_alert = ALERT_SEED;
    return srv_parse_client_hello(body, n, &parsed, offered, count, &parsed_alert);
}

static int parse(const uint8_t *body, size_t n) {
    return parse_with(body, n, NULL, 0);
}

// Whether the parser refuses body with exactly this description.
static int refused(const uint8_t *body, size_t n, uint8_t alert) {
    return parse(body, n) == CH_EPROTO && parsed_alert == alert;
}

// Whether p points at len bytes inside body.
static int inside(const uint8_t *body, size_t n, const uint8_t *p, size_t len) {
    return p != NULL && p >= body && p <= body + n && len <= (size_t)(body + n - p);
}

// A hello over the given head and the golden extensions.
static int head_case(size_t session_id_len, const uint8_t *suites, size_t suites_len,
                     const uint8_t *compression, size_t compression_len) {
    uint8_t head[HEAD_CAP];
    uint8_t buf[HELLO_CAP];
    size_t head_len =
        make_head(head, session_id_len, suites, suites_len, compression, compression_len);
    size_t n = assemble(buf, head, head_len, golden_exts, GOLDEN_EXT_COUNT);
    return parse(buf, n);
}

// A key_share extension holding one entry for group, with a
// key_exchange of key_len bytes.
static size_t make_key_share(uint8_t *dst, uint16_t group, size_t key_len) {
    wbuf w;
    wb_init(&w, dst, HELLO_CAP);
    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, (uint16_t)(2 + 4 + key_len));
    wb_u16(&w, (uint16_t)(4 + key_len));
    wb_u16(&w, group);
    wb_u16(&w, (uint16_t)key_len);
    for (size_t i = 0; i < key_len; i++) {
        wb_u8(&w, 0x40);
    }
    CHECK(!w.err);
    return w.len;
}

// A pre_shared_key extension over the two list bodies given, each
// written with its own two-byte length. It builds the lists §4.2.11's
// vector bounds forbid as readily as the ones they admit, which is what
// the bound cases need: a list shorter than its minimum still fills the
// extension exactly, so the exact-fill check does not refuse it first
// and the bound is the only thing left to refuse it.
static size_t make_psk(uint8_t *dst, const uint8_t *identities, size_t identities_len,
                       const uint8_t *binders, size_t binders_len) {
    wbuf w;
    wb_init(&w, dst, HELLO_CAP);
    wb_u16(&w, EXT_PRE_SHARED_KEY);
    wb_u16(&w, (uint16_t)(4 + identities_len + binders_len));
    wb_u16(&w, (uint16_t)identities_len);
    wb_bytes(&w, identities, identities_len);
    wb_u16(&w, (uint16_t)binders_len);
    wb_bytes(&w, binders, binders_len);
    CHECK(!w.err);
    return w.len;
}

// The golden hello with one pre_shared_key appended, which is where
// §4.2.11 requires it, reporting the parse.
static int psk_case(const uint8_t *identities, size_t identities_len, const uint8_t *binders,
                    size_t binders_len) {
    uint8_t buf[HELLO_CAP];
    uint8_t ext[HELLO_CAP];
    size_t m = make_psk(ext, identities, identities_len, binders, binders_len);
    size_t n = appended(buf, ext, m);
    return parse(buf, n);
}

static const uint8_t name_h2[] = {'h', '2'};
static const uint8_t name_http11[] = {'h', 't', 't', 'p', '/', '1', '.', '1'};
static const uint8_t name_spdy[] = {'s', 'p', 'd', 'y', '/', '3'};

// The golden hello against an offer of `count` names, reporting the
// selection.
static uint8_t alpn_case(const ch_alpn_protocol *offer, size_t count) {
    uint8_t buf[HELLO_CAP];
    size_t n = golden(buf);
    CHECK(parse_with(buf, n, offer, count) == CH_OK);
    return parsed.alpn_selected;
}

#endif
