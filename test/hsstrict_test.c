// Encoding strictness for the ServerHello and EncryptedExtensions
// parsers (issue #10): every extension body must match its struct
// exactly (RFC 8446 §4.2 makes trailing bytes a decode error) and no
// extension type may repeat. Each behavior gets a boundary pair: the
// exact-length body parses, the same body plus one byte fails. Both
// parsers are static in handshake.c, so this test includes the
// translation unit, stubbing the session hooks the parsers never call —
// the same shape as fuzz/fuzz_hsparse.c. Its own binary with a private
// main, like the other standalone test mains.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "cfg.h"
#include "ch_assert.h"
#include "io.h"
#include "p256.h"
#include "rand.h"
#include "rsa.h"
#include "session.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    abort();
}
// The stub writes exist only to match the non-const prototypes; the
// parsers never call any of these hooks.
void ch_rand_bytes(uint8_t *p, size_t n) {
    memset(p, 0, n);
    abort();
}
int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    (void)cfg;
    (void)p;
    (void)n;
    abort();
}
int io_read_record(const ch_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer, size_t *reclen) {
    (void)cfg;
    memset(buf, 0, cap);
    *outer = 0;
    *reclen = 0;
    abort();
}
void tlsi_fail(ch_tls *t, uint8_t desc) {
    (void)t;
    (void)desc;
    abort();
}
int tlsi_send_alert(ch_tls *t, uint8_t level, uint8_t desc) {
    (void)t;
    (void)level;
    (void)desc;
    abort();
}
int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    (void)pub;
    (void)msg_hash;
    (void)sig_der;
    (void)sig_len;
    abort();
}
int rsa_pss_verify(const uint8_t *n, size_t nlen, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t siglen) {
    (void)n;
    (void)nlen;
    (void)msg_hash;
    (void)sig;
    (void)siglen;
    abort();
}

#include "handshake.c"

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
static const uint8_t sh_golden[] = {
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
static const uint8_t ee_golden[] = {
    0x00, 0x06, // extensions length: 6
    0x00, 0x1c, // extension_type: record_size_limit (28)
    0x00, 0x02, // extension length: 2
    0x04, 0x01, // limit: 1025
};

// Assembles a ServerHello body around the given extension bytes: the
// golden message's fixed fields, then the extension block. hrr swaps
// the random for the HRR sentinel.
static size_t mk_sh(uint8_t *out, int hrr, const uint8_t *exts, size_t n) {
    size_t fixed = 2 + 32 + 1 + 2 + 1;
    memcpy(out, sh_golden, fixed);
    if (hrr) {
        memcpy(out + 2, hrr_magic, 32);
    }
    out[fixed] = (uint8_t)(n >> 8);
    out[fixed + 1] = (uint8_t)n;
    memcpy(out + fixed + 2, exts, n);
    return fixed + 2 + n;
}

static size_t mk_ee(uint8_t *out, const uint8_t *exts, size_t n) {
    out[0] = (uint8_t)(n >> 8);
    out[1] = (uint8_t)n;
    if (n > 0) {
        memcpy(out + 2, exts, n);
    }
    return 2 + n;
}

static int sh_parse(const uint8_t *body, size_t n, int psk_mode) {
    sh_info si;
    memset(&si, 0, sizeof si);
    return parse_sh(body, n, &si, psk_mode);
}

static int ee_parse(const uint8_t *body, size_t n) {
    ch_tls t;
    memset(&t, 0, sizeof t);
    t.peer_limit = CH_TX_PT;
    hs h;
    memset(&h, 0, sizeof h);
    h.t = &t;
    return parse_ee(&h, body, n);
}

// Extension blobs for the ServerHello cases. sv = supported_versions,
// ks = key_share, psk = pre_shared_key, ck = cookie.
static const uint8_t sv_exact[] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
static const uint8_t sv_trail[] = {0x00, 0x2b, 0x00, 0x03, 0x03, 0x04, 0x00};
// The issue's lenient input: 4 junk bytes after a valid selected_version.
static const uint8_t sv_junk[] = {0x00, 0x2b, 0x00, 0x06, 0x03, 0x04, 0xde, 0xad, 0xbe, 0xef};
static const uint8_t sv_dup[] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
                                 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
static const uint8_t ks_exact[] = {0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x09, 0x09,
                                   0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                                   0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                                   0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09};
static const uint8_t ks_trail[] = {0x00, 0x33, 0x00, 0x25, 0x00, 0x1d, 0x00, 0x20, 0x09, 0x09, 0x09,
                                   0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                                   0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                                   0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x00};
static const uint8_t psk_exact[] = {0x00, 0x29, 0x00, 0x02, 0x00, 0x00};
static const uint8_t psk_trail[] = {0x00, 0x29, 0x00, 0x03, 0x00, 0x00, 0x00};
static const uint8_t ck_exact[] = {0x00, 0x2c, 0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb};
static const uint8_t ck_trail[] = {0x00, 0x2c, 0x00, 0x05, 0x00, 0x02, 0xaa, 0xbb, 0x00};

// Extension blobs for the EncryptedExtensions cases. rsl =
// record_size_limit, sg = supported_groups.
static const uint8_t rsl_exact[] = {0x00, 0x1c, 0x00, 0x02, 0x04, 0x01};
static const uint8_t rsl_trail[] = {0x00, 0x1c, 0x00, 0x03, 0x04, 0x01, 0x00};
static const uint8_t rsl_dup[] = {0x00, 0x1c, 0x00, 0x02, 0x04, 0x01,
                                  0x00, 0x1c, 0x00, 0x02, 0x04, 0x01};
static const uint8_t sg_tolerated[] = {0x00, 0x0a, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef};
static const uint8_t sg_dup[] = {0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d,
                                 0x00, 0x0a, 0x00, 0x02, 0x00, 0x17};

// Parses a ServerHello assembled around the given extension bytes.
static int sh_case(const uint8_t *exts, size_t n, int hrr, int psk_mode) {
    uint8_t buf[192];
    size_t len = mk_sh(buf, hrr, exts, n);
    return sh_parse(buf, len, psk_mode);
}

// Parses an EncryptedExtensions assembled from the given extension bytes.
static int ee_case(const uint8_t *exts, size_t n) {
    uint8_t buf[64];
    size_t len = mk_ee(buf, exts, n);
    return ee_parse(buf, len);
}

// Same, with supported_versions prepended: CH_OK requires a selected
// version, so this isolates the extension under test.
static int sh_case2(const uint8_t *ext2, size_t n, int hrr, int psk_mode) {
    uint8_t exts[96];
    memcpy(exts, sv_exact, sizeof sv_exact);
    memcpy(exts + sizeof sv_exact, ext2, n);
    return sh_case(exts, sizeof sv_exact + n, hrr, psk_mode);
}

int main(void) {
    // The golden messages parse clean.
    CHECK(sh_parse(sh_golden, sizeof sh_golden, 0) == CH_OK);
    CHECK(ee_parse(ee_golden, sizeof ee_golden) == CH_OK);

    // Boundary pairs, ServerHello: each extension's exact-length body
    // parses; the same body plus one trailing byte is a decode error.
    CHECK(sh_case(sv_exact, sizeof sv_exact, 0, 0) == CH_OK);
    CHECK(sh_case(sv_trail, sizeof sv_trail, 0, 0) == CH_EPROTO);
    CHECK(sh_case2(ks_exact, sizeof ks_exact, 0, 0) == CH_OK);
    CHECK(sh_case2(ks_trail, sizeof ks_trail, 0, 0) == CH_EPROTO);
    CHECK(sh_case2(psk_exact, sizeof psk_exact, 0, 1) == CH_OK);
    CHECK(sh_case2(psk_trail, sizeof psk_trail, 0, 1) == CH_EPROTO);
    CHECK(sh_case2(ck_exact, sizeof ck_exact, 1, 0) == CH_OK);
    CHECK(sh_case2(ck_trail, sizeof ck_trail, 1, 0) == CH_EPROTO);

    // Regression, issue #10: junk after a valid selected_version once
    // parsed as valid TLS 1.3.
    CHECK(sh_case(sv_junk, sizeof sv_junk, 0, 0) == CH_EPROTO);

    // Duplicate extensions are illegal (§4.2), even byte-identical ones.
    CHECK(sh_case(sv_dup, sizeof sv_dup, 0, 0) == CH_EPROTO);

    // Boundary pair, EncryptedExtensions: record_size_limit exact
    // (the golden message) versus one trailing byte.
    CHECK(ee_case(rsl_exact, sizeof rsl_exact) == CH_OK);
    CHECK(ee_case(rsl_trail, sizeof rsl_trail) == CH_EPROTO);
    CHECK(ee_case(rsl_dup, sizeof rsl_dup) == CH_EPROTO);
    // supported_groups stays tolerated with an unread body...
    CHECK(ee_case(sg_tolerated, sizeof sg_tolerated) == CH_OK);
    // ...but may not repeat either.
    CHECK(ee_case(sg_dup, sizeof sg_dup) == CH_EPROTO);
    // An empty extension block is a legal EncryptedExtensions.
    CHECK(ee_case(NULL, 0) == CH_OK);

    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("hsstrict_test: all checks passed\n");
    return 0;
}
