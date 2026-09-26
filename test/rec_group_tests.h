// This tree's tcp-nonblocking server against ClientHellos the test writes by hand,
// because no client this tree builds offers secp256r1 alone: a raw or ca
// client offers its build's one group, and a TRUST=webpki client lists
// secp256r1 after two groups it shares (docs/decisions.md 63). Each hello
// offers TLS_CHACHA20_POLY1305_SHA256, rsa_pss_rsae_sha256 for the
// server's RSA identity, and the groups and shares a row names, and the
// row reads the group the server's first plaintext record names. The
// server holds three groups and takes secp256r1 last (srv_kex.h), so a
// hello that lists secp256r1 alone gets it, and one that lists x25519
// beside it gets x25519 whatever it shares. Included by
// test/tcp_nonblocking_loop_test.c after its fixtures.
#ifndef CH_TEST_REC_GROUP_TESTS_H
#define CH_TEST_REC_GROUP_TESTS_H

#include "p256_ecdh.h"
#include "x25519.h"

// The client half: a P-256 point and an x25519 value, from fixed secrets.
static uint8_t group_p256_point[P256_POINT_LEN];
static uint8_t group_x25519_pub[X25519_LEN];

// One plaintext ClientHello record listing the groups in groups[0..count)
// and carrying a KeyShareEntry for each of those whose bit in shared is
// set, bit i for groups[i]. Returns its length.
static size_t group_hello(uint8_t *out, size_t cap, const uint16_t *groups, size_t count,
                          unsigned shared) {
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, REC_HANDSHAKE);
    wb_u16(&w, 0x0301);
    size_t rec = wb_mark(&w, 2);
    wb_u8(&w, HS_CLIENT_HELLO);
    size_t msg = wb_mark(&w, 3);
    wb_u16(&w, 0x0303);
    for (int i = 0; i < 32; i++) {
        wb_u8(&w, (uint8_t)(0x90 + i));
    }
    wb_u8(&w, 0);
    wb_u16(&w, 2);
    wb_u16(&w, SUITE_CHACHA20_POLY1305_SHA256);
    wb_u8(&w, 1);
    wb_u8(&w, 0);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 3);
    wb_u8(&w, 2);
    wb_u16(&w, TLS13);
    wb_u16(&w, EXT_SIGNATURE_ALGORITHMS);
    wb_u16(&w, 4);
    wb_u16(&w, 2);
    wb_u16(&w, SIGALG_RSA_PSS_RSAE_SHA256);
    wb_u16(&w, EXT_SUPPORTED_GROUPS);
    wb_u16(&w, (uint16_t)(2 + 2 * count));
    wb_u16(&w, (uint16_t)(2 * count));
    for (size_t i = 0; i < count; i++) {
        wb_u16(&w, groups[i]);
    }
    wb_u16(&w, EXT_KEY_SHARE);
    size_t ext = wb_mark(&w, 2);
    size_t list = wb_mark(&w, 2);
    for (size_t i = 0; i < count; i++) {
        if ((shared >> i & 1U) == 0) {
            continue;
        }
        int p256 = groups[i] == CH_GROUP_SECP256R1;
        wb_u16(&w, groups[i]);
        wb_u16(&w, p256 ? P256_POINT_LEN : X25519_LEN);
        wb_bytes(&w, p256 ? group_p256_point : group_x25519_pub,
                 p256 ? P256_POINT_LEN : X25519_LEN);
    }
    wb_patch16(&w, list);
    wb_patch16(&w, ext);
    wb_patch16(&w, exts);
    wb_patch24(&w, msg);
    wb_patch16(&w, rec);
    return w.err ? 0 : w.len;
}

// The key_share of the server's first record: the NamedGroup, and in
// *share the key_exchange with its length in *share_len, or NULL for a
// HelloRetryRequest, whose key_share names a group alone. *hrr says which
// message the record carried. Returns 0 when the record holds neither.
static uint16_t first_record_group(int *hrr, const uint8_t **share, size_t *share_len) {
    rbuf r;
    rb_init(&r, to_client.bytes, to_client.len);
    (void)rb_bytes(&r, REC_HDR + 4 + 2); // record, handshake header, legacy_version
    const uint8_t *random = rb_bytes(&r, 32);
    (void)rb_bytes(&r, rb_u8(&r));
    (void)rb_bytes(&r, 3); // cipher_suite, legacy_compression_method
    size_t exts_len = rb_u16(&r);
    if (r.err || random == NULL || exts_len > rb_left(&r)) {
        return 0;
    }
    *hrr = memcmp(random, hsp_hrr_magic, 32) == 0;
    *share = NULL;
    size_t end = r.off + exts_len;
    while (r.off < end) {
        uint16_t type = rb_u16(&r);
        size_t len = rb_u16(&r);
        const uint8_t *data = rb_bytes(&r, len);
        if (data == NULL) {
            return 0;
        }
        rbuf e;
        rb_init(&e, data, len);
        if (type == EXT_KEY_SHARE) {
            uint16_t group = rb_u16(&e);
            if (!*hrr) {
                *share_len = rb_u16(&e);
                *share = rb_bytes(&e, *share_len);
            }
            return e.err ? 0 : group;
        }
    }
    return 0;
}

// Feeds one hand-written hello to a fresh server and reports the group
// its first record names, with the share and whether it was a retry.
static uint16_t server_answers(const uint16_t *groups, size_t count, unsigned shared, int *hrr,
                               const uint8_t **share, size_t *share_len) {
    static ch_record server;
    ch_cfg scfg;
    server_config(&scfg);
    to_client.len = 0;
    logged_count = 0; // the server logs its handshake secrets per hello
    CHECK(ch_srv_record_init(&server, &scfg) == CH_OK);
    uint8_t hello[512];
    size_t n = group_hello(hello, sizeof hello, groups, count, shared);
    size_t consumed = 0;
    CHECK(n > 0 && ch_srv_record_in(&server, hello, n, &consumed) == CH_OK && consumed == n);
    return first_record_group(hrr, share, share_len);
}

static void test_server_group_order(void) {
    static const uint8_t p256_draw[P256_SCALAR_LEN] = {0x3d, 0x4e};
    static const uint8_t x25519_priv[X25519_LEN] = {0x5f};
    uint8_t p256_priv[P256_SCALAR_LEN];
    CHECK(p256_ecdh_keygen(p256_draw, p256_priv, group_p256_point) == 1);
    x25519_base(group_x25519_pub, x25519_priv);
    int hrr = 0;
    const uint8_t *share = NULL;
    size_t share_len = 0;

    // secp256r1 alone, with its share: a ServerHello selecting it, whose
    // share is a point on the curve.
    static const uint16_t p256_only[] = {CH_GROUP_SECP256R1};
    CHECK(server_answers(p256_only, 1, 1U, &hrr, &share, &share_len) == CH_GROUP_SECP256R1);
    CHECK(!hrr && share != NULL && share_len == P256_POINT_LEN && p256_ecdh_point_valid(share));
    // secp256r1 alone, with no share: a HelloRetryRequest naming it.
    CHECK(server_answers(p256_only, 1, 0U, &hrr, &share, &share_len) == CH_GROUP_SECP256R1);
    CHECK(hrr);

    // x25519 and secp256r1 listed: x25519, in one round trip when it is
    // shared, whatever else is, and through a retry when only the P-256
    // share came.
    static const uint16_t both[] = {CH_GROUP_X25519, CH_GROUP_SECP256R1};
    CHECK(server_answers(both, 2, 3U, &hrr, &share, &share_len) == CH_GROUP_X25519);
    CHECK(!hrr && share_len == X25519_LEN);
    static const uint16_t p256_first[] = {CH_GROUP_SECP256R1, CH_GROUP_X25519};
    CHECK(server_answers(p256_first, 2, 3U, &hrr, &share, &share_len) == CH_GROUP_X25519);
    CHECK(!hrr);
    CHECK(server_answers(both, 2, 2U, &hrr, &share, &share_len) == CH_GROUP_X25519);
    CHECK(hrr);
}

#endif
