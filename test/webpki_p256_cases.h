// The secp256r1 half of a TRUST=webpki client's key exchange
// (docs/decisions.md 63): the first hello lists secp256r1 after the two
// shared groups and sends no share for it, a HelloRetryRequest naming it
// gets a retry hello whose key_share holds one P-256 share, and the
// ServerHello that answers must select it with a point on the curve. RFC
// 9846 §9.1 makes key exchange with secp256r1 a MUST
// (rfc9846.txt:4548-4550), and a server with no other group, nghttpd on
// OpenSSL 3.0 for one, reaches this client only this way. The rows run
// against the mock server in test/webpki_session_test.c, whose
// secp256r1 side is test/webpki_mock_kex.h, and bad_certificate under the
// handshake keys is the evidence both sides derived one P-256 secret.
// Included by that file after the mock and test/webpki_groups_cases.h.
#ifndef CH_TEST_WEBPKI_P256_CASES_H
#define CH_TEST_WEBPKI_P256_CASES_H

#include "handshake_groups.h"
#include "p256_ecdh.h"

// The retry hello a HelloRetryRequest naming secp256r1 asks for: its
// key_share holds one 69-byte entry, the group, the length and the 65-byte
// point, where the first hello's holds the hybrid's 1220 bytes and
// x25519's 36. It is 1187 bytes shorter than the first hello with the same
// cookie, so CH_HELLO_MAX needs no term for it.
static void test_webpki_p256_retry_hello_size(void) {
    static uint8_t out[CH_HELLO_MAX];
    static uint8_t cookie[HSP_COOKIE_MAX];
    static uint8_t ek[MLKEM_EK_LEN];
    static const uint8_t p256_pub[P256_POINT_LEN] = {0x04};
    uint8_t pub[32] = {0};
    uint8_t random32[32] = {0};
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    size_t first = hs_build_client_hello(out, CH_HELLO_MAX, &cfg, ek, NULL, pub, random32, 0xffff,
                                         cookie, sizeof cookie);
    size_t retry = hs_build_client_hello(out, CH_HELLO_MAX, &cfg, ek, p256_pub, pub, random32,
                                         0xffff, cookie, sizeof cookie);
    CHECK(first > 1187 && retry == first - 1187);
}

// A mock that answers the first hello with a HelloRetryRequest naming
// secp256r1, with a cookie beside it when cookie is set.
static ch_cfg p256_retry_cfg(mock_server *s, int cookie) {
    ch_cfg cfg = valid_cfg(s);
    s->answer = 1;
    s->retry = 1;
    s->retry_group = CH_GROUP_SECP256R1;
    s->retry_cookie = cookie;
    return cfg;
}

// The retry hello §4.2.2 asks for (rfc9846.txt:1194-1196): the first
// hello's random and supported_groups, a key_share holding one secp256r1
// entry whose 65 bytes are a point on the curve, the cookie echoed when
// the retry sent one, and legacy_record_version 0x0303 (RFC 9846 §5.1)
// with or without that cookie. The ServerHello's P-256 share then keys
// the handshake: the mock's bad_certificate arrives under those keys, and
// ch_tls.group reports secp256r1.
static void test_webpki_p256_retry(void) {
    for (int cookie = 0; cookie <= 1; cookie++) {
        mock_server s;
        ch_tls t;
        ch_cfg cfg = p256_retry_cfg(&s, cookie);
        CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
        CHECK(s.alert == ALERT_BAD_CERTIFICATE);
        CHECK(t.group == CH_GROUP_SECP256R1);
        CHECK(s.retry_hello_len > 0 && s.retry_record_version == 0x03);
        CHECK(memcmp(s.retry_hello + 6, s.hello + 6, 32) == 0); // the random
        size_t first_len = 0;
        size_t again_len = 0;
        const uint8_t *first = hello_ext(s.hello, s.hello_len, EXT_SUPPORTED_GROUPS, &first_len);
        const uint8_t *again =
            hello_ext(s.retry_hello, s.retry_hello_len, EXT_SUPPORTED_GROUPS, &again_len);
        CHECK(first != NULL && again != NULL && first_len == again_len &&
              memcmp(first, again, first_len) == 0);
        hello_share_entry shares[2] = {{0}};
        CHECK(hello_key_shares(s.retry_hello, s.retry_hello_len, shares, 2) == 1);
        CHECK(shares[0].group == CH_GROUP_SECP256R1 && shares[0].key_len == P256_POINT_LEN &&
              shares[0].key[0] == 0x04 && p256_ecdh_point_valid(shares[0].key));
        size_t echo_len = 0;
        const uint8_t *echo = hello_ext(s.retry_hello, s.retry_hello_len, EXT_COOKIE, &echo_len);
        CHECK(cookie ? echo != NULL && echo_len == 2 + 4 : echo == NULL);
    }
}

// Every server share RFC 9846 §4.3.8.2 has the client refuse
// (rfc9846.txt:2277-2286): off the curve, (0, 0), the wrong form byte, and
// the point at infinity, whose encoding is one byte; and the lengths one
// byte either side of the 65 the uncompressed form fixes
// (rfc9846.txt:2261-2275). Each is illegal_parameter, before any key
// exists. The parser refuses a length other than 65, so no group is
// reported; a 65-byte share reaches the key exchange, which refuses the
// point after hsf_accept_server_hello has reported the group.
// MOCK_P256_VALID, the last valid shape, is test_webpki_p256_retry's.
static void test_webpki_p256_share_refusals(void) {
    for (int mode = MOCK_P256_VALID + 1; mode < MOCK_P256_MODES; mode++) {
        mock_server s;
        ch_tls t;
        ch_cfg cfg = p256_retry_cfg(&s, 0);
        s.p256_mode = mode;
        CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
        CHECK(s.alert == ALERT_ILLEGAL_PARAMETER);
        int length_ok =
            mode != MOCK_P256_LEN_64 && mode != MOCK_P256_LEN_66 && mode != MOCK_P256_INFINITY;
        CHECK(t.group == (length_ok ? CH_GROUP_SECP256R1 : 0));
    }
}

// Which group a ServerHello may select, and which retry this client takes
// (RFC 9846 §4.3.8, rfc9846.txt:2205-2215 and 2233-2238). Without a retry
// the hello carried no secp256r1 share, so a ServerHello selecting it is
// refused; after a retry naming secp256r1 the retry hello carried that
// share alone, so a ServerHello selecting the hybrid or x25519 is refused.
// require_pq kept secp256r1 off the hello, so a retry naming it names a
// group never listed and no retry hello goes out. Every refusal is
// illegal_parameter.
static void test_webpki_p256_group_rules(void) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    s.answer = 1;
    s.sh_group = CH_GROUP_SECP256R1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.retry_hello_len == 0);

    static const uint16_t others[] = {CH_GROUP_X25519MLKEM768, CH_GROUP_X25519};
    for (size_t i = 0; i < sizeof others / sizeof others[0]; i++) {
        cfg = p256_retry_cfg(&s, 1);
        s.sh_group = others[i];
        CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
        CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.retry_hello_len > 0);
    }

    for (int cookie = 0; cookie <= 1; cookie++) {
        cfg = p256_retry_cfg(&s, cookie);
        cfg.require_pq = 1;
        CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
        CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.retry_hello_len == 0);
    }
}

// Whether all n bytes at p are zero.
static int p256_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

// What the key exchange leaves in a handshake_state the test can read,
// which the blocking driver's frame hides. Taking the retry draws the
// P-256 key pair and wipes the first hello's x25519 and ML-KEM key pairs,
// which no later message uses. The exchange then wipes the P-256 scalar,
// after a point it accepts and after one it refuses (INV-17).
static void test_webpki_p256_wipes(void) {
    uint8_t server_priv[P256_SCALAR_LEN];
    uint8_t server_point[P256_POINT_LEN];
    CHECK(p256_ecdh_keygen(server_p256_draw, server_priv, server_point) == 1);
    for (int refuse = 0; refuse <= 1; refuse++) {
        mock_server s;
        ch_tls t;
        memset(&t, 0, sizeof t);
        t.cfg = valid_cfg(&s);
        handshake_state h;
        memset(&h, 0, sizeof h);
        h.t = &t;
        hsf_begin(&h);
        server_hello_info retry;
        memset(&retry, 0, sizeof retry);
        retry.hrr = 1;
        retry.retry_group = CH_GROUP_SECP256R1;
        CHECK(hsg_take_retry(&h, &retry) == CH_OK);
        CHECK(h.retry_group == CH_GROUP_SECP256R1);
        CHECK(!p256_zero(h.p256_priv, sizeof h.p256_priv) && p256_ecdh_point_valid(h.p256_pub));
        CHECK(p256_zero(h.priv, sizeof h.priv) && p256_zero(h.pub, sizeof h.pub) &&
              p256_zero(h.dz, sizeof h.dz));

        uint8_t point[P256_POINT_LEN];
        memcpy(point, server_point, sizeof point);
        point[P256_POINT_LEN - 1] ^= (uint8_t)refuse; // off the curve when set
        server_hello_info info;
        memset(&info, 0, sizeof info);
        info.group = CH_GROUP_SECP256R1;
        info.have_share = 1;
        info.server_p256 = point;
#ifdef CH_SUITE_AES_GCM
        // The suite hsf_read_server_hello would have taken, which names
        // the hash the secrets derive at.
        h.suite = SUITE_CHACHA20_POLY1305_SHA256;
#endif
        CHECK(hsf_derive_handshake_secrets(&h, &info) == (refuse ? CH_EPROTO : CH_OK));
        CHECK(p256_zero(h.p256_priv, sizeof h.p256_priv));
        CHECK(!refuse || h.alert == ALERT_ILLEGAL_PARAMETER);
    }
}

#endif
