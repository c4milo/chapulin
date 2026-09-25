// The server's secp256r1 key exchange through srv_flight.c
// (docs/decisions.md 63): the group it selects last, after the hybrid and
// x25519, the P-256 exchange from the ServerHello to the handshake
// secrets, the client points it refuses before it answers, and the
// HelloRetryRequest that asks for a secp256r1 share. It continues
// test/srv_flight_kex_tests.h, whose fixtures and preference helper it
// reads.
//
// The exchange cases run a client half beside the server: a P-256 key
// pair from a fixed draw, whose point is the client's share and whose
// scalar computes the secret the server's point gives the client. The
// handshake secrets both halves derive must be one secret.
#ifndef CH_SRV_FLIGHT_P256_TESTS_H
#define CH_SRV_FLIGHT_P256_TESTS_H

#include "p256_ecdh.h"
#include "srv_flight_kex_tests.h"

// The client half of a secp256r1 exchange.
static uint8_t p256_client_priv[P256_SCALAR_LEN];
static uint8_t p256_client_point[P256_POINT_LEN];

static void make_p256_client(void) {
    static const uint8_t draw[P256_SCALAR_LEN] = {0x51, 0x62, 0x73};
    CHECK(p256_ecdh_keygen(draw, p256_client_priv, p256_client_point) == 1);
}

// A client_hello that lists groups and shares secp256r1 alone when
// shared is set, with the client half's point as that share.
static void offer_p256(uint8_t groups, int shared) {
    offer_x25519();
    parse_result.groups = groups;
    parse_result.shares = shared ? SRV_GROUP_SECP256R1 : 0;
    parse_result.x25519_share = NULL;
    parse_result.p256_share = shared ? p256_client_point : NULL;
    flight_hello = parse_result;
}

// The preference rows docs/decisions.md 63 adds: secp256r1 only when the
// client lists neither the hybrid nor x25519, and a retry when it listed
// one of those and shared secp256r1 alone.
static void test_flight_select_p256(void) {
    const uint8_t x = SRV_GROUP_X25519;
    const uint8_t pq = SRV_GROUP_X25519MLKEM768;
    const uint8_t p = SRV_GROUP_SECP256R1;
    CHECK(selects(p, p, CH_GROUP_SECP256R1, 0));
    CHECK(selects(p, 0, CH_GROUP_SECP256R1, 1));
    CHECK(selects(x | p, x, CH_GROUP_X25519, 0));
    CHECK(selects(x | p, x | p, CH_GROUP_X25519, 0));
    CHECK(selects(x | p, p, CH_GROUP_X25519, 1));
    CHECK(selects(pq | x | p, p, CH_GROUP_X25519MLKEM768, 1));
    CHECK(selects(pq | p, pq | p, CH_GROUP_X25519MLKEM768, 0));
}

// Reads the hello the parser stand-in reports and answers it with a
// ServerHello, for a client that lists and shares secp256r1 alone.
static int p256_hello_exchange(selection *sel) {
    flight_reset();
    srv_begin(&hs);
    offer_p256(SRV_GROUP_SECP256R1, 1);
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(srv_select(&hs, &flight_hello, sel) == CH_OK && sel->need_retry == 0);
    return srv_send_server_hello(&hs, &flight_hello, sel);
}

// The secp256r1 exchange end to end. The ServerHello carries group 0x0017
// and the server's 65-byte point, which is on the curve; the client's
// scalar times that point gives the X coordinate the server computed
// from its own scalar and the client's point (RFC 9846 §7.4.2,
// rfc9846.txt:4266-4276), and the key schedule over it gives the
// handshake secrets the server derived. The P-256 scalar and the x25519
// pair srv_begin drew are gone once the exchange has run.
static void test_flight_p256_secret(void) {
    selection sel;
    make_p256_client();
    CHECK(p256_hello_exchange(&sel) == CH_OK);
    CHECK(sel.group == CH_GROUP_SECP256R1);
    CHECK(wire[KEX_SH_GROUP_AT] == 0x00 && wire[KEX_SH_GROUP_AT + 1] == 0x17);
    CHECK(((size_t)wire[KEX_SH_GROUP_AT + 2] << 8 | wire[KEX_SH_GROUP_AT + 3]) == P256_POINT_LEN);
    CHECK(p256_ecdh_point_valid(wire + KEX_SH_SHARE_AT));
    CHECK(!all_zero(hs.p256_priv, sizeof hs.p256_priv));

    uint8_t ikm[P256_SECRET_LEN];
    CHECK(p256_ecdh(p256_client_priv, wire + KEX_SH_SHARE_AT, ikm) == 1);
    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, &sel) == CH_OK);
    CHECK(all_zero(hs.p256_priv, sizeof hs.p256_priv));
    CHECK(all_zero(hs.priv, sizeof hs.priv) && all_zero(hs.pub, sizeof hs.pub));

    static const uint8_t no_psk[SHA256_LEN] = {0};
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    uint8_t hash[SHA256_LEN];
    uint8_t secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    ks_early(SHA256_LEN, no_psk, sizeof no_psk, 0, early, binder_key);
    (void)hsr_transcript_hash(&hs, SHA256_LEN, hash);
    ks_handshake(SHA256_LEN, early, ikm, sizeof ikm, hash, secret, c_hs, s_hs);
    CHECK(memcmp(c_hs, hs.c_hs, sizeof c_hs) == 0 && memcmp(s_hs, hs.s_hs, sizeof s_hs) == 0);
}

// The client points RFC 9846 §4.3.8.2 has the server refuse
// (rfc9846.txt:2277-2286): Y with its last bit flipped, which leaves the
// curve, the pair (0, 0), and the form byte 0x05. Each is
// illegal_parameter before the ServerHello goes out and before the server
// draws its P-256 scalar. The lengths either side of 65 are the parser's
// refusal, which test/srv_parser_tests.h holds. The valid point, the last
// case that passes, is test_flight_p256_secret's.
static void test_flight_p256_refusals(void) {
    for (int shape = 0; shape < 3; shape++) {
        selection sel;
        make_p256_client();
        if (shape == 0) {
            p256_client_point[P256_POINT_LEN - 1] ^= 1;
        } else if (shape == 1) {
            memset(p256_client_point + 1, 0, P256_POINT_LEN - 1);
        } else {
            p256_client_point[0] = 0x05;
        }
        CHECK(p256_hello_exchange(&sel) == CH_EPROTO);
        CHECK(hs.alert == ALERT_ILLEGAL_PARAMETER && wire_len == 0);
        CHECK(all_zero(hs.p256_priv, sizeof hs.p256_priv));
    }
}

// The retry that asks for secp256r1: a client that lists it alone and
// shares nothing gets a HelloRetryRequest naming 0x0017, and its second
// hello's secp256r1 share is taken and runs the exchange.
static void test_flight_p256_retry(void) {
    selection sel;
    make_p256_client();
    flight_reset();
    srv_begin(&hs);
    offer_p256(SRV_GROUP_SECP256R1, 0);
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK && sel.need_retry == 1);
    CHECK(srv_send_hello_retry_request(&hs, &flight_hello, &sel) == CH_OK);
    CHECK(wire[KEX_SH_GROUP_AT - 2] == 0x00 && wire[KEX_SH_GROUP_AT - 1] == 0x02);
    CHECK(wire[KEX_SH_GROUP_AT] == 0x00 && wire[KEX_SH_GROUP_AT + 1] == 0x17);

    memcpy(cookie_echo, hs.cookie, hs.cookie_len);
    flight_hello.cookie = cookie_echo;
    flight_hello.cookie_len = hs.cookie_len;
    flight_hello.shares = SRV_GROUP_SECP256R1;
    flight_hello.p256_share = p256_client_point;
    selection second;
    memset(&second, 0, sizeof second);
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_OK);
    CHECK(second.group == CH_GROUP_SECP256R1 && second.need_retry == 0);
    wire_len = 0;
    CHECK(srv_send_server_hello(&hs, &flight_hello, &second) == CH_OK);
    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, &second) == CH_OK);
    CHECK(all_zero(hs.p256_priv, sizeof hs.p256_priv));
}

#endif
