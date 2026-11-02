// The server's ML-KEM-1024 key exchange through srv_flight.c
// (docs/decisions.md 179): the group it selects first, ahead of the
// hybrid, the exchange from the ServerHello to the handshake secrets, the
// encapsulation keys it refuses, and the HelloRetryRequest that asks for
// an ML-KEM-1024 share. It continues test/srv_flight_kex_tests.h, whose
// fixtures and preference helper it reads.
//
// The exchange cases run a client half beside the server: an ML-KEM-1024
// key pair from fixed seeds, whose encapsulation key is the client's
// share and whose decapsulation key opens the ciphertext the server
// writes. The handshake secrets both halves derive must be one secret.
#ifndef CH_SRV_FLIGHT_MLKEM1024_TESTS_H
#define CH_SRV_FLIGHT_MLKEM1024_TESTS_H

#include "mlkem.h"
#include "srv_flight_kex_tests.h"
#include "test_widemul.h"

// The client half of an ML-KEM-1024 exchange.
static uint8_t mlkem1024_client_dk[MLKEM_DK_LEN_1024];
static uint8_t mlkem1024_client_ek[MLKEM_EK_LEN_1024];

static void make_mlkem1024_client(void) {
    static const uint8_t d[32] = {0x41, 0x42, 0x43, 0x44};
    static const uint8_t z[32] = {0x51, 0x52, 0x53, 0x54};
    mlkem_keygen_derand_rank(MLKEM_RANK_1024, mlkem1024_client_ek, mlkem1024_client_dk, d, z);
}

// A client_hello that lists the hybrid, x25519 and ML-KEM-1024, with the
// shares named in shares.
static void offer_mlkem1024(uint8_t shares) {
    offer_both_groups(shares & (SRV_GROUP_X25519 | SRV_GROUP_X25519MLKEM768));
    flight_hello.groups |= SRV_GROUP_MLKEM1024;
    flight_hello.shares = shares;
    flight_hello.mlkem_share = (shares & SRV_GROUP_MLKEM1024) != 0 ? mlkem1024_client_ek : NULL;
    parse_result = flight_hello;
}

// ML-KEM-1024 ahead of the three groups docs/decisions.md 54 and 63
// order, and the retry that asks for it.
static void test_flight_select_mlkem1024(void) {
    const uint8_t x = SRV_GROUP_X25519;
    const uint8_t pq = SRV_GROUP_X25519MLKEM768;
    const uint8_t p = SRV_GROUP_SECP256R1;
    const uint8_t m = SRV_GROUP_MLKEM1024;
    // An ML-KEM-1024 share is taken, alone or beside every other share.
    CHECK(selects(m, m, CH_GROUP_MLKEM1024, 0));
    CHECK(selects(m | pq | x | p, m | pq | x, CH_GROUP_MLKEM1024, 0));
    // ML-KEM-1024 listed and the hybrid shared: a retry that asks for
    // ML-KEM-1024, rather than the hybrid share the hello carried.
    CHECK(selects(m | pq | x, pq | x, CH_GROUP_MLKEM1024, 1));
    CHECK(selects(m, 0, CH_GROUP_MLKEM1024, 1));
    // A hello that does not list it selects as before.
    CHECK(selects(pq | x, pq, CH_GROUP_X25519MLKEM768, 0));
}

// Reads the hello the parser stand-in reports and answers it with a
// ServerHello, for a client that shares the groups in shares.
static int mlkem1024_hello_exchange(selection *sel, uint8_t shares) {
    flight_reset();
    srv_begin(&hs);
    offer_mlkem1024(shares);
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(srv_select(&hs, &flight_hello, sel) == CH_OK && sel->need_retry == 0);
    return srv_send_server_hello(&hs, &flight_hello, sel);
}

// The ML-KEM-1024 exchange end to end. The ServerHello carries 0x0202 and
// a 1568-byte ciphertext, the client decapsulates it at rank 4, and its
// 32-byte shared secret, through the key schedule, gives the handshake
// secrets the server derived.
static void test_flight_mlkem1024_secret(void) {
    selection sel;
    make_mlkem1024_client();
    CHECK(mlkem1024_hello_exchange(&sel, SRV_GROUP_MLKEM1024 | SRV_GROUP_X25519MLKEM768) == CH_OK);
    CHECK(sel.group == CH_GROUP_MLKEM1024);
    CHECK(wire[KEX_SH_GROUP_AT] == 0x02 && wire[KEX_SH_GROUP_AT + 1] == 0x02);
    CHECK(((size_t)wire[KEX_SH_GROUP_AT + 2] << 8 | wire[KEX_SH_GROUP_AT + 3]) ==
          MLKEM_CT_LEN_1024);
    CHECK(!all_zero(hs.mlkem_ss, sizeof hs.mlkem_ss));

    uint8_t ikm[MLKEM_SS_LEN];
    mlkem_decaps_rank(TEST_WIDEMUL, MLKEM_RANK_1024, ikm, wire + KEX_SH_SHARE_AT,
                      mlkem1024_client_dk);

    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, &sel) == CH_OK);
    // The key exchange is over, so everything it consumed is gone, the
    // x25519 pair srv_begin drew included.
    CHECK(all_zero(hs.mlkem_ss, sizeof hs.mlkem_ss));
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

// The encapsulation key FIPS 203 §7.2's modulus check refuses, at its
// exact boundary: 3328 in the first coefficient is taken, and 3329 is
// illegal_parameter before any ServerHello, with no ML-KEM secret left.
static void test_flight_mlkem1024_refusals(void) {
    selection sel;
    make_mlkem1024_client();
    mlkem1024_client_ek[0] = 0x00;
    mlkem1024_client_ek[1] = (uint8_t)((mlkem1024_client_ek[1] & 0xf0) | 0x0d);
    CHECK(mlkem1024_hello_exchange(&sel, SRV_GROUP_MLKEM1024) == CH_OK);
    make_mlkem1024_client();
    mlkem1024_client_ek[0] = 0x01;
    mlkem1024_client_ek[1] = (uint8_t)((mlkem1024_client_ek[1] & 0xf0) | 0x0d);
    CHECK(mlkem1024_hello_exchange(&sel, SRV_GROUP_MLKEM1024) == CH_EPROTO);
    CHECK(hs.alert == ALERT_ILLEGAL_PARAMETER && wire_len == 0);
    CHECK(all_zero(hs.mlkem_ss, sizeof hs.mlkem_ss));
}

// The retry that asks for ML-KEM-1024. A client that lists it and shares
// the hybrid alone gets a HelloRetryRequest naming 0x0202; a second hello
// with the hybrid alone again has nothing left to retry, and one that
// carries the ML-KEM-1024 share is taken.
static void test_flight_mlkem1024_retry(void) {
    selection sel;
    make_client_half();
    make_mlkem1024_client();
    flight_reset();
    srv_begin(&hs);
    offer_mlkem1024(SRV_GROUP_X25519MLKEM768);
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK && sel.need_retry == 1);
    CHECK(sel.group == CH_GROUP_MLKEM1024);
    CHECK(srv_send_hello_retry_request(&hs, &flight_hello, &sel) == CH_OK);
    // The HelloRetryRequest's key_share is the selected_group alone.
    CHECK(wire[KEX_SH_GROUP_AT - 2] == 0x00 && wire[KEX_SH_GROUP_AT - 1] == 0x02);
    CHECK(wire[KEX_SH_GROUP_AT] == 0x02 && wire[KEX_SH_GROUP_AT + 1] == 0x02);

    memcpy(cookie_echo, hs.cookie, hs.cookie_len);
    flight_hello.cookie = cookie_echo;
    flight_hello.cookie_len = hs.cookie_len;
    selection second;
    memset(&second, 0, sizeof second);
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_EPROTO);
    CHECK(hs.alert == ALERT_HANDSHAKE_FAILURE);
    flight_hello.shares = SRV_GROUP_MLKEM1024;
    flight_hello.mlkem_share = mlkem1024_client_ek;
    flight_hello.hybrid_share = NULL;
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_OK);
    CHECK(second.group == CH_GROUP_MLKEM1024 && second.need_retry == 0);
    wire_len = 0;
    CHECK(srv_send_server_hello(&hs, &flight_hello, &second) == CH_OK);
    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, &second) == CH_OK);
}

#endif
