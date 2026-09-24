// The server's key exchange through srv_flight.c: which group srv_select
// takes for each shape of offer, and the X25519MLKEM768 exchange from the
// ServerHello to the handshake secrets. It continues
// test/srv_flight_tests.h, whose transport, parser stand-in and fixtures
// it reads, and includes it for the reason test/srv_flight_keys_tests.h
// gives.
//
// The hybrid cases run a real client half beside the server: an
// ML-KEM-768 key pair from fixed seeds and an x25519 key pair, whose
// public values make the client's share, and whose secret values
// decapsulate and complete the exchange the way handshake_flight.c's
// hybrid_secret does. The handshake secrets both halves derive must be
// one secret, which is what holds the byte order RFC 10024 fixes.
#ifndef CH_SRV_FLIGHT_KEX_TESTS_H
#define CH_SRV_FLIGHT_KEX_TESTS_H

#include "mlkem.h"
#include "srv_flight_tests.h"
#include "srv_kex.h"

// Where the key_share extension's group sits in the record the server
// wrote, for a hello whose legacy_session_id was empty: the record header,
// the handshake header, legacy_version, random, the empty session id's
// length byte, cipher_suite, compression, the extensions length,
// supported_versions, and key_share's type and length words. The share
// follows the group and its own two-byte length.
#define KEX_SH_GROUP_AT (REC_HDR + 4 + 2 + SRV_RANDOM + 1 + 2 + 1 + 2 + 6 + 4)
#define KEX_SH_SHARE_AT (KEX_SH_GROUP_AT + 4)

// The client half of a hybrid exchange: the decapsulation key, the x25519
// secret, and the share the client sends, the encapsulation key then the
// x25519 public value.
static uint8_t kex_client_dk[MLKEM_DK_LEN];
static uint8_t kex_client_priv[X25519_LEN];
static uint8_t kex_client_share[CH_HYBRID_CLIENT_SHARE];

static void make_client_half(void) {
    static const uint8_t d[32] = {0xd0, 0xd1, 0xd2, 0xd3};
    static const uint8_t z[32] = {0x20, 0x21, 0x22, 0x23};
    mlkem_keygen_derand(kex_client_share, kex_client_dk, d, z);
    memset(kex_client_priv, 0x3c, sizeof kex_client_priv);
    x25519_base(kex_client_share + MLKEM_EK_LEN, kex_client_priv);
}

// A client_hello that lists X25519MLKEM768 and x25519, with the shares
// named in shares.
static void offer_both_groups(uint8_t shares) {
    offer_x25519();
    parse_result.groups = SRV_GROUP_X25519 | SRV_GROUP_X25519MLKEM768;
    parse_result.shares = shares;
    parse_result.x25519_share = NULL;
    if ((shares & SRV_GROUP_X25519) != 0) {
        parse_result.x25519_share = kex_client_share + MLKEM_EK_LEN;
    }
    if ((shares & SRV_GROUP_X25519MLKEM768) != 0) {
        parse_result.hybrid_share = kex_client_share;
    }
    flight_hello = parse_result;
}

// Which group srv_select chooses and whether it owes a retry, for one
// offer: groups listed and shares carried.
static int selects(uint8_t groups, uint8_t shares, uint16_t group, uint8_t need_retry) {
    selection sel;
    flight_reset();
    offer_x25519();
    flight_hello.groups = groups;
    flight_hello.shares = shares;
    return srv_select(&hs, &flight_hello, &sel) == CH_OK && sel.group == group &&
           sel.need_retry == need_retry;
}

// The four rows of the preference docs/decisions.md 54 states, and the
// two that list one group with no share.
static void test_flight_select_group(void) {
    const uint8_t x = SRV_GROUP_X25519;
    const uint8_t pq = SRV_GROUP_X25519MLKEM768;
    selection sel;
    // A hybrid share is taken, beside an x25519 share or alone.
    CHECK(selects(x | pq, pq, CH_GROUP_X25519MLKEM768, 0));
    CHECK(selects(x | pq, x | pq, CH_GROUP_X25519MLKEM768, 0));
    // The hybrid listed and x25519 shared: a retry that asks for the
    // hybrid, rather than the x25519 share the hello carried.
    CHECK(selects(x | pq, x, CH_GROUP_X25519MLKEM768, 1));
    // x25519 listed alone is x25519, as before the hybrid.
    CHECK(selects(x, x, CH_GROUP_X25519, 0));
    CHECK(selects(x, 0, CH_GROUP_X25519, 1));
    CHECK(selects(pq, 0, CH_GROUP_X25519MLKEM768, 1));
    // Neither listed: no group in common, handshake_failure.
    flight_reset();
    offer_x25519();
    flight_hello.groups = 0;
    flight_hello.shares = 0;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_EPROTO);
    CHECK(hs.alert == ALERT_HANDSHAKE_FAILURE);
}

// Reads the hello the parser stand-in reports and answers it with a
// ServerHello, for a client that shares the groups in shares.
static int hybrid_hello_exchange(selection *sel, uint8_t shares) {
    flight_reset();
    srv_begin(&hs);
    offer_both_groups(shares);
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(srv_select(&hs, &flight_hello, sel) == CH_OK && sel->need_retry == 0);
    return srv_send_server_hello(&hs, &flight_hello, sel);
}

// Whether all n bytes at p are zero.
static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

// The hybrid exchange end to end. The ServerHello carries the group and a
// 1120-byte share; the client decapsulates the ciphertext in it and runs
// x25519 against the value after it; and the ML-KEM secret then the
// x25519 one, through the key schedule, give the handshake secrets the
// server derived. Swapping the halves, or taking either from the wrong
// bytes, gives another secret.
static void test_flight_hybrid_secret(void) {
    selection sel;
    make_client_half();
    CHECK(hybrid_hello_exchange(&sel, SRV_GROUP_X25519 | SRV_GROUP_X25519MLKEM768) == CH_OK);
    CHECK(sel.group == CH_GROUP_X25519MLKEM768);
    CHECK(wire[KEX_SH_GROUP_AT] == 0x11 && wire[KEX_SH_GROUP_AT + 1] == 0xec);
    CHECK(((size_t)wire[KEX_SH_GROUP_AT + 2] << 8 | wire[KEX_SH_GROUP_AT + 3]) ==
          CH_HYBRID_SERVER_SHARE);
    CHECK(!all_zero(hs.mlkem_ss, sizeof hs.mlkem_ss));

    uint8_t ikm[MLKEM_SS_LEN + X25519_LEN];
    mlkem_decaps(ikm, wire + KEX_SH_SHARE_AT, kex_client_dk);
    CHECK(x25519(ikm + MLKEM_SS_LEN, kex_client_priv, wire + KEX_SH_SHARE_AT + MLKEM_CT_LEN) == 1);

    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, &sel) == CH_OK);
    // The key exchange is over, so everything it consumed is gone.
    CHECK(all_zero(hs.mlkem_ss, sizeof hs.mlkem_ss));
    CHECK(all_zero(hs.priv, sizeof hs.priv) && all_zero(hs.pub, sizeof hs.pub));

    static const uint8_t no_psk[SHA256_LEN] = {0};
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    uint8_t hash[SHA256_LEN];
    uint8_t secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    ks_early(no_psk, sizeof no_psk, 0, early, binder_key);
    (void)hsr_transcript_hash(&hs, hash);
    ks_handshake(early, ikm, sizeof ikm, hash, secret, c_hs, s_hs);
    CHECK(memcmp(c_hs, hs.c_hs, sizeof c_hs) == 0 && memcmp(s_hs, hs.s_hs, sizeof s_hs) == 0);
}

// What the server refuses in a hybrid share: an encapsulation key that
// fails FIPS 203 §7.2's modulus check, and an x25519 half that is a
// low-order point. Both are illegal_parameter, and neither leaves the
// ML-KEM secret behind.
static void test_flight_hybrid_refusals(void) {
    selection sel;
    // The first 12-bit coefficient at 0xfff, above the modulus 3329. The
    // server refuses before it writes a ServerHello.
    make_client_half();
    kex_client_share[0] = 0xff;
    kex_client_share[1] |= 0x0f;
    CHECK(hybrid_hello_exchange(&sel, SRV_GROUP_X25519MLKEM768) == CH_EPROTO);
    CHECK(hs.alert == ALERT_ILLEGAL_PARAMETER && wire_len == 0);
    CHECK(all_zero(hs.mlkem_ss, sizeof hs.mlkem_ss));

    // The largest coefficient the check admits, 3328, is taken: the exact
    // boundary of the modulus check.
    make_client_half();
    kex_client_share[0] = 0x00;
    kex_client_share[1] = (uint8_t)((kex_client_share[1] & 0xf0) | 0x0d);
    CHECK(hybrid_hello_exchange(&sel, SRV_GROUP_X25519MLKEM768) == CH_OK);
    // 3329 itself is refused.
    make_client_half();
    kex_client_share[0] = 0x01;
    kex_client_share[1] = (uint8_t)((kex_client_share[1] & 0xf0) | 0x0d);
    CHECK(hybrid_hello_exchange(&sel, SRV_GROUP_X25519MLKEM768) == CH_EPROTO);

    // A low-order x25519 half: the encapsulation succeeds, and the x25519
    // step yields the all-zero secret RFC 9846 §7.4.2 refuses.
    make_client_half();
    memset(kex_client_share + MLKEM_EK_LEN, 0, X25519_LEN);
    CHECK(hybrid_hello_exchange(&sel, SRV_GROUP_X25519MLKEM768) == CH_OK);
    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, &sel) == CH_EPROTO);
    CHECK(hs.alert == ALERT_ILLEGAL_PARAMETER && sess.keys == 0);
    CHECK(all_zero(hs.mlkem_ss, sizeof hs.mlkem_ss));
}

// The retry that asks for the hybrid. A client that lists it and shares
// x25519 alone gets a HelloRetryRequest naming X25519MLKEM768; the second
// hello's hybrid share is taken, and a second hello with x25519 alone
// again has nothing left to retry.
static void test_flight_hybrid_retry(void) {
    selection sel;
    make_client_half();
    flight_reset();
    srv_begin(&hs);
    offer_both_groups(SRV_GROUP_X25519);
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK && sel.need_retry == 1);
    CHECK(srv_send_hello_retry_request(&hs, &flight_hello, &sel) == CH_OK);
    // The HelloRetryRequest's key_share is the selected_group alone.
    CHECK(wire[KEX_SH_GROUP_AT - 2] == 0x00 && wire[KEX_SH_GROUP_AT - 1] == 0x02);
    CHECK(wire[KEX_SH_GROUP_AT] == 0x11 && wire[KEX_SH_GROUP_AT + 1] == 0xec);

    memcpy(cookie_echo, hs.cookie, hs.cookie_len);
    flight_hello.cookie = cookie_echo;
    flight_hello.cookie_len = hs.cookie_len;
    selection second;
    memset(&second, 0, sizeof second);
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_EPROTO);
    CHECK(hs.alert == ALERT_HANDSHAKE_FAILURE);
    flight_hello.shares = SRV_GROUP_X25519MLKEM768;
    flight_hello.hybrid_share = kex_client_share;
    flight_hello.x25519_share = NULL;
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_OK);
    CHECK(second.group == CH_GROUP_X25519MLKEM768 && second.need_retry == 0);
    wire_len = 0;
    CHECK(srv_send_server_hello(&hs, &flight_hello, &second) == CH_OK);
    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, &second) == CH_OK);
}

#endif
