// srv_flight.c under live handshake keys: the key exchange, the
// authentication flight and both Finished messages. It continues
// test/srv_flight_tests.h, whose transport, parser stand-in and fixtures
// it reads, and is included after it.
//
// The file is split from that one because CLAUDE.md caps a hand-written
// file at 500 lines and the two halves together are longer. It includes
// that half itself rather than relying on the order a caller lists the
// two, because clang-format sorts an include block by name and this
// file's name sorts first.
//
// Two cases read a value back against a second construction rather than
// against a printed vector, because the rule under test is an argument
// order and no RFC prints one: the two directions bind to the opposite
// secrets from the client's, and ks_master writes the client secret
// before the server one (keysched.h).
#ifndef CH_SRV_FLIGHT_KEYS_TESTS_H
#define CH_SRV_FLIGHT_KEYS_TESTS_H

#include "srv_flight_tests.h"

static void test_flight_keys(void) {
    selection sel;
    uint8_t sealed[64];
    uint8_t plain[64];
    uint8_t zero[X25519_LEN] = {0};
    static const uint8_t note[3] = {1, 2, 3};

    hello_exchange(&sel);
    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, &sel) == CH_OK);
    // The exchange is over, so the two values it consumed are gone.
    CHECK(memcmp(hs.priv, zero, sizeof zero) == 0 && memcmp(hs.pub, zero, sizeof zero) == 0);
    CHECK(sess.keys == 1);

    // The two directions bind to the opposite secrets from the client's.
    // A record this server seals opens under a reader built from the
    // server handshake secret, which is what a swapped assignment breaks.
    rec_dir peer_rd;
    rec_dir_init(&peer_rd, hs.s_hs);
    size_t sealed_len = 0;
    size_t plain_len = 0;
    uint8_t inner = 0;
    CHECK(rec_seal(&sess.wr, REC_HANDSHAKE, note, sizeof note, sealed, sizeof sealed,
                   &sealed_len) == 0);
    CHECK(rec_open(&peer_rd, sealed, sealed_len, plain, sizeof plain, &plain_len, &inner) == 0);
    CHECK(plain_len == sizeof note && memcmp(plain, note, sizeof note) == 0);
    CHECK(inner == REC_HANDSHAKE);

    // A share that yields the all-zero shared secret is the abort RFC
    // 9846 section 7.4.2 requires.
    hello_exchange(&sel);
    flight_hello.x25519_share = low_order_share;
    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, &sel) == CH_EPROTO);
    CHECK(hs.alert == ALERT_ILLEGAL_PARAMETER && sess.keys == 0);
}

// The flight from the EncryptedExtensions to the server Finished, over
// live handshake keys. The client's copy of them is returned through rd,
// so a case can open what the server sealed.
static void auth_flight(selection *sel, rec_dir *rd) {
    hello_exchange(sel);
    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, sel) == CH_OK);
    rec_dir_init(rd, hs.s_hs);
    wire_len = 0;
}

static void test_flight_auth(void) {
    selection sel;
    rec_dir rd;

    auth_flight(&sel, &rd);
    CHECK(srv_send_encrypted_extensions(&hs, &sel) == CH_OK);
    CHECK(records_written() == 1 && wire[0] == REC_APPDATA);

    // The Certificate goes out whatever the chain's size, and the caller
    // reads its own bytes back out of the record stream.
    wire_len = 0;
    CHECK(srv_send_certificate(&hs, &sel) == CH_OK);
    CHECK(records_written() == 1);

    // An identity the caller never provisioned is a local fault.
    memset(&sess.cfg.srv.ecdsa_p256, 0, sizeof sess.cfg.srv.ecdsa_p256);
    CHECK(srv_send_certificate(&hs, &sel) == CH_EINVAL);
    CHECK(hs.alert == ALERT_INTERNAL_ERROR);

    // This configuration sets both key pointers and neither key length,
    // so srv_auth.c refuses the slot before it reaches a signer, and
    // the CertificateVerify carries that refusal out unchanged.
    // bin/srv_auth_test signs with real key pairs.
    auth_flight(&sel, &rd);
    CHECK(srv_send_certificate_verify(&hs, &sel) == CH_EINVAL);
    CHECK(hs.alert == ALERT_INTERNAL_ERROR);
}

// Builds the client Finished the server expects, sealed under the client
// handshake write key, into the bytes the server will read.
static void feed_client_finished(int correct) {
    uint8_t hash[SHA256_LEN];
    uint8_t msg[4 + SHA256_LEN];
    rec_dir wr;
    size_t n = 0;

    (void)hsr_transcript_hash(&hs, SHA256_LEN, hash);
    msg[0] = HS_FINISHED;
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = SHA256_LEN;
    ks_verify_data(SHA256_LEN, hs.c_hs, hash, msg + 4);
    if (!correct) {
        msg[4] ^= 0x01;
    }
    rec_dir_init(&wr, hs.c_hs);
    CHECK(rec_seal(&wr, REC_HANDSHAKE, msg, sizeof msg, feed, sizeof feed, &n) == 0);
    feed_len = n;
    feed_off = 0;
}

static void test_flight_finish(void) {
    selection sel;
    rec_dir rd;

    // The peer's record_size_limit at its exact boundary: a Finished of
    // 4 + SHA256_LEN bytes fits one record at that limit, and one byte
    // less splits it into two.
    auth_flight(&sel, &rd);
    sess.peer_limit = 4 + SHA256_LEN;
    CHECK(srv_send_finished(&hs) == CH_OK);
    CHECK(records_written() == 1);

    auth_flight(&sel, &rd);
    sess.peer_limit = 4 + SHA256_LEN - 1;
    CHECK(srv_send_finished(&hs) == CH_OK);
    CHECK(records_written() == 2);

    // The client's Finished, read under the handshake key the write
    // direction has already left behind.
    auth_flight(&sel, &rd);
    CHECK(srv_send_finished(&hs) == CH_OK);
    // keysched.h writes the client application secret before the server
    // one, and this endpoint reads the first and writes the second. A
    // swapped pair would leave both directions unopenable.
    uint8_t hash[SHA256_LEN];
    uint8_t master[SHA256_LEN];
    uint8_t c_ap[SHA256_LEN];
    uint8_t s_ap[SHA256_LEN];
    (void)hsr_transcript_hash(&hs, SHA256_LEN, hash);
    ks_master(SHA256_LEN, hs.handshake_secret, hash, master, c_ap, s_ap);
    CHECK(memcmp(sess.rd_secret, c_ap, sizeof c_ap) == 0);
    CHECK(memcmp(sess.wr_secret, s_ap, sizeof s_ap) == 0);
    feed_client_finished(1);
    CHECK(srv_read_client_finished(&hs) == CH_OK);
    srv_complete(&hs);
    CHECK(sess.state == CH_ST_CONNECTED && sess.pt_off == 0 && sess.pt_len == 0);

    // A verify_data with one bit moved is the decrypt_error abort RFC
    // 9846 section 4.5.3 requires.
    auth_flight(&sel, &rd);
    CHECK(srv_send_finished(&hs) == CH_OK);
    feed_client_finished(0);
    CHECK(srv_read_client_finished(&hs) == CH_EAUTH);
    CHECK(hs.alert == ALERT_DECRYPT_ERROR && sess.state != CH_ST_CONNECTED);
}

// The selected hash length at its exact boundary: a Finished of exactly
// that many bytes is read, and one byte either side is out of turn. The
// message is sealed by hand, because the length is what is under test.
static void test_flight_finished_length(void) {
    selection sel;
    rec_dir rd;
    uint8_t msg[4 + SHA256_LEN + 1];
    rec_dir wr;
    size_t n = 0;

    // The three verify_data lengths: one byte short, exact, one byte long.
    static const size_t bodies[3] = {SHA256_LEN - 1, SHA256_LEN, SHA256_LEN + 1};

    for (size_t i = 0; i < 3; i++) {
        size_t body = bodies[i];
        auth_flight(&sel, &rd);
        CHECK(srv_send_finished(&hs) == CH_OK);
        uint8_t hash[SHA256_LEN];
        (void)hsr_transcript_hash(&hs, SHA256_LEN, hash);
        memset(msg, 0, sizeof msg);
        msg[0] = HS_FINISHED;
        msg[3] = (uint8_t)body;
        ks_verify_data(SHA256_LEN, hs.c_hs, hash, msg + 4);
        rec_dir_init(&wr, hs.c_hs);
        CHECK(rec_seal(&wr, REC_HANDSHAKE, msg, 4 + body, feed, sizeof feed, &n) == 0);
        feed_len = n;
        feed_off = 0;
        if (body == SHA256_LEN) {
            CHECK(srv_read_client_finished(&hs) == CH_OK);
        } else {
            CHECK(srv_read_client_finished(&hs) == CH_EPROTO);
            CHECK(hs.alert == ALERT_UNEXPECTED_MESSAGE);
        }
    }
}

#endif
