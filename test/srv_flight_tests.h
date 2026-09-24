// srv_flight.c: the fifteen handlers, driven one at a time over a fake
// transport. It uses CHECK from test/srv_test.c and is included after it.
//
// Two things stand in for sources this binary does not link. srv_parser.c
// is a lane of its own, so parse_result below is what
// srv_read_client_hello parses, which lets these cases drive it over every
// answer srv_parser.h's contract admits without waiting on the parser. And
// the send and recv callbacks are two arrays, so a case reads the bytes
// the server wrote and hands it the bytes it will read.
//
// Four cases carry the exact boundary pair CLAUDE.md asks of a length
// rule: the receive buffer against a ClientHello, cfg.srv.sni_cap against
// a server_name, the selected hash length against a Finished, and the
// peer's record_size_limit against one message's fragments.
#ifndef CH_SRV_FLIGHT_TESTS_H
#define CH_SRV_FLIGHT_TESTS_H

#include "keysched.h"
#include "record.h"
#include "srv_flight.h"
#include "x25519.h"

// The caller's receive buffer these cases give the server, and the two
// arrays the transport callbacks move bytes through.
#define FLIGHT_RXBUF 1024
#define FLIGHT_WIRE 4096

// The record body a fed ClientHello carries where its length is not what
// a case is about. The stand-in parser reads none of those bytes.
#define FLIGHT_HELLO_BODY 40

static uint8_t rxbuf[FLIGHT_RXBUF];
static uint8_t wire[FLIGHT_WIRE]; // what the server wrote
static size_t wire_len;
static uint8_t feed[FLIGHT_WIRE]; // what the server will read
static size_t feed_len;
static size_t feed_off;
static int send_rc; // nonzero makes the next send fail

static ch_tls sess;
static handshake_state hs;

// The message a handler is handed, what the stand-in parser reports, and
// the result it reports it with. The two client_hello objects are not
// one: srv_read_client_hello zeroes its output before the parse, so a
// case that scripted the parser through that same object would erase its
// own script.
static client_hello flight_hello;
static client_hello parse_result;
static int parse_rc;
static uint8_t parse_alert;

int srv_parse_client_hello(const uint8_t *body, size_t n, client_hello *ch,
                           const ch_alpn_protocol *offered, size_t offered_count, uint8_t *alert) {
    (void)body;
    (void)n;
    (void)offered;
    (void)offered_count;
    if (parse_rc != CH_OK) {
        *alert = parse_alert;
        return parse_rc;
    }
    *ch = parse_result;
    return CH_OK;
}

static int flight_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    if (send_rc != 0) {
        return send_rc;
    }
    if (wire_len + n > sizeof wire) {
        return -1;
    }
    memcpy(wire + wire_len, p, n);
    wire_len += n;
    return 0;
}

static int flight_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    size_t left = feed_len - feed_off;
    if (left == 0) {
        return -1; // the peer closed
    }
    size_t take = n < left ? n : left;
    memcpy(p, feed + feed_off, take);
    feed_off += take;
    return (int)take;
}

static const uint8_t cookie_key[SRV_COOKIE_KEY_LEN] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
static const uint8_t der[4] = {0x30, 0x02, 0x05, 0x00};
static const ch_cert flight_chain[1] = {
    {der, sizeof der}
};
static uint8_t sni_buf[8];

// The two protocols a case has the caller offer, in the caller's
// preference order, so a selection reads as an index into this array.
// flight_reset offers none; a case that is about ALPN sets both fields.
static const uint8_t alpn_h2[2] = {'h', '2'};
static const uint8_t alpn_http11[8] = {'h', 't', 't', 'p', '/', '1', '.', '1'};
static const ch_alpn_protocol flight_alpn[2] = {
    {alpn_h2,     sizeof alpn_h2    },
    {alpn_http11, sizeof alpn_http11}
};

// The cookie a second hello echoes and the low-order share one case
// offers. Both sit here rather than on a case's frame, because
// flight_hello points at them and outlives the case.
static uint8_t cookie_echo[HSP_COOKIE_MAX];
static uint8_t low_order_share[X25519_LEN];

// The session and the handshake state as srv_handshake.c sets them up
// before it calls the first handler, with both identity slots live.
static void flight_reset(void) {
    memset(&sess, 0, sizeof sess);
    memset(&hs, 0, sizeof hs);
    memset(&flight_hello, 0, sizeof flight_hello);
    memset(&parse_result, 0, sizeof parse_result);
    hs.t = &sess;
    hs.alert = ALERT_DECODE_ERROR;
    hs.record_size_limit = 0x4001;
    sess.cfg.buf = rxbuf;
    sess.cfg.buf_len = sizeof rxbuf;
    sess.cfg.send = flight_send;
    sess.cfg.recv = flight_recv;
    sess.cfg.srv.cookie_key = cookie_key;
    sess.cfg.srv.ecdsa_p256.chain = flight_chain;
    sess.cfg.srv.ecdsa_p256.chain_count = 1;
    sess.cfg.srv.ecdsa_p256.priv = der;
    sess.cfg.srv.ecdsa_p256.pub = der;
    sess.cfg.srv.rsa_pss = sess.cfg.srv.ecdsa_p256;
    sess.peer_limit = CH_TX_PT;
    sess.alpn_selected = CH_ALPN_NONE;
    sess.hash_len = SHA256_LEN;
    wire_len = 0;
    feed_len = 0;
    feed_off = 0;
    send_rc = 0;
    parse_rc = CH_OK;
    parse_alert = ALERT_DECODE_ERROR;
}

// A client_hello that offers everything this build holds, written to both
// objects so a case may drive a handler that reads a message or one that
// takes the message a read already produced.
static void offer_everything(void) {
    memset(&flight_hello, 0, sizeof flight_hello);
    flight_hello.suites = SRV_SUITE_CHACHA20_POLY1305;
    flight_hello.groups = SRV_GROUP_KEX;
    flight_hello.shares = SRV_GROUP_KEX;
    flight_hello.sigalgs = SRV_SIGALG_ECDSA_P256 | SRV_SIGALG_RSA_PSS;
    flight_hello.alpn_selected = CH_ALPN_NONE;
    parse_result = flight_hello;
}

// Puts one plaintext handshake record of the given record-body length
// into the bytes the server will read. The body opens with a handshake
// header naming type, so the record carries exactly one message.
static void feed_handshake(uint8_t type, size_t body_len) {
    size_t msg_len = body_len - 4;
    feed[0] = REC_HANDSHAKE;
    feed[1] = 0x03;
    feed[2] = 0x03;
    feed[3] = (uint8_t)(body_len >> 8);
    feed[4] = (uint8_t)body_len;
    feed[5] = type;
    feed[6] = (uint8_t)(msg_len >> 16);
    feed[7] = (uint8_t)(msg_len >> 8);
    feed[8] = (uint8_t)msg_len;
    memset(feed + 9, 0, body_len - 4);
    feed_len = REC_HDR + body_len;
    feed_off = 0;
}

// How many records the server wrote, counted by walking their headers.
static size_t records_written(void) {
    size_t count = 0;
    size_t off = 0;
    while (off + REC_HDR <= wire_len) {
        off += REC_HDR + (((size_t)wire[off + 3] << 8) | wire[off + 4]);
        count++;
    }
    return count;
}

static void test_flight_begin(void) {
    // SHA-256 of the empty string, which is the transcript srv_begin
    // leaves behind, and the value a caller that never hashed a message
    // reads back.
    static const uint8_t empty[SHA256_LEN] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                                              0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                                              0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                                              0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    uint8_t zero[X25519_LEN] = {0};
    uint8_t hash[SHA256_LEN];

    flight_reset();
    srv_begin(&hs);
    CHECK(memcmp(hs.priv, zero, sizeof zero) != 0);
    CHECK(memcmp(hs.pub, zero, sizeof zero) != 0);
    (void)hsr_transcript_hash(&hs, hash);
    CHECK(memcmp(hash, empty, sizeof empty) == 0);
}

static void test_flight_select(void) {
    selection sel;

    // No overlap in suites, then in groups, then in schemes: each is the
    // handshake_failure RFC 9846 section 4.2.1 names.
    flight_reset();
    offer_everything();
    flight_hello.suites = 0;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_EPROTO && hs.alert == ALERT_HANDSHAKE_FAILURE);
    offer_everything();
    flight_hello.groups = 0;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_EPROTO && hs.alert == ALERT_HANDSHAKE_FAILURE);
    offer_everything();
    flight_hello.sigalgs = 0;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_EPROTO && hs.alert == ALERT_HANDSHAKE_FAILURE);

    // A client that offers a scheme this deployment provisioned no
    // identity for gets the same answer.
    offer_everything();
    flight_hello.sigalgs = SRV_SIGALG_ECDSA_P256;
    memset(&sess.cfg.srv.ecdsa_p256, 0, sizeof sess.cfg.srv.ecdsa_p256);
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_EPROTO && hs.alert == ALERT_HANDSHAKE_FAILURE);
    // With both offered and only RSA-PSS provisioned, RSA-PSS signs.
    flight_hello.sigalgs = SRV_SIGALG_ECDSA_P256 | SRV_SIGALG_RSA_PSS;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);
    CHECK(sel.sigalg == SIGALG_RSA_PSS_RSAE_SHA256);

    // The whole offer, answered under this build's preference order.
    flight_reset();
    offer_everything();
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);
    CHECK(sel.suite == SUITE_CHACHA20_POLY1305_SHA256 && sel.hash_len == SHA256_LEN);
    CHECK(sel.group == CH_KEX_GROUP && sel.sigalg == SIGALG_ECDSA_P256_SHA256);
    CHECK(sel.need_retry == 0 && sel.psk_selected == 0);

    // supported_groups names the group and key_share carries nothing for
    // it, which is the one condition that owes a HelloRetryRequest.
    flight_hello.shares = 0;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK && sel.need_retry == 1);
}

// RFC 7301 section 3.2's verdict, which srv_select reaches and the
// parser does not. Each case moves one of srv_flight.h's three terms,
// and the parser's two outputs stand in for a real ALPN extension:
// SRV_EXT_ALPN in seen says the client sent one, and alpn_selected says
// whether a name was on both lists.
static void test_flight_alpn(void) {
    selection sel;

    // The caller offers two protocols and the client sent no extension.
    // Nothing was asked for, so nothing failed.
    flight_reset();
    offer_everything();
    sess.cfg.alpn_protocols = flight_alpn;
    sess.cfg.alpn_count = 2;
    CHECK((flight_hello.seen & SRV_EXT_ALPN) == 0);
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);

    // The lists intersect: the client sent a list and the parser found
    // the caller's second name in it.
    offer_everything();
    flight_hello.seen = SRV_EXT_ALPN;
    flight_hello.alpn_selected = 1;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);

    // The lists are disjoint: the client sent a list and no offered name
    // was in it. This is the case section 3.2 makes fatal.
    offer_everything();
    flight_hello.seen = SRV_EXT_ALPN;
    CHECK(flight_hello.alpn_selected == CH_ALPN_NONE);
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_EPROTO);
    CHECK(hs.alert == ALERT_NO_APPLICATION_PROTOCOL);

    // That same hello against a caller that offers no protocol. This
    // server negotiates no ALPN at all, which section 3.2 permits, so
    // the disjoint lists are not a failed negotiation.
    sess.cfg.alpn_protocols = NULL;
    sess.cfg.alpn_count = 0;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);
}

static void test_flight_read_hello(void) {
    // Any other handshake type at this call position is out of turn.
    flight_reset();
    srv_begin(&hs);
    feed_handshake(HS_FINISHED, 36);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_EPROTO);
    CHECK(hs.alert == ALERT_UNEXPECTED_MESSAGE);

    // The parser's own refusal, with the alert it chose.
    flight_reset();
    srv_begin(&hs);
    parse_rc = CH_EPROTO;
    parse_alert = ALERT_ILLEGAL_PARAMETER;
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_EPROTO);
    CHECK(hs.alert == ALERT_ILLEGAL_PARAMETER);

    // The receive buffer's exact boundary: the largest record that fits
    // cfg.buf_len is read, and one byte more is CH_ECAP. The RFC names no
    // alert for a local limit, so the answer is internal_error.
    flight_reset();
    srv_begin(&hs);
    offer_everything();
    feed_handshake(HS_CLIENT_HELLO, sizeof rxbuf - REC_HDR);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    flight_reset();
    srv_begin(&hs);
    offer_everything();
    feed_handshake(HS_CLIENT_HELLO, sizeof rxbuf - REC_HDR + 1);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_ECAP);
    CHECK(hs.alert == ALERT_INTERNAL_ERROR);
}

static void test_flight_server_name(void) {
    static const uint8_t name[sizeof sni_buf + 1] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'};

    // sni_cap's exact boundary: a name of exactly that many bytes is
    // copied whole, and one byte more is dropped, which is the answer a
    // hello that carried no name gets.
    flight_reset();
    srv_begin(&hs);
    offer_everything();
    sess.cfg.srv.sni_buf = sni_buf;
    sess.cfg.srv.sni_cap = sizeof sni_buf;
    parse_result.server_name = name;
    parse_result.server_name_len = sizeof sni_buf;
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(sess.sni_len == sizeof sni_buf && memcmp(sni_buf, name, sizeof sni_buf) == 0);

    parse_result.server_name_len = sizeof sni_buf + 1;
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(sess.sni_len == 0);

    // A caller that requires the name refuses the hello that carried none.
    sess.cfg.srv.require_server_name = 1;
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_EPROTO);
    CHECK(hs.alert == ALERT_MISSING_EXTENSION);
}

// Runs the first hello and the retry, and leaves the minted cookie in
// hs.cookie so the cases below can echo it back.
static void retry_round(selection *sel) {
    flight_reset();
    srv_begin(&hs);
    offer_everything();
    parse_result.shares = 0;
    parse_result.session_id_len = 32;
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(srv_select(&hs, &flight_hello, sel) == CH_OK && sel->need_retry == 1);
    CHECK(srv_send_hello_retry_request(&hs, &flight_hello, sel) == CH_OK);
}

// The transcript a retry leaves behind is RFC 9846 section 4.1's
// synthetic construction over the first ClientHello, then the
// HelloRetryRequest itself. A retry that left the first hello in the
// transcript instead would make every Finished below disagree with the
// client's, and nothing else here would notice.
static void check_hrr_transcript(const uint8_t *ch1, size_t ch1_len, const uint8_t *hrr,
                                 size_t hrr_len) {
    static const uint8_t synth[4] = {HS_MESSAGE_HASH, 0, 0, SHA256_LEN};
    uint8_t first[SHA256_LEN];
    uint8_t want[SHA256_LEN];
    uint8_t got[SHA256_LEN];
    sha256 s;

    sha256_init(&s);
    sha256_update(&s, ch1, ch1_len);
    sha256_final(&s, first);
    sha256_init(&s);
    sha256_update(&s, synth, sizeof synth);
    sha256_update(&s, first, sizeof first);
    sha256_update(&s, hrr, hrr_len);
    sha256_final(&s, want);
    (void)hsr_transcript_hash(&hs, got);
    CHECK(memcmp(got, want, sizeof want) == 0);
}

static void test_flight_retry(void) {
    selection sel;

    retry_round(&sel);
    // One plaintext record carrying one HelloRetryRequest, which is a
    // ServerHello by type, and the cookie the session now holds.
    CHECK(records_written() == 1 && wire[0] == REC_HANDSHAKE);
    CHECK(wire[REC_HDR] == HS_SERVER_HELLO);
    CHECK(hs.cookie_len > 0 && sess.hrr_sent == 1);
    memcpy(cookie_echo, hs.cookie, hs.cookie_len);
    check_hrr_transcript(feed + REC_HDR, FLIGHT_HELLO_BODY, wire + REC_HDR,
                         ((size_t)wire[3] << 8) | wire[4]);

    // The dummy change_cipher_spec follows it, because the client sent a
    // non-empty legacy_session_id.
    wire_len = 0;
    CHECK(srv_send_compat_ccs(&hs, &flight_hello) == CH_OK);
    CHECK(wire_len == SRV_CCS_RECORD_LEN && wire[0] == REC_CCS && wire[5] == 1);
    CHECK(sess.compat_ccs == 1);

    // The second hello, echoing the cookie and carrying the share the
    // retry asked for.
    flight_hello.cookie = cookie_echo;
    flight_hello.cookie_len = hs.cookie_len;
    flight_hello.shares = SRV_GROUP_KEX;
    selection second = sel;
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_OK);
    CHECK(second.need_retry == 0 && second.suite == sel.suite && second.group == sel.group);
    CHECK(second.sigalg == sel.sigalg && second.hash_len == sel.hash_len);

    // A second hello that changed a frozen field, one that dropped the
    // cookie, one that echoed a cookie with a flipped bit, and one that
    // added early_data: every one is illegal_parameter.
    flight_hello.frozen[0] ^= 0x01;
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_EPROTO);
    CHECK(hs.alert == ALERT_ILLEGAL_PARAMETER);
    flight_hello.frozen[0] ^= 0x01;
    flight_hello.cookie = NULL;
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_EPROTO);
    flight_hello.cookie = cookie_echo;
    cookie_echo[0] ^= 0x01;
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_EPROTO);
    cookie_echo[0] ^= 0x01;
    flight_hello.seen = SRV_EXT_EARLY_DATA;
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_EPROTO);
    flight_hello.seen = 0;

    // A second hello that still carries no share has nothing left to
    // retry, which is handshake_failure and not illegal_parameter.
    flight_hello.shares = 0;
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_EPROTO);
    CHECK(hs.alert == ALERT_HANDSHAKE_FAILURE);
}

// Brings the session to the point where the handshake keys are live,
// with the client's share drawn from client_priv and its offer holding
// the suites named in suites.
static uint8_t client_priv[X25519_LEN];
static uint8_t client_share[X25519_LEN];

static void hello_exchange_offering(selection *sel, uint8_t suites) {
    flight_reset();
    srv_begin(&hs);
    offer_everything();
    parse_result.suites = suites;
    memset(client_priv, 0x5a, sizeof client_priv);
    x25519_base(client_share, client_priv);
    parse_result.share = client_share;
    parse_result.share_len = sizeof client_share;
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(srv_select(&hs, &flight_hello, sel) == CH_OK && sel->need_retry == 0);
    CHECK(srv_send_server_hello(&hs, &flight_hello, sel) == CH_OK);
    sess.suite = sel->suite;
    sess.hash_len = sel->hash_len;
    sess.sigalg = sel->sigalg;
}

static void hello_exchange(selection *sel) {
    hello_exchange_offering(sel, SRV_SUITE_CHACHA20_POLY1305);
}

static void test_flight_server_hello(void) {
    selection sel;
    hello_exchange(&sel);

    // One plaintext record carrying one ServerHello whose length field
    // matches the record body.
    CHECK(records_written() == 1 && wire[0] == REC_HANDSHAKE);
    CHECK(wire[1] == 0x03 && wire[2] == 0x03);
    size_t body = ((size_t)wire[3] << 8) | wire[4];
    CHECK(wire[REC_HDR] == HS_SERVER_HELLO);
    size_t msg =
        ((size_t)wire[REC_HDR + 1] << 16) | ((size_t)wire[REC_HDR + 2] << 8) | wire[REC_HDR + 3];
    CHECK(msg + 4 == body);

    // An empty legacy_session_id owes no change_cipher_spec record.
    wire_len = 0;
    CHECK(srv_send_compat_ccs(&hs, &flight_hello) == CH_OK);
    CHECK(wire_len == 0 && sess.compat_ccs == 0);

    // A transport that refuses the write reports CH_EIO.
    send_rc = -1;
    CHECK(srv_send_server_hello(&hs, &flight_hello, &sel) == CH_EIO);
}

#endif
