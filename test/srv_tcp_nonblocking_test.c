// The tcp-nonblocking server driver end to end: this tree's own ClientHello,
// built by handshake_message.c, wrapped in a plaintext record, fed to
// srv_tcp_nonblocking.c, and the records it pushes back. docs/server.md
// names this binary bin/srv_tcp_nonblocking_test.
//
// Why the client's builder rather than a byte vector: the message a
// client sends is the thing the server has to read, and a vector written
// by hand beside the parser it feeds can drift with it. bin/srv_test
// holds the hand-written hello that pins the parser's format; this binary
// asks a different question -- whether the driver runs a whole flight
// over records and hands each one to the caller -- and the two builders
// are on opposite sides of the connection, so neither can hide a mistake
// in the other. It is bin/srv_quic_test's question on the transport that
// keeps its records.
//
// What it does not check: the client Finished, which needs a real
// client's transcript and key schedule. The steps up to it are what this
// covers.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "handshake_message.h"
#include "p256_sign_vectors.h"
#include "rand.h"
#include "record.h"
#include "rsa_sign.h"
#include "rsa_sign_vectors.h"
#include "srv_auth.h"
#include "srv_message.h"
#include "srv_parser.h"
#include "srv_tcp_nonblocking.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// A counter, not entropy: these cases compare structure and codes rather
// than bytes, and a fixed stream replays a failure exactly.
void ch_rand_bytes(uint8_t *p, size_t n) {
    static uint8_t counter = 1;
    for (size_t i = 0; i < n; i++) {
        p[i] = counter++;
    }
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// What on_record_out recorded, so main() can ask how many records left,
// in what order and of which outer type.
#define MAX_RECORDS 32
static struct {
    uint8_t type[MAX_RECORDS];
    size_t len[MAX_RECORDS];
    size_t count;
    size_t total;
    int refuse;      // when set, the sink fails the way a broken socket would
    size_t io_calls; // times the driver reached for the socket itself
} seen;

// Every push carries one whole record, header and all, which is what
// srv_cfg.h promises the caller.
static int sink(void *io, const uint8_t *p, size_t n) {
    (void)io;
    if (seen.refuse) {
        return -1;
    }
    if (seen.count < MAX_RECORDS) {
        seen.type[seen.count] = p[0];
        seen.len[seen.count] = n;
    }
    seen.count++;
    seen.total += n;
    return 0;
}

// INV-28: a tcp-nonblocking server calls neither of these while the
// handshake runs. They are required all the same, because ch_read and
// ch_write call them once the session is connected (srv.c's
// transport_ok), so the test supplies both and counts instead of
// leaving them NULL, which the configuration check would refuse.
//
// They count rather than fail on the spot, so every scenario below can
// state the claim where it checks the rest of its result.
static int never_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    seen.io_calls++;
    return -1;
}

// It poisons the buffer as well as counting: a driver that read the
// socket would otherwise get whatever was already there, and could still
// look like it worked.
static int never_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    memset(p, 0xEE, n);
    seen.io_calls++;
    return -1;
}

// One certificate the chain pointer names. No line of the flight reads a
// byte of it: a ROLE=server object links no X.509 reader at all.
static const uint8_t cert_der[4] = {0x30, 0x02, 0x05, 0x00};
static const ch_cert chain[1] = {
    {cert_der, sizeof cert_der}
};
static const uint8_t cookie_key[SHA256_LEN] = {7};
static const uint8_t alpn_h2[] = {'h', '2'};
static const ch_alpn_protocol alpn[1] = {
    {alpn_h2, sizeof alpn_h2}
};

static uint8_t srv_buf[CH_MIN_RXBUF];

// Both identities, because the hello this tree's client builds offers the
// signature scheme its TRUST value chose and the server has to hold the
// matching key. Provisioning both keeps the test independent of that axis.
static ch_rsa_priv rsa_key;

static void provision(ch_cfg *cfg) {
    cfg->srv.ecdsa_p256.chain = chain;
    cfg->srv.ecdsa_p256.chain_count = 1;
    cfg->srv.ecdsa_p256.priv = p256_sign_vectors[0].priv;
    cfg->srv.ecdsa_p256.priv_len = sizeof p256_sign_vectors[0].priv;
    cfg->srv.ecdsa_p256.pub = p256_sign_vectors[0].pub;
    cfg->srv.ecdsa_p256.pub_len = sizeof p256_sign_vectors[0].pub;

    memset(&rsa_key, 0, sizeof rsa_key);
    rsa_key.n_len = sizeof rsa_sign_2048_n;
    memcpy(rsa_key.n, rsa_sign_2048_n, sizeof rsa_sign_2048_n);
    memcpy(rsa_key.d, rsa_sign_2048_d, sizeof rsa_sign_2048_d);
    cfg->srv.rsa_pss.chain = chain;
    cfg->srv.rsa_pss.chain_count = 1;
    cfg->srv.rsa_pss.priv = &rsa_key;
    cfg->srv.rsa_pss.priv_len = sizeof rsa_key;
    cfg->srv.rsa_pss.pub = rsa_sign_2048_n;
    cfg->srv.rsa_pss.pub_len = sizeof rsa_sign_2048_n;
}

static void server_config(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = srv_buf;
    cfg->buf_len = sizeof srv_buf;
    cfg->send = never_send;
    cfg->recv = never_recv;
    cfg->alpn_protocols = alpn;
    cfg->alpn_count = 1;
    cfg->srv.cookie_key = cookie_key;
    cfg->srv.on_record_out = sink;
    provision(cfg);
}

// One plaintext handshake record around a message, the shape a
// ClientHello arrives in. RFC 9846 section 5.1 fixes legacy_record_version
// at 0x0303.
static size_t wrap(uint8_t *out, const uint8_t *msg, size_t n) {
    out[0] = REC_HANDSHAKE;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (uint8_t)(n >> 8);
    out[4] = (uint8_t)n;
    memcpy(out + REC_HDR, msg, n);
    return REC_HDR + n;
}

static size_t build_hello(uint8_t *hello, size_t cap) {
    ch_cfg client;
    memset(&client, 0, sizeof client);
    client.alpn_protocols = alpn;
    client.alpn_count = 1;
    uint8_t pub[32];
    uint8_t random32[32];
    memset(pub, 0x11, sizeof pub);
    memset(random32, 0x22, sizeof random32);
    // The client's own record_size_limit, the arithmetic ch_record_init
    // does over the same buffer. Passing 0 the way a QUIC client may is
    // what a tcp-nonblocking server refuses: RFC 8449 has no such limit, and
    // srv_parser_ext.c answers illegal_parameter.
    size_t room = sizeof srv_buf - REC_HDR - AEAD_TAG;
    uint16_t limit = room > 0x4001 ? 0x4001 : (uint16_t)room;
    return hs_build_client_hello(hello, cap, &client, pub, random32, limit, NULL, 0);
}

// A configuration with no sink completes no handshake, so the driver
// refuses it before it reads a byte and sends nothing.
static void test_init_refuses_a_missing_sink(void) {
    ch_cfg cfg;
    server_config(&cfg);
    cfg.srv.on_record_out = NULL;

    ch_record r;
    memset(&seen, 0, sizeof seen);
    CHECK(ch_srv_record_init(&r, &cfg) == CH_EINVAL);
    CHECK(ch_record_state(&r) == CH_ST_FAILED);
    CHECK(seen.count == 0);
}

// A record the caller has only half of is left whole for the next call:
// nothing is consumed and the session stays alive.
static void test_a_partial_record_is_not_consumed(void) {
    uint8_t hello[CH_HELLO_MAX];
    size_t hello_len = build_hello(hello, sizeof hello);
    CHECK(hello_len > 0);
    static uint8_t rec[CH_HELLO_MAX + REC_HDR];
    size_t rec_len = wrap(rec, hello, hello_len);

    ch_cfg cfg;
    server_config(&cfg);
    ch_record r;
    memset(&seen, 0, sizeof seen);
    CHECK(ch_srv_record_init(&r, &cfg) == CH_OK);

    size_t consumed = 1;
    CHECK(ch_srv_record_in(&r, rec, rec_len - 1, &consumed) == CH_OK);
    CHECK(consumed == 0);
    CHECK(seen.count == 0);
    CHECK(seen.io_calls == 0);
    CHECK(ch_record_state(&r) == CH_ST_START);
    ch_record_close(&r);
}

// A sink that refuses fails the handshake rather than losing the record.
static void test_a_refusing_sink_kills_the_session(void) {
    uint8_t hello[CH_HELLO_MAX];
    size_t hello_len = build_hello(hello, sizeof hello);
    static uint8_t rec[CH_HELLO_MAX + REC_HDR];
    size_t rec_len = wrap(rec, hello, hello_len);

    ch_cfg cfg;
    server_config(&cfg);
    ch_record r;
    memset(&seen, 0, sizeof seen);
    seen.refuse = 1;
    CHECK(ch_srv_record_init(&r, &cfg) == CH_OK);

    size_t consumed = 0;
    CHECK(ch_srv_record_in(&r, rec, rec_len, &consumed) != CH_OK);
    CHECK(ch_record_state(&r) == CH_ST_FAILED);
    CHECK(seen.io_calls == 0);
}

// The offset of legacy_session_id's length byte in a ClientHello message:
// the 4-byte handshake header, legacy_version and the 32-byte random.
#define HELLO_SESSION_ID_AT (4 + 2 + 32)
#define SESSION_ID_LEN 32

// A client in RFC 9846 Appendix E.4's middlebox compatibility mode sends
// a non-empty legacy_session_id, as Go's crypto/tls does, and the server
// answers with a change_cipher_spec after its ServerHello. In tcp-nonblocking mode
// that record leaves through on_record_out like every other one; a
// server that sent it through cfg.send broke INV-28, which colibri found
// against a Go client. This tree's client sends an empty session id, so
// the case rebuilds its hello with a 32-byte one.
static void test_a_session_id_draws_the_change_cipher_spec_through_the_sink(void) {
    uint8_t plain[CH_HELLO_MAX];
    size_t plain_len = build_hello(plain, sizeof plain);
    CHECK(plain_len > HELLO_SESSION_ID_AT && plain[HELLO_SESSION_ID_AT] == 0);

    uint8_t hello[CH_HELLO_MAX + SESSION_ID_LEN];
    size_t hello_len = plain_len + SESSION_ID_LEN;
    size_t body_len = hello_len - 4;
    memcpy(hello, plain, HELLO_SESSION_ID_AT);
    hello[1] = (uint8_t)(body_len >> 16);
    hello[2] = (uint8_t)(body_len >> 8);
    hello[3] = (uint8_t)body_len;
    hello[HELLO_SESSION_ID_AT] = SESSION_ID_LEN;
    memset(hello + HELLO_SESSION_ID_AT + 1, 0x5A, SESSION_ID_LEN);
    memcpy(hello + HELLO_SESSION_ID_AT + 1 + SESSION_ID_LEN, plain + HELLO_SESSION_ID_AT + 1,
           plain_len - HELLO_SESSION_ID_AT - 1);
    static uint8_t rec[CH_HELLO_MAX + SESSION_ID_LEN + REC_HDR];
    size_t rec_len = wrap(rec, hello, hello_len);

    ch_cfg cfg;
    server_config(&cfg);
    ch_record r;
    memset(&seen, 0, sizeof seen);
    CHECK(ch_srv_record_init(&r, &cfg) == CH_OK);

    size_t consumed = 0;
    int rc = ch_srv_record_in(&r, rec, rec_len, &consumed);
    CHECK(rc == CH_OK);
    CHECK(consumed == rec_len);
    // The ServerHello, then the change_cipher_spec, then the protected
    // flight, all through the sink.
    CHECK(seen.count >= 6);
    CHECK(seen.type[0] == REC_HANDSHAKE);
    CHECK(seen.type[1] == REC_CCS);
    CHECK(seen.len[1] == SRV_CCS_RECORD_LEN);
    for (size_t i = 2; i < seen.count && i < MAX_RECORDS; i++) {
        CHECK(seen.type[i] == REC_APPDATA);
    }
    // INV-28: not one byte through cfg.send.
    CHECK(seen.io_calls == 0);
    ch_record_close(&r);
}

// The count bound, SRV_CLIENT_HELLO_EXT_MAX, on the record path. This
// tree's own hello, filled out with empty extensions of distinct unknown
// types after its last one, draws the server's flight at the bound and
// illegal_parameter one past it (docs/decisions.md 59). The hello at the
// bound is larger than srv_buf, so the case gives the server a buffer of
// its own.
#define PAD_TYPE 0x1000
#define PADDED_CAP (CH_HELLO_MAX + 4 * SRV_CLIENT_HELLO_EXT_MAX)
static uint8_t padded_buf[PADDED_CAP + REC_HDR];

// Fills hello, a message of hello_len bytes in a buffer of PADDED_CAP,
// out to count extensions, and returns its new length.
static size_t pad_to(uint8_t *hello, size_t hello_len, size_t count) {
    rbuf r;
    rb_init(&r, hello + 4, hello_len - 4);
    rb_skip(&r, 2 + 32);
    rb_skip(&r, rb_u8(&r));
    rb_skip(&r, rb_u16(&r));
    rb_skip(&r, rb_u8(&r));
    size_t block_at = 4 + (hello_len - 4 - rb_left(&r));
    rb_skip(&r, 2);
    size_t have = 0;
    while (rb_left(&r) > 0 && !r.err) {
        (void)rb_u16(&r);
        rb_skip(&r, rb_u16(&r));
        have++;
    }
    CHECK(!r.err && have < count);
    wbuf w;
    wb_init(&w, hello + hello_len, PADDED_CAP - hello_len);
    for (size_t i = have; i < count; i++) {
        wb_u16(&w, (uint16_t)(PAD_TYPE + i));
        wb_u16(&w, 0);
    }
    CHECK(!w.err);
    size_t len = hello_len + w.len;
    size_t block_len = len - block_at - 2;
    hello[block_at] = (uint8_t)(block_len >> 8);
    hello[block_at + 1] = (uint8_t)block_len;
    hello[1] = (uint8_t)((len - 4) >> 16);
    hello[2] = (uint8_t)((len - 4) >> 8);
    hello[3] = (uint8_t)(len - 4);
    return len;
}

static void test_extension_count_bound(void) {
    for (size_t count = SRV_CLIENT_HELLO_EXT_MAX; count <= SRV_CLIENT_HELLO_EXT_MAX + 1; count++) {
        static uint8_t hello[PADDED_CAP];
        size_t hello_len = pad_to(hello, build_hello(hello, PADDED_CAP), count);
        static uint8_t rec[PADDED_CAP + REC_HDR];
        size_t rec_len = wrap(rec, hello, hello_len);

        ch_cfg cfg;
        server_config(&cfg);
        cfg.buf = padded_buf;
        cfg.buf_len = sizeof padded_buf;
        ch_record r;
        memset(&seen, 0, sizeof seen);
        CHECK(ch_srv_record_init(&r, &cfg) == CH_OK);
        size_t consumed = 0;
        int rc = ch_srv_record_in(&r, rec, rec_len, &consumed);
        if (count <= SRV_CLIENT_HELLO_EXT_MAX) {
            CHECK(rc == CH_OK && seen.count >= 5);
        } else {
            CHECK(rc == CH_EPROTO && ch_record_alert(&r) == ALERT_ILLEGAL_PARAMETER);
            CHECK(seen.count == 0);
        }
        ch_record_close(&r);
    }
}

int main(void) {
    uint8_t hello[CH_HELLO_MAX];
    size_t hello_len = build_hello(hello, sizeof hello);
    CHECK(hello_len > 0);
    static uint8_t rec[CH_HELLO_MAX + REC_HDR];
    size_t rec_len = wrap(rec, hello, hello_len);

    ch_cfg cfg;
    server_config(&cfg);

    ch_record r;
    memset(&seen, 0, sizeof seen);
    CHECK(ch_srv_record_init(&r, &cfg) == CH_OK);
    CHECK(ch_record_state(&r) == CH_ST_START);
    // A server speaks second: nothing is owed before the hello arrives.
    CHECK(seen.count == 0);

    size_t consumed = 0;
    int rc = ch_srv_record_in(&r, rec, rec_len, &consumed);
    if (rc != CH_OK) {
        (void)fprintf(stderr, "record_in rc=%d alert=%u\n", rc, ch_record_alert(&r));
    }
    CHECK(rc == CH_OK);
    CHECK(consumed == rec_len);

    // The whole flight left inside that one call, because a server pushes
    // rather than staging for a caller to collect: the ServerHello, the
    // EncryptedExtensions, the Certificate, the CertificateVerify and the
    // Finished. A longer chain spans more records, so five is the floor.
    CHECK(seen.count >= 5);
    CHECK(seen.total > 0);

    // The ServerHello goes out in the clear and every record after it is
    // protected, which puts application_data in the outer type (RFC 9846
    // section 5.2). No compatibility-mode change_cipher_spec sits between
    // them: this tree's client sends an empty legacy_session_id, and
    // srv_send_compat_ccs answers one only when the client sent one.
    CHECK(seen.type[0] == REC_HANDSHAKE);
    for (size_t i = 1; i < seen.count && i < MAX_RECORDS; i++) {
        CHECK(seen.type[i] == REC_APPDATA);
    }

    // No record is larger than the record layer allows.
    for (size_t i = 0; i < seen.count && i < MAX_RECORDS; i++) {
        CHECK(seen.len[i] >= REC_HDR);
        CHECK(seen.len[i] <= REC_HDR + 0x4000 + 256);
    }

    // The handshake is not done: the client Finished has not arrived, so
    // the session is still CH_ST_START and the caller keeps feeding.
    CHECK(ch_record_state(&r) == CH_ST_START);
    CHECK(ch_record_alert(&r) == 0);

    // INV-28: the whole flight ran without the driver touching the
    // socket, which is the one thing this mode exists to promise.
    CHECK(seen.io_calls == 0);

    // The sub-tests below each reset seen, so the flight's own numbers
    // are kept here for the line main prints.
    size_t records = seen.count;
    size_t bytes = seen.total;

    test_init_refuses_a_missing_sink();
    test_a_partial_record_is_not_consumed();
    test_a_refusing_sink_kills_the_session();
    test_a_session_id_draws_the_change_cipher_spec_through_the_sink();
    test_extension_count_bound();

    if (failures == 0) {
        (void)printf("srv_tcp_nonblocking: a ClientHello in, %zu records out (%zu bytes)\n",
                     records, bytes);
    }
    return failures != 0;
}
