// Application records of CH_TX_PT bytes, in a build that raised CH_TX_PT
// with TX_RECORD (docs/decisions.md 71): this tree's TRUST=webpki client
// against this tree's server, both from the ROLE=both
// TRANSPORT=tcp-nonblocking object's sources. The Makefile builds
// test/webpki_loop_test.c at TX_RECORD=16384 as bin/webpki_loop_tx_record,
// and a build at the default CH_TX_PT compiles none of this file.
//
// The cases:
//   - a write of CH_TX_PT bytes goes out as one record, and a write of
//     CH_TX_PT + 1 bytes as two;
//   - a peer whose record_size_limit (RFC 8449) is below CH_TX_PT gets
//     records of that limit, and one byte more takes a second record;
//   - a transfer of more than two records moves each way, client to server
//     and server to client, through test_write and test_read
//     (test/test_write.h, test/test_read.h);
//   - a protected handshake message the server seals goes out in records
//     of CH_TX_HANDSHAKE_PT bytes, what ch_tls.tx holds of one record,
//     because a tcp-nonblocking build stages its handshake alone
//     (session.h, docs/decisions.md 248).
// The first two sit at the exact boundary: the last size that fits one
// record, and the first that takes two.
// The handshakes in main() run in this build too, and their record counts
// hold srv_frag to SRV_FRAG_MAX: a Certificate fragment that grew with
// CH_TX_PT would send one record where they count three.
#ifndef CH_TEST_WEBPKI_LOOP_TX_RECORD_H
#define CH_TEST_WEBPKI_LOOP_TX_RECORD_H
#if CH_TX_PT > 512

#include "srv_out.h"
#include "test_write.h"

// A receive buffer whose record_size_limit lets the peer send CH_TX_PT
// bytes in one record: the record header, the plaintext, the inner
// content type and the tag.
#define TX_LOOP_BUF (REC_HDR + CH_TX_PT + 1 + AEAD_TAG)
static uint8_t tx_srv_buf[TX_LOOP_BUF];
static uint8_t tx_cli_buf[TX_LOOP_BUF];

// The transfer each way: two whole records and 100 bytes more.
#define TX_TRANSFER (2 * CH_TX_PT + 100)

// One direction's records once connected: what one end's test_write sent,
// for the other end's test_read. test_write hands cfg.send one whole
// record a call, and pipe_send takes all of it, so send_calls counts
// records and last_len is the length of the last one.
typedef struct {
    uint8_t bytes[4 * TX_LOOP_BUF];
    size_t len;
    size_t off;
    size_t send_calls;
    size_t last_len;
} tx_pipe;
static tx_pipe up;   // client to server
static tx_pipe down; // server to client

static int pipe_send(tx_pipe *pipe, const uint8_t *p, size_t n) {
    if (pipe->len + n > sizeof pipe->bytes) {
        return -1;
    }
    memcpy(pipe->bytes + pipe->len, p, n);
    pipe->len += n;
    pipe->send_calls++;
    pipe->last_len = n;
    return (int)n;
}

// Hands over what the pipe holds, and 0 when it holds nothing more, which
// is the recv test_read reads through (test/test_read.h).
static int pipe_recv(tx_pipe *pipe, uint8_t *p, size_t n) {
    size_t left = pipe->len - pipe->off;
    size_t take = n < left ? n : left;
    memcpy(p, pipe->bytes + pipe->off, take);
    pipe->off += take;
    return (int)take;
}

static int client_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    return pipe_send(&up, p, n);
}

static int client_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    return pipe_recv(&down, p, n);
}

static int server_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    return pipe_send(&down, p, n);
}

static int server_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    return pipe_recv(&up, p, n);
}

// One full handshake between a server on tx_srv_buf and a client on
// cli_len bytes of cli, then both ends moved onto the pipes. Returns 1
// when both ends connected.
static int tx_connect(uint8_t *cli, size_t cli_len) {
    ch_cfg scfg;
    ch_cfg ccfg;
    server_config(&scfg, ticket_key);
    scfg.buf = tx_srv_buf;
    scfg.buf_len = sizeof tx_srv_buf;
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    ccfg.buf = cli;
    ccfg.buf_len = cli_len;
    if (!run(&ccfg, &scfg)) {
        return 0;
    }
    memset(&up, 0, sizeof up);
    memset(&down, 0, sizeof down);
    client.t.cfg.send = client_send;
    client.t.cfg.recv = client_recv;
    server.t.cfg.send = server_send;
    server.t.cfg.recv = server_recv;
    return 1;
}

// Reads n bytes through test_read into got and requires them to equal
// want. test_read hands over at most one record's plaintext per call.
static int read_all(ch_tls_priv *t, uint8_t *got, const uint8_t *want, size_t n) {
    size_t at = 0;
    while (at < n) {
        int rc = test_read(tls_public(t), got + at, n - at);
        if (rc <= 0) {
            return 0;
        }
        at += (size_t)rc;
    }
    return memcmp(got, want, n) == 0;
}

static uint8_t tx_data[TX_TRANSFER];
static uint8_t tx_got[TX_TRANSFER];

// A write of CH_TX_PT bytes is one record and CH_TX_PT + 1 bytes is two,
// against a server that takes records of CH_TX_PT, and the server reads
// every byte back.
static void check_tx_record_boundary(void) {
    CHECK(tx_connect(tx_cli_buf, sizeof tx_cli_buf));
    CHECK(client.t.peer_limit == CH_TX_PT && server.t.peer_limit == CH_TX_PT);
    CHECK(test_write(tls_public(&client.t), tx_data, CH_TX_PT) == CH_OK);
    CHECK(up.send_calls == 1 && up.last_len == REC_OVERHEAD + CH_TX_PT);
    CHECK(read_all(&server.t, tx_got, tx_data, CH_TX_PT));
    CHECK(test_write(tls_public(&client.t), tx_data, CH_TX_PT + 1) == CH_OK);
    CHECK(up.send_calls == 3 && up.last_len == REC_OVERHEAD + 1);
    CHECK(read_all(&server.t, tx_got, tx_data, CH_TX_PT + 1));
}

// TX_TRANSFER bytes each way on one connection: three records up, read by
// the server, then three records down, read by the client.
static void check_tx_transfer(void) {
    CHECK(tx_connect(tx_cli_buf, sizeof tx_cli_buf));
    CHECK(test_write(tls_public(&client.t), tx_data, sizeof tx_data) == CH_OK);
    CHECK(up.send_calls == 3 && up.last_len == REC_OVERHEAD + 100);
    CHECK(read_all(&server.t, tx_got, tx_data, sizeof tx_data));
    CHECK(test_write(tls_public(&server.t), tx_data, sizeof tx_data) == CH_OK);
    CHECK(down.send_calls == 3 && down.last_len == REC_OVERHEAD + 100);
    CHECK(read_all(&client.t, tx_got, tx_data, sizeof tx_data));
}

// A client on the build's floor, CH_MIN_RXBUF, advertises a
// record_size_limit below CH_TX_PT, and the server's records follow it:
// the limit in one record, and the limit plus one in two.
static void check_tx_peer_limit_wins(void) {
    size_t limit = sizeof cli_buf - REC_OVERHEAD;
    CHECK(limit < CH_TX_PT);
    CHECK(tx_connect(cli_buf, sizeof cli_buf));
    CHECK(server.t.peer_limit == limit && client.t.peer_limit == CH_TX_PT);
    CHECK(test_write(tls_public(&server.t), tx_data, limit) == CH_OK);
    CHECK(down.send_calls == 1 && down.last_len == REC_OVERHEAD + limit);
    CHECK(read_all(&client.t, tx_got, tx_data, limit));
    CHECK(test_write(tls_public(&server.t), tx_data, limit + 1) == CH_OK);
    CHECK(down.send_calls == 3 && down.last_len == REC_OVERHEAD + 1);
    CHECK(read_all(&client.t, tx_got, tx_data, limit + 1));
}

// A message of two whole handshake records and a byte, sealed by
// srv_out_sealed on the connected server as the flight's handlers seal
// theirs: three records of at most CH_TX_HANDSHAKE_PT bytes each, which
// the server's tx holds. Nothing reads them: the check counts the records
// the sink takes and their bytes.
static void check_tx_handshake_records(void) {
    _Static_assert(CH_TX_HANDSHAKE_PT < CH_TX_PT, "this build cuts handshake records below CH_TX_PT");
    _Static_assert(CH_TX_HANDSHAKE_PT + 1 + AEAD_TAG <= sizeof server.t.tx - REC_HDR,
                   "tx holds one handshake record");
    CHECK(tx_connect(tx_cli_buf, sizeof tx_cli_buf));
    CHECK(srv_out_limit(&server.t) == CH_TX_HANDSHAKE_PT);
    static uint8_t msg[2 * CH_TX_HANDSHAKE_PT + 1];
    memset(msg, HS_FINISHED, sizeof msg);
    static handshake_state h;
    memset(&h, 0, sizeof h);
    h.t = &server.t;
    to_client.len = 0;
    to_client.off = 0;
    records_pushed = 0;
    CHECK(srv_out_sealed(&h, msg, sizeof msg) == CH_OK);
    CHECK(records_pushed == 3 && to_client.len == sizeof msg + 3 * REC_OVERHEAD);
}

static void check_tx_records(void) {
    for (size_t i = 0; i < sizeof tx_data; i++) {
        tx_data[i] = (uint8_t)(i * 7 + 3);
    }
    check_tx_record_boundary();
    check_tx_transfer();
    check_tx_peer_limit_wins();
    check_tx_handshake_records();
}

#endif // CH_TX_PT > 512
#endif
