// Session-level tests over a mock transport: the paths e2e cannot steer
// (fragmented post-handshake messages, KeyUpdate both ways, close
// semantics) and ch_connect's config validation. This file holds the
// mock transport every one of those tests drives; the tests themselves
// live in session_post_tests.h and session_cfg_tests.h, included at the
// bottom. Included by test/unit_test.c only, after its CHECK macro and
// includes.
#ifndef CH_SESSION_TESTS_H
#define CH_SESSION_TESTS_H

// Mock transport: the "server" is a byte queue we stuff records into.
// The send side captures the client's bytes so tests can decrypt them
// with the server's copy of the client write key, and fail_after makes
// the Nth send call return an I/O error (0 = never fail).
typedef struct {
    uint8_t data[4096];
    size_t len;
    size_t off;
    int tickets;
    size_t sent;      // bytes the client transmitted (KeyUpdate replies etc.)
    uint8_t tx[4096]; // capture of everything the client sent
    size_t tx_len;
    int sends;      // send calls so far
    int fail_after; // fail the send when sends reaches this count
} mock_io;

static int mock_send(void *io, const uint8_t *p, size_t n) {
    mock_io *m = io;
    m->sends++;
    if (m->fail_after != 0 && m->sends >= m->fail_after) {
        return -1;
    }
    if (m->tx_len + n <= sizeof m->tx) {
        memcpy(m->tx + m->tx_len, p, n);
        m->tx_len += n;
    }
    m->sent += n;
    return 0;
}

static int mock_recv(void *io, uint8_t *p, size_t n) {
    mock_io *m = io;
    size_t left = m->len - m->off;
    if (left == 0) {
        return -1;
    }
    size_t take = n < left ? n : left;
    memcpy(p, m->data + m->off, take);
    m->off += take;
    return (int)take;
}

static void mock_on_ticket(void *io, const ch_ticket *ticket) {
    (void)ticket;
    ((mock_io *)io)->tickets++;
}

// Builds a connected session whose read keys mirror server, fed by m.
static void mock_session(ch_tls *t, mock_io *m, uint8_t *rxbuf, size_t rxlen,
                         const uint8_t secret[SHA256_LEN], uint8_t wr_secret_out[SHA256_LEN]) {
    memset(t, 0, sizeof *t);
    t->cfg.buf = rxbuf;
    t->cfg.buf_len = rxlen;
    t->cfg.send = mock_send;
    t->cfg.recv = mock_recv;
    t->cfg.io = m;
    t->cfg.on_ticket = mock_on_ticket;
    memcpy(t->rd_secret, secret, SHA256_LEN);
    rec_dir_init(&t->rd, t->rd_secret);
    uint8_t write_secret[SHA256_LEN];
    ch_rand_bytes(write_secret, sizeof write_secret);
    if (wr_secret_out != NULL) {
        memcpy(wr_secret_out, write_secret, SHA256_LEN);
    }
    memcpy(t->wr_secret, write_secret, SHA256_LEN);
    rec_dir_init(&t->wr, t->wr_secret);
    t->state = CH_ST_CONNECTED;
    t->keys = 1;
    t->peer_limit = CH_TX_PT;
}

static void mock_push(mock_io *m, rec_dir *server, uint8_t type, const uint8_t *pt, size_t n) {
    size_t record_len = 0;
    CHECK(rec_seal(server, type, pt, n, m->data + m->len, sizeof m->data - m->len, &record_len) ==
          0);
    m->len += record_len;
}

// Pops one record off the client's captured transmit bytes and opens it
// with the server's copy of the client write key.
static size_t mock_pop_client_record(mock_io *m, size_t at, rec_dir *reader, uint8_t *pt,
                                     size_t cap, size_t *pt_len, uint8_t *type) {
    CHECK(m->tx_len >= at + REC_HDR);
    size_t body = ((size_t)m->tx[at + 3] << 8) | m->tx[at + 4];
    CHECK(m->tx_len >= at + REC_HDR + body);
    CHECK(rec_open(reader, m->tx + at, REC_HDR + body, pt, cap, pt_len, type) == 0);
    return at + REC_HDR + body;
}

#include "session_cfg_tests.h"
#include "session_post_tests.h"

#endif
