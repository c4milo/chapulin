// The PROFILE=cnsa2 client over a mock transport (docs/decisions.md 151):
// ch_connect's refusals of every authentication but an external PSK, the
// ClientHello's one suite, one group and SHA-384 binder, the largest hello
// against CH_HELLO_MAX, and the ServerHello refusals. A mock server then
// runs two whole handshakes: one under the external PSK and one that
// resumes the ticket it issued (test/cnsa2_mock.h). It keys every record
// with TLS_AES_256_GCM_SHA384. The Makefile builds this file under the
// profile's defines, once for each of TRUST=raw-rsa and TRUST=ca-rsa.
// test/cnsa2_quic_test.c runs the same mock over QUIC, and test/e2e.sh
// runs the profile against OpenSSL.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_message.h"
#include "handshake_parser.h"
#include "keysched.h"
#include "mlkem.h"
#include "record.h"
#include "test_random.h"
#include "test_widemul.h"
#include "tls.h"
#include "transcript.h"
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#include "tcp_nonblocking.h"
#endif

#ifndef CH_PROFILE_CNSA2
#error "test/cnsa2_test.c checks the PROFILE=cnsa2 client: build it with -DCH_PROFILE_CNSA2"
#endif

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#include "hello_exts.h"

#include "cnsa2_mock.h"

// The mock transport. send captures the ClientHello and opens every
// record after it; recv answers the hello with the ServerHello in the
// clear and EncryptedExtensions and Finished in one record under s_hs.
// The client Finished gets a NewSessionTicket, and each application data
// record is echoed. With answer clear, recv fails at once, which is how
// the config tests see a config that passed validation: CH_EIO, not
// CH_EINVAL.
typedef struct {
    cnsa2_mock m;
    int answer;
    int sends;
    int rendered;
    uint8_t echo[64];
    size_t echo_len;
    uint8_t queue[8192];
    size_t queue_len;
    size_t queue_off;
    rec_dir wr;
    rec_dir rd;
    int keys;
} mock_server;

static void push_clear(mock_server *s, const uint8_t *msg, size_t n) {
    wbuf w;
    wb_init(&w, s->queue + s->queue_len, sizeof s->queue - s->queue_len);
    wb_u8(&w, REC_HANDSHAKE);
    wb_u16(&w, 0x0303);
    wb_u16(&w, (uint16_t)n);
    wb_bytes(&w, msg, n);
    CHECK(!w.err);
    s->queue_len += w.len;
}

static void push_sealed(mock_server *s, uint8_t type, const uint8_t *msg, size_t n) {
    size_t out_len = 0;
    CHECK(rec_seal(&s->wr, type, msg, n, s->queue + s->queue_len, sizeof s->queue - s->queue_len,
                   &out_len) == 0);
    s->queue_len += out_len;
}

static void render_flight(mock_server *s) {
    static uint8_t msg[128 + MLKEM_CT_LEN];
    push_clear(s, msg, mock_server_hello(&s->m, msg, sizeof msg));
    REC_DIR_INIT_SUITE(&s->wr, s->m.s_hs, SUITE_AES_256_GCM_SHA384);
    REC_DIR_INIT_SUITE(&s->rd, s->m.c_hs, SUITE_AES_256_GCM_SHA384);
    s->keys = 1;
    push_sealed(s, REC_HANDSHAKE, msg, mock_server_flight(&s->m, NULL, 0, msg, sizeof msg));
    REC_DIR_INIT_SUITE(&s->wr, s->m.s_ap, SUITE_AES_256_GCM_SHA384);
}

// Opens one record the client sent after its hello.
static void take_record(mock_server *s, const uint8_t *p, size_t n) {
    uint8_t pt[256];
    size_t pt_len = 0;
    uint8_t type = 0;
    if (!s->keys || p[0] == REC_CCS || rec_open(&s->rd, p, n, pt, sizeof pt, &pt_len, &type) != 0) {
        return;
    }
    if (type == REC_HANDSHAKE && !s->m.client_finished_ok) {
        mock_client_finished(&s->m, pt, pt_len);
        REC_DIR_INIT_SUITE(&s->rd, s->m.c_ap, SUITE_AES_256_GCM_SHA384);
        uint8_t ticket[64];
        size_t ticket_len = mock_ticket(ticket, sizeof ticket);
        push_sealed(s, REC_HANDSHAKE, ticket, ticket_len);
    } else if (type == REC_APPDATA && pt_len <= sizeof s->echo) {
        memcpy(s->echo, pt, pt_len);
        s->echo_len = pt_len;
        push_sealed(s, REC_APPDATA, pt, pt_len);
    }
}

static int mock_send(void *io, const uint8_t *p, size_t n) {
    mock_server *s = io;
    s->sends++;
    if (s->m.hello_len == 0 && n > REC_HDR && p[0] == REC_HANDSHAKE && n - REC_HDR <= CH_TX_STAGE) {
        memcpy(s->m.hello, p + REC_HDR, n - REC_HDR);
        s->m.hello_len = n - REC_HDR;
        return (int)n;
    }
    const uint8_t *rec = p;
    size_t left = n;
    while (left >= REC_HDR) {
        size_t len = REC_HDR + (((size_t)rec[3] << 8) | rec[4]);
        if (len > left) {
            break;
        }
        take_record(s, rec, len);
        rec += len;
        left -= len;
    }
    return (int)n;
}

static int mock_recv(void *io, uint8_t *p, size_t n) {
    mock_server *s = io;
    if (!s->answer || s->m.hello_len == 0) {
        return -1;
    }
    if (!s->rendered) {
        s->rendered = 1;
        render_flight(s);
    }
    size_t left = s->queue_len - s->queue_off;
    if (left == 0) {
        return -1;
    }
    size_t take = n < left ? n : left;
    memcpy(p, s->queue + s->queue_off, take);
    s->queue_off += take;
    return (int)take;
}

static uint8_t rxbuf[CH_MIN_RXBUF];
static ch_saved_ticket saved;
static int tickets;

static void on_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    tickets++;
    CHECK(ticket->psk_len == SHA384_LEN);
    CHECK(ch_ticket_save(&saved, ticket) == 0);
}

// A valid profile config: the external PSK and nothing else.
static ch_cfg valid_cfg(mock_server *s) {
    memset(s, 0, sizeof *s);
    ch_cfg cfg = {0};
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = s;
    cfg.psk = external_psk;
    cfg.psk_len = sizeof external_psk;
    cfg.psk_id = external_id;
    cfg.psk_id_len = sizeof external_id;
    cfg.on_ticket = on_ticket;
    return cfg;
}

#ifdef CH_TRANSPORT_TCP_NONBLOCKING
// The handshake through ch_record_init, ch_record_out and ch_record_in,
// with the mock's send and recv as the caller's socket. Returns what
// ch_connect would: CH_OK once connected, the refusal or failure code, or
// CH_EIO when the mock has nothing more to answer.
static ch_record record;
static int test_connect(ch_tls **t, const ch_cfg *cfg) {
    *t = &record.t;
    int rc = ch_record_init(&record, cfg);
    while (rc == CH_OK) {
        static uint8_t wire[8192];
        size_t n = 0;
        rc = ch_record_out(&record, wire, sizeof wire, &n);
        CHECK(n <= sizeof wire);
        if (rc == CH_OK && n > 0 && n <= sizeof wire) {
            CHECK(mock_send(cfg->io, wire, n) == (int)n);
            continue;
        }
        if (rc != CH_OK || ch_record_state(&record) == CH_ST_CONNECTED) {
            break;
        }
        int got = mock_recv(cfg->io, wire, sizeof wire);
        if (got <= 0) {
            return CH_EIO;
        }
        size_t off = 0;
        while (rc == CH_OK && off < (size_t)got) {
            size_t used = 0;
            rc = ch_record_in(&record, wire + off, (size_t)got - off, &used);
            off += used;
        }
    }
    return rc;
}
#else
static ch_tls session;
static int test_connect(ch_tls **t, const ch_cfg *cfg) {
    *t = &session;
    return ch_connect(&session, cfg);
}
#endif

#include "cnsa2_cases.h"

int main(void) {
    test_cnsa2_cfg();
    test_cnsa2_hello();
    test_cnsa2_hello_boundary();
    test_cnsa2_handshake();
    test_cnsa2_server_hello_refusals();
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("cnsa2_test: all checks passed\n");
    return 0;
}
