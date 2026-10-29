// io_read_record (io.h) at each record length limit: the bodies of RFC
// 9846 §5.1 and §5.4 (record.h), and the buffer this side's
// record_size_limit sized (RFC 8449 §4). Included by test/unit_test.c
// only, after its CHECK macro and includes.
#ifndef CH_IO_READ_TESTS_H
#define CH_IO_READ_TESTS_H

#include "handshake_message.h"
#include "io.h"

// A recv that gives a header of type outer naming body_len bytes, and then
// that many zero bytes, in reads of the size the caller asks for.
typedef struct {
    uint8_t outer;
    size_t body_len;
    size_t off;
} io_read_wire;

static int io_read_step(void *io, uint8_t *p, size_t n) {
    io_read_wire *w = io;
    for (size_t i = 0; i < n; i++, w->off++) {
        uint8_t b = 0;
        if (w->off == 0) {
            b = w->outer;
        } else if (w->off == 1 || w->off == 2) {
            b = 0x03;
        } else if (w->off == 3) {
            b = (uint8_t)(w->body_len >> 8);
        } else if (w->off == 4) {
            b = (uint8_t)w->body_len;
        } else if (w->off >= REC_HDR + w->body_len) {
            return -1;
        }
        p[i] = b;
    }
    return (int)n;
}

static uint8_t io_read_buf[REC_HDR + 0x4000 + 256];

// Reads one record of type outer and body_len bytes into a session whose
// cfg.buf holds buf_len bytes, cap of them free. alert starts at
// decode_error, and *alert_out is what it holds after; *header_only says
// the call read the header and no byte of the body.
static int io_read_one(uint8_t outer, size_t body_len, size_t buf_len, size_t cap, int limit_sent,
                       uint8_t *alert_out, int *header_only) {
    static ch_tls t;
    static io_read_wire wire;
    memset(&t, 0, sizeof t);
    wire = (io_read_wire){.outer = outer, .body_len = body_len};
    t.cfg.recv = io_read_step;
    t.cfg.io = &wire;
    t.cfg.buf = io_read_buf;
    t.cfg.buf_len = buf_len;
    t.limit_sent = (uint8_t)limit_sent;
    uint8_t got_outer = 0;
    size_t record_len = 0;
    uint8_t alert = ALERT_DECODE_ERROR;
    int rc = io_read_record(&t, io_read_buf, cap, &got_outer, &record_len, &alert);
    *alert_out = alert;
    *header_only = wire.off == REC_HDR;
    if (rc == CH_OK) {
        CHECK(got_outer == outer && record_len == REC_HDR + body_len);
    }
    return rc;
}

// The last body each rule allows is read whole and leaves the alert
// alone. One byte more fails with CH_EPROTO and record_overflow before a
// byte of the body is read: 2^14 + 17 bytes protected, 2^14 + 1 in the
// clear, and 2^14 + 257 of either. An empty body fails with CH_EPROTO and
// leaves the alert alone. The lengths are the RFC's numbers written out,
// not record.h's constants, so a constant that moves fails here.
static void test_io_read_body_limits(void) {
    const size_t big = sizeof io_read_buf;
    uint8_t alert = 0;
    int header_only = 0;
    CHECK(io_read_one(REC_APPDATA, 0x4000 + 17, big, big, 1, &alert, &header_only) == CH_OK);
    CHECK(alert == ALERT_DECODE_ERROR);
    CHECK(io_read_one(REC_APPDATA, 0x4000 + 18, big, big, 1, &alert, &header_only) == CH_EPROTO);
    CHECK(alert == ALERT_RECORD_OVERFLOW && header_only);
    CHECK(io_read_one(REC_HANDSHAKE, 0x4000, big, big, 1, &alert, &header_only) == CH_OK);
    CHECK(alert == ALERT_DECODE_ERROR);
    CHECK(io_read_one(REC_HANDSHAKE, 0x4000 + 1, big, big, 1, &alert, &header_only) == CH_EPROTO);
    CHECK(alert == ALERT_RECORD_OVERFLOW && header_only);
    CHECK(io_read_one(REC_APPDATA, 0x4000 + 257, big, big, 1, &alert, &header_only) == CH_EPROTO);
    CHECK(alert == ALERT_RECORD_OVERFLOW && header_only);
    CHECK(io_read_one(REC_APPDATA, 0, big, big, 1, &alert, &header_only) == CH_EPROTO);
    CHECK(alert == ALERT_DECODE_ERROR);
}

// A buffer of 64 bytes reads a record of 64 bytes whole. A record one byte
// longer gets CH_ECAP with record_overflow once limit_sent is set, and
// with internal_error before. A record that fits cfg.buf but not cap, the
// room behind a message in part, gets CH_ECAP and leaves the alert alone.
static void test_io_read_buffer_limits(void) {
    const size_t buf_len = 64;
    uint8_t alert = 0;
    int header_only = 0;
    CHECK(io_read_one(REC_APPDATA, buf_len - REC_HDR, buf_len, buf_len, 1, &alert, &header_only) ==
          CH_OK);
    CHECK(alert == ALERT_DECODE_ERROR);
    CHECK(io_read_one(REC_APPDATA, buf_len - REC_HDR + 1, buf_len, buf_len, 1, &alert,
                      &header_only) == CH_ECAP);
    CHECK(alert == ALERT_RECORD_OVERFLOW && header_only);
    CHECK(io_read_one(REC_APPDATA, buf_len - REC_HDR + 1, buf_len, buf_len, 0, &alert,
                      &header_only) == CH_ECAP);
    CHECK(alert == ALERT_INTERNAL_ERROR && header_only);
    CHECK(io_read_one(REC_APPDATA, buf_len - REC_HDR, buf_len, buf_len - 1, 1, &alert,
                      &header_only) == CH_ECAP);
    CHECK(alert == ALERT_DECODE_ERROR && header_only);
}

static void test_io_read_record_limit(void) {
    test_io_read_body_limits();
    test_io_read_buffer_limits();
}

#endif
