// io_read_record (io.h) at the record length limit of RFC 9846 §5.2.
// Included by test/unit_test.c only, after its CHECK macro and includes.
#ifndef CH_IO_READ_TESTS_H
#define CH_IO_READ_TESTS_H

#include "handshake_message.h"
#include "io.h"

// A recv that gives a header naming body_len bytes and then that many
// zero bytes, in reads of the size the caller asks for.
typedef struct {
    size_t body_len;
    size_t off;
} io_read_wire;

static int io_read_step(void *io, uint8_t *p, size_t n) {
    io_read_wire *w = io;
    for (size_t i = 0; i < n; i++, w->off++) {
        uint8_t b = 0;
        if (w->off == 0) {
            b = REC_APPDATA;
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

// A body of 2^14 + 256 bytes, the last length RFC 9846 §5.2 allows, is
// read whole and leaves the alert alone. One byte more fails with
// CH_EPROTO and writes record_overflow, and an empty body fails with
// CH_EPROTO and leaves the alert alone.
static void test_io_read_record_limit(void) {
    static uint8_t buf[REC_HDR + 0x4000 + 256];
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.recv = io_read_step;
    uint8_t outer = 0;
    size_t record_len = 0;

    io_read_wire longest = {.body_len = 0x4000 + 256};
    cfg.io = &longest;
    uint8_t alert = ALERT_DECODE_ERROR;
    CHECK(io_read_record(&cfg, buf, sizeof buf, &outer, &record_len, &alert) == CH_OK);
    CHECK(record_len == sizeof buf && outer == REC_APPDATA && alert == ALERT_DECODE_ERROR);

    io_read_wire over = {.body_len = 0x4000 + 257};
    cfg.io = &over;
    alert = ALERT_DECODE_ERROR;
    CHECK(io_read_record(&cfg, buf, sizeof buf, &outer, &record_len, &alert) == CH_EPROTO);
    CHECK(alert == ALERT_RECORD_OVERFLOW && over.off == REC_HDR);

    io_read_wire empty = {.body_len = 0};
    cfg.io = &empty;
    alert = ALERT_DECODE_ERROR;
    CHECK(io_read_record(&cfg, buf, sizeof buf, &outer, &record_len, &alert) == CH_EPROTO);
    CHECK(alert == ALERT_DECODE_ERROR);
}

#endif
