// io_send_all (io.h) over sends that move part of a record or answer a
// count no send may give. Included by test/unit_test.c only, after its
// CHECK macro and includes.
#ifndef CH_IO_SEND_TESTS_H
#define CH_IO_SEND_TESTS_H

#include "io.h"

// A send that moves at most step bytes a call into wire. With
// answer_once set it moves nothing: its first call returns answer and
// every later call returns -1, so a test can count the calls a refusal
// takes.
typedef struct {
    uint8_t wire[64];
    size_t len;
    size_t step;
    int answer_once;
    int answer;
    int calls;
} io_send_wire;

static int io_send_step(void *io, const uint8_t *p, size_t n) {
    io_send_wire *w = io;
    w->calls++;
    if (w->answer_once) {
        return w->calls == 1 ? w->answer : -1;
    }
    size_t moved = n < w->step ? n : w->step;
    if (moved > sizeof w->wire - w->len) {
        return -1;
    }
    memcpy(w->wire + w->len, p, moved);
    w->len += moved;
    return (int)moved;
}

// A send that moves 3 bytes a call gets 20 bytes in 7 calls, in order. A
// send that moves all 20 at once gets one call. A send that answers 0, 21
// or -1 fails the record with CH_EIO after that one call: 0 moved
// nothing, and 21 is one byte more than the call was handed.
static void test_io_send_all(void) {
    uint8_t record[20];
    for (size_t i = 0; i < sizeof record; i++) {
        record[i] = (uint8_t)(i + 1);
    }
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.send = io_send_step;

    io_send_wire partial = {.step = 3};
    cfg.io = &partial;
    CHECK(io_send_all(&cfg, record, sizeof record) == CH_OK);
    CHECK(partial.calls == 7 && partial.len == sizeof record);
    CHECK(memcmp(partial.wire, record, sizeof record) == 0);

    io_send_wire whole = {.step = sizeof record};
    cfg.io = &whole;
    CHECK(io_send_all(&cfg, record, sizeof record) == CH_OK);
    CHECK(whole.calls == 1 && whole.len == sizeof record);

    static const int refusals[] = {0, (int)sizeof record + 1, -1};
    for (size_t i = 0; i < sizeof refusals / sizeof refusals[0]; i++) {
        io_send_wire refusing = {.answer_once = 1, .answer = refusals[i]};
        cfg.io = &refusing;
        CHECK(io_send_all(&cfg, record, sizeof record) == CH_EIO);
        CHECK(refusing.calls == 1);
    }
}

#endif
