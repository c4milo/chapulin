// ch_record_whole_len, the call a TRANSPORT=tcp-nonblocking caller asks
// where the record at the front of its bytes ends (tcp_nonblocking.h).
// Included by test/tcp_nonblocking_loop_test.c after
// test/tcp_nonblocking_read_tests.h, whose hold_record seals the real
// records the last rows frame.
#ifndef CH_TEST_TCP_NONBLOCKING_FRAME_TESTS_H
#define CH_TEST_TCP_NONBLOCKING_FRAME_TESTS_H

#include "tcp_nonblocking_read_tests.h"

// The largest value RFC 9846 §5.2 lets a record's length field hold
// (rfc9846.txt:3595-3596), and the longest whole record it frames.
#define FRAME_BODY_MAX (0x4000 + 256)
#define FRAME_WHOLE_MAX (REC_HDR + FRAME_BODY_MAX)

// Room for the longest whole record and one byte of the next.
static uint8_t frame_bytes[FRAME_WHOLE_MAX + 1];

// Writes an application_data header whose length field is body_len.
static void frame_header(size_t body_len) {
    frame_bytes[0] = REC_APPDATA;
    frame_bytes[1] = 0x03;
    frame_bytes[2] = 0x03;
    frame_bytes[3] = (uint8_t)(body_len >> 8);
    frame_bytes[4] = (uint8_t)body_len;
}

static void test_record_whole_len(ch_record *server) {
    // Every cut of the header is less than a record.
    CHECK(ch_record_whole_len(NULL, 0) == 0);
    frame_header(3);
    for (size_t cut = 0; cut < REC_HDR; cut++) {
        CHECK(ch_record_whole_len(frame_bytes, cut) == 0);
    }
    // A record that names 3 bytes: one byte short, whole, and whole with
    // the next record's bytes behind it.
    CHECK(ch_record_whole_len(frame_bytes, REC_HDR + 2) == 0);
    CHECK(ch_record_whole_len(frame_bytes, REC_HDR + 3) == REC_HDR + 3);
    CHECK(ch_record_whole_len(frame_bytes, 2 * (size_t)(REC_HDR + 3)) == REC_HDR + 3);
    // A length field of 0 frames the header alone.
    frame_header(0);
    CHECK(ch_record_whole_len(frame_bytes, REC_HDR) == REC_HDR);

    // The largest length RFC 9846 §5.2 allows: one byte short, and whole.
    frame_header(FRAME_BODY_MAX);
    CHECK(ch_record_whole_len(frame_bytes, FRAME_WHOLE_MAX - 1) == 0);
    CHECK(ch_record_whole_len(frame_bytes, FRAME_WHOLE_MAX) == FRAME_WHOLE_MAX);
    // One more names no record a peer may send: the header alone is the
    // answer, as soon as the header is whole, whatever follows it.
    frame_header(FRAME_BODY_MAX + 1);
    CHECK(ch_record_whole_len(frame_bytes, REC_HDR - 1) == 0);
    CHECK(ch_record_whole_len(frame_bytes, REC_HDR) == REC_HDR);
    CHECK(ch_record_whole_len(frame_bytes, sizeof frame_bytes) == REC_HDR);
    frame_header(0xffff);
    CHECK(ch_record_whole_len(frame_bytes, REC_HDR) == REC_HDR);

    // Records the server sealed: each frames at the length it was sealed
    // to, with the next one behind it.
    memset(&held, 0, sizeof held);
    static const uint8_t hola[4] = {'h', 'o', 'l', 'a'};
    hold_record(server, REC_APPDATA, hola, sizeof hola, 0);
    size_t first = held.len;
    CHECK(first == sizeof hola + REC_OVERHEAD);
    hold_record(server, REC_APPDATA, hola, sizeof hola, 0);
    CHECK(ch_record_whole_len(held.bytes, held.len) == first);
    CHECK(ch_record_whole_len(held.bytes + first, held.len - first) == held.len - first);
    CHECK(ch_record_whole_len(held.bytes + first, held.len - first - 1) == 0);
    memset(&held, 0, sizeof held);
}

#endif
