// Edits a test makes to the records one endpoint wrote before the other
// endpoint reads them: bytes added after the message a record carries,
// in a plaintext record or under the key that sealed it. The two loop
// tests that hold RFC 9846 §5.1 (INV-39) use them,
// test/tcp_nonblocking_record_end_tests.h and
// test/tcp_blocking_loop_test.c. Included after CHECK; not a standalone
// translation unit.
#ifndef CH_TEST_RECORD_EDIT_H
#define CH_TEST_RECORD_EDIT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "record.h"
#include "sha256.h"
#include "test_cpu.h"

// The length of the record at wire[off..), header included.
static size_t record_at(const uint8_t *wire, size_t off) {
    return REC_HDR + (((size_t)wire[off + 3] << 8) | wire[off + 4]);
}

// Adds extra zero bytes to the plaintext record at the front of wire,
// after the message it holds, and moves the records behind it along. The
// wire holds *len bytes and has room for cap.
static void grow_first_record(uint8_t *wire, size_t *len, size_t cap, size_t extra) {
    size_t end = record_at(wire, 0);
    CHECK(end <= *len && *len + extra <= cap);
    memmove(wire + end + extra, wire + end, *len - end);
    memset(wire + end, 0, extra);
    size_t body = end - REC_HDR + extra;
    wire[3] = (uint8_t)(body >> 8);
    wire[4] = (uint8_t)body;
    *len += extra;
}

// Seals the last record of wire[0..*len) again under secret, with extra
// zero bytes after its plaintext. The protected records before it are
// opened in order, so the last one keeps the sequence number its sender
// gave it; a plaintext record carries none and is passed over.
static void reseal_last_record(uint8_t *wire, size_t *len, size_t cap,
                               const uint8_t secret[SHA256_LEN], size_t extra) {
    static uint8_t pt[0x4000 + 256];
    rec_dir d;
    rec_dir_init(&d, secret);
    TEST_CPU_DIR(d);
    size_t pt_len = 0;
    uint8_t type = 0;
    size_t off = 0;
    while (off + REC_HDR <= *len && off + record_at(wire, off) < *len) {
        if (wire[off] == REC_APPDATA) {
            CHECK(rec_open(&d, wire + off, record_at(wire, off), pt, sizeof pt, &pt_len, &type) ==
                  0);
        }
        off += record_at(wire, off);
    }
    rec_dir at = d;
    CHECK(rec_open(&d, wire + off, *len - off, pt, sizeof pt, &pt_len, &type) == 0);
    CHECK(pt_len + extra <= sizeof pt);
    memset(pt + pt_len, 0, extra);
    size_t out_len = 0;
    CHECK(rec_seal(&at, type, pt, pt_len + extra, wire + off, cap - off, &out_len) == 0);
    *len = off + out_len;
}

#endif
