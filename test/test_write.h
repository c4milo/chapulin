// ch_write's, ch_close's and ch_fail's shape for the tests that a
// TRANSPORT=tcp-blocking build and a TRANSPORT=tcp-nonblocking build
// share. A blocking build calls the three. A nonblocking build has none of
// them: its sessions seal in the caller's storage with ch_seal_in_place,
// close with ch_close_out and fail with ch_fail_out (tcp_nonblocking.h,
// docs/decisions.md 248). So the calls below write the plaintext into a
// buffer of this header's, seal it there, and hand the records to the
// session's cfg.send, one record a call, which the test sets on the
// session after the handshake and which the library never calls in that
// transport. A KeyUpdate or an alert the call writes into its side buffer
// goes out first.
//
// The tests of the in-place seal's own contract call ch_seal_in_place
// directly (test/tcp_nonblocking_seal_tests.h). This header serves the
// tests whose subject is something else: a ticket, a KeyUpdate, a suite.
#ifndef CH_TEST_WRITE_H
#define CH_TEST_WRITE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ch_assert.h"
#include "session.h"
#include "session_convert.h"
#include "tls.h"

#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#include "tcp_nonblocking.h"

// Room for four records of the largest plaintext a TX_RECORD build seals,
// so a long write takes a few calls of the seal.
#define TEST_WRITE_CAP ((size_t)4 * (0x4000 + REC_OVERHEAD))

static uint8_t test_write_buf[TEST_WRITE_CAP];

// Sends n bytes through the sink the test set in the session's cfg.send,
// as io_send_all does on the blocking transport.
static inline int test_write_send(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    CH_ASSERT(cfg->send != NULL); // the test sets its sink after the handshake
    while (n > 0) {
        int sent = cfg->send(cfg->io, p, n);
        if (sent <= 0 || (size_t)sent > n) {
            return CH_EIO;
        }
        p += sent;
        n -= (size_t)sent;
    }
    return CH_OK;
}

// Sends len bytes of whole records at p through the sink, one record a
// call, as ch_write hands io_send_all one record at a time. So a sink
// that counts its calls counts records in both transports. The loop ends
// because each pass sends one record of REC_HDR bytes or more.
static inline int test_write_records(const ch_cfg *cfg, const uint8_t *p, size_t len) {
    size_t at = 0;
    while (at < len) {
        CH_ASSERT(len - at >= REC_HDR); // the seal writes whole records
        size_t record_len = REC_HDR + (((size_t)p[at + 3] << 8) | p[at + 4]);
        CH_ASSERT(record_len <= len - at);
        int rc = test_write_send(cfg, p + at, record_len);
        if (rc != CH_OK) {
            return rc;
        }
        at += record_len;
    }
    return CH_OK;
}

// One ch_seal_in_place of take bytes, then its records out through the
// sink: side's record first, then the buffer's.
static inline int test_write_once(ch_tls *t, const uint8_t *p, size_t take) {
    const ch_cfg *cfg = &tls_priv(t)->cfg;
    if (take > 0) {
        memcpy(test_write_buf + REC_HDR, p, take);
    }
    uint8_t side[CH_KEY_UPDATE_RECORD_LEN];
    ch_seal_result result = {0};
    int rc = ch_seal_in_place(t, test_write_buf, sizeof test_write_buf, take, side, sizeof side,
                              &result);
    if (result.side_len > 0 && test_write_send(cfg, side, result.side_len) != CH_OK) {
        return CH_EIO;
    }
    if (rc != CH_OK) {
        return rc;
    }
    return test_write_records(cfg, test_write_buf, result.records_len);
}

// ch_write's contract, over ch_seal_in_place: n bytes in as many calls as
// the buffer above needs. A sink that fails returns CH_EIO and leaves the
// session as the seal left it, where ch_write would fail it.
static inline int test_write(ch_tls *t, const uint8_t *p, size_t n) {
    size_t off = 0;
    do {
        size_t room = ch_writable_len(t, sizeof test_write_buf);
        size_t take = n - off < room ? n - off : room;
        if (take == 0 && n > off) {
            // A session with no room takes one byte to the seal, whose
            // answer is ch_write's: CH_EPROTO on a session that is not
            // connected, and CH_ECAP on one that is.
            take = 1;
        }
        int rc = test_write_once(t, p + off, take);
        if (rc != CH_OK) {
            return rc;
        }
        off += take;
    } while (off < n);
    return CH_OK;
}

// ch_close's contract, over ch_close_out: this side's close_notify out
// through the sink. A session that is not connected writes nothing, and
// stays as it was, where ch_close would close it.
static inline void test_close(ch_tls *t) {
    const ch_cfg *cfg = &tls_priv(t)->cfg;
    uint8_t out[CH_ALERT_RECORD_LEN];
    size_t out_len = 0;
    if (ch_close_out(t, out, sizeof out, &out_len) == CH_OK && out_len > 0) {
        (void)test_write_send(cfg, out, out_len);
    }
}

// ch_fail's contract, over ch_fail_out: the alert out through the sink,
// CH_OK when the sink took it, CH_EIO when it did not.
static inline int test_fail(ch_tls *t, uint8_t description) {
    const ch_cfg *cfg = &tls_priv(t)->cfg;
    uint8_t out[CH_ALERT_RECORD_LEN];
    size_t out_len = 0;
    int rc = ch_fail_out(t, description, out, sizeof out, &out_len);
    if (out_len > 0 && test_write_send(cfg, out, out_len) != CH_OK && rc == CH_OK) {
        rc = CH_EIO;
    }
    return rc;
}
#else
#define test_write(t, p, n) ch_write((t), (p), (n))
#define test_close(t) ch_close(t)
#define test_fail(t, description) ch_fail((t), (description))
#endif

#endif
