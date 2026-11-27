// ch_read's shape for the tests that a TRANSPORT=tcp-blocking build and a
// TRANSPORT=tcp-nonblocking build share. A blocking build reads with
// ch_read. A nonblocking build has no ch_read: its sessions read in place
// with ch_read_in_place (tcp_nonblocking.h, docs/decisions.md 247). So
// test_read below takes the peer's records from the session's cfg.recv,
// which the test sets on the session after the handshake and which the
// library never calls in that transport, opens them in place, and copies
// the plaintext out, as ch_read did. An alert the read fails with goes out
// through the session's cfg.send, as ch_read sent it.
//
// The tests of the in-place read's own contract call ch_read_in_place
// directly (test/tcp_nonblocking_read_tests.h). This header serves the
// tests whose subject is something else: a ticket, a KeyUpdate, a suite.
#ifndef CH_TEST_READ_H
#define CH_TEST_READ_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ch_assert.h"
#include "session.h"
#include "session_convert.h"
#include "tls.h"

#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#include "tcp_nonblocking.h"

// Room for two of the longest records a peer may send, the bytes of a
// message in parts and the record after them.
#define TEST_READ_STASH ((size_t)2 * (REC_HDR + 0x4000 + 256))
// The sessions one test binary reads with at once: a client and a server.
#define TEST_READ_SESSIONS 4

typedef struct {
    const ch_tls *session;
    size_t len;
    size_t pt_off;
    size_t pt_len;
    // Plaintext of the last record that did not fit the caller's p.
    uint8_t pt[0x4000 + 1];
    uint8_t bytes[TEST_READ_STASH];
} test_read_stash;

static test_read_stash test_read_stashes[TEST_READ_SESSIONS];

// The stash of t, taken on first use. A test that reads with more
// sessions than TEST_READ_SESSIONS gets NULL and fails its read.
static inline test_read_stash *test_read_stash_of(const ch_tls *t) {
    test_read_stash *free_slot = NULL;
    for (size_t i = 0; i < TEST_READ_SESSIONS; i++) {
        if (test_read_stashes[i].session == t) {
            return &test_read_stashes[i];
        }
        if (test_read_stashes[i].session == NULL && free_slot == NULL) {
            free_slot = &test_read_stashes[i];
        }
    }
    if (free_slot != NULL) {
        memset(free_slot, 0, sizeof *free_slot);
        free_slot->session = t;
    }
    return free_slot;
}

// Forgets every stash. A test that starts a new pair of sessions in the
// same storage calls it first.
static inline void test_read_reset(void) {
    memset(test_read_stashes, 0, sizeof test_read_stashes);
}

// Reads want bytes from the session's recv onto the end of the stash.
// Returns 1 when all of them came, 0 when recv had nothing before the
// first byte and empty_ok is set, and -1 when recv failed or stopped
// before the last byte. The loop ends because each pass takes one byte or
// more.
static inline int test_read_fill(const ch_cfg *cfg, test_read_stash *s, size_t want, int empty_ok) {
    size_t got_total = 0;
    while (got_total < want) {
        int got = cfg->recv(cfg->io, s->bytes + s->len + got_total, want - got_total);
        if (got == 0 && empty_ok && got_total == 0) {
            return 0;
        }
        if (got <= 0 || (size_t)got > want - got_total) {
            return -1;
        }
        got_total += (size_t)got;
    }
    s->len += want;
    return 1;
}

// Pulls one more whole record from the session's recv into s, the way
// io_read_record read one on the blocking transport. Returns 1 when one
// came, 0 when recv had nothing at a record boundary, and -1 when recv
// failed or stopped inside a record.
static inline int test_read_pull(const ch_cfg *cfg, test_read_stash *s) {
    if (cfg->recv == NULL || TEST_READ_STASH - s->len < REC_HDR) {
        return -1;
    }
    int rc = test_read_fill(cfg, s, REC_HDR, 1);
    if (rc != 1) {
        return rc;
    }
    const uint8_t *hdr = s->bytes + s->len - REC_HDR;
    size_t body = ((size_t)hdr[3] << 8) | hdr[4];
    if (body > TEST_READ_STASH - s->len) {
        return -1;
    }
    return test_read_fill(cfg, s, body, 0);
}

// Hands the caller what the last record left, as much as p holds.
static inline int test_read_give(test_read_stash *s, uint8_t *p, size_t n) {
    size_t take = s->pt_len - s->pt_off < n ? s->pt_len - s->pt_off : n;
    memcpy(p, s->pt + s->pt_off, take);
    s->pt_off += take;
    return (int)take;
}

// One ch_read_in_place over the stash and what its answer means for a
// ch_read caller: 1 to read again, 0 to return rc. Plaintext goes into
// s->pt, and the consumed bytes leave the stash.
static inline int test_read_once(ch_tls *t, test_read_stash *s, int *rc) {
    uint8_t reply[CH_ALERT_RECORD_LEN];
    // A refusal on entry, CH_EINVAL or CH_EPROTO, writes no result.
    ch_read_result result = {0};
    *rc = ch_read_in_place(t, s->bytes, s->len, reply, sizeof reply, &result);
    if (*rc == CH_OK || *rc == CH_ECLOSED) {
        if (result.pt_len > 0) {
            memcpy(s->pt, s->bytes + result.pt_off, result.pt_len);
            s->pt_off = 0;
            s->pt_len = result.pt_len;
        }
        memmove(s->bytes, s->bytes + result.consumed, s->len - result.consumed);
        s->len -= result.consumed;
        return *rc == CH_OK && result.pt_len == 0;
    }
    if (*rc == CH_TCP_AGAIN) {
        return 0;
    }
    const ch_cfg *cfg = &tls_priv(t)->cfg;
    if (result.reply_len > 0 && cfg->send != NULL) {
        (void)cfg->send(cfg->io, reply, result.reply_len);
    }
    return 0;
}

// One pass of test_read: one ch_read_in_place, and one more record from
// recv when that call needs more bytes. Returns 1 to read again, and 0
// with *rc the answer: CH_OK when s holds plaintext, CH_ECLOSED, the
// in-place read's error codes, CH_TCP_AGAIN when recv holds no whole
// record, and CH_EIO when recv stops inside a record.
static inline int test_read_step(ch_tls *t, test_read_stash *s, int *rc) {
    if (test_read_once(t, s, rc)) {
        return 1;
    }
    if (*rc != CH_TCP_AGAIN) {
        return 0;
    }
    int pulled = test_read_pull(&tls_priv(t)->cfg, s);
    if (pulled <= 0) {
        *rc = pulled == 0 ? CH_TCP_AGAIN : CH_EIO;
        return 0;
    }
    return 1;
}

// ch_read's contract, over ch_read_in_place: plaintext into p, 0 for the
// peer's close_notify and after it, CH_TCP_AGAIN when recv holds no whole
// record, and the in-place read's error codes. A recv that stops inside a
// record is CH_EIO, and the session stays as the in-place read left it.
static inline int test_read(ch_tls *t, uint8_t *p, size_t n) {
    test_read_stash *s = test_read_stash_of(t);
    if (s == NULL || n == 0) {
        return CH_EINVAL;
    }
    if (s->pt_len > s->pt_off) {
        return test_read_give(s, p, n);
    }
    for (int quiet = 0; quiet < CH_QUIET_CAP; quiet++) {
        int rc = CH_OK;
        if (test_read_step(t, s, &rc)) {
            continue;
        }
        if (rc == CH_OK) {
            return test_read_give(s, p, n);
        }
        // Every code but CH_OK is negative (result.h), so no code reads
        // as a count of bytes.
        CH_ASSERT(rc < 0);
        return rc == CH_ECLOSED ? 0 : rc;
    }
    return CH_EPROTO;
}
#else
#define test_read(t, p, n) ch_read((t), (p), (n))
#endif

#endif
