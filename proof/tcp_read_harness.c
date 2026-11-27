// Proves: tls_read_in_place (tcp_read.c), the body of ch_read_in_place, is
// memory safe and free of UB over unconstrained caller bytes p[0..n), an
// unconstrained session, a reply and a result that may each be NULL, and
// any held_len and held_fill its contract-point guard admits. p sits at
// the start or at the end of a fixed array, either way on one path each:
// an access below p[0] leaves the array in the first placement, and one
// at p[n] or past it in the second, so every bounds check, the ones
// CBMC's memmove and memset make included, holds each access to p[0..n).
// reply sits at the start or the end of its array the same way. The code
// reads no address, so its path is the same in both placements. A heap
// object of n bytes states the same bound, and one record took the
// formula past 6 GB that way. And that the call keeps what
// tcp_nonblocking.h states:
// - CH_EINVAL, and CH_EPROTO on a session that is not connected, change
//   neither p, the session nor result;
// - CH_OK consumes exactly the bytes the call opened, the held ones
//   among them, at most n, and names the last record's plaintext or none;
// - CH_TCP_AGAIN consumes nothing, and held_len then counts exactly the
//   bytes the call opened, which the caller presents again;
// - CH_ECLOSED consumes the close_notify record and closes the read side,
//   or consumes nothing on a session that is closed already;
// - a message in parts reaches hspost_handle as one run: the held bytes,
//   then the new record's plaintext, ending where that plaintext ends,
//   which the KeyUpdate rule of RFC 9846 §5.1 reads. The bytes the run
//   leaves are the last held_fill bytes of the held_len the next call
//   presents;
// - every other code leaves the session dead and holding no secret, with
//   p[0..opened) zero, consumed 0, and one alert sealed into reply before
//   the wipe, none after the peer's fatal alert (INV-13, INV-17);
// - bytes past the ones the call opened stay as they were, on every path;
// - held_fill <= held_len on every path, held_len <= n when the session
//   stays connected, and the state a connected session holds between
//   calls (both 0, or 0 < held_fill < held_len <= cfg.buf_len) holds after
//   a call that found it.
//
// What is real and what is a stub. tcp_read.c, session.c's tlsi_wipe and
// tlsi_close_read_side, and buf.c's reader are real. rec_open and rec_seal
// are stubs of record.h's contract, which record.c's harness proves. The
// rec_open stub takes a record of any body of 1 byte or more, and returns
// any plaintext shorter than the body and any inner type. record.c needs
// a body of 17 bytes or more, so the stub's answers are a superset of its
// answers. It may write any bytes over the body whether or not it opens
// the record. hspost_handle is a stub: handshake_post's harness proves
// handle_post_handshake, the function it calls, used <= n among it.
// hsr_refuse_alert is a stub of handshake_record.h's contract. ct_wipe
// writes its zeros with one memset, as in proof/tcp_nonblocking_harness.c;
// ct_wipe's harness proves the body. A connected session gave cfg.buf
// back (session.h, tlsi_give_back_buf), so cfg.buf is NULL here and
// cfg.buf_len is any value.
//
// Bounds. n is at most CH_PROOF_INBUF, 20 bytes. A record takes 6 bytes
// at least under the stub, so p holds three whole records and two bytes
// of a fourth header, or a held record of 7 bytes, whose 2-byte body
// opens to a 1-byte plaintext, then one more of 7 and one of 6. So a
// message in parts arrives with the call and grows inside it. The record
// loop runs at most four times, and read_records.0's bound of 4 covers
// it; unwinding assertions prove the bound. At 24 bytes, four whole
// records, the formula took 359 s, past the fast tier's five minutes.
// The header's length field takes every value from 0 to 65535, so the
// record_overflow arm runs too.
#include "harness.h"

#include <string.h>

#include "handshake_message.h"
#include "handshake_post.h"
#include "handshake_record.h"
#include "record.h"
#include "session.h"
#include "tls_calls.h"

#ifndef CH_PROOF_INBUF
#define CH_PROOF_INBUF 20
#endif
// The largest reply_cap the harness gives: room for one alert record and
// some bytes past it.
#define CH_PROOF_REPLY (CH_ALERT_RECORD_LEN + 8)

int nondet_int(void);

static ch_tls_priv t;
static ch_read_result res;
static uint8_t in[CH_PROOF_INBUF];
static uint8_t out[CH_PROOF_REPLY];

// The caller's buffers, as the stubs see them.
static uint8_t *p_base;
static size_t p_len;
static uint8_t *reply_base;

// What the stubs record. opened_end is the end of the last record
// rec_open saw, in bytes of p, or held_len before the first one: the
// call's opened count. plain_off and plain_len name that record's
// plaintext.
static size_t opened_end;
static size_t records_opened;
static size_t plain_off;
static size_t plain_len;
static size_t seal_count;
static uint8_t sealed_alert;

// One byte of each part of the run, each at an index of any value, taken
// where the part lies before tcp_read.c moves it: a byte of the held
// bytes, a byte of the new plaintext, and a byte of what the run left.
static int held_valid;
static size_t held_k;
static uint8_t held_byte;
static int plain_valid;
static size_t plain_k;
static uint8_t plain_byte;
static int left_valid;
static size_t left_k;
static uint8_t left_byte;

void ct_wipe(void *p, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(p, n), "wipe: the bytes are writable");
    if (n != 0) {
        memset(p, 0, n);
    }
}

// Takes a byte of the bytes a message in parts holds, at the end of the
// held bytes before the record at off, and checks the byte the last run
// left there.
static void note_held(size_t off) {
    size_t fill = t.held_fill;
    __CPROVER_assert(fill <= off, "open: the held bytes end where this record starts");
    if (left_valid) {
        __CPROVER_assert(left_k < fill && p_base[off - fill + left_k] == left_byte,
                         "the bytes a run left wait at the end of its record");
        left_valid = 0;
    }
    held_valid = 0;
    if (fill > 0) {
        size_t k = nondet_size_t();
        __CPROVER_assume(k < fill);
        held_k = k;
        held_byte = p_base[off - fill + k];
        held_valid = 1;
    }
}

// Record protection, proved in record.c's harness. tcp_read.c opens each
// record in place with pt == rec + REC_HDR.
int rec_open(rec_dir *d, const uint8_t *rec, size_t rec_len, uint8_t *pt, size_t pt_cap,
             size_t *pt_len, uint8_t *inner) {
    __CPROVER_assert(d == &t.rd, "open: under the read key");
    __CPROVER_assert(p_base != NULL && __CPROVER_same_object(rec, p_base) && rec >= p_base,
                     "open: the record lies in p");
    size_t off = (size_t)(rec - p_base);
    __CPROVER_assert(rec_len > REC_HDR && off <= p_len && rec_len <= p_len - off,
                     "open: the whole record lies in p[0..n)");
    __CPROVER_assert(pt == rec + REC_HDR && pt_cap == rec_len - REC_HDR,
                     "open: in place, the plaintext over the body");
    __CPROVER_assert(pt_len != NULL && inner != NULL, "open: outputs valid");
    note_held(off);
    records_opened++;
    opened_end = off + rec_len;
    size_t written = nondet_size_t();
    __CPROVER_assume(written <= pt_cap);
    __CPROVER_havoc_slice(pt, written);
    d->seq = (uint64_t)nondet_i64();
    if (nondet_u8() & 1) {
        return -1;
    }
    size_t len = nondet_size_t();
    __CPROVER_assume(len < pt_cap);
    *pt_len = len;
    *inner = nondet_u8();
    plain_off = off + REC_HDR;
    plain_len = len;
    plain_valid = 0;
    if (len > 0) {
        size_t k = nondet_size_t();
        __CPROVER_assume(k < len);
        plain_k = k;
        plain_byte = pt[k];
        plain_valid = 1;
    }
    return 0;
}

// The alert seal of the failure funnel, proved in record.c's harness.
int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *dst, size_t cap,
             size_t *out_len) {
    __CPROVER_assert(d == &t.wr, "seal: under the write key");
    __CPROVER_assert(t.state == CH_ST_CONNECTED, "seal: before the wipe kills the session");
    __CPROVER_assert(t.alert_received == 0, "seal: never after the peer's fatal alert");
    __CPROVER_assert(type == REC_ALERT && n == 2 && __CPROVER_r_ok(pt, n) && pt[0] == 2,
                     "seal: one fatal alert");
    __CPROVER_assert(dst == reply_base && cap == CH_ALERT_RECORD_LEN && out_len != NULL,
                     "seal: one alert record into the caller's reply");
    __CPROVER_assert(__CPROVER_w_ok(dst, cap), "seal: the reply holds the record");
    seal_count++;
    sealed_alert = pt[1];
    __CPROVER_havoc_slice(dst, cap);
    if (nondet_u8() & 1) {
        *out_len = nondet_size_t();
        return -1; // the last sequence number (RFC 9846 §5.3)
    }
    *out_len = REC_OVERHEAD + n;
    return 0;
}

// handshake_post.h's contract for the tcp-nonblocking transport. The run
// is checked part by part against the bytes the stubs above took.
int hspost_handle(ch_tls_priv *s, const uint8_t *pt, size_t n, size_t *used, uint8_t *alert) {
    __CPROVER_assert(s == &t && used != NULL && alert != NULL, "handle: the session, outputs");
    __CPROVER_assert(*alert == ALERT_UNEXPECTED_MESSAGE, "handle: the caller's default alert");
    size_t fill = s->held_fill;
    __CPROVER_assert(n == fill + plain_len && __CPROVER_same_object(pt, p_base) &&
                         pt + n == p_base + plain_off + plain_len,
                     "handle: one run that ends where the record's plaintext ends");
    if (held_valid) {
        __CPROVER_assert(pt[held_k] == held_byte, "handle: the held bytes lead the run");
    }
    if (plain_valid) {
        __CPROVER_assert(pt[fill + plain_k] == plain_byte,
                         "handle: the record's plaintext follows them");
    }
    // A KeyUpdate moves the read key and the run count; a ticket reads
    // the session and writes none of what tcp_read.c reads.
    s->key_update_run = nondet_u8();
    s->key_update_owed = nondet_u8();
    s->rd.seq = (uint64_t)nondet_i64();
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EPROTO || rc == CH_KEY_UPDATE_LIMIT);
    if (rc != CH_OK) {
        if (nondet_u8() & 1) {
            *alert = nondet_u8();
        }
        return rc;
    }
    size_t took = nondet_size_t();
    __CPROVER_assume(took <= n);
    *used = took;
    left_valid = 0;
    if (took < n) {
        size_t k = nondet_size_t();
        __CPROVER_assume(k < n - took);
        left_k = k;
        left_byte = pt[took + k];
        left_valid = 1;
    }
    return CH_OK;
}

// handshake_record.h's contract: a record that is not one 2-byte alert
// writes decode_error, an error alert is written to alert_received, and
// the answer is CH_EPROTO.
int hsr_refuse_alert(ch_tls_priv *s, const uint8_t *pt, size_t n, uint8_t *alert) {
    __CPROVER_assert(s == &t && alert != NULL, "refuse alert: the session, outputs");
    __CPROVER_assert(pt == p_base + plain_off && n == plain_len,
                     "refuse alert: the record's plaintext");
    if (n != 2) {
        *alert = ALERT_DECODE_ERROR;
        return CH_EPROTO;
    }
    if (pt[1] != ALERT_CLOSE_NOTIFY && pt[1] != ALERT_USER_CANCELED) {
        s->alert_received = pt[1];
    }
    return CH_EPROTO;
}

// The state a connected session holds between calls (session.h): no
// message in parts, or one whose held_fill bytes end the held_len bytes
// of its records, which take at most cfg.buf_len bytes together.
static int held_state_ok(const ch_tls_priv *s) {
    if (s->held_len == 0) {
        return s->held_fill == 0;
    }
    return s->held_fill > 0 && s->held_fill < s->held_len && s->held_len <= s->cfg.buf_len;
}

static void check_refused(int rc, uint8_t state, size_t held_len, size_t held_fill,
                          const ch_read_result *result, const ch_read_result *before) {
    __CPROVER_assert(rc == CH_EINVAL || rc == CH_EPROTO || rc == CH_ECLOSED,
                     "a call that reads nothing refuses it or reports the close");
    __CPROVER_assert(t.state == state && t.held_len == held_len && t.held_fill == held_fill &&
                         records_opened == 0 && seal_count == 0,
                     "and changes nothing of the session");
    if (result == NULL) {
        return;
    }
    if (rc == CH_ECLOSED) {
        __CPROVER_assert(res.consumed == 0 && res.pt_off == 0 && res.pt_len == 0 &&
                             res.reply_len == 0,
                         "CH_ECLOSED on a closed session consumes nothing");
    } else {
        __CPROVER_assert(res.consumed == before->consumed && res.pt_off == before->pt_off &&
                             res.pt_len == before->pt_len && res.reply_len == before->reply_len,
                         "a refusal on entry leaves result as it was");
    }
}

static void check_failed(int rc, uint8_t limit_sent) {
    __CPROVER_assert(t.state == CH_ST_FAILED && t.keys == 0 && t.held_len == 0 && t.held_fill == 0,
                     "a failure leaves the session dead, holding no message in parts");
    size_t k = nondet_size_t();
    __CPROVER_assume(k < sizeof t.rd_secret);
    __CPROVER_assert(t.rd_secret[k] == 0 && t.wr_secret[k] == 0 && t.res_master[k] == 0,
                     "and holding no secret (INV-17)");
    __CPROVER_assert(res.consumed == 0 && res.pt_off == 0 && res.pt_len == 0,
                     "a failure consumes nothing and names no plaintext");
    __CPROVER_assert(res.reply_len == 0 || res.reply_len == CH_ALERT_RECORD_LEN,
                     "the reply holds one alert record or nothing");
    if (t.alert_received != 0) {
        __CPROVER_assert(seal_count == 0 && res.reply_len == 0,
                         "no alert after the peer's fatal alert (RFC 9846 §6.2)");
    } else {
        __CPROVER_assert(seal_count == 1 && t.alert_sent == sealed_alert,
                         "one alert sealed, and alert_sent names it");
    }
    if (opened_end > 0) {
        size_t i = nondet_size_t();
        __CPROVER_assume(i < opened_end);
        __CPROVER_assert(p_base[i] == 0, "every byte the call opened is wiped");
    }
    if (seal_count != 0 && rc == CH_EAUTH) {
        __CPROVER_assert(sealed_alert == ALERT_BAD_RECORD_MAC,
                         "a record that does not open gets bad_record_mac");
    }
    if (seal_count != 0 && rc == CH_ECAP) {
        __CPROVER_assert(sealed_alert ==
                             (limit_sent ? ALERT_RECORD_OVERFLOW : ALERT_INTERNAL_ERROR),
                         "a record over cfg.buf_len gets the answer io.c gives");
    }
}

static void check_read(int rc, size_t n, size_t held_len, int held_ok) {
    __CPROVER_assert(t.state == CH_ST_CONNECTED && seal_count == 0 && res.reply_len == 0,
                     "a read that does not fail leaves the session connected, with no alert");
    __CPROVER_assert(t.held_len <= n, "held_len stays within the caller's bytes");
    if (held_ok) {
        __CPROVER_assert(held_state_ok(&t), "the held state stays one a connected session holds");
    }
    if (rc == CH_OK) {
        __CPROVER_assert(res.consumed > 0 && res.consumed <= n && res.consumed == opened_end &&
                             res.consumed >= held_len,
                         "CH_OK consumes exactly the bytes it opened, the held ones among them");
        __CPROVER_assert(res.pt_off + res.pt_len <= res.consumed, "the plaintext lies inside them");
        if (res.pt_len == 0) {
            __CPROVER_assert(res.pt_off == 0, "no plaintext names offset 0");
        } else {
            __CPROVER_assert(res.pt_off == plain_off && res.pt_len == plain_len &&
                                 t.key_update_run == 0,
                             "the plaintext is the last record's, and it ends a KeyUpdate run");
        }
        if (held_ok) {
            __CPROVER_assert(t.held_len == 0 && t.held_fill == 0,
                             "and no message in parts stays behind it");
        }
    } else if (rc == CH_TCP_AGAIN) {
        __CPROVER_assert(res.consumed == 0 && res.pt_off == 0 && res.pt_len == 0,
                         "CH_TCP_AGAIN consumes nothing");
        __CPROVER_assert(t.held_len == opened_end, "held_len counts the bytes the call opened");
        if (left_valid) {
            __CPROVER_assert(left_k < t.held_fill &&
                                 p_base[t.held_len - t.held_fill + left_k] == left_byte,
                             "the bytes the run left end the held bytes");
        }
    } else {
        __CPROVER_assert(t.read_closed == 1 && res.consumed > 0 && res.consumed == opened_end &&
                             res.pt_len == 0,
                         "close_notify is consumed and closes the read side");
        size_t k = nondet_size_t();
        __CPROVER_assume(k < sizeof t.rd_secret);
        __CPROVER_assert(t.rd_secret[k] == 0 && t.res_master[k] == 0,
                         "with the read secrets wiped (INV-17)");
    }
}

int main(void) {
    __CPROVER_havoc_object(&t);
    uint8_t state = t.state;
    __CPROVER_assume(state <= CH_ST_FAILED);
    __CPROVER_assume(t.held_fill <= t.held_len);
    t.cfg.buf = NULL;
    size_t held_len = t.held_len;
    size_t held_fill = t.held_fill;
    uint8_t limit_sent = t.limit_sent;
    int held_ok = held_state_ok(&t);

    size_t n = nondet_size_t();
    __CPROVER_assume(n <= CH_PROOF_INBUF);
    __CPROVER_havoc_object(in);
    uint8_t *p = (nondet_u8() & 1) ? NULL : in + ((nondet_u8() & 1) ? 0 : sizeof in - n);
    size_t reply_cap = nondet_size_t();
    __CPROVER_assume(reply_cap <= CH_PROOF_REPLY);
    uint8_t *reply = NULL;
    if (nondet_u8() & 1) {
        reply = out + ((nondet_u8() & 1) ? 0 : sizeof out - reply_cap);
    }
    ch_read_result *result = (nondet_u8() & 1) ? NULL : &res;
    __CPROVER_havoc_object(&res);
    ch_read_result before = res;
    p_base = p;
    p_len = n;
    reply_base = reply;

    int walk = result != NULL && reply != NULL && reply_cap >= CH_ALERT_RECORD_LEN &&
               !(p == NULL && n != 0) && state == CH_ST_CONNECTED && n >= held_len &&
               t.read_closed == 0;
    opened_end = walk ? held_len : 0;
    int have_j = p != NULL && n > 0;
    size_t j = nondet_size_t();
    uint8_t orig = 0;
    if (have_j) {
        __CPROVER_assume(j < n);
        orig = p[j];
    }

    int rc = tls_read_in_place(&t, p, n, reply, reply_cap, result);

    __CPROVER_assert(rc == CH_OK || rc == CH_TCP_AGAIN || rc == CH_ECLOSED || rc == CH_EINVAL ||
                         rc == CH_EPROTO || rc == CH_EAUTH || rc == CH_ECAP ||
                         rc == CH_KEY_UPDATE_LIMIT,
                     "the call answers a code its header lists");
    __CPROVER_assert(t.held_fill <= t.held_len, "held_fill stays within held_len");
    __CPROVER_assert(opened_end <= n, "the call opens nothing past n");
    if (have_j && j >= opened_end) {
        __CPROVER_assert(p[j] == orig, "bytes past the ones the call opened stay as they were");
    }
    if (!walk) {
        check_refused(rc, state, held_len, held_fill, result, &before);
        return 0;
    }
    if (rc == CH_OK || rc == CH_TCP_AGAIN || rc == CH_ECLOSED) {
        check_read(rc, n, held_len, held_ok);
    } else {
        check_failed(rc, limit_sent);
    }
    return 0;
}
