// Proves: tls_seal_in_place, tls_writable_len, tls_close_out and
// tls_fail_out (tcp_seal.c), the bodies of ch_seal_in_place,
// ch_writable_len, ch_close_out and ch_fail_out, are memory safe and free
// of UB over an unconstrained session, any cap and n, a buf, a side and a
// result that may each be NULL, and any side_cap. buf sits at the start or
// at the end of a fixed array, either way on one path each, as in
// proof/tcp_read_harness.c, so every bounds check holds each access to
// buf[0..cap). And that the calls keep what tcp_nonblocking.h states:
// - every refusal on entry, CH_EINVAL, CH_EPROTO and the CH_ECAP of an n
//   above ch_writable_len, writes no byte of buf or side and changes no
//   field of the session;
// - a seal that no key can make fails the session through
//   tlsi_fail_into with internal_error into side, and writes no byte of
//   buf;
// - a seal that succeeds seals ceil(n / limit) records, from the last to
//   the first, each at i * (limit + REC_OVERHEAD) bytes into buf with its
//   plaintext at REC_HDR after that, every one but the last of limit bytes,
//   each holding the bytes the caller wrote at REC_HDR + i * limit and each
//   at sequence number first + i, where first is the key's number before
//   the records. The key ends at first + ceil(n / limit). records_len counts
//   the records, at most cap, and no byte of buf past them changes;
// - the KeyUpdate goes into side before the first record, exactly when the
//   key has fewer data records left than the write holds, and no
//   KeyUpdate goes between two records;
// - ch_writable_len's answer is the most plaintext whose records fit cap;
// - ch_close_out and ch_fail_out close or fail a connected session alone,
//   wiped, and write the alert record's length, or 0 when the alert's seal
//   was refused at the last sequence number.
//
// Three launch lines split the formula, because each 64-bit division costs
// the solver a divider: tcp_seal and tcp_seal_suite prove the seal, and
// tcp_seal_rest (-DCH_PROOF_SEAL_REST) ch_writable_len's answer, the close
// and the failure. At one formula the seal took 291 s to 342 s of CPU,
// over the fast tier's five minutes.
//
// What is real and what is a stub. tcp_seal.c is real, and so are the
// rules of tls_write_rules.h it reads. The harness states the KeyUpdate
// rule again in its own words, records_left, and does not include the
// header, so each check holds the code to that statement and not to the
// code itself. rec_seal is a stub of record.h's
// contract, which record.c's harness proves: it asserts each record's
// place, length and content, at one symbolic byte, then writes unknown
// bytes over the header before the plaintext and over the inner type and
// tag after it, as the real seal writes them. So a seal that wrote over a
// record's plaintext before that plaintext moved would fail the content
// assertion of that record. hspost_seal_key_update,
// tlsi_fail_into, tlsi_seal_alert and tlsi_wipe are stubs of their
// contracts (handshake_post.h, session.h). proof/tcp_read_harness.c
// proves the bodies of tlsi_fail_into and tlsi_seal_alert's fatal alert,
// proof/key_update_seal_harness.c the body of hspost_seal_key_update, and
// the unit tests hold the rest.
//
// Bounds. buf's array holds CH_PROOF_SEAL_BUF bytes, 72, and the record
// limit, the smaller of peer_limit and CH_TX_PT, takes every value but
// the content check follows it at 1 to 4 bytes. 72 bytes hold three
// records at a limit of 1 or 2, so the seal moves two of them, and two
// records at a limit of 3 or 4. A record takes 23 bytes at least, so no
// cap of 72 bytes or less holds a fourth. -DCH_SUITE_AES_GCM
// builds the formula again with the write key's suite and sequence number
// unconstrained, so records_per_key's AES-GCM arm runs too.
#include "harness.h"

#include <string.h>

#include "handshake_message.h"
#include "handshake_post.h"
#include "record.h"
#include "session.h"
#include "suite.h"
#include "tls_calls.h"

#ifndef CH_PROOF_SEAL_BUF
#define CH_PROOF_SEAL_BUF 72
#endif
// The largest limit the content check follows.
#define SEAL_LIMIT_MAX 4
#define SIDE_ARRAY (CH_KEY_UPDATE_RECORD_LEN + 4)

static ch_tls_priv t;
static ch_seal_result res;
static uint8_t store[CH_PROOF_SEAL_BUF];
static uint8_t side_store[SIDE_ARRAY];
static uint8_t *buf;
static size_t cap;
// The side the seal was given.
static const uint8_t *side_given;

// What the stubs saw, for the checks after the call.
static size_t limit_seen;
static size_t seal_n;
// The records a seal of seal_n bytes holds, and the sequence number the
// first of them takes: the key's before the call, or 0 after a KeyUpdate.
static size_t seal_count;
static uint64_t seq_first;
static size_t pt_len_total;
static size_t seals;
static size_t key_updates;
static size_t fails;
static size_t wipes;
static size_t seal_alerts;
static uint8_t fail_description;
// One symbolic byte of the caller's plaintext, its offset in buf and its
// value before the call.
static size_t pick;
static uint8_t picked;

// record.h's contract, with the layout tcp_seal.c states asserted.
int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap_out,
             size_t *out_len) {
    __CPROVER_assert(d == &t.wr, "seal: under the write key");
    __CPROVER_assert(type == REC_APPDATA, "seal: a record of application data");
    __CPROVER_assert(seals < seal_count, "seal: ceil(n / limit) records at most");
    size_t i = seal_count - 1 - seals;
    __CPROVER_assert(d->seq == seq_first + i, "seal: record i at sequence number first + i");
    __CPROVER_assert(out == buf + i * (limit_seen + REC_OVERHEAD),
                     "seal: record i starts at i * (limit + REC_OVERHEAD)");
    __CPROVER_assert(pt == out + REC_HDR, "seal: the plaintext lies REC_HDR after its record");
    __CPROVER_assert(cap_out == n + REC_OVERHEAD, "seal: the record's room is its length");
    __CPROVER_assert(n >= 1 && n <= limit_seen, "seal: 1 to limit bytes in a record");
    __CPROVER_assert(n == limit_seen || i + 1 == seal_count, "seal: only the last record is short");
    __CPROVER_assert(__CPROVER_w_ok(out, n + REC_OVERHEAD), "seal: the record is in buf");
    size_t from = REC_HDR + i * limit_seen;
    if (limit_seen <= SEAL_LIMIT_MAX && pick >= from && pick < from + n) {
        __CPROVER_assert(pt[pick - from] == picked, "seal: the record holds the caller's bytes");
    }
    fill_nondet(out, REC_HDR);
    fill_nondet(out + REC_HDR + n, 1 + AEAD_TAG);
    pt_len_total += n;
    seals++;
    d->seq++;
    *out_len = n + REC_OVERHEAD;
    return 0;
}

// handshake_post.h's contract: one record of CH_KEY_UPDATE_RECORD_LEN
// bytes in out, the next key, one more KeyUpdate counted and no answer
// owed; CH_ECAP with nothing written at the last sequence number.
int hspost_seal_key_update(ch_tls_priv *session, uint8_t *out, size_t out_cap, size_t *out_len) {
    __CPROVER_assert(session == &t, "key update: the session sealed for");
    __CPROVER_assert(seals == 0, "key update: before the first record");
    __CPROVER_assert(out == side_given, "key update: into side");
    __CPROVER_assert(out_cap >= CH_KEY_UPDATE_RECORD_LEN, "key update: side holds the record");
    __CPROVER_assert(session->send_epochs < HSPOST_SEND_EPOCHS_MAX, "key update: below the cap");
    *out_len = 0;
    if (session->wr.seq == UINT64_MAX) {
        return CH_ECAP;
    }
    fill_nondet(out, CH_KEY_UPDATE_RECORD_LEN);
    *out_len = CH_KEY_UPDATE_RECORD_LEN;
    session->wr.seq = 0;
    seq_first = 0;
    session->send_epochs++;
    session->key_update_owed = 0;
    key_updates++;
    return CH_OK;
}

// session.h's contract: the alert sealed into out, the session failed.
int tlsi_fail_into(ch_tls_priv *session, uint8_t description, uint8_t *out, size_t *out_len) {
    __CPROVER_assert(session == &t, "fail: the session sealed for");
    __CPROVER_assert(__CPROVER_w_ok(out, CH_ALERT_RECORD_LEN), "fail: out holds an alert");
    fail_description = description;
    fails++;
    *out_len = 0;
    if (nondet_u8() & 1) {
        fill_nondet(out, CH_ALERT_RECORD_LEN);
        *out_len = CH_ALERT_RECORD_LEN;
    }
    session->state = CH_ST_FAILED;
    session->keys = 0;
    return *out_len == 0 ? CH_ECAP : CH_OK;
}

int tlsi_seal_alert(ch_tls_priv *session, uint8_t level, uint8_t description, uint8_t *out,
                    size_t *out_len) {
    __CPROVER_assert(session == &t && session->keys, "close: under the live write key");
    __CPROVER_assert(level == 1 && description == ALERT_CLOSE_NOTIFY, "close: close_notify");
    __CPROVER_assert(__CPROVER_w_ok(out, CH_ALERT_RECORD_LEN), "close: out holds an alert");
    seal_alerts++;
    *out_len = 0;
    if (nondet_u8() & 1) {
        return CH_ECAP; // the last sequence number (RFC 9846 §5.3)
    }
    fill_nondet(out, CH_ALERT_RECORD_LEN);
    *out_len = CH_ALERT_RECORD_LEN;
    return CH_OK;
}

void tlsi_wipe(ch_tls_priv *session) {
    session->keys = 0;
    wipes++;
}

// The data records the write key has left before a KeyUpdate is due:
// none while the peer's request is owed an answer (RFC 9846 §4.7.3),
// REC_AES_GCM_RECORDS_MAX - 1 less the sequence number under an AES-GCM
// key, whose last number the KeyUpdate takes (RFC 9846 §5.5), and no
// limit under ChaCha20-Poly1305.
static size_t records_left(const ch_tls_priv *s) {
    if (s->key_update_owed) {
        return 0;
    }
#ifdef CH_SUITE_AES_GCM
    if (suite_runs_aes_gcm(s->wr.suite)) {
        uint64_t per_key = REC_AES_GCM_RECORDS_MAX - 1;
        return s->wr.seq < per_key ? (size_t)(per_key - s->wr.seq) : 0;
    }
#endif
    return SIZE_MAX;
}

// Whether m bytes of plaintext go out in records that fit cap_in, at limit
// bytes a record: tcp_nonblocking.h's n + ceil(n / limit) * REC_OVERHEAD.
static int fits(size_t m, size_t limit, size_t cap_in) {
    if (m == 0) {
        return 1;
    }
    size_t records = (m - 1) / limit + 1;
    return m + records * REC_OVERHEAD <= cap_in;
}

// The fields of the session a refusal must leave as they were.
typedef struct {
    uint8_t state;
    uint8_t owed;
    uint64_t seq;
    uint64_t epochs;
} session_fields;

static session_fields fields_of(const ch_tls_priv *s) {
    session_fields f = {s->state, s->key_update_owed, s->wr.seq, s->send_epochs};
    return f;
}

static int fields_kept(session_fields f) {
    return f.state == t.state && f.owed == t.key_update_owed && f.seq == t.wr.seq &&
           f.epochs == t.send_epochs;
}

// The answers of a seal that succeeded with n of 1 or more.
static void check_sealed(size_t n, size_t left_before) {
    size_t records = seal_count;
    __CPROVER_assert(seals == records && pt_len_total == n,
                     "seal: ceil(n / limit) records of n bytes");
    __CPROVER_assert(res.records_len == n + records * REC_OVERHEAD,
                     "seal: records_len counts them");
    __CPROVER_assert(res.records_len <= cap, "seal: the records fit cap");
    int due = left_before < records;
    __CPROVER_assert(key_updates == (size_t)due, "seal: a KeyUpdate exactly when one is due");
    __CPROVER_assert(res.side_len == (due ? CH_KEY_UPDATE_RECORD_LEN : 0), "seal: side_len");
    __CPROVER_assert(!due || t.key_update_owed == 0, "seal: no answer owed after a KeyUpdate");
    __CPROVER_assert(t.wr.seq == seq_first + records, "seal: the key ends past the last record");
    if (pick >= res.records_len) {
        __CPROVER_assert(buf[pick] == picked, "seal: no byte past the records changes");
    }
}

static void check_seal(void) {
    cap = nondet_size_t();
    __CPROVER_assume(cap <= CH_PROOF_SEAL_BUF);
    buf = (nondet_u8() & 1) ? store : store + (CH_PROOF_SEAL_BUF - cap);
    fill_nondet(store, sizeof store);
    size_t side_cap = nondet_size_t();
    __CPROVER_assume(side_cap <= SIDE_ARRAY);
    uint8_t *side = (nondet_u8() & 1) ? side_store : side_store + (SIDE_ARRAY - side_cap);
    size_t n = nondet_size_t();
    uint8_t *b = (nondet_u8() & 1) ? NULL : buf;
    uint8_t *s = (nondet_u8() & 1) ? NULL : side;
    side_given = s;
    ch_seal_result *r = (nondet_u8() & 1) ? NULL : &res;
    limit_seen = t.peer_limit < CH_TX_PT ? t.peer_limit : CH_TX_PT;
    seal_n = n;
    seal_count = n > 0 && limit_seen > 0 ? (n - 1) / limit_seen + 1 : 0;
    seq_first = t.wr.seq;
    pick = nondet_size_t();
    __CPROVER_assume(pick < cap);
    picked = buf[pick];
    size_t side_pick = nondet_size_t();
    __CPROVER_assume(side_pick < side_cap);
    uint8_t side_picked = side[side_pick];
    size_t left_before = records_left(&t);
    session_fields before = fields_of(&t);

    int rc = tls_seal_in_place(&t, b, cap, n, s, side_cap, r);

    int refused = rc == CH_EINVAL || rc == CH_EPROTO || (rc == CH_ECAP && fails == 0);
    if (refused) {
        __CPROVER_assert(fields_kept(before) && seals == 0 && key_updates == 0,
                         "seal: a refusal changes no field");
        __CPROVER_assert(buf[pick] == picked && side[side_pick] == side_picked,
                         "seal: a refusal writes no byte of buf or side");
    }
    if (rc == CH_EINVAL) {
        __CPROVER_assert(r == NULL || s == NULL || side_cap < CH_KEY_UPDATE_RECORD_LEN ||
                             (b == NULL && n != 0),
                         "seal: CH_EINVAL for the refusals on entry alone");
    }
    if (rc == CH_EPROTO) {
        __CPROVER_assert(before.state != CH_ST_CONNECTED,
                         "seal: CH_EPROTO off a connected session");
    }
    if (fails > 0) {
        __CPROVER_assert(rc == CH_ECAP && fail_description == ALERT_INTERNAL_ERROR,
                         "seal: a failure is CH_ECAP with internal_error");
        __CPROVER_assert(t.state == CH_ST_FAILED && seals == 0 && res.records_len == 0,
                         "seal: a failure seals no record");
        __CPROVER_assert(buf[pick] == picked, "seal: a failure writes no byte of buf");
    }
    if (rc == CH_OK && n == 0) {
        __CPROVER_assert(seals == 0 && key_updates == 0 && res.records_len == 0 &&
                             res.side_len == 0,
                         "seal: n of 0 writes nothing");
    }
    if (rc == CH_OK && n > 0) {
        check_sealed(n, left_before);
    }
}

// ch_writable_len's answer is the most plaintext whose records fit cap, at
// any record limit and any cap of CH_PROOF_WRITABLE_CAP_BITS bits.
#define CH_PROOF_WRITABLE_CAP_BITS 11

static void check_writable_len(void) {
    size_t limit = t.peer_limit < CH_TX_PT ? t.peer_limit : CH_TX_PT;
    size_t any_cap = nondet_size_t() & (((size_t)1 << CH_PROOF_WRITABLE_CAP_BITS) - 1);
    size_t wl = tls_writable_len(&t, any_cap);
    if (limit == 0) {
        __CPROVER_assert(wl == 0, "writable_len: 0 at a limit of 0");
        return;
    }
    __CPROVER_assert(fits(wl, limit, any_cap), "writable_len: the answer's records fit cap");
    __CPROVER_assert(!fits(wl + 1, limit, any_cap), "writable_len: one byte more does not");
}

// An out of up to SIDE_ARRAY bytes at either end of side_store, or NULL,
// and an out_len that may be NULL.
static uint8_t *any_out(size_t *out_cap) {
    *out_cap = nondet_size_t();
    __CPROVER_assume(*out_cap <= SIDE_ARRAY);
    if (nondet_u8() & 1) {
        return NULL;
    }
    return (nondet_u8() & 1) ? side_store : side_store + (SIDE_ARRAY - *out_cap);
}

static void check_close(void) {
    size_t out_cap = 0;
    uint8_t *out = any_out(&out_cap);
    size_t out_len = 1;
    size_t *len = (nondet_u8() & 1) ? NULL : &out_len;
    session_fields before = fields_of(&t);
    int rc = tls_close_out(&t, out, out_cap, len);
    if (rc == CH_EINVAL) {
        __CPROVER_assert(out == NULL || len == NULL || out_cap < CH_ALERT_RECORD_LEN,
                         "close: CH_EINVAL for the refusals on entry alone");
    }
    if (rc == CH_EINVAL || rc == CH_EPROTO) {
        __CPROVER_assert(fields_kept(before) && wipes == 0, "close: a refusal changes nothing");
    }
    if (rc == CH_EPROTO) {
        __CPROVER_assert(before.state != CH_ST_CONNECTED,
                         "close: CH_EPROTO off a connected session");
    }
    __CPROVER_assert(rc == CH_OK || rc == CH_ECAP || rc == CH_EINVAL || rc == CH_EPROTO,
                     "close: the codes tcp_nonblocking.h lists");
    if (rc == CH_OK || rc == CH_ECAP) {
        __CPROVER_assert(before.state == CH_ST_CONNECTED && t.state == CH_ST_CLOSED && wipes == 1 &&
                             seal_alerts == 1,
                         "close: a connected session closes, wiped, after one close_notify");
        __CPROVER_assert(out_len == (rc == CH_OK ? CH_ALERT_RECORD_LEN : 0),
                         "close: one alert record, or none at the last sequence number");
    }
}

static void check_fail(void) {
    size_t out_cap = 0;
    uint8_t *out = any_out(&out_cap);
    size_t out_len = 1;
    size_t *len = (nondet_u8() & 1) ? NULL : &out_len;
    uint8_t description = nondet_u8();
    session_fields before = fields_of(&t);
    int rc = tls_fail_out(&t, description, out, out_cap, len);
    if (description == ALERT_CLOSE_NOTIFY || description == ALERT_USER_CANCELED) {
        __CPROVER_assert(rc == CH_EINVAL, "fail: the two closure alerts are refused");
    }
    if (rc == CH_EINVAL || rc == CH_EPROTO) {
        __CPROVER_assert(fields_kept(before) && fails == 0, "fail: a refusal changes nothing");
    }
    if (rc == CH_EPROTO) {
        __CPROVER_assert(before.state != CH_ST_CONNECTED,
                         "fail: CH_EPROTO off a connected session");
    }
    __CPROVER_assert(rc == CH_OK || rc == CH_ECAP || rc == CH_EINVAL || rc == CH_EPROTO,
                     "fail: the codes tcp_nonblocking.h lists");
    if (rc == CH_OK || rc == CH_ECAP) {
        __CPROVER_assert(fails == 1 && fail_description == description,
                         "fail: one alert through tlsi_fail_into");
        __CPROVER_assert(before.state == CH_ST_CONNECTED && t.state == CH_ST_FAILED,
                         "fail: a connected session alone, which fails");
        __CPROVER_assert(out_len == (rc == CH_OK ? CH_ALERT_RECORD_LEN : 0),
                         "fail: one alert record, or none at the last sequence number");
    }
}

int main(void) {
    t.state = nondet_u8();
    __CPROVER_assume(t.state <= CH_ST_FAILED);
    t.keys = t.state == CH_ST_CONNECTED ? 1 : nondet_u8();
    t.peer_limit = (uint16_t)nondet_u32();
    t.key_update_owed = nondet_u8() & 1;
    t.send_epochs = (uint64_t)nondet_i64();
    t.wr.seq = (uint64_t)nondet_i64();
#ifdef CH_SUITE_AES_GCM
    t.wr.suite = (uint16_t)nondet_u32();
#endif
#ifdef CH_PROOF_SEAL_REST
    // ch_writable_len over any session and any cap, then its answer, the
    // close and the failure.
    (void)tls_writable_len(&t, nondet_size_t());
    switch (nondet_u8() % 3) {
    case 0:
        check_writable_len();
        break;
    case 1:
        check_close();
        break;
    default:
        check_fail();
        break;
    }
#else
    check_seal();
#endif
    return 0;
}
