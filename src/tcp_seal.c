// ch_seal_in_place, ch_writable_len, ch_close_out and ch_fail_out: the
// send path of a connected TRANSPORT=tcp-nonblocking session, in both
// roles (tcp_nonblocking.h and tls.h state the contracts,
// docs/decisions.md 248 the reasons). Each record goes into storage the
// caller passes, and no call here sends through cfg.send (INV-28).
//
// The rules are tls_write.c's, read through tls_write_rules.h: the most
// plaintext of one record, the KeyUpdate a write owes or a key's ceiling
// asks for, and what a buffer of cap bytes of records carries. Two things
// differ. A write's records are sealed where the caller wrote the
// plaintext, so no byte is copied into ch_tls.tx. And the KeyUpdate a
// write needs goes first, into the caller's side buffer, so every record
// of one write goes out under one key and the write seals all of its
// records or none.
#include "tls_calls.h"

#ifdef CH_TRANSPORT_TCP_NONBLOCKING

#include "ch_assert.h"

#include <string.h>

#include "handshake_message.h"
#include "handshake_post.h"
#include "record.h"
#include "tls_write_rules.h"

// Where the records of one write go. count records carry limit bytes of
// plaintext each, but the last, which carries last_len bytes, 1 to limit.
// Record i starts i * (limit + REC_OVERHEAD) bytes into the caller's
// buffer, and its plaintext REC_HDR bytes after that.
typedef struct {
    size_t limit;
    size_t count;
    size_t last_len;
} seal_layout;

// The layout of n bytes, n of 1 or more, at limit bytes a record. It
// divides once; the caller checked that the records fit its buffer
// (ch_writable_len), so no product below passes the buffer's length.
static seal_layout layout_of(size_t n, size_t limit) {
    CH_ASSERT(n > 0 && limit > 0);
    seal_layout layout;
    layout.limit = limit;
    layout.count = (n - 1) / limit + 1;
    layout.last_len = n - (layout.count - 1) * limit;
    CH_ASSERT(layout.last_len >= 1 && layout.last_len <= limit);
    return layout;
}

// The plaintext length of record i.
static size_t record_len_at(const seal_layout *layout, size_t i) {
    return i + 1 == layout->count ? layout->last_len : layout->limit;
}

// Moves each record's plaintext to its place among the records and seals
// it there, from the last record to the first. The caller wrote the
// plaintext in one run at REC_HDR, so record i's plaintext starts REC_HDR
// + i * limit bytes into buf and its place REC_HDR + i * (limit +
// REC_OVERHEAD) bytes in: i * REC_OVERHEAD bytes further on. Record i then
// takes the bytes from i * (limit + REC_OVERHEAD), its header, to where
// record i + 1 starts, its inner type and tag. Each lies past the
// plaintext of every record before i, which waits in its first place, so
// no byte that waits is overwritten, and the first record's plaintext is
// in its place from the start. Each record is sealed right after its move,
// while its bytes are in the cache.
//
// rec_seal writes the header before the plaintext and the inner type and
// the tag after it, and seals with pt == out + REC_HDR, which record.h
// allows. It seals at the write key's sequence number and adds one, so
// each record takes first + i, the number it takes when the records are
// sealed front to back, and the peer opens them in the order the caller
// sends them. The key ends at first + count. The checks before this call
// leave the key a sequence number for each record (key_for_write) and the
// buffer room for each (ch_writable_len), so a seal that refuses is a
// fault of this file, and it halts.
static void seal_records(ch_tls_priv *t, uint8_t *buf, const seal_layout *layout) {
    size_t stride = layout->limit + REC_OVERHEAD;
    uint64_t first = t->wr.seq;
    for (size_t i = layout->count; i-- > 0;) {
        size_t len = record_len_at(layout, i);
        uint8_t *rec = buf + i * stride;
        if (i > 0) {
            memmove(rec + REC_HDR, buf + i * layout->limit + REC_HDR, len);
        }
        t->wr.seq = first + i;
        size_t out_len = 0;
        int rc =
            rec_seal(&t->wr, REC_APPDATA, rec + REC_HDR, len, rec, len + REC_OVERHEAD, &out_len);
        CH_ASSERT(rc == 0 && out_len == len + REC_OVERHEAD);
    }
    t->wr.seq = first + layout->count;
}

// The failure of a write that no key can seal. It fails the session as
// tlsi_fail does, with internal_error sealed into side, and seals nothing
// in the caller's buffer. ch_write answers CH_ECAP for the same
// conditions on the other transport (tls_write.c).
static int fail_write(ch_tls_priv *t, uint8_t *side, ch_seal_result *result) {
    result->records_len = 0;
    (void)tlsi_fail_into(t, ALERT_INTERNAL_ERROR, side, &result->side_len);
    return CH_ECAP;
}

// Readies the write key for count records, before any of them is sealed.
// When the current key has fewer data records left than the write holds,
// a KeyUpdate goes first, into side: records_before_key_update answers 0
// while the peer's request is owed an answer, which RFC 9846 §4.7.3 sends
// before the next data record (rfc9846.txt:3367-3370), and the number of
// records an AES-GCM key has left before its ceiling otherwise (RFC 9846
// §5.5, rfc9846.txt:3743-3744). The records then go out under the next
// key, which seals as many as one write holds (ch_writable_len). Under the
// current key a ChaCha20-Poly1305 key, which records_per_key leaves
// unbounded, still stops before its sequence number would wrap (RFC 9846
// §5.3). A write that no key can seal fails the session, at the cap of
// KeyUpdates §4.7.3 sets (rfc9846.txt:3400-3402) or at that wrap.
static int key_for_write(ch_tls_priv *t, size_t count, uint8_t *side, size_t side_cap,
                         ch_seal_result *result) {
    if (records_before_key_update(t) >= count) {
        if ((uint64_t)count > UINT64_MAX - t->wr.seq) {
            return fail_write(t, side, result);
        }
        return CH_OK;
    }
    if (t->send_epochs >= HSPOST_SEND_EPOCHS_MAX ||
        hspost_seal_key_update(t, side, side_cap, &result->side_len) != CH_OK) {
        return fail_write(t, side, result);
    }
    return CH_OK;
}

// The refusals that change nothing, in the order tcp_nonblocking.h lists
// them.
static int seal_refusal(const ch_tls_priv *t, const uint8_t *buf, size_t n, const uint8_t *side,
                        size_t side_cap, const ch_seal_result *result) {
    if (result == NULL || side == NULL || side_cap < CH_KEY_UPDATE_RECORD_LEN ||
        (buf == NULL && n != 0)) {
        return CH_EINVAL;
    }
    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    return CH_OK;
}

int tls_seal_in_place(ch_tls_priv *t, uint8_t *buf, size_t cap, size_t n, uint8_t *side,
                      size_t side_cap, ch_seal_result *result) {
    // Contract-point guard, as ch_read_in_place's: no input sets an undefined state.
    CH_ASSERT(t->state <= CH_ST_FAILED);
    int rc = seal_refusal(t, buf, n, side, side_cap, result);
    if (rc != CH_OK) {
        return rc;
    }
    memset(result, 0, sizeof *result);
    if (n == 0) {
        return CH_OK;
    }
    if (n > tls_writable_len(t, cap)) {
        return CH_ECAP;
    }
    seal_layout layout = layout_of(n, record_plaintext_max(t));
    CH_ASSERT(layout.count <= records_per_key(t));
    rc = key_for_write(t, layout.count, side, side_cap, result);
    if (rc != CH_OK) {
        return rc;
    }
    seal_records(t, buf, &layout);
    result->records_len = n + layout.count * REC_OVERHEAD;
    CH_ASSERT(result->records_len <= cap);
    return CH_OK;
}

// tls.h states the contract. It is tls_write.c's tls_writable_len less the
// KeyUpdate record, which ch_seal_in_place writes into side and not into
// the cap bytes this counts (tls_write_rules.h, writable_len_in_place).
size_t tls_writable_len(const ch_tls_priv *t, size_t cap) {
    return writable_len_in_place(cap, record_plaintext_max(t), records_per_key(t));
}

int tls_close_out(ch_tls_priv *t, uint8_t *out, size_t cap, size_t *out_len) {
    CH_ASSERT(t->state <= CH_ST_FAILED); // the guard ch_read_in_place states
    if (out == NULL || out_len == NULL || cap < CH_ALERT_RECORD_LEN) {
        return CH_EINVAL;
    }
    *out_len = 0;
    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    // close_notify is a warning, level 1 (RFC 9846 §6.1).
    int rc = tlsi_seal_alert(t, 1, ALERT_CLOSE_NOTIFY, out, out_len);
    tlsi_wipe(t);
    t->state = CH_ST_CLOSED;
    return rc;
}

int tls_fail_out(ch_tls_priv *t, uint8_t description, uint8_t *out, size_t cap, size_t *out_len) {
    CH_ASSERT(t->state <= CH_ST_FAILED); // the guard ch_read_in_place states
    if (!is_error_alert(description) || out == NULL || out_len == NULL ||
        cap < CH_ALERT_RECORD_LEN) {
        return CH_EINVAL;
    }
    *out_len = 0;
    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    return tlsi_fail_into(t, description, out, out_len);
}

#endif // CH_TRANSPORT_TCP_NONBLOCKING
