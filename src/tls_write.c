// The connected session's send path, in both roles on the
// TRANSPORT=tcp-blocking transport: ch_write, ch_write_parts,
// ch_writable_len and ch_fail, whose contracts tls.h states, and the
// KeyUpdate ch_write sends before a data record, as the answer the peer's
// request owes or as the last record an AES-GCM write key seals
// (record.h). tls.c holds the other public calls tls.h declares.
// tls_write_rules.h holds the rules this file shares with tcp_seal.c, the
// send path of TRANSPORT=tcp-nonblocking, which seals in the caller's
// storage and declares none of these calls (docs/decisions.md 248).
#include "tls.h"
#include "tls_calls.h"

#include "buf.h"
#include "ch_assert.h"
#include "handshake_message.h"
#include "handshake_post.h"
#include "io.h"
#include "tls_write_rules.h"

#ifndef CH_TRANSPORT_TCP_NONBLOCKING

// The step ch_write takes before each data record it seals. When the
// current write key has no data record left, it sends one KeyUpdate and
// moves the write direction to the next key (hspost_send_key_update). The
// record that follows goes out under that key, and the peer opens it
// because its read direction moved to that key when it read the KeyUpdate.
// The KeyUpdate asks for no answer. Two causes make it due, and one
// KeyUpdate serves both when they fall due at one record:
//   - an answer is owed: the peer asked for one (handshake_post.c), and RFC
//     9846 §4.7.3 sends it before the next data record
//     (rfc9846.txt:3367-3370). One answer serves every request read since
//     the last KeyUpdate this side sent (rfc9846.txt:3370-3373).
//   - an AES-GCM key is at its ceiling: RFC 9846 §5.5 has a sender close
//     the connection or send a KeyUpdate while a key is still below its
//     AEAD's usage limit (rfc9846.txt:3743-3744), and this KeyUpdate takes
//     the key's last sequence number, REC_AES_GCM_RECORDS_MAX - 1.
//
// RFC 9846 §4.7.3 lets a sender send HSPOST_SEND_EPOCHS_MAX KeyUpdates. No
// answer is owed at that cap (handle_key_update), and a key at its ceiling
// after that many cannot be replaced, so the session closes: tlsi_fail
// seals internal_error at that last sequence number and wipes the keys,
// and ch_write returns CH_ECAP, its code for a record it cannot seal
// (tls.h).
//
// ch_write is the one sender that checks. Every other record sealed under
// an application write key is a single record that cannot pass the
// ceiling:
//   - a server's NewSessionTicket goes out at sequence number 0 of the key
//     its handshake installed;
//   - an alert, from ch_close or from tlsi_fail, is the last record before
//     the keys are wiped.
// After every record ch_write seals, an AES-GCM key has at least its last
// sequence number left, and each of those two takes at most that one.
// Neither sends an owed answer first, because §4.7.3 owes it before
// application data alone, and no data record follows either of them.
static int key_update_before_record(ch_tls_priv *t) {
    if (records_before_key_update(t) != 0) {
        return CH_OK;
    }
    if (t->send_epochs >= HSPOST_SEND_EPOCHS_MAX) {
        tlsi_fail(t, ALERT_INTERNAL_ERROR);
        return CH_ECAP;
    }
    int rc = hspost_send_key_update(t);
    if (rc != CH_OK) {
        tlsi_fail(t, ALERT_INTERNAL_ERROR);
    }
    return rc;
}

// Where ch_write_parts has read to: parts[index] is the part it reads
// next, and offset counts the bytes of that part it has already copied.
// After parts_skip_empty, index is part_count or names a part with a byte
// left at offset.
typedef struct {
    const ch_part *parts;
    size_t part_count;
    size_t index;
    size_t offset;
} parts_cursor;

static void parts_skip_empty(parts_cursor *c) {
    while (c->index < c->part_count && c->offset == c->parts[c->index].pt_len) {
        c->index++;
        c->offset = 0;
    }
}

// Copies the next record's plaintext into w: bytes from the parts at the
// cursor until w holds limit bytes or the parts end. It moves the cursor
// past the bytes it copied. Each pass copies one byte or more, because the
// cursor names a part with a byte left, so the loop ends.
static void parts_copy_record(parts_cursor *c, wbuf *w, size_t limit) {
    while (w->len < limit && c->index < c->part_count) {
        const ch_part *part = &c->parts[c->index];
        size_t left = part->pt_len - c->offset;
        size_t room = limit - w->len;
        size_t take = left < room ? left : room;
        wb_bytes(w, part->pt + c->offset, take);
        c->offset += take;
        parts_skip_empty(c);
    }
}

// tls.h states the contract. The plaintext of each record is copied into
// ch_tls.tx at REC_HDR, where rec_seal builds the record, after the
// KeyUpdate that may go first, because that KeyUpdate is sealed in
// ch_tls.tx too. So each byte is copied once, as rec_seal copied the one
// buffer ch_write took before this call existed.
int tls_write_parts(ch_tls_priv *t, const ch_part *parts, size_t part_count) {
    CH_ASSERT(t->state <= CH_ST_FAILED); // the guard ch_read states (tls.c)

    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    parts_cursor cursor = {parts, part_count, 0, 0};
    parts_skip_empty(&cursor);
    size_t limit = record_plaintext_max(t);
    while (cursor.index < cursor.part_count) {
        int rc = key_update_before_record(t);
        if (rc != CH_OK) {
            return rc; // it failed the session
        }
        wbuf inner;
        wb_init(&inner, t->tx + REC_HDR, sizeof t->tx - REC_HDR);
        parts_copy_record(&cursor, &inner, limit);
        size_t out_len = 0;
        if (inner.err ||
            rec_seal(&t->wr, REC_APPDATA, inner.p, inner.len, t->tx, sizeof t->tx, &out_len) != 0) {
            tlsi_fail(t, ALERT_INTERNAL_ERROR);
            return CH_ECAP;
        }
        rc = io_send_all(&t->cfg, t->tx, out_len);
        if (rc != CH_OK) {
            tlsi_fail(t, ALERT_INTERNAL_ERROR);
            return rc;
        }
    }
    return CH_OK;
}

int tls_write(ch_tls_priv *t, const uint8_t *p, size_t n) {
    const ch_part part = {p, n};
    return tls_write_parts(t, &part, 1);
}

// What ch_writable_len returns when the records cap carries are more than
// the room records the write key has left (records_before_key_update).
// ch_write sends room whole records under that key, then the KeyUpdate
// record, then the rest under the next key. So it returns room records
// of plaintext and what cap carries after them and after the KeyUpdate's
// CH_KEY_UPDATE_RECORD_LEN bytes. It counts one KeyUpdate and no second:
// under the next key it counts at most the per_key records that go out
// before that key's own KeyUpdate, the records_per_key of the session
// (tls.h).
//
// No sum or product here wraps a size_t, whatever its width:
// spec/lean/Spec/TlsWrite.lean's fillAcrossKeyUpdate_fits proves each is at
// most cap. The records cap carries are more than room, and every one but
// the last is whole, so room whole records fit in cap.
static size_t fill_across_key_update(size_t cap, size_t limit, size_t room, size_t per_key) {
    size_t left = cap - room * (limit + REC_OVERHEAD);
    size_t rest = left > CH_KEY_UPDATE_RECORD_LEN ? left - CH_KEY_UPDATE_RECORD_LEN : 0;
    size_t records = 0;
    size_t after = records_fill(rest, limit, &records);
    if (records > per_key) {
        after = per_key * limit;
    }
    return room * limit + after;
}

// tls.h states the contract. spec/lean/Spec/TlsWrite.lean models this
// function and its two helpers, writableLen_le_cap proves that the value
// it returns is at most cap, and test/diff_writable_len.h compares the
// model with this code.
size_t tls_writable_len(const ch_tls_priv *t, size_t cap) {
    size_t limit = record_plaintext_max(t);
    if (limit == 0) {
        return 0;
    }
    size_t records = 0;
    size_t fill = records_fill(cap, limit, &records);
    size_t room = records_before_key_update(t);
    if (records > room) {
        return fill_across_key_update(cap, limit, room, records_per_key(t));
    }
    return fill;
}

// tls.h states the contract. tlsi_fail is the failure funnel ch_read's
// failures run through too, so this call writes alert_sent, wipes and
// marks the session failed the same way.
int tls_fail(ch_tls_priv *t, uint8_t description) {
    CH_ASSERT(t->state <= CH_ST_FAILED); // the guard ch_read states (tls.c)
    if (!is_error_alert(description)) {
        return CH_EINVAL;
    }
    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    return tlsi_fail(t, description);
}
#endif // CH_TRANSPORT_TCP_NONBLOCKING

// tls.h writes the two lengths out from REC_OVERHEAD, and these hold them
// to the 24 and 27 bytes a caller sizes buffers by. tls.h cannot say it
// itself: a QUIC build reads no record.h, and a translation unit of that
// build that includes tls.h would fail on the assertion.
_Static_assert(CH_ALERT_RECORD_LEN == 24, "one sealed alert record is 24 bytes");
_Static_assert(CH_KEY_UPDATE_RECORD_LEN == 27, "one sealed KeyUpdate record is 27 bytes");
