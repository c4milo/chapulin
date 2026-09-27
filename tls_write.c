// The connected session's send path, in both roles and on both TCP
// transports: ch_write and ch_writable_len, whose contracts tls.h states,
// and the KeyUpdate ch_write sends as the last record an AES-GCM write key
// seals (record.h). tls.c holds the other public calls tls.h declares.
#include "tls.h"

#include "ch_assert.h"
#include "handshake_message.h"
#include "handshake_post.h"
#include "io.h"

// The most plaintext one outgoing record carries: CH_TX_PT, or the peer's
// record_size_limit when that is lower (INV-38). ch_write cuts records at
// it and ch_writable_len counts in it, so the two read one limit.
static size_t record_plaintext_max(const ch_tls *t) {
    return t->peer_limit < CH_TX_PT ? t->peer_limit : CH_TX_PT;
}

#ifdef CH_SUITE_AES_GCM
// How many more data records ch_write seals under the current write key
// before it must send the KeyUpdate that retires the key. An AES-GCM key
// seals at sequence numbers 0 to REC_AES_GCM_RECORDS_MAX - 1 (record.h),
// and the last of them is the KeyUpdate's, so a data record takes a
// sequence number below REC_AES_GCM_RECORDS_MAX - 1. A ChaCha20-Poly1305
// key has no such limit, because its sequence number would wrap first
// (rfc9846.txt:3752-3754), so the answer for one is SIZE_MAX. ch_write and
// ch_writable_len both read the ceiling here, as they both read the record
// limit through record_plaintext_max.
static size_t records_before_key_update(const ch_tls *t) {
    if (!suite_runs_aes_gcm(t->wr.suite)) {
        return SIZE_MAX;
    }
    uint64_t last = REC_AES_GCM_RECORDS_MAX - 1;
    return t->wr.seq < last ? (size_t)(last - t->wr.seq) : 0;
}

// The step ch_write takes before each record it seals. RFC 9846 §5.5 has a
// sender close the connection or send a KeyUpdate while a key is still
// below its AEAD's usage limit (rfc9846.txt:3743-3744). When an AES-GCM
// write key has no data record left, this sends a KeyUpdate at the key's
// last sequence number, REC_AES_GCM_RECORDS_MAX - 1, and moves the write
// direction to the next key (hspost_send_key_update). The record that
// follows goes out at sequence number 0 of the next key, and the peer
// opens it because its read direction moved to that key when it read the
// KeyUpdate. The KeyUpdate asks for no answer: the key at its ceiling is
// this side's write key, and the peer's write key keeps a count of its own.
//
// RFC 9846 §4.7.3 lets a sender send HSPOST_SEND_EPOCHS_MAX KeyUpdates. A
// key at its ceiling after that many cannot be replaced, so the session
// closes: tlsi_fail seals internal_error at that last sequence number and
// wipes the keys, and ch_write returns CH_ECAP, its code for a record it
// cannot seal (tls.h).
//
// ch_write is the one sender that checks. Every other record sealed under
// an application write key is a single record that cannot pass the
// ceiling:
//   - a server's NewSessionTicket goes out at sequence number 0 of the key
//     its handshake installed;
//   - the answer to a peer's KeyUpdate moves the write direction to the
//     next key right after its one record;
//   - an alert, from ch_close or from tlsi_fail, is the last record before
//     the keys are wiped.
// After every record ch_write seals, the key has at least its last
// sequence number left, and each of those three takes at most that one.
static int key_update_at_ceiling(ch_tls *t) {
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
#else
// A build without -DCH_SUITE_AES_GCM runs ChaCha20-Poly1305 alone, whose
// only limit is the wrap rec_seal refuses, so there is nothing to send.
static int key_update_at_ceiling(ch_tls *t) {
    (void)t;
    return CH_OK;
}
#endif

int ch_write(ch_tls *t, const uint8_t *p, size_t n) {
    CH_ASSERT(t->state <= CH_ST_FAILED); // the guard ch_read states (tls.c)

    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    size_t limit = record_plaintext_max(t);
    while (n > 0) {
        size_t take = n < limit ? n : limit;
        int rc = key_update_at_ceiling(t);
        if (rc != CH_OK) {
            return rc; // it failed the session
        }
        size_t out_len = 0;
        if (rec_seal(&t->wr, REC_APPDATA, p, take, t->tx, sizeof t->tx, &out_len) != 0) {
            tlsi_fail(t, ALERT_INTERNAL_ERROR);
            return CH_ECAP;
        }
        rc = io_send_all(&t->cfg, t->tx, out_len);
        if (rc != CH_OK) {
            tlsi_fail(t, ALERT_INTERNAL_ERROR);
            return rc;
        }
        p += take;
        n -= take;
    }
    return CH_OK;
}

// What cap bytes of records carry at limit bytes of plaintext per record:
// the most plaintext, and through *records the number of records ch_write
// sends it in. cap holds `whole` records of limit bytes of plaintext, each
// REC_OVERHEAD bytes longer on the wire, and less than one more. So the
// answer is the larger of two: the whole records' plaintext, and what is
// left of cap once whole + 1 records' overhead is paid, which is less than
// whole + 1 records of plaintext and is larger only when the last record
// carries a byte. ch_write sends exactly those records for that many
// bytes: whole records of limit bytes, then the last.
//
// It divides once. The overhead is counted per record rather than taken
// as cap's remainder after the division, because gcc turns a remainder
// into a second division, which lint-wide-multiply counts.
static size_t records_fill(size_t cap, size_t limit, size_t *records) {
    size_t whole = cap / (limit + REC_OVERHEAD);
    size_t in_whole = whole * limit;
    size_t overhead = (whole + 1) * REC_OVERHEAD;
    size_t with_one_more = cap > overhead ? cap - overhead : 0;
    if (with_one_more > in_whole) {
        *records = whole + 1;
        return with_one_more;
    }
    *records = whole;
    return in_whole;
}

#ifdef CH_SUITE_AES_GCM
// ch_writable_len's answer when the records cap carries are more than the
// room records the write key has left (records_before_key_update).
// ch_write sends room whole records under that key, then the KeyUpdate
// record, then the rest under the next key. So the answer is room records
// of plaintext and what cap carries after them and after the KeyUpdate's
// CH_KEY_UPDATE_RECORD_LEN bytes. It counts one KeyUpdate and no second:
// under the next key it counts at most the REC_AES_GCM_RECORDS_MAX - 1
// records that go out before that key's own KeyUpdate (tls.h).
//
// No product here overflows. The records cap carries are more than room,
// and every one but the last is whole, so room whole records fit in cap.
// rest carries more than REC_AES_GCM_RECORDS_MAX - 1 records only when it
// holds that many whole ones, so their plaintext is less than rest.
static size_t fill_across_key_update(size_t cap, size_t limit, size_t room) {
    size_t left = cap - room * (limit + REC_OVERHEAD);
    size_t rest = left > CH_KEY_UPDATE_RECORD_LEN ? left - CH_KEY_UPDATE_RECORD_LEN : 0;
    size_t records = 0;
    size_t after = records_fill(rest, limit, &records);
    if (records > REC_AES_GCM_RECORDS_MAX - 1) {
        after = (REC_AES_GCM_RECORDS_MAX - 1) * limit;
    }
    return room * limit + after;
}
#endif

// tls.h states the contract.
size_t ch_writable_len(const ch_tls *t, size_t cap) {
    size_t limit = record_plaintext_max(t);
    if (limit == 0) {
        return 0;
    }
    size_t records = 0;
    size_t fill = records_fill(cap, limit, &records);
#ifdef CH_SUITE_AES_GCM
    size_t room = records_before_key_update(t);
    if (records > room) {
        return fill_across_key_update(cap, limit, room);
    }
#endif
    return fill;
}

// tls.h writes the two lengths out from REC_OVERHEAD, and these hold them
// to the 24 and 27 bytes a caller sizes buffers by. tls.h cannot say it
// itself: a QUIC build reads no record.h, and a translation unit of that
// build that includes tls.h would fail on the assertion.
_Static_assert(CH_ALERT_RECORD_LEN == 24, "one sealed alert record is 24 bytes");
_Static_assert(CH_KEY_UPDATE_RECORD_LEN == 27, "one sealed KeyUpdate record is 27 bytes");
