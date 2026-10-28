// The connected session's send path, in both roles and on both TCP
// transports: ch_write and ch_writable_len, whose contracts tls.h states,
// and the KeyUpdate ch_write sends before a data record, as the answer the
// peer's request owes or as the last record an AES-GCM write key seals
// (record.h). tls.c holds the other public calls tls.h declares.
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

// How many data records one write key seals before ch_write sends the
// KeyUpdate that retires it. An AES-GCM key seals at sequence numbers 0 to
// REC_AES_GCM_RECORDS_MAX - 1 (record.h), and the last of them is the
// KeyUpdate's, so it seals REC_AES_GCM_RECORDS_MAX - 1 data records. A
// ChaCha20-Poly1305 key has no such limit, because its sequence number
// would wrap first (rfc9846.txt:3752-3754), so for one this returns
// SIZE_MAX. A build without -DCH_SUITE_AES_GCM runs ChaCha20-Poly1305
// alone. A KeyUpdate keeps the direction's suite (record.h), so the key
// after one seals as many as the key before it.
static size_t records_per_key(const ch_tls *t) {
#ifdef CH_SUITE_AES_GCM
    if (suite_runs_aes_gcm(t->wr.suite)) {
        return REC_AES_GCM_RECORDS_MAX - 1;
    }
#endif
    (void)t;
    return SIZE_MAX;
}

// How many more data records ch_write seals under the current write key
// before it sends a KeyUpdate. It is 0 while the peer's request is owed an
// answer (ch_tls.key_update_owed), because RFC 9846 §4.7.3 sends that
// answer before the next data record (rfc9846.txt:3367-3370). Otherwise it
// is the part of records_per_key the key has not sealed: an AES-GCM data
// record takes a sequence number below REC_AES_GCM_RECORDS_MAX - 1.
// ch_write and ch_writable_len both read it, as they both read the record
// limit through record_plaintext_max.
static size_t records_before_key_update(const ch_tls *t) {
    if (t->key_update_owed) {
        return 0;
    }
    size_t per_key = records_per_key(t);
    if (per_key == SIZE_MAX) {
        return SIZE_MAX;
    }
    // At most 2^24 - 1, which the cast keeps whole: ct.h refuses a size_t
    // of fewer than 32 bits.
    return t->wr.seq < per_key ? (size_t)(per_key - t->wr.seq) : 0;
}

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
static int key_update_before_record(ch_tls *t) {
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

int ch_write(ch_tls *t, const uint8_t *p, size_t n) {
    CH_ASSERT(t->state <= CH_ST_FAILED); // the guard ch_read states (tls.c)

    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    size_t limit = record_plaintext_max(t);
    while (n > 0) {
        size_t take = n < limit ? n : limit;
        int rc = key_update_before_record(t);
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
// REC_OVERHEAD bytes longer on the wire, and less than one more. So it
// returns the larger of two: the whole records' plaintext, and what is
// left of cap once whole + 1 records' overhead is paid, which is less than
// whole + 1 records of plaintext and is larger only when the last record
// carries a byte. ch_write sends exactly those records for that many
// bytes: whole records of limit bytes, then the last.
//
// It divides once. The overhead is counted per record rather than taken
// as cap's remainder after the division, because gcc turns a remainder
// into a second division, which lint-wide-multiply counts.
//
// No sum or product here wraps a size_t, whatever its width, for a limit
// of 1 to 16384: spec/lean/Spec/TlsWrite.lean's recordsFill_fits proves
// each is below 2^w when cap is, for every w of 15 bits or more.
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
size_t ch_writable_len(const ch_tls *t, size_t cap) {
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

// tls.h writes the two lengths out from REC_OVERHEAD, and these hold them
// to the 24 and 27 bytes a caller sizes buffers by. tls.h cannot say it
// itself: a QUIC build reads no record.h, and a translation unit of that
// build that includes tls.h would fail on the assertion.
_Static_assert(CH_ALERT_RECORD_LEN == 24, "one sealed alert record is 24 bytes");
_Static_assert(CH_KEY_UPDATE_RECORD_LEN == 27, "one sealed KeyUpdate record is 27 bytes");

// The error alerts of RFC 9846 §6.2: the AlertDescription values of
// rfc9846.txt:3796-3823 less close_notify and user_canceled, the two
// closure alerts of §6.1. ch_fail sends these and no other.
static const uint8_t error_alerts[] = {
    10,  // unexpected_message
    20,  // bad_record_mac
    22,  // record_overflow
    40,  // handshake_failure
    42,  // bad_certificate
    43,  // unsupported_certificate
    44,  // certificate_revoked
    45,  // certificate_expired
    46,  // certificate_unknown
    47,  // illegal_parameter
    48,  // unknown_ca
    49,  // access_denied
    50,  // decode_error
    51,  // decrypt_error
    70,  // protocol_version
    71,  // insufficient_security
    80,  // internal_error
    86,  // inappropriate_fallback
    109, // missing_extension
    110, // unsupported_extension
    112, // unrecognized_name
    113, // bad_certificate_status_response
    115, // unknown_psk_identity
    116, // certificate_required
    117, // general_error
    120, // no_application_protocol
};

static int is_error_alert(uint8_t description) {
    for (size_t i = 0; i < sizeof error_alerts; i++) {
        if (error_alerts[i] == description) {
            return 1;
        }
    }
    return 0;
}

// tls.h states the contract. tlsi_fail is the failure funnel ch_read's
// failures run through too, so this call writes alert_sent, wipes and
// marks the session failed the same way.
int ch_fail(ch_tls *t, uint8_t description) {
    CH_ASSERT(t->state <= CH_ST_FAILED); // the guard ch_read states (tls.c)
    if (!is_error_alert(description)) {
        return CH_EINVAL;
    }
    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    return tlsi_fail(t, description);
}
