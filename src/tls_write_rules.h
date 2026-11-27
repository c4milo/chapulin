// The rules the two TCP writes share: tls_write.c's copy write of a
// TRANSPORT=tcp-blocking session and tcp_seal.c's in-place seal of a
// TRANSPORT=tcp-nonblocking one (docs/decisions.md 248). Each record
// carries at most record_plaintext_max bytes, a KeyUpdate goes out when an
// answer is owed or an AES-GCM key is at its last data record, and
// records_fill says what a buffer of cap bytes of records carries. tls.h
// and tcp_nonblocking.h state the calls' contracts; this header holds one
// copy of each rule, so the two writes cannot drift. A
// TRANSPORT=quic-nonblocking build seals no TLS record and includes it
// nowhere.
#ifndef CH_TLS_WRITE_RULES_H
#define CH_TLS_WRITE_RULES_H

#include <stddef.h>
#include <stdint.h>

#include "record.h"
#include "session.h"
#include "tls.h"

// The most plaintext one outgoing record carries: CH_TX_PT, or the peer's
// record_size_limit when that is lower (INV-38). ch_write cuts records at
// it and ch_writable_len counts in it, so the two read one limit.
static inline size_t record_plaintext_max(const ch_tls_priv *t) {
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
static inline size_t records_per_key(const ch_tls_priv *t) {
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
static inline size_t records_before_key_update(const ch_tls_priv *t) {
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
static inline size_t records_fill(size_t cap, size_t limit, size_t *records) {
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

// ch_writable_len in a TRANSPORT=tcp-nonblocking build (tcp_seal.c), over
// the values record_plaintext_max and records_per_key give: the most
// plaintext one ch_seal_in_place seals in cap bytes, at limit bytes a
// record. It counts no KeyUpdate record, which that call writes into its
// side buffer, and cuts at per_key records, which one key seals, because
// that call seals every record of a write under one key. A pure function
// of three numbers, so test/diff_writable_len.h compares it in every build
// with spec/lean/Spec/TlsWrite.lean's writableLenInPlace, whose
// writableLenInPlace_le_cap proves the answer is at most cap. per_key *
// limit does not wrap: records_fill found more than per_key records of
// limit bytes of plaintext in cap, so the product is below cap.
static inline size_t writable_len_in_place(size_t cap, size_t limit, size_t per_key) {
    if (limit == 0) {
        return 0;
    }
    size_t records = 0;
    size_t fill = records_fill(cap, limit, &records);
    if (records > per_key) {
        return per_key * limit;
    }
    return fill;
}

// The error alerts of RFC 9846 §6.2: the AlertDescription values of
// rfc9846.txt:3796-3823 less close_notify and user_canceled, the two
// closure alerts of §6.1. ch_fail and ch_fail_out send these and no other.
static inline int is_error_alert(uint8_t description) {
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
    for (size_t i = 0; i < sizeof error_alerts; i++) {
        if (error_alerts[i] == description) {
            return 1;
        }
    }
    return 0;
}

#endif
