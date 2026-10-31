// Proves: ch_write_parts (tls_write.c) seals the parts joined, in the
// records ch_write seals for them in one buffer, at a bound. For any three
// parts of 0 to WRITE_PARTS_MAX bytes in all, any of them with no pointer
// when it is empty, any record limit from 1 to WRITE_LIMIT_MAX and any
// key_update_owed, it returns CH_OK, and:
//   - the plaintexts of the records it seals, joined, are the parts
//     joined, byte for byte;
//   - every record holds 1 to limit bytes, and every record but the last
//     holds limit, so the records are the ones ch_write cuts;
//   - the owed KeyUpdate goes out before the first data record, and a
//     write of a byte or more leaves key_update_owed clear.
// The copy into ch_tls.tx runs through proof/wbuf_byte_stub.c, buf.c's
// contract with a store per byte, so each copy from a part is a
// bounds-checked read of that part and write into ch_tls.tx.
//
// rec_seal is a stub that records each record's plaintext: record.h's
// contract, which the record harness proves, with the bytes kept, because
// they are the property here. hspost_send_key_update is its contract
// (handshake_post.h), io_send_all succeeds, and tlsi_fail fails the proof,
// because no path here may call it.
//
// Why the bounds. The loops' work grows with the bytes and the records,
// and none of the claims depends on a record's size: a limit of 1 to 4
// gives a record of one byte, a part that ends inside a record, a part
// longer than a record and a record that holds three parts. Nine bytes
// make up to nine records. writable_len and writable_len_suite prove the
// lengths at the real limits.
#include "harness.h"

#include <string.h>

#include "handshake_post.h"
#include "io.h"
#include "record.h"
#include "session.h"
#include "tls.h"

#define WRITE_PARTS_MAX 9
#define WRITE_LIMIT_MAX 4

static ch_tls t;
static uint8_t plaintext[WRITE_PARTS_MAX];

// The records' plaintexts, joined, and the shape of the records.
static uint8_t sealed[WRITE_PARTS_MAX];
static size_t sealed_len;
static size_t records;
static size_t last_record_len;

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    (void)cfg;
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "send: the record is readable");
    return CH_OK;
}

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    (void)d;
    __CPROVER_assert(type == REC_APPDATA, "seal: a data record");
    __CPROVER_assert(t.key_update_owed == 0, "seal: no data record while key_update_owed is set");
    __CPROVER_assert(n >= 1 && n <= t.peer_limit, "seal: 1 to limit bytes");
    __CPROVER_assert(records == 0 || last_record_len == t.peer_limit,
                     "seal: every record before this one is full");
    __CPROVER_assert(__CPROVER_r_ok(pt, n), "seal: pt readable");
    __CPROVER_assert(REC_OVERHEAD + n <= cap, "seal: the record fits its buffer");
    __CPROVER_assert(__CPROVER_w_ok(out, n + REC_OVERHEAD), "seal: out writable");
    __CPROVER_assert(sealed_len + n <= WRITE_PARTS_MAX, "seal: no more bytes than the parts hold");
    for (size_t i = 0; i < n; i++) {
        sealed[sealed_len + i] = pt[i];
    }
    sealed_len += n;
    records++;
    last_record_len = n;
    *out_len = n + REC_OVERHEAD;
    return 0;
}

int hspost_send_key_update(ch_tls *session) {
    __CPROVER_assert(session == &t, "key update: the session written from");
    __CPROVER_assert(session->key_update_owed == 1, "key update: key_update_owed is set");
    __CPROVER_assert(records == 0, "key update: before the first data record");
    session->send_epochs++;
    session->key_update_owed = 0;
    return CH_OK;
}

int tlsi_fail(ch_tls *session, uint8_t description) {
    (void)session;
    (void)description;
    __CPROVER_assert(0, "tlsi_fail unreachable: every seal and send succeeds");
    return CH_EIO;
}

#include "tls_write.c"

// A part of len bytes at plaintext[at], or no pointer at all when it is
// empty and the solver picks that.
static ch_part part_at(size_t at, size_t len) {
    ch_part part = {plaintext + at, len};
    if (len == 0 && (nondet_u8() & 1) != 0) {
        part.pt = NULL;
    }
    return part;
}

int main(void) {
    t.state = CH_ST_CONNECTED;
    t.peer_limit = (uint16_t)nondet_u32();
    __CPROVER_assume(t.peer_limit >= 1 && t.peer_limit <= WRITE_LIMIT_MAX);
    t.key_update_owed = nondet_u8() & 1;
    fill_nondet(plaintext, sizeof plaintext);

    size_t n = nondet_size_t();
    __CPROVER_assume(n <= WRITE_PARTS_MAX);
    size_t first = nondet_size_t();
    __CPROVER_assume(first <= n);
    size_t second = nondet_size_t();
    __CPROVER_assume(second <= n - first);
    const ch_part parts[3] = {
        part_at(0, first),
        part_at(first, second),
        part_at(first + second, n - first - second),
    };
    uint8_t owed = t.key_update_owed;

    __CPROVER_assert(ch_write_parts(&t, parts, 3) == CH_OK, "write: every record goes out");
    __CPROVER_assert(sealed_len == n, "write: the records hold every byte of the parts");
    for (size_t i = 0; i < n; i++) {
        __CPROVER_assert(sealed[i] == plaintext[i], "write: the records hold the parts joined");
    }
    __CPROVER_assert(n == 0 || t.key_update_owed == 0, "write: key_update_owed clear after it");
    __CPROVER_assert(n > 0 || t.key_update_owed == owed, "write: no byte leaves an answer owed");
    return 0;
}
