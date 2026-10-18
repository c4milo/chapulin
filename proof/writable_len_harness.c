// Proves: ch_writable_len (tls_write.c) is memory-safe and UB-free for any
// peer_limit a uint16_t holds, any key_update_owed and any cap a size_t
// holds. And its answer is the most plaintext the real ch_write sends in
// cap bytes, at a bound: for every cap up to three whole records of
// CH_TX_PT bytes, a KeyUpdate record and one byte more, every peer_limit
// from 63 up, and with key_update_owed set and clear, ch_write hands
// cfg.send at most cap bytes for the answer, and more than cap bytes for
// one byte more. On the way it proves that ch_write sends the KeyUpdate
// that key_update_owed records before its first data record, and that the
// write leaves key_update_owed clear.
//
// ch_write is the code tls.h's contract names, so the second half runs it
// rather than a formula of its own. rec_seal is replaced by its contract
// (record.h), which the record harness proves and
// spec/lean/Spec/Record.lean's seal_size states: it writes n +
// REC_OVERHEAD bytes into a buffer that holds them. hspost_send_key_update
// is its contract (handshake_post.h): one record of
// CH_KEY_UPDATE_RECORD_LEN bytes, one more KeyUpdate counted and
// key_update_owed clear. io_send_all adds up the lengths it is handed and
// succeeds, so the
// proof counts exactly the bytes ch_write sends. tlsi_fail is a stub that
// fails the proof, because no path here may call it.
//
// Why the bounds. 63 is the least peer_limit a connected session holds: a
// peer's record_size_limit of 64, RFC 8449 §4's floor, less the content
// type byte, which both parsers subtract (INV-38). With it ch_write loops
// at most 20 times here. The cap is written as 11 low bits, as
// docs/proofs.md advises, because the claim is an equality over a
// division, which is hard for a SAT solver: a model of the same claim
// over any peer_limit took 40 to 55 seconds at 12 bits of cap and returned
// no verdict in 600 at 16. Asking only that the answer never exceed cap
// held over the whole range in 41 seconds alone, and took the formula
// from 100 seconds to 233 beside this one, so the harness leaves it out
// and bin/unit checks the answer at SIZE_MAX.
#include "harness.h"

#include <string.h>

#include "handshake_post.h"
#include "io.h"
#include "record.h"
#include "session.h"
#include "tls.h"

// The bytes ch_write handed cfg.send.
static size_t sent_bytes;

// The session the ch_write half writes from, which the stubs read.
static ch_tls t;

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    (void)cfg;
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "send: the record is readable");
    sent_bytes += n;
    return CH_OK;
}

// record.h's contract: out gets n + REC_OVERHEAD bytes. The bytes are no
// property here, so the stub writes none and the formula holds lengths
// alone.
int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    (void)d;
    (void)type;
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "seal: pt readable");
    __CPROVER_assert(REC_OVERHEAD + n <= cap, "seal: ch_write stages a record its buffer holds");
    __CPROVER_assert(__CPROVER_w_ok(out, n + REC_OVERHEAD), "seal: out writable");
    __CPROVER_assert(t.key_update_owed == 0, "seal: no data record while key_update_owed is set");
    *out_len = n + REC_OVERHEAD;
    return 0;
}

// handshake_post.h's contract: one KeyUpdate record sent, one more
// KeyUpdate counted, and key_update_owed clear. This build has no AES-GCM
// ceiling, so key_update_owed is the one cause of a KeyUpdate here.
int hspost_send_key_update(ch_tls *session) {
    __CPROVER_assert(session == &t, "key update: the session written from");
    __CPROVER_assert(session->key_update_owed == 1, "key update: key_update_owed is set");
    __CPROVER_assert(session->send_epochs < HSPOST_SEND_EPOCHS_MAX,
                     "key update: below the sender cap");
    sent_bytes += CH_KEY_UPDATE_RECORD_LEN;
    session->send_epochs++;
    session->key_update_owed = 0;
    return CH_OK;
}

void tlsi_fail(ch_tls *t, uint8_t description) {
    (void)t;
    (void)description;
    __CPROVER_assert(0, "tlsi_fail unreachable: every seal and send succeeds");
}

#include "tls_write.c"

// The largest cap the ch_write half takes: three whole records at
// CH_TX_PT, a KeyUpdate record and one byte, which 11 bits hold at the
// default CH_TX_PT.
#define WRITE_CAP_BITS 11
#define WRITE_CAP_MAX (3 * (CH_TX_PT + REC_OVERHEAD) + CH_KEY_UPDATE_RECORD_LEN + 1)
_Static_assert(WRITE_CAP_MAX < (1 << WRITE_CAP_BITS), "the cap's bits hold the largest cap");

// The least peer_limit a connected session holds.
#define WRITE_LIMIT_MIN 63

static ch_tls any;
static uint8_t plaintext[WRITE_CAP_MAX + 1];

// The bytes ch_write hands cfg.send for n bytes of plaintext, from the
// session main set up; key_update_owed and the KeyUpdate count are put
// back afterwards. A write of a byte or more leaves key_update_owed clear.
static size_t written(size_t n) {
    uint8_t owed = t.key_update_owed;
    uint64_t epochs = t.send_epochs;
    sent_bytes = 0;
    int rc = ch_write(&t, plaintext, n);
    __CPROVER_assert(rc == CH_OK, "write: every record goes out");
    __CPROVER_assert(n == 0 || t.key_update_owed == 0, "write: key_update_owed clear after it");
    t.key_update_owed = owed;
    t.send_epochs = epochs;
    return sent_bytes;
}

int main(void) {
    // Any session and any cap.
    any.peer_limit = (uint16_t)nondet_u32();
    any.key_update_owed = nondet_u8();
    (void)ch_writable_len(&any, nondet_size_t());

    // A connected session, through the real ch_write.
    t.state = CH_ST_CONNECTED;
    t.peer_limit = (uint16_t)nondet_u32();
    __CPROVER_assume(t.peer_limit >= WRITE_LIMIT_MIN);
    t.key_update_owed = nondet_u8() & 1;
    size_t write_cap = nondet_size_t() & (((size_t)1 << WRITE_CAP_BITS) - 1);
    __CPROVER_assume(write_cap <= WRITE_CAP_MAX);
    size_t n = ch_writable_len(&t, write_cap);
    __CPROVER_assert(written(n) <= write_cap, "writable_len: the answer's records fit cap");
    __CPROVER_assert(written(n + 1) > write_cap, "writable_len: one byte more does not fit");
    return 0;
}
