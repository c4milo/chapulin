// Proves: hspost_seal_key_update (handshake_post.c), the KeyUpdate that
// ch_seal_in_place writes into side on the tcp-nonblocking transport, is
// memory safe and free of UB over an unconstrained session below the cap
// of KeyUpdates, any cap and an out of cap bytes. And that the call keeps
// what handshake_post.h states:
// - CH_OK seals one KeyUpdate that asks for no answer (RFC 9846 §4.7.3)
//   into out under the old write key, writes CH_KEY_UPDATE_RECORD_LEN to
//   *out_len, and then moves the write key: one rec_dir_update over
//   wr_secret and wr, one more KeyUpdate sent and no answer owed;
// - CH_ECAP, when rec_seal refuses the record, writes 0 to *out_len
//   whatever rec_seal wrote there, and leaves the write key, the count of
//   KeyUpdates sent and the owed answer as they were.
//
// What is real and what is a stub. handshake_post.c is real. rec_seal and
// rec_dir_update are stubs of record.h's contract. The rec_seal stub
// refuses a cap below the record and may refuse any other call, for the
// sequence number rules of RFC 9846 §5.3 and §5.5, and on a refusal it
// writes any length, because record.h states none. On success it writes
// unknown bytes over the record, as the real seal writes a header and
// ciphertext.
//
// Bounds. out's array holds CH_KEY_UPDATE_RECORD_LEN + 8 bytes, and cap
// takes every value up to that. The call has no loop.
#include "harness.h"

#include <string.h>

#include "handshake_message.h"
#include "handshake_post.h"
#include "record.h"
#include "session.h"
#include "tls.h"

#define CH_PROOF_OUT (CH_KEY_UPDATE_RECORD_LEN + 8)

static ch_tls_priv t;
static uint8_t out_buf[CH_PROOF_OUT];
static size_t out_cap;
static size_t seals;
static size_t updates;

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    __CPROVER_assert(d == &t.wr, "seal: under the write key");
    __CPROVER_assert(updates == 0, "seal: before the key moves");
    __CPROVER_assert(type == REC_HANDSHAKE && n == 5 && __CPROVER_r_ok(pt, n),
                     "seal: one handshake message of 5 bytes");
    __CPROVER_assert(pt[0] == HS_KEY_UPDATE && pt[1] == 0 && pt[2] == 0 && pt[3] == 1 && pt[4] == 0,
                     "seal: a KeyUpdate that asks for no answer (RFC 9846 §4.7.3)");
    __CPROVER_assert(out == out_buf && cap == out_cap && out_len != NULL,
                     "seal: into the caller's out");
    seals++;
    if (cap < CH_KEY_UPDATE_RECORD_LEN || (nondet_u8() & 1)) {
        *out_len = nondet_size_t();
        return -1;
    }
    fill_nondet(out, CH_KEY_UPDATE_RECORD_LEN);
    d->seq++;
    *out_len = CH_KEY_UPDATE_RECORD_LEN;
    return 0;
}

void rec_dir_update(uint8_t *secret, rec_dir *d) {
    __CPROVER_assert(secret == t.wr_secret && d == &t.wr, "update: the write key");
    __CPROVER_assert(seals == 1, "update: after the record is sealed");
    updates++;
    d->seq = 0;
}

int main(void) {
    t.send_epochs = (uint64_t)nondet_i64();
    __CPROVER_assume(t.send_epochs < HSPOST_SEND_EPOCHS_MAX);
    t.key_update_owed = nondet_u8() & 1;
    t.wr.seq = (uint64_t)nondet_i64();
    out_cap = nondet_size_t();
    __CPROVER_assume(out_cap <= sizeof out_buf);
    uint64_t epochs = t.send_epochs;
    uint8_t owed = t.key_update_owed;
    uint64_t seq = t.wr.seq;
    size_t out_len = nondet_size_t();

    int rc = hspost_seal_key_update(&t, out_buf, out_cap, &out_len);

    __CPROVER_assert(rc == CH_OK || rc == CH_ECAP, "the two codes handshake_post.h lists");
    __CPROVER_assert(seals == 1, "one seal a call");
    if (rc == CH_OK) {
        __CPROVER_assert(out_len == CH_KEY_UPDATE_RECORD_LEN && out_cap >= out_len,
                         "CH_OK: one KeyUpdate record inside out");
        __CPROVER_assert(updates == 1 && t.send_epochs == epochs + 1 && t.key_update_owed == 0,
                         "CH_OK: the next write key, one more KeyUpdate sent, no answer owed");
    } else {
        __CPROVER_assert(out_len == 0, "CH_ECAP: *out_len is 0");
        __CPROVER_assert(updates == 0 && t.send_epochs == epochs && t.key_update_owed == owed &&
                             t.wr.seq == seq,
                         "CH_ECAP: the write key, the KeyUpdates sent and the owed answer stay");
    }
    return 0;
}
