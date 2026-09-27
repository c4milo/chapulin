// Proves, in a -DCH_SUITE_AES_GCM build: ch_writable_len's answer
// (tls_write.c) is the most plaintext the real ch_write sends in cap bytes,
// the KeyUpdate record ch_write sends at an AES-GCM write key's ceiling
// included, at a bound: for every peer_limit from 63 up, every cap up to
// three whole records of the session's own record limit, a KeyUpdate
// record and one byte, each of the three suites and every write sequence
// number below REC_AES_GCM_RECORDS_MAX (record.h), ch_write hands cfg.send
// at most cap bytes for the answer, and more than cap bytes for one byte
// more.
// proof/writable_len_suite_any_harness.c proves ch_writable_len safe and
// UB-free over any input in this build; the two claims sit apart because
// each costs a division, and docs/proofs.md splits a formula along its
// arithmetic.
//
// On the way it proves what ch_write does at the ceiling. Under AES-GCM no
// data record takes the key's last sequence number,
// REC_AES_GCM_RECORDS_MAX - 1; the KeyUpdate takes that one and no other;
// and when a write returns, the key still has that last sequence number
// free. Under ChaCha20-Poly1305 no KeyUpdate goes out at all.
//
// proof/writable_len_harness.c proves the one-suite build, where neither
// the ceiling nor ch_writable_len's KeyUpdate term compiles. This is the
// same shape over the build where both do. rec_seal is its contract
// (record.h): it writes n + REC_OVERHEAD bytes and moves the sequence
// number on by one. hspost_send_key_update is its contract
// (handshake_post.h): one record of CH_KEY_UPDATE_RECORD_LEN bytes sent
// under the current key, then the next key at sequence number 0 and one
// more KeyUpdate counted. send_epochs stays below HSPOST_SEND_EPOCHS_MAX,
// so tlsi_fail is a stub that fails the proof, because no path here may
// call it; test/key_limit_cases.h tests the write at the cap.
//
// Why the bounds. The cap holds three records of the session's own limit,
// a KeyUpdate record and one byte, so ch_write loops at most four times,
// and every place the KeyUpdate can fall among a write's records is
// covered: before the first, between two, and after the last whole one.
// writable_len bounds its cap by CH_TX_PT instead, which at a limit of 63
// lets ch_write loop 20 times; with that bound and the KeyUpdate term, this
// formula returned no verdict in 10 minutes of kissat, and each of its two
// claims alone took 300 and 393 seconds. The cap is also written as its 11
// low bits and the sequence number as its 24 low bits, a power-of-two
// bound as bit structure rather than as a comparison (docs/proofs.md).
#include "harness.h"

#include <string.h>

#include "handshake_post.h"
#include "io.h"
#include "record.h"
#include "session.h"
#include "tls.h"

#if !defined(CH_SUITE_AES_GCM)
#error "writable_len_suite proves the suite build; its launch line must pass -DCH_SUITE_AES_GCM"
#endif

uint64_t nondet_u64(void);

// The bytes ch_write handed cfg.send.
static size_t sent_bytes;

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    (void)cfg;
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "send: the record is readable");
    sent_bytes += n;
    return CH_OK;
}

// record.h's contract: out gets n + REC_OVERHEAD bytes, and the sequence
// number moves on by one. The bytes are no property here, so the stub
// writes none. ch_write seals application data alone, and never at an
// AES-GCM key's last sequence number, which is the KeyUpdate's.
int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    __CPROVER_assert(type == REC_APPDATA, "seal: ch_write seals application data");
    __CPROVER_assert(!suite_runs_aes_gcm(d->suite) || d->seq < REC_AES_GCM_RECORDS_MAX - 1,
                     "seal: no data record at an AES-GCM key's last sequence number");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "seal: pt readable");
    __CPROVER_assert(REC_OVERHEAD + n <= cap, "seal: ch_write stages a record its buffer holds");
    __CPROVER_assert(__CPROVER_w_ok(out, n + REC_OVERHEAD), "seal: out writable");
    d->seq++;
    *out_len = n + REC_OVERHEAD;
    return 0;
}

// handshake_post.h's contract: one KeyUpdate record sent under the current
// key, then the next key at sequence number 0, and one more counted.
int hspost_send_key_update(ch_tls *t) {
    __CPROVER_assert(suite_runs_aes_gcm(t->wr.suite), "key update: under AES-GCM alone");
    __CPROVER_assert(t->wr.seq == REC_AES_GCM_RECORDS_MAX - 1,
                     "key update: at the key's last sequence number");
    __CPROVER_assert(t->send_epochs < HSPOST_SEND_EPOCHS_MAX, "key update: below the sender cap");
    sent_bytes += CH_KEY_UPDATE_RECORD_LEN;
    t->wr.seq = 0;
    t->send_epochs++;
    return CH_OK;
}

void tlsi_fail(ch_tls *t, uint8_t description) {
    (void)t;
    (void)description;
    __CPROVER_assert(0, "tlsi_fail unreachable: every seal and send succeeds, below the cap");
}

#include "tls_write.c"

// The largest cap: three whole records at CH_TX_PT, a KeyUpdate record and
// one byte, which 11 bits hold at the default CH_TX_PT.
#define WRITE_CAP_BITS 11
#define WRITE_CAP_MAX (3 * (CH_TX_PT + REC_OVERHEAD) + CH_KEY_UPDATE_RECORD_LEN + 1)
_Static_assert(WRITE_CAP_MAX < (1 << WRITE_CAP_BITS), "the cap's bits hold the largest cap");

// The least peer_limit a connected session holds.
#define WRITE_LIMIT_MIN 63

// The ceiling is a power of two, so its low bits span every sequence
// number below it.
_Static_assert((REC_AES_GCM_RECORDS_MAX & (REC_AES_GCM_RECORDS_MAX - 1)) == 0,
               "the ceiling is a power of two");

static ch_tls t;
static uint8_t plaintext[WRITE_CAP_MAX + 1];

// The bytes ch_write hands cfg.send for n bytes of plaintext, from the
// session main set up; the sequence number and the KeyUpdate count are put
// back afterwards. An AES-GCM key still has its last sequence number free
// when the write returns.
static size_t written(size_t n) {
    uint64_t seq = t.wr.seq;
    uint64_t epochs = t.send_epochs;
    sent_bytes = 0;
    int rc = ch_write(&t, plaintext, n);
    __CPROVER_assert(rc == CH_OK, "write: every record goes out");
    __CPROVER_assert(!suite_runs_aes_gcm(t.wr.suite) || t.wr.seq < REC_AES_GCM_RECORDS_MAX,
                     "write: an AES-GCM key keeps its last sequence number free");
    t.wr.seq = seq;
    t.send_epochs = epochs;
    return sent_bytes;
}

int main(void) {
    // A connected session under one of the three suites, with its write
    // sequence number anywhere ch_write leaves it, through the real
    // ch_write.
    t.state = CH_ST_CONNECTED;
    t.peer_limit = (uint16_t)nondet_u32();
    __CPROVER_assume(t.peer_limit >= WRITE_LIMIT_MIN);
    uint8_t pick = nondet_u8();
    __CPROVER_assume(pick < 3);
    t.wr.suite = SUITE_CHACHA20_POLY1305_SHA256;
    if (pick == 1) {
        t.wr.suite = SUITE_AES_128_GCM_SHA256;
    }
    if (pick == 2) {
        t.wr.suite = SUITE_AES_256_GCM_SHA384;
    }
    t.wr.seq = nondet_u64() & ((uint64_t)REC_AES_GCM_RECORDS_MAX - 1);
    t.send_epochs = nondet_u64();
    __CPROVER_assume(t.send_epochs < HSPOST_SEND_EPOCHS_MAX);
    size_t write_cap = nondet_size_t() & (((size_t)1 << WRITE_CAP_BITS) - 1);
    size_t limit = t.peer_limit < CH_TX_PT ? t.peer_limit : CH_TX_PT;
    __CPROVER_assume(write_cap <= 3 * (limit + REC_OVERHEAD) + CH_KEY_UPDATE_RECORD_LEN + 1);
    size_t n = ch_writable_len(&t, write_cap);
    __CPROVER_assert(written(n) <= write_cap, "writable_len: the answer's records fit cap");
    __CPROVER_assert(written(n + 1) > write_cap, "writable_len: one byte more does not fit");
    return 0;
}
