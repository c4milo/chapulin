// Proves: handshake_record.c is memory-safe and UB-free on any record
// stream a peer can send -- compaction, CCS tolerance, the quiet cap,
// in-place decryption, and message reassembly across records -- and that
// a yielded message lies wholly inside cfg.buf with a 3-byte length that
// agrees with the length the reader reports. Driving hsr_next_msg drives
// hsr_fetch_record, which it calls, so one formula covers both entry
// points; hsr_transcript_hash runs after it and must leave the running
// transcript byte for byte as it found it.
//
// The harness exists so the two drivers can stub this module. Before it,
// proof-coverage reported handshake_record.c as covered by handshake_psk
// and handshake_pin alone, and neither returned a verdict
// (https://github.com/c4milo/chapulin/issues/37). Both converge over the
// stub now; proof/run.sh's launch lines carry the nightly's numbers.
//
// Layered proof: io_read_record and rec_open are stubs asserting the
// contracts their own proofs establish -- io_harness for the record
// length io.c hands back, record_harness for rec_open on hostile bytes
// in the in-place shape this module uses -- and havocing every output.
// SHA-256 is harness.h's stub. Nothing is linked: handshake_record.c
// includes buf.h but calls no rbuf, wbuf or ct function.
//
// Bounds, measured rather than chosen. hsr_fetch_record.0 is 6: the loop
// takes its back edge only on a tolerated CCS record, ccs_tolerable
// allows four, and a fifth comes from an entry ccs_seen of 255, which
// wraps to 0 on the increment. At 5 the unwinding assertion fails.
// hsr_next_msg.0 is 11 at a 12-byte receive buffer: at most 7 fetches
// grow pt_len before io_read_record refuses for want of REC_HDR + 1
// bytes of room, at most CH_QUIET_CAP + 2 add nothing, and one more
// returns. The buffer and the cap are small because the formula's cost
// is their product with the fetch bound; every state the reader can be
// in is still reachable, because the harness havocs pt_off, pt_len and
// every buffer byte on entry rather than reaching them through records.
// Larger receive buffers only repeat the middle: the same formula at 16
// bytes proves in 2234 s against 487 s here.
//
// What this harness does not carry: the record stream feeding a whole
// handshake flight. That stays with handshake_psk, handshake_pin,
// test/e2e.sh and fuzz/fuzz_handshake_record.c.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "cfg.h"
#include "handshake_message.h"
#include "io.h"
#include "record.h"
#include "session.h"

// The receive buffer. Its size and CH_QUIET_CAP come from the launch
// line, per session.h, which makes the cap a build-time constant so a
// proof can drive the same loop bodies at a smaller bound.
#ifndef CH_PROOF_RXBUF
#define CH_PROOF_RXBUF 12
#endif

uint32_t nondet_u32(void);
uint64_t nondet_u64(void);
int nondet_int(void);

// The record path's own fill loop. harness.h's fill_nondet is one static
// function whose single --unwindset bound every call site shares, and
// the SHA-256 stub's 32-byte digest sets that bound. A separate loop
// keeps the two record stubs, which unroll inside both loops under
// proof, at the receive buffer's size instead of the digest's.
static void fill_buf_nondet(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = nondet_u8();
    }
}

// The hostile input source: any outer type, any body bytes, any length
// io.c admits, or any of its three errors. The clause that matters is
// REC_HDR <= record_len <= cap (io.c:23-35). handshake_record.c never
// re-checks it, and the memmove at accept_record, the rec_open call and
// the CCS payload byte all read within it.
int io_read_record(const ch_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer,
                   size_t *record_len) {
    __CPROVER_assert(cfg != NULL, "read: cfg valid");
    uint8_t choice = nondet_u8();
    if (choice == 0) {
        return CH_EIO;
    }
    if (choice == 1) {
        return CH_EPROTO;
    }
    if (choice == 2 || cap < REC_HDR + 1) {
        return CH_ECAP;
    }
    size_t body = nondet_size_t();
    __CPROVER_assume(body >= 1 && body <= 0x4000 + 256 && REC_HDR + body <= cap);
    __CPROVER_assert(__CPROVER_w_ok(buf, REC_HDR + body), "read: buffer writable");
    fill_buf_nondet(buf, REC_HDR + body);
    *outer = nondet_u8();
    *record_len = REC_HDR + body;
    return CH_OK;
}

// Typed stores: a byte-pointer fill through a member pointer makes every
// store a whole-object update of the enclosing struct in the SSA
// (docs/proofs.md).
static void fill_rec_dir_nondet(rec_dir *d) {
    fill_nondet(d->key, sizeof d->key);
    fill_nondet(d->iv, sizeof d->iv);
    d->seq = nondet_u64();
}

// All-or-nothing, the contract record_harness proves of the real
// rec_open: plaintext appears only on success, and never more than the
// buffer or 2^14+1 bytes of it.
int rec_open(rec_dir *d, const uint8_t *rec, size_t n, uint8_t *pt, size_t cap, size_t *pt_len,
             uint8_t *type) {
    __CPROVER_assert(__CPROVER_w_ok(d, sizeof *d), "open: dir writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(rec, n), "open: record readable");
    if (nondet_u8() & 1) {
        return -1;
    }
    size_t out = nondet_size_t();
    __CPROVER_assume(out <= cap && out <= 0x4001);
    __CPROVER_assert(out == 0 || __CPROVER_w_ok(pt, out), "open: pt writable");
    fill_buf_nondet(pt, out);
    *pt_len = out;
    *type = nondet_u8();
    return 0;
}

#include "handshake_record.c"

static void fill_transcript_nondet(sha256 *s) {
    for (size_t i = 0; i < 8; i++) {
        s->h[i] = nondet_u32();
    }
    s->total_bytes = nondet_u64();
    // Its own loop, for the reason fill_buf_nondet has one: this 64-byte
    // fill is wider than anything the record path writes.
    for (size_t i = 0; i < SHA256_BLOCK; i++) {
        s->block[i] = nondet_u8();
    }
    s->fill = nondet_size_t();
}

// handshake_record.h says hsr_transcript_hash leaves the running hash
// alone. Comparing field by field also catches an edit that passed
// &h->t->transcript to sha256_final instead of the copy.
static void assert_transcript_kept(const sha256 *a, const sha256 *b) {
    for (size_t i = 0; i < 8; i++) {
        __CPROVER_assert(a->h[i] == b->h[i], "hash: state word kept");
    }
    __CPROVER_assert(a->total_bytes == b->total_bytes, "hash: byte count kept");
    __CPROVER_assert(a->fill == b->fill, "hash: pending count kept");
    for (size_t i = 0; i < SHA256_BLOCK; i++) {
        __CPROVER_assert(a->block[i] == b->block[i], "hash: pending block kept");
    }
}

int main(void) {
    ch_tls t;
    handshake_state h;
    uint8_t buf[CH_PROOF_RXBUF];

    memset(&t, 0, sizeof t);
    memset(&h, 0, sizeof h);
    h.t = &t;
    t.cfg.buf = buf;
    t.cfg.buf_len = sizeof buf;
    // Every byte of the receive buffer is a byte an earlier record left
    // there, so all of it is the peer's.
    fill_buf_nondet(buf, sizeof buf);
    fill_rec_dir_nondet(&t.rd);
    fill_transcript_nondet(&t.transcript);

    // The one thing a caller guarantees and this module never checks:
    // the unread window sits inside the buffer. tls.c and handshake.c
    // establish it before the first call. Without it the pt_len - pt_off
    // and buf_len - part subtractions wrap, and the harness would report
    // a fault no caller can produce. Asserting it again on exit is what
    // makes assuming it inductive rather than free.
    size_t off = nondet_size_t();
    size_t len = nondet_size_t();
    __CPROVER_assume(off <= len && len <= sizeof buf);
    t.pt_off = off;
    t.pt_len = len;

    // Full range on both counters. ccs_seen at 255 wraps on the
    // increment and buys one more tolerated CCS record, which is what
    // sets the fetch loop's bound; quiet wraps the same way.
    h.encrypted = nondet_int();
    h.ccs_seen = nondet_u8();
    h.quiet = nondet_u8();
    h.alert = nondet_u8();

    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = hsr_next_msg(&h, &type, &raw, &raw_len);
    if (rc == CH_OK) {
        // What every parser above rests on: handshake.c and
        // handshake_auth.c hand raw + 4 and raw_len - 4 straight to the
        // parsers, so a message that ran past the buffer, or a length
        // that disagreed with the header, would hand them a lie.
        __CPROVER_assert(raw >= buf, "msg: starts inside the buffer");
        __CPROVER_assert(raw_len >= 4 && raw_len <= 4 + 0x4000, "msg: length in range");
        __CPROVER_assert((size_t)(raw - buf) <= sizeof buf - raw_len,
                         "msg: ends inside the buffer");
        __CPROVER_assert((size_t)(raw - buf) + raw_len <= t.pt_len, "msg: inside the plaintext");
        size_t msg_len = ((size_t)raw[1] << 16) | ((size_t)raw[2] << 8) | raw[3];
        __CPROVER_assert(raw_len == 4 + msg_len, "msg: header agrees with the length");
    }
    __CPROVER_assert(t.pt_off <= t.pt_len && t.pt_len <= t.cfg.buf_len, "window inside the buffer");

    uint8_t digest[SHA256_LEN];
    sha256 before = t.transcript;
    int hash_rc = hsr_transcript_hash(&h, digest);
    __CPROVER_assert(hash_rc == CH_OK, "hash: snapshot never fails");
    assert_transcript_kept(&t.transcript, &before);
    return 0;
}
