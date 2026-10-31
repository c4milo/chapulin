// Proves: srv_out.c's calls are memory safe and free of UB over an
// unconstrained peer limit, message and transport answer, in the build
// the defines name. Also:
// - srv_out_limit is at least 1 and at most CH_TX_PT, and over TLS at
//   most the peer's limit;
// - srv_out_plain writes a handshake record header that names n bytes
//   and sends exactly that record;
// - srv_out_sealed seals pt in order, each record at most srv_out_limit
//   bytes, and sends each sealed record whole; on CH_OK it sealed all n;
// - srv_frag_bytes and srv_frag_flush send every byte they took once, in
//   records of at most srv_out_limit and SRV_FRAG_MAX bytes, while rc is
//   CH_OK;
// - every refusal is CH_EIO, or CH_ECAP from a seal, and writes
//   internal_error into h->alert first (srv_out.h).
//
// The record layer's seal, the caller's transport and the transcript's
// SHA-256 are contract stubs. proof/srv_out_quic_harness.c and
// proof/srv_out_nonblocking_harness.c include this file under the other
// two transports.
//
// memcpy is a contract stub too. srv_frag_bytes copies into a 512-byte
// buffer at an offset the peer's limit decides, and CBMC models that copy
// byte by byte: the formula ran out of memory before the solver started.
// No property here reads the bytes a copy writes, so the stub asserts both
// ranges and copies nothing.
//
// One bound is the harness's: MSG_MAX bytes in a message. srv_store_selection
// stores a peer limit of 64 or more (srv_flight.h, srv_parser.h), so a
// message of MSG_MAX bytes runs the record loop at most 4 times and the
// writer's loop at most 5; a longer message runs the same loops more times.
// Over QUIC two writes of MSG_MAX bytes pass CH_TX_PT, so the writer fills.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "handshake_message.h"
#include "srv_out.h"

int nondet_int(void);
uint16_t nondet_u16(void);

// Over QUIC the writer's limit is CH_TX_PT, so two writes need more bytes
// to fill it.
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define MSG_MAX 260
#else
#define MSG_MAX 200
#endif
#define ALERT_UNWRITTEN 0xff
#define PEER_LIMIT_MIN 64 // srv_parser.h refuses a record_size_limit below it

void *memcpy(void *dst, const void *src, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(dst, n), "memcpy: destination writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(src, n), "memcpy: source readable");
    return dst;
}

static ch_tls t;
static handshake_state h;
// No property reads a message byte, so both stay zero.
static uint8_t msg[MSG_MAX];
static uint8_t more[MSG_MAX];

// What the stubs saw since reset(): the bytes handed to the transport and
// the plaintext bytes sealed or pushed, in order from expect_pt.
static size_t sent_count;     // transport calls
static size_t sent_len;       // bytes in the last transport call
static const uint8_t *sent_p; // where the last transport call read
static size_t taken;          // plaintext bytes sealed or pushed
static const uint8_t *expect_pt;
static size_t sealed_len; // out_len of the last seal

static void reset(const uint8_t *pt) {
    sent_count = 0;
    sent_len = 0;
    sent_p = NULL;
    taken = 0;
    expect_pt = pt;
    sealed_len = 0;
    h.alert = ALERT_UNWRITTEN;
}

// The limit the record loop must hold each piece to.
static size_t piece_max(void) {
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    return CH_TX_PT;
#else
    return t.peer_limit < CH_TX_PT ? t.peer_limit : CH_TX_PT;
#endif
}

// One transport answer: 0 takes the bytes, anything else refuses them.
static int transport(const uint8_t *p, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "transport: bytes readable");
    sent_count++;
    sent_len = n;
    sent_p = p;
    return nondet_int();
}

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
static int on_crypto_out(void *io, uint8_t level, const uint8_t *p, size_t n) {
    (void)io;
    __CPROVER_assert(level == h.level, "crypto out: the driver's level");
    if (expect_pt != NULL) {
        __CPROVER_assert(p == expect_pt + taken, "crypto out: bytes in order");
    }
    taken += n;
    return transport(p, n);
}
#else
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
static int on_record_out(void *io, const uint8_t *p, size_t n) {
    (void)io;
    return transport(p, n);
}
#else
int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    __CPROVER_assert(cfg == &t.cfg, "send: the session's cfg");
    return transport(p, n) == 0 ? CH_OK : CH_EIO;
}
#endif

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    __CPROVER_assert(d == &t.wr, "seal: the write direction");
    __CPROVER_assert(type == REC_HANDSHAKE, "seal: a handshake record");
    __CPROVER_assert(n >= 1 && n <= piece_max(), "seal: a piece within the limit");
    __CPROVER_assert(__CPROVER_r_ok(pt, n), "seal: plaintext readable");
    __CPROVER_assert(out == t.tx && cap == sizeof t.tx, "seal: into tx whole");
    if (expect_pt != NULL) {
        __CPROVER_assert(pt == expect_pt + taken, "seal: plaintext in order");
    }
    if ((nondet_u8() & 1) != 0) {
        return -1;
    }
    __CPROVER_assert(n + REC_OVERHEAD <= cap, "seal: the record fits tx");
    taken += n;
    sealed_len = n + REC_OVERHEAD;
    *out_len = sealed_len;
    return 0;
}
#endif

// srv_out.h's rule for every call's result.
static void refusal_named(int rc, int allow_ecap) {
    __CPROVER_assert(rc == CH_OK || rc == CH_EIO || (allow_ecap && rc == CH_ECAP),
                     "a result srv_out.h names");
    if (rc != CH_OK) {
        __CPROVER_assert(h.alert == ALERT_INTERNAL_ERROR, "a refusal names internal_error");
    } else {
        __CPROVER_assert(h.alert == ALERT_UNWRITTEN, "success writes no alert");
    }
}

static void fresh(void) {
    memset(&t, 0, sizeof t);
    memset(&h, 0, sizeof h);
    h.t = &t;
    t.hash_len = SHA256_LEN;
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    h.level = nondet_u8();
    t.cfg.srv.on_crypto_out = on_crypto_out;
#else
    t.peer_limit = nondet_u16();
    __CPROVER_assume(t.peer_limit >= PEER_LIMIT_MIN && t.peer_limit <= CH_TX_PT);
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    t.cfg.srv.on_record_out = on_record_out;
#endif
#endif
}

static void prove_limit(void) {
    size_t limit = srv_out_limit(&t);
    __CPROVER_assert(limit >= 1 && limit == piece_max(), "the limit is the smaller cap");
}

static void prove_plain(void) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof t.tx - SRV_OUT_STAGE);
    reset(NULL);
    int rc = srv_out_plain(&h, n);
    refusal_named(rc, 0);
    __CPROVER_assert(sent_count == 1, "one call to the transport");
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    __CPROVER_assert(sent_p == t.tx && sent_len == n, "the staged bytes alone");
#else
    __CPROVER_assert(sent_p == t.tx && sent_len == REC_HDR + n, "the record whole");
    __CPROVER_assert(t.tx[0] == REC_HANDSHAKE && t.tx[1] == 0x03 && t.tx[2] == 0x03,
                     "a handshake record at version 0x0303");
    __CPROVER_assert(((size_t)t.tx[3] << 8 | t.tx[4]) == n, "the header names n bytes");
#endif
}

#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
static void prove_record(void) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);
    reset(NULL);
    int rc = srv_out_record(&h, msg, n);
    refusal_named(rc, 0);
    __CPROVER_assert(sent_count == 1 && sent_p == msg && sent_len == n, "the record as given");
}
#endif

static void prove_sealed(void) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);
    reset(msg);
    int rc = srv_out_sealed(&h, msg, n);
    refusal_named(rc, 1);
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
    if (sent_count != 0) {
        __CPROVER_assert(sent_p == t.tx && sent_len == sealed_len, "each sealed record whole");
    }
#endif
    if (rc == CH_OK) {
        __CPROVER_assert(taken == n, "every byte went out");
    }
}

// Two writes of any length and a flush, the shape of srv_send_certificate.
static void prove_frag(void) {
    srv_frag f;
    f.h = &h;
    f.len = 0;
    f.rc = CH_OK;
    reset(NULL);
    size_t a = nondet_size_t();
    size_t b = nondet_size_t();
    __CPROVER_assume(a <= sizeof msg && b <= sizeof more);
    size_t room = piece_max() < SRV_FRAG_MAX ? piece_max() : SRV_FRAG_MAX;
    srv_frag_bytes(&f, msg, a);
    __CPROVER_assert(f.rc != CH_OK || (f.len < room && taken + f.len == a),
                     "the writer holds what it has not sent");
    srv_frag_bytes(&f, more, b);
    __CPROVER_assert(f.rc != CH_OK || (f.len < room && taken + f.len == a + b),
                     "the writer holds what it has not sent");
    srv_frag_flush(&f);
    refusal_named(f.rc, 1);
    if (f.rc == CH_OK) {
        __CPROVER_assert(f.len == 0 && taken == a + b, "a flush sends the rest");
    }
}

int main(void) {
    fresh();
    prove_limit();
    fresh();
    prove_plain();
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
    fresh();
    prove_record();
#endif
    fresh();
    prove_sealed();
    fresh();
    prove_frag();
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    fresh();
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);
    reset(NULL);
    srv_out_alert(&t, msg, n);
    __CPROVER_assert(sent_count == 1 && sent_p == msg && sent_len == n, "the alert as given");
#endif
    return 0;
}
