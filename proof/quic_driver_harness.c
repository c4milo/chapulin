// Proves: quic.c's public entries and its input loop are memory-safe
// and UB-free over any saved state and any caller argument, and that
// each one keeps the contract quic.h states. The QUIC arm of
// handshake_record.c and all of quic_config.c are real here, so one
// formula covers the reader the loop drives and the rules ch_quic_init
// applies.
//
// Layered proof: hsq_advance is a stub asserting the contract
// quic_step.h states and havocing every field a step may write, so the
// driver's proof rests on no handler; quic_step proves the table over
// the same contract, and the two read as a pair. hsf_begin,
// hsf_build_client_hello and the packet calls are the contract stubs
// proof/quic_driver_stubs.h states. SHA-256 is harness.h's stub, called
// only through hsr_transcript_hash, which the driver never calls.
//
// What is havocked and what is not. Every scalar the driver branches
// on, both offsets, the staging array, the three traffic secrets, the
// stored Destination Connection ID and every byte of the receive buffer
// are unconstrained. The packet protection key structs are not: quic.c
// passes their addresses to the stubs above and reads no byte of one,
// so their content decides no path here. quic.c holds no
// aes_public_key at all, which is what INV-26 asks of every file
// outside the four that may write one.
//
// Bounds. CH_PROOF_RXBUF is 12, the value handshake_record's own
// harness uses, so every state this leg drives is inside the window
// that proof discharges. CH_TX_STAGE keeps the build's own 1141,
// because quic.c's static assertion holds it against CH_HELLO_MAX, and
// CH_PROOF_TX bounds the staged length at 32 instead: the drain is a
// memcpy of tx_len bytes and one length compare, so a larger tx_len
// repeats those two operations and runs no further path. drive.0 is
// 5: each iteration past the first runs a step, a step consumes at
// least four buffer bytes, and twelve bytes hold at most three of them.
// ct_wipe.0 is 441, one past sizeof(handshake_state), the largest
// object quic_wipe clears; fill_nondet.0 is 33, one past CH_PROOF_TX.
//
// What this harness does not carry: what a step does. That is
// quic_step's, and the flight handlers under it stay with
// handshake_psk and handshake_pin.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "handshake_message.h"
#include "quic.h"
#include "quic_packet.h"

#ifndef CH_PROOF_RXBUF
#define CH_PROOF_RXBUF 12
#endif

// The staged message length this leg considers, above.
#ifndef CH_PROOF_TX
#define CH_PROOF_TX 32
#endif

uint64_t nondet_u64(void);
int nondet_int(void);

// The step table's contract, as quic_step.h states it. It consumes the
// one whole message hsr_peek_message found, which is at least four
// bytes, and it may raise the step, move rx_level, stage a message and
// install keys. It never raises t.state and never touches the packet
// counters.
//
// Its error codes are the three quic.h lists for ch_quic_crypto_in and
// not the four quic_step.h lists: the driver runs a step only after
// hsr_peek_message answered CH_OK, and the CH_EINVAL a step can return
// is hsr_next_msg's answer to no whole message.
int hsq_advance(ch_quic *q) {
    __CPROVER_assert(q != NULL, "advance: session valid");
    __CPROVER_assert(q->hs.t == &q->t, "advance: back pointer written");
    __CPROVER_assert(q->t.state == CH_ST_START || q->t.state == CH_ST_CONNECTED,
                     "advance: session live");
    __CPROVER_assert(q->t.pt_off + 4 <= q->t.pt_len, "advance: a whole message is unread");
    size_t taken = nondet_size_t();
    __CPROVER_assume(taken >= 4 && taken <= q->t.pt_len - q->t.pt_off);
    q->t.pt_off += taken;
    q->step = nondet_u8();
    q->rx_level = nondet_u8();
    q->levels_ready = nondet_u8();
    int rc = nondet_int();
    if (rc != CH_OK) {
        __CPROVER_assume(rc == CH_EPROTO || rc == CH_EAUTH || rc == CH_ECAP);
        q->hs.alert = nondet_u8();
        return rc;
    }
    size_t staged = nondet_size_t();
    __CPROVER_assume(staged <= CH_PROOF_TX);
    q->tx_len = staged;
    q->tx_level = nondet_u8();
    return CH_OK;
}

#include "quic_driver_stubs.h"

#include "quic.c"

static uint8_t buf[CH_PROOF_RXBUF];
static ch_quic q;
static ch_cfg cfg;
static ch_alpn_protocol alpn;
static uint8_t alpn_name[2];
static uint8_t params[2];
static uint8_t pin[256];
// One byte past RFC 9000 §17.2's cap, so the refusal is inside the formula.
static uint8_t dcid[CH_QUIC_DCID_MAX + 1];

// cfg.on_level_ready is read for NULL by ch_quic_init and called by a
// step, which is stubbed here, so this body never runs.
static void level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    (void)level;
    (void)direction;
}

// Any saved state a call can meet, with the one invariant every entry
// establishes and this harness asserts again on exit: the unread window
// sits inside the receive buffer.
static void havoc_session(void) {
    q.step = nondet_u8();
    q.rx_level = nondet_u8();
    q.tx_level = nondet_u8();
    q.alert = nondet_u8();
    q.key_phase = nondet_u8();
    q.levels_ready = nondet_u8();
    q.error_code = nondet_u64();
    q.open_failures = nondet_u64();
    q.initial_sealed = nondet_u64();
    fill_nondet(q.initial_dcid, sizeof q.initial_dcid);
    uint8_t stored_dcid_len = nondet_u8();
    __CPROVER_assume(stored_dcid_len <= CH_QUIC_DCID_MAX);
    q.initial_dcid_len = stored_dcid_len;
    size_t staged = nondet_size_t();
    __CPROVER_assume(staged <= CH_PROOF_TX);
    q.tx_len = staged;
    fill_nondet(q.t.tx, CH_PROOF_TX);
    fill_nondet(q.t.rd_secret, sizeof q.t.rd_secret);
    fill_nondet(q.t.wr_secret, sizeof q.t.wr_secret);
    fill_nondet(q.t.res_master, sizeof q.t.res_master);
    fill_nondet(buf, sizeof buf);
    q.hs.alert = nondet_u8();
    q.hs.t = &q.t;
    q.t.cfg = cfg;
    uint8_t state = nondet_u8();
    __CPROVER_assume(state <= CH_ST_FAILED);
    q.t.state = state;
    size_t off = nondet_size_t();
    size_t len = nondet_size_t();
    __CPROVER_assume(off <= len && len <= sizeof buf);
    q.t.pt_off = off;
    q.t.pt_len = len;
}

static void assert_window(void) {
    __CPROVER_assert(q.t.pt_off <= q.t.pt_len && q.t.pt_len <= q.t.cfg.buf_len,
                     "window inside the buffer");
    __CPROVER_assert(q.tx_len <= CH_PROOF_TX, "staged message inside the staging array");
}

// quic.h: every error but CH_EINVAL from ch_quic_crypto_in leaves the
// session dead, with nothing staged and nothing unread.
static void assert_dead(void) {
    __CPROVER_assert(q.t.state == CH_ST_FAILED, "failure marks the session dead");
    __CPROVER_assert(q.tx_len == 0, "failure stages nothing");
    __CPROVER_assert(q.t.pt_off == 0 && q.t.pt_len == 0, "failure leaves nothing unread");
    __CPROVER_assert(q.levels_ready == 0, "failure protects no packet");
    for (size_t i = 0; i < SHA256_LEN; i++) {
        __CPROVER_assert(q.t.rd_secret[i] == 0 && q.t.wr_secret[i] == 0 && q.t.res_master[i] == 0,
                         "failure wipes the traffic secrets");
    }
}

static void drive_crypto_in(void) {
    uint8_t in[CH_PROOF_RXBUF];
    fill_nondet(in, sizeof in);
    uint8_t level = nondet_u8();
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof in);
    uint8_t was_level = q.rx_level;
    size_t was_tx = q.tx_len;
    uint8_t was_state = q.t.state;
    size_t was_off = q.t.pt_off;
    size_t was_len = q.t.pt_len;
    int live = was_state != CH_ST_CLOSED && was_state != CH_ST_FAILED;
    int rc = ch_quic_crypto_in(&q, level, in, n);
    assert_window();
    if (rc == CH_EINVAL) {
        __CPROVER_assert(live, "CH_EINVAL means the session was live");
        __CPROVER_assert(q.rx_level == was_level && q.tx_len == was_tx && q.t.state == was_state &&
                             q.t.pt_off == was_off && q.t.pt_len == was_len,
                         "CH_EINVAL changes nothing");
        __CPROVER_assert(level > CH_LEVEL_APPLICATION || was_tx != 0 ||
                             (level > was_level && was_off == was_len),
                         "CH_EINVAL names one of the three refusals quic.h lists");
    }
    if (rc != CH_OK && rc != CH_EINVAL && live) {
        assert_dead();
        __CPROVER_assert(ch_quic_error_code(&q) != 0, "a failed session reports a code");
    }
    if (live && was_tx == 0 && level <= CH_LEVEL_APPLICATION &&
        (level < was_level || (level > was_level && was_off != was_len))) {
        __CPROVER_assert(rc == CH_EPROTO, "a level out of order is a protocol error");
        __CPROVER_assert(ch_quic_error_code(&q) == QUIC_PROTOCOL_VIOLATION,
                         "RFC 9001 4.1.3: that error is PROTOCOL_VIOLATION");
    }
}

static void drive_crypto_out(void) {
    uint8_t out[CH_PROOF_TX];
    size_t out_len = nondet_size_t();
    uint8_t level = nondet_u8();
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof out);
    size_t was_tx = q.tx_len;
    uint8_t was_state = q.t.state;
    int rc = ch_quic_crypto_out(&q, level, out, cap, &out_len);
    if (rc == CH_ECAP) {
        __CPROVER_assert(q.tx_len == was_tx && q.t.state == was_state,
                         "a short buffer consumes nothing");
        __CPROVER_assert(cap < was_tx, "CH_ECAP means the buffer was short");
    }
    if (rc == CH_OK) {
        __CPROVER_assert(out_len <= cap, "the message fits the caller's buffer");
        __CPROVER_assert(q.tx_len == 0 || level != q.tx_level, "a drained level owes nothing");
    }
    assert_window();
}

static void drive_packets(void) {
    uint8_t pkt[CH_PROOF_RXBUF];
    uint8_t out[CH_PROOF_RXBUF + 4 + GCM_TAG];
    uint8_t hdr[4];
    uint8_t tag[GCM_TAG];
    size_t out_len = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    uint8_t key_set = 0;
    fill_nondet(pkt, sizeof pkt);
    fill_nondet(hdr, sizeof hdr);
    fill_nondet(tag, sizeof tag);

    uint8_t level = nondet_u8();
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof out);
    uint64_t was_sealed = q.initial_sealed;
    int rc = ch_quic_seal(&q, level, nondet_u64(), nondet_size_t(), hdr, sizeof hdr, pkt,
                          sizeof pkt, out, cap, &out_len);
    __CPROVER_assert(rc == CH_OK || q.initial_sealed == was_sealed,
                     "RFC 9001 6.6: a seal that did not happen counts nowhere");

    level = nondet_u8();
    size_t pkt_len = nondet_size_t();
    size_t pn_off = nondet_size_t();
    __CPROVER_assume(pkt_len <= sizeof pkt && pn_off <= pkt_len);
    uint8_t was_state = q.t.state;
    uint64_t was_failures = q.open_failures;
    rc = ch_quic_open(&q, level, pkt, pkt_len, pn_off, nondet_u64(), nondet_u64(), &key_set, &pn,
                      &pt_len);
    if (rc == CH_OK) {
        __CPROVER_assert(key_set < CH_QUIC_KEY_SETS, "the set that opened it is a named index");
        __CPROVER_assert(pt_len <= pkt_len, "the plaintext is inside the packet");
        __CPROVER_assert(level != CH_LEVEL_APPLICATION || was_state == CH_ST_CONNECTED,
                         "RFC 9001 5.7: no 1-RTT packet before the handshake completes");
    }
    if (pn_off > pkt_len || pkt_len - pn_off < QUIC_PN_MAX_LEN + QUIC_HP_SAMPLE_LEN) {
        __CPROVER_assert(q.open_failures == was_failures,
                         "RFC 9001 5.4.2: a packet too short to sample counts nowhere");
    }
    (void)ch_quic_retry_ok(&q, pkt, sizeof pkt, tag);
    (void)ch_quic_key_update(&q);
    ch_quic_drop_previous_keys(&q);
    (void)ch_quic_discard(&q, nondet_u8());
    (void)ch_quic_key_phase(&q);
    (void)ch_quic_alert(&q);
    (void)ch_quic_state(&q);
    (void)ch_quic_error_code(&q);
}

// The configuration ch_quic_init judges. Three fields vary, one per
// rule quic.h adds to the trust mode's: the callback, the encoded
// transport parameters and the receive buffer floor.
static void build_cfg(void) {
    memset(&cfg, 0, sizeof cfg);
    fill_nondet(alpn_name, sizeof alpn_name);
    fill_nondet(params, sizeof params);
    fill_nondet(pin, sizeof pin);
    pin[sizeof pin - 1] |= 1; // an RSA modulus is odd
    alpn.name = alpn_name;
    alpn.name_len = sizeof alpn_name;
    cfg.buf = buf;
    cfg.buf_len = sizeof buf;
    cfg.alpn_protocols = &alpn;
    cfg.alpn_count = 1;
    cfg.transport_params = params;
    cfg.transport_params_len = sizeof params;
    cfg.on_level_ready = level_ready;
    cfg.server_pubkey = pin;
    cfg.server_pubkey_len = sizeof pin;
}

int main(void) {
    build_cfg();
    fill_nondet(buf, sizeof buf);
    cfg.on_level_ready = (nondet_u8() & 1) ? NULL : level_ready;
    cfg.transport_params_len = (nondet_u8() & 1) ? 0 : sizeof params;
    cfg.buf_len = (nondet_u8() & 1) ? 1 : sizeof buf;
    int rc = ch_quic_init(&q, &cfg);
    if (rc != CH_OK) {
        __CPROVER_assert(rc == CH_EINVAL, "ch_quic_init has one refusal code");
        __CPROVER_assert(q.t.state == CH_ST_FAILED, "a refused config leaves a dead session");
        __CPROVER_assert(q.tx_len == 0, "a refused config stages nothing");
    } else {
        __CPROVER_assert(q.t.state == CH_ST_START, "an accepted config starts the handshake");
        __CPROVER_assert(q.step == HSQ_STEP_AWAIT_SERVER_HELLO, "the first step waits on the SH");
        __CPROVER_assert(q.tx_level == CH_LEVEL_INITIAL && q.rx_level == CH_LEVEL_INITIAL,
                         "both levels start at Initial");
    }

    // The entries over arbitrary saved state, each operand havocked
    // freshly before the call.
    build_cfg();
    havoc_session();
    fill_nondet(dcid, sizeof dcid);
    size_t dcid_len = nondet_size_t();
    __CPROVER_assume(dcid_len <= sizeof dcid);
    uint8_t was_ready = q.levels_ready;
    uint8_t was_dcid_len = q.initial_dcid_len;
    int live = q.t.state != CH_ST_CLOSED && q.t.state != CH_ST_FAILED;
    rc = ch_quic_initial_keys(&q, dcid, dcid_len);
    if (rc == CH_OK) {
        __CPROVER_assert(live && dcid_len <= CH_QUIC_DCID_MAX,
                         "the connection ID fits and the session was live");
        __CPROVER_assert(q.initial_dcid_len == dcid_len, "the stored length is the caller's");
        __CPROVER_assert((q.levels_ready & CH_QUIC_LEVEL_BIT(CH_LEVEL_INITIAL, CH_KEY_READ)) != 0 &&
                             (q.levels_ready & CH_QUIC_LEVEL_BIT(CH_LEVEL_INITIAL, CH_KEY_WRITE)) !=
                                 0,
                         "both Initial bits are set");
    } else {
        __CPROVER_assert(rc == CH_EINVAL, "ch_quic_initial_keys has one refusal code");
        __CPROVER_assert(q.levels_ready == was_ready && q.initial_dcid_len == was_dcid_len,
                         "a refusal writes neither field and clears no bit");
    }
    assert_window();

    havoc_session();
    drive_crypto_in();

    havoc_session();
    drive_crypto_out();

    havoc_session();
    drive_packets();
    assert_window();

    ch_quic_close(&q);
    __CPROVER_assert(q.t.state == CH_ST_CLOSED, "close ends the session");
    __CPROVER_assert(q.levels_ready == 0, "close protects no packet");
    __CPROVER_assert(ch_quic_error_code(&q) == 0, "a closed session reports NO_ERROR");
    return 0;
}
