// ch_seal_in_place's contract between this tree's two tcp-nonblocking
// drivers (tcp_nonblocking.h, docs/decisions.md 248, INV-74). The client
// seals plaintext it wrote at REC_HDR in one buffer, and the server opens
// the records where the seal left them, with ch_read_in_place, so each
// check reads what a peer reads:
//   - writes of one record, of a record and a byte, and of three records
//     and 100 bytes, each read back whole, records_len counting each
//     record's REC_OVERHEAD, and no byte past the records changed;
//   - ch_writable_len, to the byte, for each of those writes;
//   - every refusal on entry and an n one byte past what cap holds, each
//     writing no byte of the buffer or the side and moving no sequence
//     number, then the same write accepted;
//   - an owed KeyUpdate in side before the records, and none after it;
//   - a write whose last record takes the key's last sequence number
//     before the wrap, and one record more refused with internal_error in
//     side and the plaintext left as the caller wrote it;
//   - a KeyUpdate due at the cap of KeyUpdates, refused the same way.
// No seal calls cfg.send, and never_send counts none (INV-28). Included
// by test/tcp_nonblocking_loop_test.c after its handshake helpers.
#ifndef CH_TEST_TCP_NONBLOCKING_SEAL_TESTS_H
#define CH_TEST_TCP_NONBLOCKING_SEAL_TESTS_H

#include <string.h>

#include "handshake_message.h"
#include "handshake_post.h"
#include "record.h"
#include "session_convert.h"
#include "tcp_nonblocking.h"
#include "tls.h"

// The longest write here: three records and 100 bytes.
#define SEAL_PLAIN_MAX (3 * CH_TX_PT + 100)
#define SEAL_BUF_LEN (SEAL_PLAIN_MAX + 4 * REC_OVERHEAD + 64)
// What the seal buffer holds before each call, so a byte the call should
// not write shows.
#define SEAL_CANARY 0xA5

static uint8_t seal_plain[SEAL_PLAIN_MAX];
static uint8_t seal_buf[SEAL_BUF_LEN];
static uint8_t seal_before[SEAL_BUF_LEN];
static uint8_t seal_side[CH_KEY_UPDATE_RECORD_LEN + 8];
static uint8_t seal_read[SEAL_PLAIN_MAX];

// The records n bytes go out in at the session's limit.
static size_t seal_records_for(const ch_tcp_priv *r, size_t n) {
    size_t limit = r->t.peer_limit < CH_TX_PT ? r->t.peer_limit : CH_TX_PT;
    return (n + limit - 1) / limit;
}

// The canary, then n bytes of the plaintext at REC_HDR, and a copy of the
// buffer to compare with after the call.
static void seal_stage(size_t n) {
    memset(seal_buf, SEAL_CANARY, sizeof seal_buf);
    memcpy(seal_buf + REC_HDR, seal_plain, n);
    memcpy(seal_before, seal_buf, sizeof seal_buf);
    memset(seal_side, SEAL_CANARY, sizeof seal_side);
}

// Whether the buffer and the side are as seal_stage left them.
static int seal_untouched(void) {
    int side_kept = 1;
    for (size_t i = 0; i < sizeof seal_side; i++) {
        side_kept &= seal_side[i] == SEAL_CANARY;
    }
    return side_kept && memcmp(seal_buf, seal_before, sizeof seal_buf) == 0;
}

// The server reads len bytes of records at p in place, one record a call,
// into seal_read, and returns the plaintext bytes; *records counts the
// records that carried data and *empty those that carried none.
static size_t seal_read_back(ch_tcp_priv *server, uint8_t *p, size_t len, size_t *records,
                             size_t *empty) {
    size_t off = 0;
    size_t got = 0;
    uint8_t reply[CH_ALERT_RECORD_LEN];
    for (int i = 0; i < 8 && off < len; i++) {
        ch_read_result result;
        int rc = ch_read_in_place(tls_public(&server->t), p + off, len - off, reply, sizeof reply,
                                  &result);
        CHECK(rc == CH_OK && result.reply_len == 0);
        if (rc != CH_OK || result.consumed == 0) {
            break;
        }
        memcpy(seal_read + got, p + off + result.pt_off, result.pt_len);
        got += result.pt_len;
        *records += result.pt_len > 0;
        *empty += result.pt_len == 0;
        off += result.consumed;
    }
    CHECK(off == len);
    return got;
}

// One write of n bytes into a buffer of cap bytes, read back by the
// server: the records, their length, the canary past them and
// ch_writable_len at their length and one byte under it.
static void seal_one(ch_tcp_priv *client, ch_tcp_priv *server, size_t n, size_t cap) {
    seal_stage(n);
    size_t want = n + seal_records_for(client, n) * REC_OVERHEAD;
    ch_seal_result result;
    int rc = ch_seal_in_place(tls_public(&client->t), seal_buf, cap, n, seal_side, sizeof seal_side,
                              &result);
    CHECK(rc == CH_OK && result.side_len == 0 && result.records_len == want);
    if (rc != CH_OK) {
        return;
    }
    CHECK(memcmp(seal_buf + want, seal_before + want, sizeof seal_buf - want) == 0);
    CHECK(ch_writable_len(tls_public(&client->t), want) == n);
    CHECK(ch_writable_len(tls_public(&client->t), want - 1) < n);
    size_t records = 0;
    size_t empty = 0;
    size_t got = seal_read_back(server, seal_buf, result.records_len, &records, &empty);
    CHECK(got == n && memcmp(seal_read, seal_plain, n) == 0);
    CHECK(records == seal_records_for(client, n) && empty == 0);
}

static void test_seal_lengths(ch_tcp_priv *client, ch_tcp_priv *server) {
    const size_t lengths[] = {1, CH_TX_PT - 1, CH_TX_PT, CH_TX_PT + 1, SEAL_PLAIN_MAX};
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        seal_one(client, server, lengths[i], sizeof seal_buf);
    }
}

// One call that must refuse: rc, and no byte or sequence number moved.
static void seal_refused(ch_tcp_priv *client, int want, uint8_t *buf, size_t cap, size_t n,
                         uint8_t *side, size_t side_cap, ch_seal_result *result) {
    uint64_t seq = client->t.wr.seq;
    uint8_t state = client->t.state;
    int rc = ch_seal_in_place(tls_public(&client->t), buf, cap, n, side, side_cap, result);
    CHECK(rc == want && seal_untouched());
    CHECK(client->t.wr.seq == seq && client->t.state == state);
}

static void test_seal_refusals(ch_tcp_priv *client, ch_tcp_priv *server) {
    const size_t n = CH_TX_PT + 1;
    const size_t need = n + (size_t)2 * REC_OVERHEAD;
    ch_seal_result result;
    seal_stage(n);
    seal_refused(client, CH_EINVAL, seal_buf, sizeof seal_buf, n, seal_side, sizeof seal_side,
                 NULL);
    seal_refused(client, CH_EINVAL, seal_buf, sizeof seal_buf, n, NULL, sizeof seal_side, &result);
    seal_refused(client, CH_EINVAL, seal_buf, sizeof seal_buf, n, seal_side,
                 CH_KEY_UPDATE_RECORD_LEN - 1, &result);
    seal_refused(client, CH_EINVAL, NULL, sizeof seal_buf, n, seal_side, sizeof seal_side, &result);
    // One byte short of the two records: refused whole, and the same
    // write into all of them then opens at the next sequence number, so
    // the refusal sealed nothing.
    seal_refused(client, CH_ECAP, seal_buf, need - 1, n, seal_side, sizeof seal_side, &result);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_CONNECTED);
    seal_one(client, server, n, need);
    // A write of no byte writes nothing.
    seal_stage(0);
    CHECK(ch_seal_in_place(tls_public(&client->t), seal_buf, sizeof seal_buf, 0, seal_side,
                           sizeof seal_side, &result) == CH_OK);
    CHECK(result.records_len == 0 && result.side_len == 0 && seal_untouched());
}

// A peer's request owed an answer: the KeyUpdate in side, under the old
// key, before the records, and both records under the next key. The
// server reads the KeyUpdate as a record of no plaintext.
static void test_seal_owed_key_update(ch_tcp_priv *client, ch_tcp_priv *server) {
    const size_t n = CH_TX_PT + 1;
    uint64_t epochs = client->t.send_epochs;
    client->t.key_update_owed = 1;
    seal_stage(n);
    ch_seal_result result;
    CHECK(ch_seal_in_place(tls_public(&client->t), seal_buf, sizeof seal_buf, n, seal_side,
                           sizeof seal_side, &result) == CH_OK);
    CHECK(result.side_len == CH_KEY_UPDATE_RECORD_LEN &&
          result.records_len == n + (size_t)2 * REC_OVERHEAD);
    CHECK(client->t.key_update_owed == 0 && client->t.send_epochs == epochs + 1);
    CHECK(client->t.wr.seq == 2);
    size_t records = 0;
    size_t empty = 0;
    CHECK(seal_read_back(server, seal_side, result.side_len, &records, &empty) == 0 && empty == 1);
    CHECK(seal_read_back(server, seal_buf, result.records_len, &records, &empty) == n);
    CHECK(memcmp(seal_read, seal_plain, n) == 0 && records == 2);
    seal_one(client, server, 1, sizeof seal_buf);
}

// A seal that no key can make: CH_ECAP, the session failed, internal_error
// sealed into side, which the server reads as the client's fatal alert,
// and the plaintext where the caller wrote it.
static void seal_fails(ch_tcp_priv *client, ch_tcp_priv *server, size_t n) {
    seal_stage(n);
    ch_seal_result result;
    CHECK(ch_seal_in_place(tls_public(&client->t), seal_buf, sizeof seal_buf, n, seal_side,
                           sizeof seal_side, &result) == CH_ECAP);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_FAILED);
    CHECK(ch_alert_sent(tls_public(&client->t)) == ALERT_INTERNAL_ERROR);
    CHECK(result.records_len == 0 && result.side_len == CH_ALERT_RECORD_LEN);
    CHECK(memcmp(seal_buf, seal_before, sizeof seal_buf) == 0);
    uint8_t reply[CH_ALERT_RECORD_LEN];
    ch_read_result read;
    CHECK(ch_read_in_place(tls_public(&server->t), seal_side, result.side_len, reply, sizeof reply,
                           &read) == CH_EPROTO);
    CHECK(ch_alert_received(tls_public(&server->t)) == ALERT_INTERNAL_ERROR);
}

// The key's last two sequence numbers before the wrap: a write of two
// records takes them and reads back, the last valid write (RFC 9846
// §5.3). On a fresh pair, a write of three records there fails.
static void test_seal_wrap(ch_tcp_priv *client, ch_tcp_priv *server, const ch_cfg *ccfg,
                           const ch_cfg *scfg) {
    client->t.wr.seq = UINT64_MAX - 2;
    server->t.rd.seq = UINT64_MAX - 2;
    seal_one(client, server, CH_TX_PT + 1, sizeof seal_buf);
    CHECK(client->t.wr.seq == UINT64_MAX && ch_tcp_state(tcp_public(client)) == CH_ST_CONNECTED);

    (void)run_handshake(client, server, ccfg, scfg);
    client->t.wr.seq = UINT64_MAX - 2;
    server->t.rd.seq = UINT64_MAX - 2;
    seal_fails(client, server, 2 * CH_TX_PT + 1);
}

// A KeyUpdate due once this side has sent HSPOST_SEND_EPOCHS_MAX, the cap
// RFC 9846 §4.7.3 sets: no key can seal the write.
static void test_seal_epoch_cap(ch_tcp_priv *client, ch_tcp_priv *server) {
    client->t.send_epochs = HSPOST_SEND_EPOCHS_MAX;
    client->t.key_update_owed = 1;
    seal_fails(client, server, 1);
}

// ch_close_out and ch_fail_out at the write key's last sequence number,
// whose alert the seal refuses (RFC 9846 §5.3): each returns CH_ECAP with
// a length of 0, and still wipes the keys and ends the session as
// tcp_nonblocking.h states.
static void test_alert_at_wrap(ch_tcp_priv *client, ch_tcp_priv *server, const ch_cfg *ccfg,
                               const ch_cfg *scfg) {
    uint8_t out[CH_ALERT_RECORD_LEN];
    size_t out_len = 1;
    (void)run_handshake(client, server, ccfg, scfg);
    client->t.wr.seq = UINT64_MAX;
    CHECK(ch_close_out(tls_public(&client->t), out, sizeof out, &out_len) == CH_ECAP);
    CHECK(out_len == 0 && client->t.keys == 0);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_CLOSED);

    (void)run_handshake(client, server, ccfg, scfg);
    client->t.wr.seq = UINT64_MAX;
    out_len = 1;
    CHECK(ch_fail_out(tls_public(&client->t), ALERT_INTERNAL_ERROR, out, sizeof out, &out_len) ==
          CH_ECAP);
    CHECK(out_len == 0 && client->t.keys == 0);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_FAILED);
    CHECK(ch_alert_sent(tls_public(&client->t)) == ALERT_INTERNAL_ERROR);
}

static void test_seal_in_place(ch_tcp_priv *client, ch_tcp_priv *server) {
    for (size_t i = 0; i < sizeof seal_plain; i++) {
        seal_plain[i] = (uint8_t)(i * 7U + 3U);
    }
    ch_cfg ccfg;
    ch_cfg scfg;
    server_config(&scfg);
    client_config(&ccfg);
    // Before the handshake completes the seal refuses, as tcp_nonblocking.h
    // states, and changes nothing.
    test_read_reset();
    CHECK(client_init(client, &ccfg) == CH_OK);
    ch_seal_result result;
    seal_stage(1);
    seal_refused(client, CH_EPROTO, seal_buf, sizeof seal_buf, 1, seal_side, sizeof seal_side,
                 &result);
    ch_tcp_close(tcp_public(client));

    io_calls = 0;
    (void)run_handshake(client, server, &ccfg, &scfg);
    test_seal_lengths(client, server);
    test_seal_refusals(client, server);
    test_seal_owed_key_update(client, server);
    test_seal_wrap(client, server, &ccfg, &scfg);
    (void)run_handshake(client, server, &ccfg, &scfg);
    test_seal_epoch_cap(client, server);
    test_alert_at_wrap(client, server, &ccfg, &scfg);
    CHECK(io_calls == 0);
    ch_tcp_close(tcp_public(client));
    ch_tcp_close(tcp_public(server));
}

#endif
