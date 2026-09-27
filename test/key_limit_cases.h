// The AES-GCM key-usage ceiling between a connected client and server of
// one ROLE=both SUITE=aesgcm object, each writing across its write key's
// ceiling while the other reads (docs/decisions.md 78). RFC 9846 §5.5 has
// a sender send a KeyUpdate or close the connection while a key is still
// below its AEAD's usage limit (rfc9846.txt:3743-3744), and
// REC_AES_GCM_RECORDS_MAX (record.h) is that limit here. No case seals 2^24
// records: each moves the writer's write sequence number and the reader's
// read sequence number to the same value near the ceiling, the value that
// many records would leave.
//
// Two loop tests include this after their fixtures:
//   - test/webpki_loop_test.c, over TRANSPORT=tcp-nonblocking, as
//     bin/webpki_loop_aes and bin/webpki_loop_aes_extern;
//   - test/tcp_blocking_key_limit_test.c, over TRANSPORT=tcp-blocking, as
//     bin/tcp_blocking_key_limit.
// Each defines the CHECK macro and
//
//   key_limit_connect(suite, &client, &server)
//       one handshake whose ServerHello selects suite; 1 when both ends
//       are connected, with client and server pointing at the two sessions
//
// and this file then moves both sessions onto its own pipes.
//
// The cases, under TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384, each
// once with the client writing and once with the server writing:
//   - the boundary: from two records before the ceiling, the first record
//     goes out alone and the second after one KeyUpdate record, 27 bytes
//     with request_update 0 under the old key; the second opens at
//     sequence number 0 of the reader's next key, and the reader reads both
//     records and sends nothing back;
//   - one write of three records across the ceiling sends one KeyUpdate;
//   - the sender cap: with 2^48 - 2 KeyUpdates sent, the write sends the
//     last one RFC 9846 §4.7.3 allows; with 2^48 - 1 sent, it fails with
//     CH_ECAP and internal_error under the old key, which the reader reads
//     as the peer's fatal alert.
// Then ch_writable_len against the real ch_write at the ceiling and one and
// two records before it, and ChaCha20-Poly1305 at the same sequence
// numbers, where no KeyUpdate goes out.
#ifndef CH_TEST_KEY_LIMIT_CASES_H
#define CH_TEST_KEY_LIMIT_CASES_H

#include "handshake_post.h"

// One direction's records once connected: the bytes one session sent and
// the other has not read. io_send_all hands cfg.send one whole record per
// call, so send_len holds the length of each record, the first
// KEY_LIMIT_SENDS_MAX of them.
#define KEY_LIMIT_SENDS_MAX 8
typedef struct {
    uint8_t bytes[4096];
    size_t len;
    size_t off;
    size_t sends;
    size_t send_len[KEY_LIMIT_SENDS_MAX];
} key_limit_pipe;
static key_limit_pipe key_limit_up;   // client to server
static key_limit_pipe key_limit_down; // server to client

static int key_limit_send(key_limit_pipe *pipe, const uint8_t *p, size_t n) {
    if (pipe->len + n > sizeof pipe->bytes) {
        return -1;
    }
    memcpy(pipe->bytes + pipe->len, p, n);
    if (pipe->sends < KEY_LIMIT_SENDS_MAX) {
        pipe->send_len[pipe->sends] = n;
    }
    pipe->len += n;
    pipe->sends++;
    return 0;
}

// Hands over what the pipe holds. No case reads a pipe it left empty.
static int key_limit_recv(key_limit_pipe *pipe, uint8_t *p, size_t n) {
    size_t left = pipe->len - pipe->off;
    size_t count = n < left ? n : left;
    memcpy(p, pipe->bytes + pipe->off, count);
    pipe->off += count;
    return (int)count;
}

static int key_limit_client_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    return key_limit_send(&key_limit_up, p, n);
}

static int key_limit_client_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    return key_limit_recv(&key_limit_down, p, n);
}

static int key_limit_server_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    return key_limit_send(&key_limit_down, p, n);
}

static int key_limit_server_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    return key_limit_recv(&key_limit_up, p, n);
}

// One direction of a connected pair: the session that writes, the one
// that reads, the pipe between them, and the pipe the reader would answer
// on.
typedef struct {
    ch_tls *writer;
    ch_tls *reader;
    key_limit_pipe *wire;
    key_limit_pipe *back;
} key_limit_pair;

// One handshake under suite, both ends then on this file's pipes, and the
// direction server_writes names. Returns 0 when the handshake failed.
static int key_limit_open_pair(uint16_t suite, int server_writes, key_limit_pair *pair) {
    ch_tls *client_session = NULL;
    ch_tls *server_session = NULL;
    if (!key_limit_connect(suite, &client_session, &server_session)) {
        return 0;
    }
    memset(&key_limit_up, 0, sizeof key_limit_up);
    memset(&key_limit_down, 0, sizeof key_limit_down);
    client_session->cfg.send = key_limit_client_send;
    client_session->cfg.recv = key_limit_client_recv;
    server_session->cfg.send = key_limit_server_send;
    server_session->cfg.recv = key_limit_server_recv;
    pair->writer = server_writes ? server_session : client_session;
    pair->reader = server_writes ? client_session : server_session;
    pair->wire = server_writes ? &key_limit_down : &key_limit_up;
    pair->back = server_writes ? &key_limit_up : &key_limit_down;
    return 1;
}

// Moves the writer's write sequence number and the reader's read sequence
// number to seq, where sealing that many records under the key would
// leave them.
static void key_limit_seed(const key_limit_pair *pair, uint64_t seq) {
    pair->writer->wr.seq = seq;
    pair->reader->rd.seq = seq;
}

// Opens the record at offset at of the pipe's bytes with reader, as the
// peer does. Returns the offset after the record, or 0 when it does not
// open.
static size_t key_limit_open(const key_limit_pipe *pipe, size_t at, rec_dir *reader, uint8_t *pt,
                             size_t cap, size_t *pt_len, uint8_t *type) {
    if (pipe->len < at + REC_HDR) {
        return 0;
    }
    size_t body = ((size_t)pipe->bytes[at + 3] << 8) | pipe->bytes[at + 4];
    if (pipe->len < at + REC_HDR + body ||
        rec_open(reader, pipe->bytes + at, REC_HDR + body, pt, cap, pt_len, type) != 0) {
        return 0;
    }
    return at + REC_HDR + body;
}

// Reads n bytes through ch_read into got and requires them to equal want.
// ch_read hands over at most one record's plaintext per call.
static int key_limit_read_all(ch_tls *t, uint8_t *got, const uint8_t *want, size_t n) {
    size_t at = 0;
    while (at < n) {
        int rc = ch_read(t, got + at, n - at);
        if (rc <= 0) {
            return 0;
        }
        at += (size_t)rc;
    }
    return memcmp(got, want, n) == 0;
}

// The KeyUpdate ch_write sends at the ceiling: request_update 0,
// update_not_requested (RFC 9846 §4.7.3).
static const uint8_t key_limit_key_update[5] = {HS_KEY_UPDATE, 0, 0, 1, 0};

// The boundary. Two records before the ceiling, the first record takes
// the key's second-to-last sequence number and goes out alone. The second
// would take the last, so the KeyUpdate takes it, under the old key, and
// the record goes out at sequence number 0 of the next key. The reader
// opens it there, reads on, and answers nothing.
static void key_limit_check_boundary(uint16_t suite, int server_writes) {
    key_limit_pair pair;
    CHECK(key_limit_open_pair(suite, server_writes, &pair));
    key_limit_seed(&pair, REC_AES_GCM_RECORDS_MAX - 2);
    // The reader's key and secret as they stand, to open by hand what goes
    // out on the wire.
    rec_dir peek = pair.reader->rd;
    uint8_t secret[HKDF_HASH_MAX];
    memcpy(secret, pair.reader->rd_secret, sizeof secret);
    uint64_t epochs = pair.writer->send_epochs;
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    uint8_t got[8];

    CHECK(ch_write(pair.writer, (const uint8_t *)"a", 1) == CH_OK);
    CHECK(pair.wire->sends == 1 && pair.wire->send_len[0] == REC_OVERHEAD + 1);
    size_t at = key_limit_open(pair.wire, 0, &peek, pt, sizeof pt, &pt_len, &type);
    CHECK(at != 0 && type == REC_APPDATA && pt_len == 1 && pt[0] == 'a');
    CHECK(ch_read(pair.reader, got, sizeof got) == 1 && got[0] == 'a');

    CHECK(ch_write(pair.writer, (const uint8_t *)"b", 1) == CH_OK);
    CHECK(pair.wire->sends == 3 && pair.wire->send_len[1] == CH_KEY_UPDATE_RECORD_LEN);
    CHECK(pair.wire->send_len[2] == REC_OVERHEAD + 1);
    CHECK(pair.writer->send_epochs == epochs + 1 && pair.writer->wr.seq == 1);
    at = key_limit_open(pair.wire, at, &peek, pt, sizeof pt, &pt_len, &type);
    CHECK(at != 0 && type == REC_HANDSHAKE && pt_len == sizeof key_limit_key_update &&
          memcmp(pt, key_limit_key_update, sizeof key_limit_key_update) == 0);
    rec_dir_update(secret, &peek);
    CHECK(peek.seq == 0);
    at = key_limit_open(pair.wire, at, &peek, pt, sizeof pt, &pt_len, &type);
    CHECK(at == pair.wire->len && type == REC_APPDATA && pt_len == 1 && pt[0] == 'b');

    CHECK(ch_read(pair.reader, got, sizeof got) == 1 && got[0] == 'b');
    CHECK(pair.reader->rd.seq == 1);
    CHECK(memcmp(pair.reader->rd_secret, secret, sizeof secret) == 0);
    CHECK(pair.back->sends == 0 && pair.reader->state == CH_ST_CONNECTED);
}

// Plaintext for the cases that write whole records.
#define KEY_LIMIT_RECORD 100
static uint8_t key_limit_data[3 * KEY_LIMIT_RECORD + 2 * CH_KEY_UPDATE_RECORD_LEN];
static uint8_t key_limit_got[sizeof key_limit_data];

// One ch_write of three records from two records before the ceiling sends
// one KeyUpdate, before the second record, and the reader reads all three.
// The writer's records carry KEY_LIMIT_RECORD bytes, below every limit a
// session here holds.
static void key_limit_check_one_write(uint16_t suite, int server_writes) {
    key_limit_pair pair;
    CHECK(key_limit_open_pair(suite, server_writes, &pair));
    key_limit_seed(&pair, REC_AES_GCM_RECORDS_MAX - 2);
    pair.writer->peer_limit = KEY_LIMIT_RECORD;
    const size_t three_records = 3 * (size_t)KEY_LIMIT_RECORD;
    uint64_t epochs = pair.writer->send_epochs;
    CHECK(ch_write(pair.writer, key_limit_data, three_records) == CH_OK);
    CHECK(pair.wire->sends == 4 && pair.wire->send_len[1] == CH_KEY_UPDATE_RECORD_LEN);
    CHECK(pair.wire->send_len[0] == REC_OVERHEAD + KEY_LIMIT_RECORD &&
          pair.wire->send_len[2] == REC_OVERHEAD + KEY_LIMIT_RECORD &&
          pair.wire->send_len[3] == REC_OVERHEAD + KEY_LIMIT_RECORD);
    CHECK(pair.writer->send_epochs == epochs + 1 && pair.writer->wr.seq == 2);
    CHECK(key_limit_read_all(pair.reader, key_limit_got, key_limit_data, three_records));
    CHECK(pair.back->sends == 0);
}

// RFC 9846 §4.7.3's cap on the KeyUpdates a sender sends. With one left,
// the write at the ceiling sends it. With none left, the key cannot be
// replaced, so that write fails the session: CH_ECAP, and internal_error
// sealed at the key's last sequence number, which the reader opens and
// reads as the peer's fatal alert.
static void key_limit_check_sender_cap(uint16_t suite, int server_writes) {
    key_limit_pair pair;
    uint8_t got[8];
    CHECK(key_limit_open_pair(suite, server_writes, &pair));
    key_limit_seed(&pair, REC_AES_GCM_RECORDS_MAX - 1);
    pair.writer->send_epochs = HSPOST_SEND_EPOCHS_MAX - 1;
    CHECK(ch_write(pair.writer, (const uint8_t *)"c", 1) == CH_OK);
    CHECK(pair.writer->send_epochs == HSPOST_SEND_EPOCHS_MAX && pair.wire->sends == 2);
    CHECK(ch_read(pair.reader, got, sizeof got) == 1 && got[0] == 'c');

    CHECK(key_limit_open_pair(suite, server_writes, &pair));
    key_limit_seed(&pair, REC_AES_GCM_RECORDS_MAX - 1);
    pair.writer->send_epochs = HSPOST_SEND_EPOCHS_MAX;
    rec_dir peek = pair.reader->rd;
    CHECK(ch_write(pair.writer, (const uint8_t *)"d", 1) == CH_ECAP);
    CHECK(pair.writer->state == CH_ST_FAILED);
    CHECK(ch_alert_sent(pair.writer) == ALERT_INTERNAL_ERROR);
    CHECK(pair.wire->sends == 1 && pair.wire->send_len[0] == CH_ALERT_RECORD_LEN);
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    size_t at = key_limit_open(pair.wire, 0, &peek, pt, sizeof pt, &pt_len, &type);
    CHECK(at == pair.wire->len && type == REC_ALERT && pt_len == 2 && pt[0] == 2 &&
          pt[1] == ALERT_INTERNAL_ERROR);
    CHECK(ch_read(pair.reader, got, sizeof got) == CH_EPROTO);
    CHECK(ch_alert_received(pair.reader) == ALERT_INTERNAL_ERROR);
}

// The bytes one ch_write of n bytes sends from the writer as it stands.
// The writer and the pipe are put back afterwards, so each call starts
// from the same sequence number.
static size_t key_limit_sent_by_write(const key_limit_pair *pair, size_t n) {
    static ch_tls saved;
    saved = *pair->writer;
    size_t before = pair->wire->len;
    CHECK(ch_write(pair->writer, key_limit_data, n) == CH_OK);
    size_t sent = pair->wire->len - before;
    *pair->writer = saved;
    pair->wire->len = before;
    return sent;
}

// ch_writable_len against the ch_write that sends what it counts, at the
// least limit a peer's record_size_limit leaves, 63 bytes: at the ceiling
// and one and two records before it, for every cap up to three records, a
// KeyUpdate record and one byte, the answer's records fit cap and one
// byte more does not. The rows under it are the exact boundary: at the
// ceiling a record of one byte costs a KeyUpdate record as well, and one
// record before it the first record does not and the second does. At the
// largest cap it counts one KeyUpdate and no second (tls.h).
static void key_limit_check_writable_len(uint16_t suite) {
    key_limit_pair pair;
    CHECK(key_limit_open_pair(suite, 0, &pair));
    pair.writer->peer_limit = 63;
    const size_t record = 63 + REC_OVERHEAD;
    for (uint64_t back = 1; back <= 3; back++) {
        key_limit_seed(&pair, REC_AES_GCM_RECORDS_MAX - back);
        for (size_t cap = 0; cap <= 3 * record + CH_KEY_UPDATE_RECORD_LEN + 1; cap++) {
            size_t n = ch_writable_len(pair.writer, cap);
            CHECK(key_limit_sent_by_write(&pair, n) <= cap);
            CHECK(key_limit_sent_by_write(&pair, n + 1) > cap);
        }
    }
    const size_t key_update_and_byte = CH_KEY_UPDATE_RECORD_LEN + REC_OVERHEAD + 1;
    key_limit_seed(&pair, REC_AES_GCM_RECORDS_MAX - 1);
    CHECK(ch_writable_len(pair.writer, key_update_and_byte - 1) == 0);
    CHECK(ch_writable_len(pair.writer, key_update_and_byte) == 1);
    CHECK(ch_writable_len(pair.writer, SIZE_MAX) == (size_t)(REC_AES_GCM_RECORDS_MAX - 1) * 63);
    key_limit_seed(&pair, REC_AES_GCM_RECORDS_MAX - 2);
    CHECK(ch_writable_len(pair.writer, REC_OVERHEAD + 1) == 1);
    CHECK(ch_writable_len(pair.writer, record) == 63);
    CHECK(ch_writable_len(pair.writer, record + key_update_and_byte - 1) == 63);
    CHECK(ch_writable_len(pair.writer, record + key_update_and_byte) == 64);
    CHECK(ch_writable_len(pair.writer, SIZE_MAX) == (size_t)REC_AES_GCM_RECORDS_MAX * 63);
}

// ChaCha20-Poly1305 has no ceiling but the wrap (rfc9846.txt:3752-3754):
// at the sequence number where an AES-GCM key sends its KeyUpdate, and one
// past the AES-GCM ceiling, a ChaCha20 key seals its records and nothing
// else, and ch_writable_len counts no KeyUpdate.
static void key_limit_check_chacha(int server_writes) {
    key_limit_pair pair;
    CHECK(key_limit_open_pair(SUITE_CHACHA20_POLY1305_SHA256, server_writes, &pair));
    key_limit_seed(&pair, REC_AES_GCM_RECORDS_MAX - 1);
    uint64_t epochs = pair.writer->send_epochs;
    CHECK(ch_writable_len(pair.writer, REC_OVERHEAD + 1) == 1);
    CHECK(ch_write(pair.writer, (const uint8_t *)"e", 1) == CH_OK);
    CHECK(ch_write(pair.writer, (const uint8_t *)"f", 1) == CH_OK);
    CHECK(pair.wire->sends == 2 && pair.wire->send_len[0] == REC_OVERHEAD + 1 &&
          pair.wire->send_len[1] == REC_OVERHEAD + 1);
    CHECK(pair.writer->send_epochs == epochs &&
          pair.writer->wr.seq == (uint64_t)REC_AES_GCM_RECORDS_MAX + 1);
    CHECK(key_limit_read_all(pair.reader, key_limit_got, (const uint8_t *)"ef", 2));
}

static void check_key_limit(void) {
    for (size_t i = 0; i < sizeof key_limit_data; i++) {
        key_limit_data[i] = (uint8_t)(i * 5 + 1);
    }
    static const uint16_t suites[2] = {SUITE_AES_128_GCM_SHA256, SUITE_AES_256_GCM_SHA384};
    for (size_t i = 0; i < 2; i++) {
        for (int server_writes = 0; server_writes <= 1; server_writes++) {
            key_limit_check_boundary(suites[i], server_writes);
            key_limit_check_one_write(suites[i], server_writes);
            key_limit_check_sender_cap(suites[i], server_writes);
        }
        key_limit_check_writable_len(suites[i]);
    }
    key_limit_check_chacha(0);
    key_limit_check_chacha(1);
}

#endif
