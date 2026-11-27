// ch_read_in_place in a TRANSPORT=tcp-nonblocking session, once connected,
// over a caller that holds the records it has received in a buffer of its
// own and hands that buffer over (tcp_nonblocking.h, docs/decisions.md
// 247). The server seals each record with its own application write key,
// so the client opens exactly what a server would send. Included by
// test/tcp_nonblocking_loop_test.c after the handshake helpers.
//
// The order is the one a completion-loop caller meets: a record that
// carries no application data, then nothing, then a data record, then a
// ticket in two records with the first alone at first, and last a record
// whose tag does not match.
#ifndef CH_TEST_TCP_NONBLOCKING_READ_TESTS_H
#define CH_TEST_TCP_NONBLOCKING_READ_TESTS_H

// The records the caller holds and has not consumed, at bytes[off..len).
static struct {
    uint8_t bytes[WIRE_MAX];
    size_t len;
    size_t off;
} held;

static size_t tickets_seen;

static void count_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    (void)ticket;
    tickets_seen++;
}

// Seals pt as one record under the server's write key and appends it to
// what the caller holds. Returns the record's length.
static size_t hold_sealed(ch_tcp_priv *server, uint8_t type, const uint8_t *pt, size_t n) {
    size_t out_len = 0;
    uint8_t *out = held.bytes + held.len;
    CHECK(rec_seal(&server->t.wr, type, pt, n, out, sizeof held.bytes - held.len, &out_len) == 0);
    held.len += out_len;
    return out_len;
}

// For the tests whose subject is not the read itself, which read through
// test_read (test/test_read.h): what a session's cfg.recv hands over, the
// bytes the caller holds, and 0 when it holds none.
static int held_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    size_t left = held.len - held.off;
    size_t take = n < left ? n : left;
    memcpy(p, held.bytes + held.off, take);
    held.off += take;
    return (int)take;
}

// hold_sealed for those tests; with cut set, only the record's first cut
// bytes.
static void hold_record(ch_tcp_priv *server, uint8_t type, const uint8_t *pt, size_t n,
                        size_t cut) {
    size_t out_len = 0;
    uint8_t *out = held.bytes + held.len;
    CHECK(rec_seal(&server->t.wr, type, pt, n, out, sizeof held.bytes - held.len, &out_len) == 0);
    held.len += cut > 0 && cut < out_len ? cut : out_len;
}

// One NewSessionTicket (RFC 9846 §4.7.1): ticket_lifetime 3600,
// ticket_age_add 7, a one-byte ticket_nonce, an eight-byte ticket and no
// extensions. Returns its length.
static size_t build_ticket(uint8_t *out, size_t cap) {
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, HS_NEW_SESSION_TICKET);
    size_t msg = wb_mark(&w, 3);
    wb_u16(&w, 0);
    wb_u16(&w, 3600); // ticket_lifetime
    wb_u16(&w, 0);
    wb_u16(&w, 7); // ticket_age_add
    wb_u8(&w, 1);
    wb_u8(&w, 0); // ticket_nonce
    wb_u16(&w, 8);
    wb_bytes(&w, (const uint8_t *)"ticket-1", 8); // ticket
    wb_u16(&w, 0);                                // extensions
    wb_patch24(&w, msg);
    CHECK(!w.err);
    return w.len;
}

// One ch_read_in_place over the first avail bytes the caller holds.
static int read_held(ch_tcp_priv *client, size_t avail, ch_read_result *result, uint8_t *reply) {
    return ch_read_in_place(tls_public(&client->t), held.bytes + held.off, avail, reply,
                            CH_ALERT_RECORD_LEN, result);
}

// Whether n bytes at p are all zero.
static int all_zero(const uint8_t *p, size_t n) {
    uint8_t any = 0;
    for (size_t i = 0; i < n; i++) {
        any |= p[i];
    }
    return any == 0;
}

// The handshake buffers came back to the caller when each session
// connected: every byte wiped, and the session's copy of the pointer
// gone, while the length the record checks read stays (docs/decisions.md
// 247).
static void test_buffers_given_back(const ch_tcp_priv *client, const ch_tcp_priv *server) {
    CHECK(client->t.cfg.buf == NULL && server->t.cfg.buf == NULL);
    CHECK(client->t.cfg.buf_len == sizeof cli_buf && server->t.cfg.buf_len == sizeof srv_buf);
    CHECK(all_zero(cli_buf, sizeof cli_buf));
    CHECK(all_zero(srv_buf, sizeof srv_buf));
}

// A ticket record, nothing, then a data record, each read where it lies.
static void read_ticket_then_data(ch_tcp_priv *client, ch_tcp_priv *server) {
    uint8_t reply[CH_ALERT_RECORD_LEN];
    ch_read_result result;
    uint8_t ticket_msg[32];
    size_t ticket_len = build_ticket(ticket_msg, sizeof ticket_msg);

    size_t ticket_record = hold_sealed(server, REC_HANDSHAKE, ticket_msg, ticket_len);
    CHECK(read_held(client, held.len, &result, reply) == CH_OK);
    CHECK(result.consumed == ticket_record && result.pt_len == 0 && result.reply_len == 0);
    CHECK(tickets_seen == 1);
    held.off += result.consumed;

    // Nothing more: the session waits, connected.
    CHECK(read_held(client, 0, &result, reply) == CH_TCP_AGAIN);
    CHECK(result.consumed == 0);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_CONNECTED);

    // A data record, whose first three bytes alone are a wait too.
    static const uint8_t hola[4] = {'h', 'o', 'l', 'a'};
    size_t data_record = hold_sealed(server, REC_APPDATA, hola, sizeof hola);
    CHECK(read_held(client, 3, &result, reply) == CH_TCP_AGAIN);
    CHECK(read_held(client, held.len - held.off, &result, reply) == CH_OK);
    CHECK(result.consumed == data_record && result.pt_off == REC_HDR);
    CHECK(result.pt_len == sizeof hola);
    CHECK(memcmp(held.bytes + held.off + result.pt_off, hola, sizeof hola) == 0);
    held.off += result.consumed;
}

// A ticket split across two records. The first alone is a wait, and the
// session keeps no copy: the caller presents the same bytes again with
// the second record after them, and the data record after that is read
// on its own.
static void read_split_ticket(ch_tcp_priv *client, ch_tcp_priv *server) {
    uint8_t reply[CH_ALERT_RECORD_LEN];
    ch_read_result result;
    uint8_t ticket_msg[32];
    size_t ticket_len = build_ticket(ticket_msg, sizeof ticket_msg);
    size_t half = ticket_len / 2;

    size_t first = hold_sealed(server, REC_HANDSHAKE, ticket_msg, half);
    CHECK(read_held(client, held.len - held.off, &result, reply) == CH_TCP_AGAIN);
    CHECK(result.consumed == 0 && tickets_seen == 1);
    CHECK(client->t.held_len == first && client->t.held_fill == half);

    // Fewer bytes than the session holds names no record it can read.
    CHECK(read_held(client, first - 1, &result, reply) == CH_EINVAL);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_CONNECTED);

    static const uint8_t chau[4] = {'c', 'h', 'a', 'u'};
    size_t second = hold_sealed(server, REC_HANDSHAKE, ticket_msg + half, ticket_len - half);
    size_t data_record = hold_sealed(server, REC_APPDATA, chau, sizeof chau);
    CHECK(read_held(client, held.len - held.off, &result, reply) == CH_OK);
    CHECK(result.consumed == first + second && result.pt_len == 0);
    CHECK(tickets_seen == 2 && client->t.held_len == 0 && client->t.held_fill == 0);
    held.off += result.consumed;

    CHECK(read_held(client, held.len - held.off, &result, reply) == CH_OK);
    CHECK(result.consumed == data_record && result.pt_len == sizeof chau);
    CHECK(memcmp(held.bytes + held.off + result.pt_off, chau, sizeof chau) == 0);
    held.off += result.consumed;
}

// A record whose tag does not match: every byte of it is wiped where it
// lies, the bytes after it stay, the alert goes into reply, and the
// session is dead.
static void read_bad_tag(ch_tcp_priv *client, ch_tcp_priv *server) {
    uint8_t reply[CH_ALERT_RECORD_LEN];
    ch_read_result result;
    static const uint8_t data[6] = {'s', 'e', 'c', 'r', 'e', 't'};
    size_t bad = hold_sealed(server, REC_APPDATA, data, sizeof data);
    size_t after = hold_sealed(server, REC_APPDATA, data, sizeof data);
    uint8_t kept[WIRE_MAX];
    memcpy(kept, held.bytes + held.off + bad, after);
    held.bytes[held.off + REC_HDR + 1] ^= 1;
    CHECK(read_held(client, held.len - held.off, &result, reply) == CH_EAUTH);
    CHECK(all_zero(held.bytes + held.off, bad));
    CHECK(memcmp(held.bytes + held.off + bad, kept, after) == 0);
    CHECK(result.consumed == 0 && result.reply_len == CH_ALERT_RECORD_LEN);
    CHECK(ch_alert_sent(tls_public(&client->t)) == ALERT_BAD_RECORD_MAC);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_FAILED);
}

// A header whose length field no peer may send (RFC 9846 §5.2): four of its
// bytes are a wait, and the fifth makes the call refuse it at once, with
// record_overflow in reply, so the caller does not wait for its body.
static void read_oversize_header(ch_tcp_priv *client) {
    uint8_t reply[CH_ALERT_RECORD_LEN];
    ch_read_result result;
    uint8_t header[REC_HDR] = {REC_APPDATA, 0x03, 0x03, 0xff, 0xff};
    CHECK(ch_read_in_place(tls_public(&client->t), header, REC_HDR - 1, reply, sizeof reply,
                           &result) == CH_TCP_AGAIN);
    CHECK(ch_read_in_place(tls_public(&client->t), header, sizeof header, reply, sizeof reply,
                           &result) == CH_EPROTO);
    CHECK(result.consumed == 0 && result.reply_len == CH_ALERT_RECORD_LEN);
    CHECK(ch_alert_sent(tls_public(&client->t)) == ALERT_RECORD_OVERFLOW);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_FAILED);
}

static void test_read_waits_for_records(ch_tcp_priv *client, ch_tcp_priv *server) {
    memset(&held, 0, sizeof held);
    tickets_seen = 0;
    client->t.cfg.on_ticket = count_ticket;
    read_ticket_then_data(client, server);
    read_split_ticket(client, server);
    read_bad_tag(client, server);
}

#endif
