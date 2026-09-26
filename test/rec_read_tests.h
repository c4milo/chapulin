// ch_read in a TRANSPORT=tcp-nonblocking session, once connected, over a caller
// that hands over whole records as they arrive and has none in between
// (tcp_nonblocking.h). The server seals each record with its own application
// write key, so the client opens exactly what a server would send. Included by
// test/tcp_nonblocking_loop_test.c after the handshake helpers.
//
// The order is the one a completion-loop caller meets: a record that
// carries no application data, then nothing, then a data record. Before
// CH_RECORD_AGAIN existed the "then nothing" step killed the session, and
// the only way around it was to hold every ticket-only record back until
// a data record followed it.
#ifndef CH_TEST_REC_READ_TESTS_H
#define CH_TEST_REC_READ_TESTS_H

// The records the caller holds and has not yet handed over. recv hands
// over what it holds and returns 0 when it holds nothing.
static struct {
    uint8_t bytes[WIRE_MAX];
    size_t len;
    size_t off;
} held;

static int held_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    size_t left = held.len - held.off;
    size_t take = n < left ? n : left;
    memcpy(p, held.bytes + held.off, take);
    held.off += take;
    return (int)take;
}

static size_t tickets_seen;

static void count_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    (void)ticket;
    tickets_seen++;
}

// Seals pt as one record under the server's write key and appends it to
// what the caller holds; with cut set, only the record's first cut bytes.
static void hold_record(ch_record *server, uint8_t type, const uint8_t *pt, size_t n, size_t cut) {
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

static void test_read_waits_for_records(ch_record *client, ch_record *server) {
    memset(&held, 0, sizeof held);
    tickets_seen = 0;
    client->t.cfg.recv = held_recv;
    client->t.cfg.on_ticket = count_ticket;
    uint8_t got[32];
    uint8_t ticket_msg[32];
    size_t ticket_len = build_ticket(ticket_msg, sizeof ticket_msg);

    // A ticket-only record, then nothing: the ticket is taken and the
    // session waits, connected.
    hold_record(server, REC_HANDSHAKE, ticket_msg, ticket_len, 0);
    CHECK(ch_read(&client->t, got, sizeof got) == CH_RECORD_AGAIN);
    CHECK(tickets_seen == 1);
    CHECK(ch_record_state(client) == CH_ST_CONNECTED);

    // Then a data record, read by the same session.
    static const uint8_t hola[4] = {'h', 'o', 'l', 'a'};
    hold_record(server, REC_APPDATA, hola, sizeof hola, 0);
    CHECK(ch_read(&client->t, got, sizeof got) == (int)sizeof hola);
    CHECK(memcmp(got, hola, sizeof hola) == 0);

    // A ticket split across two records, with nothing between them: the
    // first part waits in cfg.buf, and the second completes it before
    // the data record after it is read.
    size_t half = ticket_len / 2;
    hold_record(server, REC_HANDSHAKE, ticket_msg, half, 0);
    CHECK(ch_read(&client->t, got, sizeof got) == CH_RECORD_AGAIN);
    CHECK(tickets_seen == 1 && client->t.post_fill == half);
    static const uint8_t chau[4] = {'c', 'h', 'a', 'u'};
    hold_record(server, REC_HANDSHAKE, ticket_msg + half, ticket_len - half, 0);
    hold_record(server, REC_APPDATA, chau, sizeof chau, 0);
    CHECK(ch_read(&client->t, got, sizeof got) == (int)sizeof chau);
    CHECK(memcmp(got, chau, sizeof chau) == 0);
    CHECK(tickets_seen == 2 && client->t.post_fill == 0);

    // A record that stops after its third byte breaks the whole-record
    // promise: that is a dead session, not a wait.
    hold_record(server, REC_APPDATA, hola, sizeof hola, 3);
    CHECK(ch_read(&client->t, got, sizeof got) == CH_EIO);
    CHECK(ch_record_state(client) == CH_ST_FAILED);
}

#endif
