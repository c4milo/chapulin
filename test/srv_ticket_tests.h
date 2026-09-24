// srv_ticket.c and the NewSessionTicket builder: the round trip, the
// tamper sweep, the boundary pairs, the layout byte by byte, and the
// ServerHello's pre_shared_key extension. It uses CHECK, out and built
// from test/srv_test.c and is included after them.
//
// No standard prints a ticket, because the format is this tree's own
// (srv_ticket.h). So the cases check the claims srv_ticket.h makes: a
// sealed ticket opens back to what it carried under the key that sealed
// it and under no other, a ticket that moved by one bit anywhere does not
// open, the length rule holds at its exact boundaries, and the bytes sit
// where the layout says. ChaCha20-Poly1305 itself is checked against RFC
// 8439 and Wycheproof elsewhere, so nothing here re-checks the cipher.
#ifndef CH_SRV_TICKET_TESTS_H
#define CH_SRV_TICKET_TESTS_H

// The key the cases seal under, and a second key that differs in its last
// byte.
static const uint8_t seal_key[SRV_TICKET_KEY_LEN] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
static const uint8_t other_seal_key[SRV_TICKET_KEY_LEN] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2e};
static const uint8_t ticket_nonce_a[AEAD_NONCE] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
                                                   0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab};

// What one ticket carries: a counting PSK, so a field read from the wrong
// offset shows as the wrong byte, and the protocol "h3".
static void ticket_contents(srv_ticket_contents *c) {
    memset(c, 0, sizeof *c);
    c->auth_seconds = 0x0102030405060708ULL;
    c->suite = SUITE_CHACHA20_POLY1305_SHA256;
    c->alpn_len = 2;
    c->alpn[0] = 'h';
    c->alpn[1] = '3';
    for (size_t i = 0; i < SHA256_LEN; i++) {
        c->psk[i] = (uint8_t)(0xc0 + i);
    }
}

static int ticket_opens(const uint8_t *key, const uint8_t *t, size_t n) {
    srv_ticket_contents c;
    return srv_ticket_open(key, t, n, &c) == CH_OK;
}

static void test_ticket_round_trip(void) {
    srv_ticket_contents in;
    ticket_contents(&in);
    CHECK(SRV_TICKET_LEN == 104 && SRV_TICKET_BODY_LEN == 75);
    size_t n = srv_ticket_seal(seal_key, ticket_nonce_a, &in, out, sizeof out);
    CHECK(n == SRV_TICKET_LEN);
    // The clear head: the format's own version byte, then the nonce.
    CHECK(out[0] == SRV_TICKET_VERSION);
    CHECK(memcmp(out + 1, ticket_nonce_a, AEAD_NONCE) == 0);

    // The body is sealed, not copied: the PSK appears nowhere in the ticket.
    int psk_seen = 0;
    for (size_t i = 0; i + SHA256_LEN <= n; i++) {
        psk_seen |= memcmp(out + i, in.psk, SHA256_LEN) == 0;
    }
    CHECK(!psk_seen);

    srv_ticket_contents got;
    CHECK(srv_ticket_open(seal_key, out, n, &got) == CH_OK);
    CHECK(got.auth_seconds == in.auth_seconds && got.suite == in.suite);
    CHECK(got.alpn_len == 2 && memcmp(got.alpn, "h3", 2) == 0);
    CHECK(memcmp(got.psk, in.psk, SHA256_LEN) == 0);

    // The body before sealing, byte by byte as srv_ticket.h lays it out,
    // recovered by opening the ciphertext with the AEAD directly under the
    // version byte as associated data.
    uint8_t body[SRV_TICKET_BODY_LEN];
    CHECK(aead_open(seal_key, ticket_nonce_a, out, 1, out + 1 + AEAD_NONCE, sizeof body,
                    out + 1 + AEAD_NONCE + SRV_TICKET_BODY_LEN, body) == 1);
    static const uint8_t want_head[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x13, 0x03, 0x02, 'h',  '3'};
    CHECK(memcmp(body, want_head, sizeof want_head) == 0);
    int pad_zero = 1;
    for (size_t i = sizeof want_head; i < 11 + CH_ALPN_NAME_MAX; i++) {
        pad_zero &= body[i] == 0;
    }
    CHECK(pad_zero);
    CHECK(memcmp(body + 11 + CH_ALPN_NAME_MAX, in.psk, SHA256_LEN) == 0);

    // No protocol at all: alpn_len 0 and a zero name field.
    in.alpn_len = 0;
    n = srv_ticket_seal(seal_key, ticket_nonce_a, &in, out, sizeof out);
    CHECK(srv_ticket_open(seal_key, out, n, &got) == CH_OK && got.alpn_len == 0);
    // The longest name the API admits, CH_ALPN_NAME_MAX bytes, seals and
    // opens; one byte more is refused before anything is written.
    in.alpn_len = CH_ALPN_NAME_MAX;
    memset(in.alpn, 'n', sizeof in.alpn);
    n = srv_ticket_seal(seal_key, ticket_nonce_a, &in, out, sizeof out);
    CHECK(n == SRV_TICKET_LEN);
    CHECK(srv_ticket_open(seal_key, out, n, &got) == CH_OK);
    CHECK(got.alpn_len == CH_ALPN_NAME_MAX && memcmp(got.alpn, in.alpn, sizeof in.alpn) == 0);
    in.alpn_len = CH_ALPN_NAME_MAX + 1;
    CHECK(srv_ticket_seal(seal_key, ticket_nonce_a, &in, out, sizeof out) == 0);
}

// A ticket that moved by one bit anywhere, header included, does not open,
// and neither does a whole ticket under a key one bit away.
static void test_ticket_tamper(void) {
    srv_ticket_contents in;
    ticket_contents(&in);
    uint8_t ticket[SRV_TICKET_LEN];
    CHECK(srv_ticket_seal(seal_key, ticket_nonce_a, &in, ticket, sizeof ticket) == SRV_TICKET_LEN);
    CHECK(ticket_opens(seal_key, ticket, sizeof ticket));
    CHECK(!ticket_opens(other_seal_key, ticket, sizeof ticket));
    int all_refused = 1;
    for (size_t i = 0; i < sizeof ticket; i++) {
        ticket[i] ^= 0x01;
        all_refused &= !ticket_opens(seal_key, ticket, sizeof ticket);
        ticket[i] ^= 0x01;
    }
    CHECK(all_refused);
    // A refusal leaves nothing behind: the contents come back zeroed.
    srv_ticket_contents got;
    memset(&got, 0x5a, sizeof got);
    ticket[SRV_TICKET_LEN - 1] ^= 0x80;
    CHECK(srv_ticket_open(seal_key, ticket, sizeof ticket, &got) == CH_EAUTH);
    static const uint8_t zero[SHA256_LEN] = {0};
    CHECK(got.auth_seconds == 0 && got.suite == 0 && got.alpn_len == 0);
    CHECK(memcmp(got.alpn, zero, sizeof got.alpn) == 0);
    CHECK(memcmp(got.psk, zero, sizeof got.psk) == 0);
}

// The length rule at its exact boundaries: SRV_TICKET_LEN opens, one byte
// fewer and one byte more do not, and the seal refuses a cap one byte
// short while writing the whole ticket at exactly SRV_TICKET_LEN.
static void test_ticket_bounds(void) {
    srv_ticket_contents in;
    ticket_contents(&in);
    uint8_t ticket[SRV_TICKET_LEN + 1];
    memset(ticket, 0, sizeof ticket);
    CHECK(srv_ticket_seal(seal_key, ticket_nonce_a, &in, ticket, SRV_TICKET_LEN - 1) == 0);
    CHECK(srv_ticket_seal(seal_key, ticket_nonce_a, &in, ticket, SRV_TICKET_LEN) == SRV_TICKET_LEN);
    CHECK(ticket_opens(seal_key, ticket, SRV_TICKET_LEN));
    CHECK(!ticket_opens(seal_key, ticket, SRV_TICKET_LEN - 1));
    CHECK(!ticket_opens(seal_key, ticket, SRV_TICKET_LEN + 1));
    CHECK(!ticket_opens(seal_key, ticket, 0));
    // Another version byte is another layout, refused before the AEAD.
    ticket[0] = SRV_TICKET_VERSION + 1;
    CHECK(!ticket_opens(seal_key, ticket, SRV_TICKET_LEN));
}

// The NewSessionTicket builder against bytes written out from RFC 9846
// §4.7.1's struct: lifetime 604800 (0x00093a80), age_add 0x01020304, a
// two-byte nonce, a three-byte ticket and an empty extensions vector.
static void test_new_session_ticket(void) {
    static const uint8_t nonce[2] = {0xaa, 0xbb};
    static const uint8_t ticket[3] = {0x11, 0x22, 0x33};
    static const uint8_t want[] = {
        0x04, 0x00, 0x00, 0x12,       // new_session_ticket, 18 bytes
        0x00, 0x09, 0x3a, 0x80,       // ticket_lifetime
        0x01, 0x02, 0x03, 0x04,       // ticket_age_add
        0x02, 0xaa, 0xbb,             // ticket_nonce
        0x00, 0x03, 0x11, 0x22, 0x33, // ticket
        0x00, 0x00,                   // extensions: none, so no early_data
    };
    size_t n = srv_build_new_session_ticket(out, sizeof out, 604800, 0x01020304, nonce,
                                            sizeof nonce, ticket, sizeof ticket);
    CHECK(built(n, want, sizeof want));
    // The exact cap is enough and one byte less is refused.
    CHECK(srv_build_new_session_ticket(out, sizeof want, 604800, 0x01020304, nonce, sizeof nonce,
                                       ticket, sizeof ticket) == sizeof want);
    CHECK(srv_build_new_session_ticket(out, sizeof want - 1, 604800, 0x01020304, nonce,
                                       sizeof nonce, ticket, sizeof ticket) == 0);
    // ticket<1..2^16-1>: an empty ticket names no message.
    CHECK(srv_build_new_session_ticket(out, sizeof out, 1, 0, nonce, sizeof nonce, ticket, 0) == 0);
    // The largest message this server sends fits the constant exactly.
    static uint8_t big[SRV_NEW_SESSION_TICKET_MAX];
    uint8_t whole[SRV_TICKET_LEN] = {0};
    uint8_t eight[SRV_TICKET_NONCE_LEN] = {0};
    CHECK(srv_build_new_session_ticket(big, sizeof big, 1, 0, eight, sizeof eight, whole,
                                       sizeof whole) == sizeof big);
}

// The ServerHello a resumed handshake sends: the fixed head and the two
// extensions test_server_hello checks, then pre_shared_key naming the
// selected identity (RFC 9846 §4.3.11). The extensions length and the
// message length each grow by the extension's six bytes.
static void test_server_hello_psk(void) {
    selection sel;
    memset(&sel, 0, sizeof sel);
    sel.suite = SUITE_CHACHA20_POLY1305_SHA256;
    sel.hash_len = SHA256_LEN;
    sel.group = CH_KEX_GROUP;
    sel.psk_selected = 1;
    sel.psk_identity = 0x0102;
    uint8_t random32[SRV_RANDOM];
    uint8_t share[CH_KEX_SERVER_SHARE];
    memset(random32, 0x5a, sizeof random32);
    memset(share, 0x77, sizeof share);
    size_t n =
        srv_build_server_hello(out, sizeof out, &sel, random32, NULL, 0, share, sizeof share);
    static const uint8_t want_tail[] = {0x00, 0x29, 0x00, 0x02, 0x01, 0x02};
    CHECK(n > sizeof want_tail);
    CHECK(memcmp(out + n - sizeof want_tail, want_tail, sizeof want_tail) == 0);
    size_t with_psk = n;
    sel.psk_selected = 0;
    n = srv_build_server_hello(out, sizeof out, &sel, random32, NULL, 0, share, sizeof share);
    CHECK(with_psk == n + sizeof want_tail);
}

#endif
