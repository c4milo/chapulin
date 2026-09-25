// srv_resume.c: which ticket a ClientHello resumes, and the
// NewSessionTicket a connection ends with. It continues
// test/srv_flight_keys_tests.h, whose live-key helpers it reads, and is
// included after it; it includes that half itself for the reason that
// file gives.
//
// The selection cases hand srv_select_auth a client_hello written here
// rather than one the parser produced: identities and binders built from
// real tickets, and a binder_hash chosen by the case. The parser's own
// half, holding the two lists to their syntax, is test/srv_parser_tests.h's.
// Every row CLAUDE.md asks for a boundary is an exact pair: the last
// instant a ticket is valid and the first it is not, a binder of 32 bytes
// and of 33.
#ifndef CH_SRV_RESUME_TESTS_H
#define CH_SRV_RESUME_TESTS_H

#include "srv_flight_keys_tests.h"
#include "srv_resume.h"

static const uint8_t resume_key[SRV_TICKET_KEY_LEN] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};
static const uint8_t other_resume_key[SRV_TICKET_KEY_LEN] = {
    0x41, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};

// The instant the cases issue their tickets at, on the caller's clock.
#define RESUME_AUTH 1000000U

// The PSK a case's ticket carries, and the transcript hash its binder
// covers. Counting patterns, so a swapped argument shows.
static uint8_t resume_psk[SHA256_LEN];
static uint8_t resume_hash[SHA256_LEN];

// The two lists a case offers, which flight_hello points into.
static uint8_t resume_identities[512];
static uint8_t resume_binders[256];

// Seals one ticket under key issued at auth_seconds, bound to the
// protocol at alpn_index in flight_alpn, or to none for CH_ALPN_NONE.
static void resume_ticket(uint8_t ticket[SRV_TICKET_LEN], const uint8_t *key, uint64_t auth_seconds,
                          uint8_t alpn_index) {
    srv_ticket_contents c;
    memset(&c, 0, sizeof c);
    c.auth_seconds = auth_seconds;
    c.suite = SUITE_CHACHA20_POLY1305_SHA256;
    if (alpn_index != CH_ALPN_NONE) {
        c.alpn_len = (uint8_t)flight_alpn[alpn_index].name_len;
        memcpy(c.alpn, flight_alpn[alpn_index].name, c.alpn_len);
    }
    // The ticket's PSK array holds the longest hash a build has, and a
    // SHA-256 ticket fills its first SHA256_LEN bytes.
    memset(c.psk, 0, sizeof c.psk);
    memcpy(c.psk, resume_psk, sizeof resume_psk);
    static const uint8_t nonce[AEAD_NONCE] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2};
    CHECK(srv_ticket_seal(key, nonce, &c, ticket, SRV_TICKET_LEN) == SRV_TICKET_LEN);
}

// The binder a client computes for resume_psk over resume_hash: HMAC under
// the "res binder" key, as RFC 9846 §4.3.11.2 and ks_early state it.
static void resume_binder(uint8_t binder[SHA256_LEN]) {
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    ks_early(SHA256_LEN, resume_psk, sizeof resume_psk, 1, early, binder_key);
    ks_verify_data(SHA256_LEN, binder_key, resume_hash, binder);
}

// One identity and one binder for a case to offer.
typedef struct {
    const uint8_t *identity;
    size_t identity_len;
    const uint8_t *binder;
    size_t binder_len;
} resume_offer;

// Writes n identities and n binders as the two OfferedPsks lists and points
// flight_hello at them, with pre_shared_key and psk_dhe_ke offered and
// every ALPN, suite, group and scheme bit offer_x25519 sets.
static void offer_tickets(const resume_offer *offers, size_t n) {
    offer_x25519();
    wbuf w;
    wb_init(&w, resume_identities, sizeof resume_identities);
    for (size_t i = 0; i < n; i++) {
        wb_u16(&w, (uint16_t)offers[i].identity_len);
        wb_bytes(&w, offers[i].identity, offers[i].identity_len);
        wb_u16(&w, 0);
        wb_u16(&w, 7); // obfuscated_ticket_age, which the server reads none of
    }
    CHECK(!w.err);
    flight_hello.psk_identities = resume_identities;
    flight_hello.psk_identities_len = w.len;
    wb_init(&w, resume_binders, sizeof resume_binders);
    for (size_t i = 0; i < n; i++) {
        wb_u8(&w, (uint8_t)offers[i].binder_len);
        wb_bytes(&w, offers[i].binder, offers[i].binder_len);
    }
    CHECK(!w.err);
    flight_hello.psk_binders = resume_binders;
    flight_hello.psk_binders_len = w.len;
    flight_hello.seen |= SRV_EXT_PRE_SHARED_KEY | SRV_EXT_PSK_MODES | SRV_EXT_SIGNATURE_ALGORITHMS;
    flight_hello.psk_modes = SRV_PSK_DHE_KE;
    flight_hello.truncated_len = 1;
    memcpy(flight_hello.binder_hash, resume_hash, sizeof resume_hash);
}

// A server with a ticket key and a clock reading now, and a selection as
// srv_select writes it before it asks srv_select_auth.
static void resume_reset(selection *sel, uint64_t now) {
    flight_reset();
    for (size_t i = 0; i < SHA256_LEN; i++) {
        resume_psk[i] = (uint8_t)(0x80 + i);
        resume_hash[i] = (uint8_t)(0x30 + i);
    }
    sess.cfg.srv.ticket_key = resume_key;
    sess.cfg.srv.now_seconds = now;
    memset(sel, 0, sizeof *sel);
    sel->suite = SUITE_CHACHA20_POLY1305_SHA256;
    sel->hash_len = SHA256_LEN;
    sel->group = CH_GROUP_X25519;
    sel->sigalg = SIGALG_ECDSA_P256_SHA256;
}

// Offers one ticket with its correct binder and asks srv_select_auth.
static int resume_one(selection *sel, const uint8_t *ticket) {
    uint8_t binder[SHA256_LEN];
    resume_binder(binder);
    resume_offer offer = {ticket, SRV_TICKET_LEN, binder, sizeof binder};
    offer_tickets(&offer, 1);
    return srv_select_auth(&hs, &flight_hello, sel);
}

// Whether the last srv_select_auth selected a ticket and left the early
// secret of resume_psk in hs.early.
static int resumed(const selection *sel) {
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    ks_early(SHA256_LEN, resume_psk, sizeof resume_psk, 1, early, binder_key);
    return sel->psk_selected == 1 && memcmp(hs.early, early, sizeof early) == 0;
}

static void test_resume_select(void) {
    selection sel;
    uint8_t ticket[SRV_TICKET_LEN];

    // A ticket this key sealed, inside its lifetime, with its binder: the
    // handshake resumes it, at index 0, keeping its issue instant.
    resume_reset(&sel, RESUME_AUTH);
    resume_ticket(ticket, resume_key, RESUME_AUTH, CH_ALPN_NONE);
    CHECK(resume_one(&sel, ticket) == CH_OK && resumed(&sel));
    CHECK(sel.psk_identity == 0 && hs.ticket_auth_seconds == RESUME_AUTH);
    // The hello offered a scheme beside the ticket, and no CertificateVerify
    // goes out, so the selection names none.
    CHECK(sel.sigalg == 0);

    // A client that offers no signature scheme at all still resumes: the
    // ticket is its only way to authenticate the server.
    resume_reset(&sel, RESUME_AUTH);
    sel.sigalg = 0;
    CHECK(resume_one(&sel, ticket) == CH_OK && resumed(&sel));

    // Under another key the ticket does not open. It is passed over, and a
    // hello that offered a scheme gets a full handshake.
    resume_reset(&sel, RESUME_AUTH);
    sess.cfg.srv.ticket_key = other_resume_key;
    CHECK(resume_one(&sel, ticket) == CH_OK && sel.psk_selected == 0);
    CHECK(sel.sigalg == SIGALG_ECDSA_P256_SHA256);

    // The same passed-over ticket from a client with no signature_algorithms
    // is missing_extension, and one whose schemes no slot signs is
    // handshake_failure.
    resume_reset(&sel, RESUME_AUTH);
    sess.cfg.srv.ticket_key = other_resume_key;
    sel.sigalg = 0;
    uint8_t binder[SHA256_LEN];
    resume_binder(binder);
    resume_offer offer = {ticket, SRV_TICKET_LEN, binder, sizeof binder};
    offer_tickets(&offer, 1);
    flight_hello.seen &= (uint16_t)~SRV_EXT_SIGNATURE_ALGORITHMS;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_EPROTO);
    CHECK(hs.alert == ALERT_MISSING_EXTENSION);
    flight_hello.seen |= SRV_EXT_SIGNATURE_ALGORITHMS;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_EPROTO);
    CHECK(hs.alert == ALERT_HANDSHAKE_FAILURE);

    // One bit moved anywhere in the ticket and it is passed over.
    resume_reset(&sel, RESUME_AUTH);
    resume_ticket(ticket, resume_key, RESUME_AUTH, CH_ALPN_NONE);
    ticket[SRV_TICKET_LEN / 2] ^= 0x10;
    CHECK(resume_one(&sel, ticket) == CH_OK && sel.psk_selected == 0);

    // The lifetime's exact boundary: the ticket resumes at the last
    // instant SRV_TICKET_LIFETIME admits and not one second later.
    resume_reset(&sel, (uint64_t)RESUME_AUTH + SRV_TICKET_LIFETIME);
    resume_ticket(ticket, resume_key, RESUME_AUTH, CH_ALPN_NONE);
    CHECK(resume_one(&sel, ticket) == CH_OK && resumed(&sel));
    resume_reset(&sel, (uint64_t)RESUME_AUTH + SRV_TICKET_LIFETIME + 1);
    CHECK(resume_one(&sel, ticket) == CH_OK && sel.psk_selected == 0);

    // A ticket issued one second after the server's clock reads is from the
    // future, and so is refused; one issued at the same second is not.
    resume_reset(&sel, RESUME_AUTH - 1);
    CHECK(resume_one(&sel, ticket) == CH_OK && sel.psk_selected == 0);
    resume_reset(&sel, RESUME_AUTH);
    CHECK(resume_one(&sel, ticket) == CH_OK && resumed(&sel));

    // No clock, or no key: nothing can be judged, so nothing resumes.
    resume_reset(&sel, 0);
    CHECK(resume_one(&sel, ticket) == CH_OK && sel.psk_selected == 0);
    resume_reset(&sel, RESUME_AUTH);
    sess.cfg.srv.ticket_key = NULL;
    CHECK(resume_one(&sel, ticket) == CH_OK && sel.psk_selected == 0);

    // A client that lists psk_ke alone asks for a mode this server never
    // selects, so the ticket is not considered.
    resume_reset(&sel, RESUME_AUTH);
    uint8_t good[SHA256_LEN];
    resume_binder(good);
    resume_offer only = {ticket, SRV_TICKET_LEN, good, sizeof good};
    offer_tickets(&only, 1);
    flight_hello.psk_modes = SRV_PSK_KE;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_OK && sel.psk_selected == 0);
    flight_hello.psk_modes = SRV_PSK_KE | SRV_PSK_DHE_KE;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_OK && resumed(&sel));

    // A suite this build does not hold is one whose hash the ticket's PSK
    // may not share, so the ticket is passed over.
    resume_reset(&sel, RESUME_AUTH);
    srv_ticket_contents c;
    CHECK(srv_ticket_open(resume_key, ticket, sizeof ticket, &c) == CH_OK);
    c.suite = 0x1302; // TLS_AES_256_GCM_SHA384, a SHA-384 suite
    static const uint8_t nonce[AEAD_NONCE] = {1};
    CHECK(srv_ticket_seal(resume_key, nonce, &c, ticket, sizeof ticket) == SRV_TICKET_LEN);
    CHECK(resume_one(&sel, ticket) == CH_OK && sel.psk_selected == 0);
}

// The binder: one that does not match the selected ticket ends the
// handshake with decrypt_error, and so does one of the wrong length or one
// the list does not carry, and the early secret dies with it.
static void test_resume_binder(void) {
    selection sel;
    uint8_t ticket[SRV_TICKET_LEN];
    uint8_t binder[SHA256_LEN + 1];
    static const uint8_t zero[SHA256_LEN] = {0};

    resume_reset(&sel, RESUME_AUTH);
    resume_ticket(ticket, resume_key, RESUME_AUTH, CH_ALPN_NONE);
    resume_binder(binder);
    binder[5] ^= 0x04;
    resume_offer bad = {ticket, SRV_TICKET_LEN, binder, SHA256_LEN};
    offer_tickets(&bad, 1);
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_EAUTH);
    CHECK(hs.alert == ALERT_DECRYPT_ERROR && sel.psk_selected == 0);
    CHECK(memcmp(hs.early, zero, sizeof zero) == 0);

    // The binder is over this hello: the right PSK over another transcript
    // hash does not match either.
    resume_reset(&sel, RESUME_AUTH);
    resume_binder(binder);
    resume_offer right = {ticket, SRV_TICKET_LEN, binder, SHA256_LEN};
    offer_tickets(&right, 1);
    flight_hello.binder_hash[0] ^= 0x01;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_EAUTH);

    // Its exact length: 32 bytes is SHA-256's binder and 33 is no binder
    // this PSK can have, though the parser admits it.
    resume_reset(&sel, RESUME_AUTH);
    resume_binder(binder);
    binder[SHA256_LEN] = 0;
    resume_offer longer = {ticket, SRV_TICKET_LEN, binder, SHA256_LEN + 1};
    offer_tickets(&longer, 1);
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_EAUTH);
    CHECK(hs.alert == ALERT_DECRYPT_ERROR);

    // Two identities and one binder, with the second identity the one
    // that opens: its binder is absent, which RFC 9846 §4.3.11 treats as a
    // binder that does not validate.
    resume_reset(&sel, RESUME_AUTH);
    uint8_t garbage[SRV_TICKET_LEN];
    memset(garbage, 0x33, sizeof garbage);
    resume_binder(binder);
    resume_offer pair[2] = {
        {garbage, sizeof garbage, binder, SHA256_LEN},
        {ticket,  SRV_TICKET_LEN, NULL,   0         }
    };
    offer_tickets(pair, 2);
    flight_hello.psk_binders_len = 1 + SHA256_LEN;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_EAUTH);
    CHECK(hs.alert == ALERT_DECRYPT_ERROR);
}

// The order rule and the ALPN binding.
static void test_resume_order(void) {
    selection sel;
    uint8_t ticket[SRV_TICKET_LEN];
    uint8_t binder[SHA256_LEN];
    uint8_t wrong[SHA256_LEN];

    // An identity of another length and one this key did not seal come
    // first; the third opens, so it is selected at index 2 and only its
    // binder is checked, which is why the first two carry a wrong one.
    resume_reset(&sel, RESUME_AUTH);
    resume_ticket(ticket, resume_key, RESUME_AUTH, CH_ALPN_NONE);
    resume_binder(binder);
    memset(wrong, 0xee, sizeof wrong);
    uint8_t other[SRV_TICKET_LEN];
    resume_ticket(other, other_resume_key, RESUME_AUTH, CH_ALPN_NONE);
    static const uint8_t short_id[5] = {1, 2, 3, 4, 5};
    resume_offer three[3] = {
        {short_id, sizeof short_id, wrong,  sizeof wrong },
        {other,    SRV_TICKET_LEN,  wrong,  sizeof wrong },
        {ticket,   SRV_TICKET_LEN,  binder, sizeof binder}
    };
    offer_tickets(three, 3);
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_OK && resumed(&sel));
    CHECK(sel.psk_identity == 2);

    // Two tickets that both open: the first in the client's order wins,
    // and its binder is the one checked.
    resume_reset(&sel, RESUME_AUTH);
    resume_offer two[2] = {
        {ticket, SRV_TICKET_LEN, binder, sizeof binder},
        {ticket, SRV_TICKET_LEN, wrong,  sizeof wrong }
    };
    offer_tickets(two, 2);
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_OK && sel.psk_identity == 0);
    two[0].binder = wrong;
    two[1].binder = binder;
    offer_tickets(two, 2);
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_EAUTH);

    // ALPN: a ticket issued under "h2" resumes a connection that selects
    // "h2" again, and not one that selects "http/1.1" or none.
    resume_reset(&sel, RESUME_AUTH);
    sess.cfg.alpn_protocols = flight_alpn;
    sess.cfg.alpn_count = 2;
    resume_ticket(ticket, resume_key, RESUME_AUTH, 0);
    resume_offer h2 = {ticket, SRV_TICKET_LEN, binder, sizeof binder};
    offer_tickets(&h2, 1);
    flight_hello.alpn_selected = 0;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_OK && resumed(&sel));
    // The resumed selection names no scheme, and srv_select writes the
    // hello's scheme again before every call, so these rows do too.
    sel.sigalg = SIGALG_ECDSA_P256_SHA256;
    flight_hello.alpn_selected = 1;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_OK && sel.psk_selected == 0);
    flight_hello.alpn_selected = CH_ALPN_NONE;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_OK && sel.psk_selected == 0);
    // And a ticket issued under no protocol resumes only a connection with
    // none.
    resume_ticket(ticket, resume_key, RESUME_AUTH, CH_ALPN_NONE);
    offer_tickets(&h2, 1);
    flight_hello.alpn_selected = 0;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_OK && sel.psk_selected == 0);
    flight_hello.alpn_selected = CH_ALPN_NONE;
    CHECK(srv_select_auth(&hs, &flight_hello, &sel) == CH_OK && resumed(&sel));
}

#endif
