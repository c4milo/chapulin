// The three cipher suites of a SUITE=aesgcm build, end to end: this
// tree's TRUST=webpki client against this tree's server, the ROLE=both
// TRANSPORT=tcp-nonblocking TRUST=webpki object compiled with -DCH_SUITE_AES_GCM.
// bin/webpki_loop_aes runs them on AES=hw and bin/webpki_loop_aes_extern on
// AES=extern; test/webpki_loop_test.c includes this
// file after its fixtures, and a build without the define compiles none
// of it.
//
// The client offers all three suites and the server selects by its own
// order, so each row names one suite in ch_srv_cfg.cipher_suites to run
// it: a full handshake, then the ticket it issued resumed under the same
// suite. TLS_AES_256_GCM_SHA384 runs the transcript, the key schedule,
// the Finished and the ticket's PSK on SHA-384, so its rows are the
// SHA-384 schedule's whole-handshake test (docs/decisions.md 58).
//
// It also feeds the server the offer h3spec's ClientHello carries,
// cipher_suites (0x1302, 0x1301, 0x1304), through the real parser: no
// ChaCha20, both AES-GCM suites, and TLS_AES_128_CCM_SHA256, which no
// build holds. It runs the default orders of both ends, and the
// client's own order, ch_cfg.cipher_suites, in each shape and against
// each refusal (docs/decisions.md 80). And it runs
// test/key_limit_cases.h: each end writes across its AES-GCM write
// key's ceiling while the other reads. test/webpki_loop_order.h, which
// holds offer_body and ORDER_DEFAULT_PICK, comes before it.
#ifndef CH_TEST_WEBPKI_LOOP_SUITES_H
#define CH_TEST_WEBPKI_LOOP_SUITES_H
#ifdef CH_SUITE_AES_GCM

#include "srv_flight.h"
#include "srv_parser.h"
#include "webpki_loop_order.h"

// The server's order for one row, in static storage because the config
// keeps the pointer for the life of the session.
static uint16_t row_suites[3];

// server_config, then an order of count suites for this row.
static void server_config_suites(ch_cfg *cfg, const uint8_t *key, const uint16_t *order,
                                 size_t count) {
    server_config(cfg, key);
    memcpy(row_suites, order, count * sizeof order[0]);
    cfg->srv.cipher_suites = row_suites;
    cfg->srv.cipher_suite_count = count;
}

// One suite end to end: a full handshake under it, and a resumption of
// the ticket that handshake issued, which keeps the suite and whose PSK
// is as long as the suite's hash.
static void check_suite_round_trip(uint16_t suite) {
    ch_cfg scfg;
    ch_cfg ccfg;
    server_config_suites(&scfg, ticket_key, &suite, 1);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.suite == suite && server.t.suite == suite);
    CHECK(client.t.psk_selected == 0 && server.t.psk_selected == 0);
    CHECK(kept.psk_len == suite_hash_len(suite));

    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 1);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.suite == suite && server.t.suite == suite);
    CHECK(client.t.psk_selected == 1 && server.t.psk_selected == 1);
    CHECK(kept.psk_len == suite_hash_len(suite));
}

// A ticket resumes only under a suite with its own hash
// (rfc9846.txt:3219-3220). The kept ticket is a SHA-384 one; a server
// that selects a SHA-256 suite passes it over and the connection
// completes with a certificate, and the ticket issued then is a SHA-256
// one.
static void check_ticket_hash_mismatch(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    const uint16_t aes256 = SUITE_AES_256_GCM_SHA384;
    server_config_suites(&scfg, ticket_key, &aes256, 1);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    CHECK(run(&ccfg, &scfg));
    CHECK(kept.psk_len == SHA384_LEN);

    const uint16_t aes128 = SUITE_AES_128_GCM_SHA256;
    server_config_suites(&scfg, ticket_key, &aes128, 1);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 1);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.suite == SUITE_AES_128_GCM_SHA256);
    CHECK(client.t.psk_selected == 0 && server.t.psk_selected == 0);
    CHECK(server.t.sigalg == SIGALG_ECDSA_P256_SHA256);
    CHECK(kept.psk_len == SHA256_LEN);
}

// The default orders, with no ch_srv_cfg.cipher_suites and no
// ch_cfg.cipher_suites: the client offers all three and the server takes
// ORDER_DEFAULT_PICK (test/webpki_loop_order.h), AES-256-GCM on AES=hw
// and ChaCha20 on AES=extern, and the ticket's PSK is as long as that
// suite's hash.
static void check_default_order(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    server_config(&scfg, ticket_key);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.suite == ORDER_DEFAULT_PICK && server.t.suite == ORDER_DEFAULT_PICK);
    CHECK(kept.psk_len == suite_hash_len(ORDER_DEFAULT_PICK));
}

// h3spec's ClientHello offer: TLS_AES_256_GCM_SHA384,
// TLS_AES_128_GCM_SHA256, TLS_AES_128_CCM_SHA256, in that order.
static size_t h3spec_offer(uint8_t *out, size_t cap, const uint8_t share[X25519_LEN]) {
    static const uint16_t h3spec_suites[] = {SUITE_AES_256_GCM_SHA384, SUITE_AES_128_GCM_SHA256,
                                             0x1304}; // TLS_AES_128_CCM_SHA256
    return offer_body(out, cap, share, h3spec_suites, 3);
}

// srv_select over ch on a fresh session whose server order is count
// code points at order, or the default order when order is NULL. Writes
// the alert the call left.
static int select_under(const client_hello *ch, const uint16_t *order, size_t count, selection *sel,
                        uint8_t *alert) {
    static ch_tls t;
    handshake_state h;
    memset(&t, 0, sizeof t);
    server_config(&t.cfg, ticket_key);
    t.cfg.srv.cipher_suites = order;
    t.cfg.srv.cipher_suite_count = count;
    memset(&h, 0, sizeof h);
    h.t = &t;
    int rc = srv_select(&h, ch, sel);
    *alert = h.alert;
    return rc;
}

// The server parses that offer to the two AES-GCM bits, and its default
// order selects the first AES suite in it, whatever order the client
// listed them in: AES-256-GCM on AES=hw, whose order puts it first, and
// AES-128-GCM on AES=extern, whose order puts ChaCha20 and then
// AES-128-GCM first (docs/decisions.md 80). An order that names
// AES-128-GCM first selects that, and one that names ChaCha20 alone finds
// nothing in common: handshake_failure.
static void check_h3spec_offer(void) {
    uint8_t share[X25519_LEN] = {0x09};
    uint8_t body[128];
    size_t n = h3spec_offer(body, sizeof body, share);
    CHECK(n > 0);
    client_hello ch;
    memset(&ch, 0, sizeof ch);
    uint8_t alert = 0;
    CHECK(srv_parse_client_hello(body, n, &ch, NULL, 0, &alert) == CH_OK);
    CHECK(ch.suites == (SRV_SUITE_AES_128_GCM | SRV_SUITE_AES_256_GCM));

    selection sel;
    uint8_t select_alert = 0;
    CHECK(select_under(&ch, NULL, 0, &sel, &select_alert) == CH_OK);
#if (defined(CH_AES_HW) || defined(CH_AES_RUNTIME)) && defined(CH_NATIVE_AES)
    CHECK(sel.suite == SUITE_AES_256_GCM_SHA384 && sel.hash_len == SHA384_LEN);
#else
    CHECK(sel.suite == SUITE_AES_128_GCM_SHA256 && sel.hash_len == SHA256_LEN);
#endif

    static const uint16_t aes128_first[] = {SUITE_AES_128_GCM_SHA256, SUITE_AES_256_GCM_SHA384};
    CHECK(select_under(&ch, aes128_first, 2, &sel, &select_alert) == CH_OK);
    CHECK(sel.suite == SUITE_AES_128_GCM_SHA256 && sel.hash_len == SHA256_LEN);

    static const uint16_t chacha_only[] = {SUITE_CHACHA20_POLY1305_SHA256};
    CHECK(select_under(&ch, chacha_only, 1, &sel, &select_alert) == CH_EPROTO);
    CHECK(select_alert == ALERT_HANDSHAKE_FAILURE);
}

// ch_srv_cfg.cipher_suites is checked before a byte moves: a code point
// the build does not hold, a count without its list, a list without its
// count and a list longer than the three suites are each CH_EINVAL, and
// the longest valid list, all three, is taken.
static void check_suite_order_rules(void) {
    static const uint16_t unheld[] = {0x1304};
    static const uint16_t all[] = {SUITE_AES_256_GCM_SHA384, SUITE_AES_128_GCM_SHA256,
                                   SUITE_CHACHA20_POLY1305_SHA256};
    static const uint16_t four[] = {SUITE_AES_256_GCM_SHA384, SUITE_AES_128_GCM_SHA256,
                                    SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256};
    ch_cfg scfg;
    server_config(&scfg, ticket_key);
    scfg.srv.cipher_suites = unheld;
    scfg.srv.cipher_suite_count = 1;
    CHECK(ch_srv_record_init(&server, &scfg) == CH_EINVAL);
    scfg.srv.cipher_suites = NULL;
    CHECK(ch_srv_record_init(&server, &scfg) == CH_EINVAL);
    scfg.srv.cipher_suites = all;
    scfg.srv.cipher_suite_count = 0;
    CHECK(ch_srv_record_init(&server, &scfg) == CH_EINVAL);
    scfg.srv.cipher_suites = four;
    scfg.srv.cipher_suite_count = 4;
    CHECK(ch_srv_record_init(&server, &scfg) == CH_EINVAL);
    scfg.srv.cipher_suites = all;
    scfg.srv.cipher_suite_count = 3;
    CHECK(ch_srv_record_init(&server, &scfg) == CH_OK);
}

// The client's order for one row, in static storage because the config
// keeps the pointer for the life of the session.
static uint16_t client_row_suites[3];

// This tree's client offers the three suites in each of their six orders
// through ch_cfg.cipher_suites, and the server's default order selects
// ORDER_DEFAULT_PICK from every one, as test/webpki_loop_order.h's raw
// hellos do. A list of one suite offers that suite alone, and the server
// selects it.
static void check_client_orders(void) {
    static const uint16_t singles[3] = {SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256,
                                        SUITE_AES_256_GCM_SHA384};
    ch_cfg scfg;
    ch_cfg ccfg;
    server_config(&scfg, ticket_key);
    for (size_t i = 0; i < 6; i++) {
        memcpy(client_row_suites, suite_orders[i], sizeof suite_orders[i]);
        client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
        ccfg.cipher_suites = client_row_suites;
        ccfg.cipher_suite_count = 3;
        CHECK(run(&ccfg, &scfg));
        CHECK(client.t.suite == ORDER_DEFAULT_PICK && server.t.suite == ORDER_DEFAULT_PICK);
    }
    for (size_t i = 0; i < 3; i++) {
        client_row_suites[0] = singles[i];
        client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
        ccfg.cipher_suites = client_row_suites;
        ccfg.cipher_suite_count = 1;
        CHECK(run(&ccfg, &scfg));
        CHECK(client.t.suite == singles[i] && server.t.suite == singles[i]);
    }
}

// ch_cfg.cipher_suites is checked before a byte moves, by ch_record_init
// as by ch_connect: a code point the build does not hold, a repeat, a
// count without its list, a list without its count and a fourth entry are
// each CH_EINVAL, and the longest valid list, all three, is taken.
static void check_client_suite_rules(void) {
    static const uint16_t unheld[] = {0x1304};
    static const uint16_t repeat[] = {SUITE_AES_128_GCM_SHA256, SUITE_AES_128_GCM_SHA256};
    static const uint16_t four[] = {SUITE_AES_256_GCM_SHA384, SUITE_AES_128_GCM_SHA256,
                                    SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256};
    ch_cfg ccfg;
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    ccfg.cipher_suites = unheld;
    ccfg.cipher_suite_count = 1;
    CHECK(ch_record_init(&client, &ccfg) == CH_EINVAL);
    ccfg.cipher_suites = repeat;
    ccfg.cipher_suite_count = 2;
    CHECK(ch_record_init(&client, &ccfg) == CH_EINVAL);
    ccfg.cipher_suites = NULL;
    CHECK(ch_record_init(&client, &ccfg) == CH_EINVAL);
    ccfg.cipher_suites = four;
    ccfg.cipher_suite_count = 0;
    CHECK(ch_record_init(&client, &ccfg) == CH_EINVAL);
    ccfg.cipher_suite_count = 4;
    CHECK(ch_record_init(&client, &ccfg) == CH_EINVAL);
    ccfg.cipher_suite_count = 3;
    CHECK(ch_record_init(&client, &ccfg) == CH_OK);
}

// One handshake whose ServerHello selects suite, for
// test/key_limit_cases.h. run leaves the ticket the server sent read, so
// both ends are connected and nothing waits on either pipe.
static int key_limit_connect(uint16_t suite, ch_tls **client_out, ch_tls **server_out) {
    ch_cfg scfg;
    ch_cfg ccfg;
    server_config_suites(&scfg, ticket_key, &suite, 1);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    if (!run(&ccfg, &scfg) || client.t.suite != suite || server.t.suite != suite) {
        return 0;
    }
    *client_out = &client.t;
    *server_out = &server.t;
    return 1;
}

#include "key_limit_cases.h"

static void check_suites(void) {
    check_suite_round_trip(SUITE_CHACHA20_POLY1305_SHA256);
    check_suite_round_trip(SUITE_AES_128_GCM_SHA256);
    check_suite_round_trip(SUITE_AES_256_GCM_SHA384);
    check_ticket_hash_mismatch();
    check_default_order();
    check_h3spec_offer();
    check_suite_order_rules();
    check_client_orders();
    check_client_suite_rules();
    check_key_limit();
}

#endif // CH_SUITE_AES_GCM
#endif
