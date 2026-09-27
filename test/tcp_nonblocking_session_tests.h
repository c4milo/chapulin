// The RAND=session checks over the tcp-nonblocking drivers
// (test/rand_session_cases.h), and the refusals of their two init calls.
// bin/tcp_nonblocking_loop_session builds tcp_nonblocking_loop_test.c
// with -DCH_RAND_SESSION and the KEX=pq client, so a full handshake runs
// seven of the ten draw sites: the client draws its x25519 scalar, its
// random and the ML-KEM seed in ch_record_init, and the
// server its x25519 scalar in ch_srv_record_init, then the ML-KEM
// encapsulation randomness and its random for the ServerHello, then the
// RSA-PSS salt for the CertificateVerify.
#ifndef CH_TEST_TCP_NONBLOCKING_SESSION_TESTS_H
#define CH_TEST_TCP_NONBLOCKING_SESSION_TESTS_H

#ifndef CH_KEX_PQ
#error "the tcp-nonblocking session checks count the KEX=pq client's draws"
#endif

#define SESSION_CLIENT_DRAWS 3
#define SESSION_SERVER_DRAWS 4
#define SESSION_SERVER_RANDOM_DRAW 2
#define SESSION_RANDOM_OFF 11

// Everything the client owes, into out's client-to-server direction and
// then into the server.
static int session_client_turn(ch_record *client, ch_record *server, crossed *out) {
    uint8_t wire[WIRE_MAX];
    size_t total = 0;
    size_t n = 0;
    do {
        n = 0;
        if (ch_record_out(client, wire + total, sizeof wire - total, &n) != CH_OK) {
            return 0;
        }
        total += n;
    } while (n != 0);
    size_t consumed = 0;
    return total == 0 || (cross(out->to_server, &out->to_server_len, wire, total) &&
                          ch_srv_record_in(server, wire, total, &consumed) == CH_OK);
}

// Everything the server pushed, into out's server-to-client direction and
// then into the client.
static int session_server_turn(ch_record *client, crossed *out) {
    size_t consumed = 0;
    int ok = to_client.len == 0 ||
             (cross(out->to_client, &out->to_client_len, to_client.bytes, to_client.len) &&
              ch_record_in(client, to_client.bytes, to_client.len, &consumed) == CH_OK);
    to_client.len = 0;
    return ok;
}

// test/rand_session_cases.h's handshake: the ClientHello and the
// server's flight, then the client Finished.
static int run_seeded(uint64_t client_seed, uint64_t server_seed, crossed *out) {
    static ch_record client;
    static ch_record server;
    ch_cfg ccfg;
    ch_cfg scfg;
    client_config(&ccfg);
    server_config(&scfg);
    seed_source(&client_source, client_seed);
    seed_source(&server_source, server_seed);
    memset(out, 0, sizeof *out);
    // What run_handshake resets, the key log's rows among them.
    to_client.len = 0;
    records_pushed = 0;
    logged_count = 0;
    if (ch_srv_record_init(&server, &scfg) != CH_OK || ch_record_init(&client, &ccfg) != CH_OK) {
        return 0;
    }
    for (int round = 0; round < 2; round++) {
        if (!session_client_turn(&client, &server, out) || !session_server_turn(&client, out)) {
            return 0;
        }
    }
    return ch_record_state(&client) == CH_ST_CONNECTED &&
           ch_record_state(&server) == CH_ST_CONNECTED;
}

#include "rand_session_cases.h"

// Each init call refuses a configuration with no source, with CH_EINVAL,
// before it draws or sends anything: ch_record_init stages no ClientHello
// and ch_srv_record_init pushes nothing. A rand_io with no rand_bytes is
// no source. On the other side of the boundary, a rand_bytes with a NULL
// rand_io is a source, and both calls take it.
static void check_session_refusals(void) {
    static ch_record client;
    static ch_record server;
    ch_cfg ccfg;
    ch_cfg scfg;
    client_config(&ccfg);
    server_config(&scfg);
    ccfg.rand_bytes = NULL;
    scfg.rand_bytes = NULL;
    seed_source(&client_source, 1);
    seed_source(&server_source, 2);
    hook_draws = 0;
    to_client.len = 0;
    records_pushed = 0;
    CHECK(ch_record_init(&client, &ccfg) == CH_EINVAL);
    CHECK(ch_record_state(&client) == CH_ST_FAILED);
    uint8_t out[64];
    size_t n = 0;
    CHECK(ch_record_out(&client, out, sizeof out, &n) == CH_EINVAL && n == 0);
    CHECK(ch_srv_record_init(&server, &scfg) == CH_EINVAL);
    CHECK(ch_record_state(&server) == CH_ST_FAILED);
    CHECK(records_pushed == 0 && to_client.len == 0);
    CHECK(client_source.calls == 0 && server_source.calls == 0 && hook_draws == 0);

    ccfg.rand_bytes = contextless_draw;
    ccfg.rand_io = NULL;
    scfg.rand_bytes = contextless_draw;
    scfg.rand_io = NULL;
    contextless_calls = 0;
    CHECK(ch_record_init(&client, &ccfg) == CH_OK);
    CHECK(ch_srv_record_init(&server, &scfg) == CH_OK);
    CHECK(contextless_calls == SESSION_CLIENT_DRAWS + 1 && stray_draws == 0 && hook_draws == 0);
    ch_record_close(&client);
    ch_record_close(&server);
}

static void test_session(void) {
    check_session_draws();
    check_session_replay();
    check_session_refusals();
    check_pss_salt_from_source();
}

#endif
