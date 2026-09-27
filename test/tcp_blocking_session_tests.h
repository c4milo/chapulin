// The RAND=session checks over the tcp-blocking drivers
// (test/rand_session_cases.h), and the refusals of their two init calls.
// bin/tcp_blocking_loop_session builds tcp_blocking_loop_test.c with
// -DCH_RAND_SESSION. Its handshake is client_reads_flight's: ch_connect
// against the server's handlers, which draw from the server's source as
// srv_handshake.c would. The client draws its x25519 scalar and its
// random, and the server its x25519 scalar, its random and the RSA-PSS
// salt for the CertificateVerify.
#ifndef CH_TEST_TCP_BLOCKING_SESSION_TESTS_H
#define CH_TEST_TCP_BLOCKING_SESSION_TESTS_H

#define SESSION_CLIENT_DRAWS 2
#define SESSION_SERVER_DRAWS 3
#define SESSION_SERVER_RANDOM_DRAW 1
#define SESSION_RANDOM_OFF 11

// test/rand_session_cases.h's handshake. The two wires keep every byte
// sent; take only moves a read offset past them.
static int run_seeded(uint64_t client_seed, uint64_t server_seed, crossed *out) {
    memset(&to_server, 0, sizeof to_server);
    memset(&to_client, 0, sizeof to_client);
    ch_cfg scfg;
    server_config(&scfg, read_to_server);
    ch_cfg ccfg;
    client_config(&ccfg, client_recv);
    seed_source(&client_source, client_seed);
    seed_source(&server_source, server_seed);
    peer_state(&srv_t, &srv_h, &scfg);
    edit_finished = 0;
    flight_extra = 0;
    served = 0;
    static ch_tls client;
    int connected =
        ch_connect(&client, &ccfg) == CH_OK && srv_read_client_finished(&srv_h) == CH_OK;
    memset(out, 0, sizeof *out);
    return connected &&
           cross(out->to_server, &out->to_server_len, to_server.bytes, to_server.len) &&
           cross(out->to_client, &out->to_client_len, to_client.bytes, to_client.len);
}

#include "rand_session_cases.h"

// Each init call refuses a configuration with no source, with CH_EINVAL,
// before it draws or sends anything. A rand_io with no rand_bytes is no
// source. On the other side of the boundary, a rand_bytes with a NULL
// rand_io is a source: ch_connect draws and sends its ClientHello, and
// ch_srv_accept draws its key share, and each stops only at a recv that
// finds nothing.
static void check_session_refusals(void) {
    memset(&to_server, 0, sizeof to_server);
    memset(&to_client, 0, sizeof to_client);
    ch_cfg ccfg;
    client_config(&ccfg, read_to_client);
    ch_cfg scfg;
    server_config(&scfg, read_to_server);
    ccfg.rand_bytes = NULL;
    scfg.rand_bytes = NULL;
    seed_source(&client_source, 1);
    seed_source(&server_source, 2);
    hook_draws = 0;
    static ch_tls client;
    static ch_tls server;
    CHECK(ch_connect(&client, &ccfg) == CH_EINVAL && client.state == CH_ST_FAILED);
    CHECK(ch_srv_accept(&server, &scfg) == CH_EINVAL && server.state == CH_ST_FAILED);
    CHECK(to_server.len == 0 && to_client.len == 0);
    CHECK(client_source.calls == 0 && server_source.calls == 0 && hook_draws == 0);

    ccfg.rand_bytes = contextless_draw;
    ccfg.rand_io = NULL;
    contextless_calls = 0;
    CHECK(ch_connect(&client, &ccfg) == CH_EIO && to_server.len > 0);
    CHECK(contextless_calls == SESSION_CLIENT_DRAWS);
    memset(&to_server, 0, sizeof to_server);
    scfg.rand_bytes = contextless_draw;
    scfg.rand_io = NULL;
    CHECK(ch_srv_accept(&server, &scfg) != CH_EINVAL);
    CHECK(contextless_calls == SESSION_CLIENT_DRAWS + 1 && stray_draws == 0 && hook_draws == 0);
}

static void test_session(void) {
    check_session_draws();
    check_session_replay();
    check_session_refusals();
    check_pss_salt_from_source();
}

#endif
