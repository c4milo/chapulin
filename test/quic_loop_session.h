// The RAND=session checks over the QUIC drivers
// (test/rand_session_cases.h), and the refusals of their two init calls.
// bin/quic_loop_session builds quic_loop_test.c with -DCH_RAND_SESSION
// under TRUST=raw-ecdsa, as bin/quic_loop_test is built. The client draws
// its x25519 scalar and its random in ch_quic_init, and the server its
// x25519 scalar in ch_srv_quic_init, its random for the ServerHello, and
// the ticket's nonces once the client Finished arrives. Its ECDSA
// signature draws nothing, so the RSA-PSS salt is checked on its own
// (check_pss_salt_from_source). The client pins the server's key through
// test/quic_loop_close.h's pinned_client_config.
#ifndef CH_TEST_QUIC_LOOP_SESSION_H
#define CH_TEST_QUIC_LOOP_SESSION_H

#ifndef CH_PIN_ECDSA
#error "the QUIC session checks pin the server's P-256 key, a TRUST=raw-ecdsa client"
#endif

#define SESSION_CLIENT_DRAWS 2
#define SESSION_SERVER_DRAWS 3
#define SESSION_SERVER_RANDOM_DRAW 1
#define SESSION_RANDOM_OFF 6

// The message the client owes at level, into out's client-to-server
// direction and then into the server.
static int session_to_server(uint8_t level, crossed *out) {
    static uint8_t message[4096];
    size_t n = 0;
    return ch_quic_crypto_out(&client, level, message, sizeof message, &n) == CH_OK &&
           cross(out->to_server, &out->to_server_len, message, n) &&
           ch_srv_quic_crypto_in(&server, level, message, n) == CH_OK;
}

// What the server wrote at level, into out's server-to-client direction
// and then into the client.
static int session_to_client(uint8_t level, crossed *out) {
    return cross(out->to_client, &out->to_client_len, from_server.bytes[level],
                 from_server.len[level]) &&
           ch_quic_crypto_in(&client, level, from_server.bytes[level], from_server.len[level]) ==
               CH_OK;
}

// test/rand_session_cases.h's handshake, run_quic's with every CRYPTO
// byte written into out, the ticket the server writes at the 1-RTT level
// among them.
static int run_seeded(uint64_t client_seed, uint64_t server_seed, crossed *out) {
    ch_cfg ccfg;
    ch_cfg scfg;
    server_config(&scfg);
    pinned_client_config(&ccfg, &server_alpn[0]);
    seed_source(&client_source, client_seed);
    seed_source(&server_source, server_seed);
    memset(out, 0, sizeof *out);
    memset(&from_server, 0, sizeof from_server);
    if (ch_quic_init(&client, &ccfg) != CH_OK || ch_srv_quic_init(&server, &scfg) != CH_OK) {
        return 0;
    }
    int ok = session_to_server(CH_LEVEL_INITIAL, out) && session_to_client(CH_LEVEL_INITIAL, out) &&
             session_to_client(CH_LEVEL_HANDSHAKE, out) &&
             session_to_server(CH_LEVEL_HANDSHAKE, out) &&
             session_to_client(CH_LEVEL_APPLICATION, out);
    return ok && ch_quic_state(&client) == CH_ST_CONNECTED &&
           ch_quic_state(&server) == CH_ST_CONNECTED;
}

#include "rand_session_cases.h"

// Each init call refuses a configuration with no source, with CH_EINVAL,
// before it draws or builds anything: ch_quic_init stages no ClientHello
// and ch_srv_quic_init writes nothing. A rand_io with no rand_bytes is no
// source. On the other side of the boundary, a rand_bytes with a NULL
// rand_io is a source, and both calls take it.
static void check_session_refusals(void) {
    ch_cfg ccfg;
    ch_cfg scfg;
    server_config(&scfg);
    pinned_client_config(&ccfg, &server_alpn[0]);
    ccfg.rand_bytes = NULL;
    scfg.rand_bytes = NULL;
    seed_source(&client_source, 1);
    seed_source(&server_source, 2);
    hook_draws = 0;
    memset(&from_server, 0, sizeof from_server);
    CHECK(ch_quic_init(&client, &ccfg) == CH_EINVAL && ch_quic_state(&client) == CH_ST_FAILED);
    uint8_t out[64];
    size_t n = 0;
    CHECK(ch_quic_crypto_out(&client, CH_LEVEL_INITIAL, out, sizeof out, &n) == CH_EINVAL &&
          n == 0);
    CHECK(ch_srv_quic_init(&server, &scfg) == CH_EINVAL && ch_quic_state(&server) == CH_ST_FAILED);
    CHECK(from_server.len[CH_LEVEL_INITIAL] == 0 && from_server.len[CH_LEVEL_HANDSHAKE] == 0 &&
          from_server.len[CH_LEVEL_APPLICATION] == 0);
    CHECK(client_source.calls == 0 && server_source.calls == 0 && hook_draws == 0);

    ccfg.rand_bytes = contextless_draw;
    ccfg.rand_io = NULL;
    scfg.rand_bytes = contextless_draw;
    scfg.rand_io = NULL;
    contextless_calls = 0;
    CHECK(ch_quic_init(&client, &ccfg) == CH_OK);
    CHECK(ch_srv_quic_init(&server, &scfg) == CH_OK);
    CHECK(contextless_calls == SESSION_CLIENT_DRAWS + 1 && stray_draws == 0 && hook_draws == 0);
    ch_quic_close(&client);
    ch_quic_close(&server);
}

static void test_session(void) {
    check_session_draws();
    check_session_replay();
    check_session_refusals();
    check_pss_salt_from_source();
}

#endif
