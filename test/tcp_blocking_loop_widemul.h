// The WIDEMUL=runtime rows of the blocking loop (docs/decisions.md 87):
// test/tcp_blocking_loop_test.c built as bin/tcp_blocking_loop_widemul, a
// ROLE=both WIDEMUL=runtime object whose client half is the raw client,
// with the files built on the widening multiply compiled under
// test/widemul_runtime_count.h's counts. Every other case of that file
// runs in the same binary with both ends answering TEST_WIDEMUL,
// CH_WIDEMUL_CONSTANT_TIME.
//
// What the rows hold: ch_connect, ch_srv_accept and ch_srv_check refuse
// ch_cfg.widemul at 0, the value a caller that never set it leaves, and at
// 3, the first value past the two answers, with CH_EINVAL, a failed
// session and nothing sent, and take each answer. Each driver's whole
// handshake, against the other role's handlers, runs every operation on
// the copy its own end's answer names: the native copies alone when both
// ends answer CH_WIDEMUL_CONSTANT_TIME, the files under their own names
// alone when both answer CH_WIDEMUL_NOT_STATED, and both when the answers
// differ. The handlers' session is set up as its driver's init sets it up
// (peer_state), so the driver half of each handshake is what shows that
// ch_connect and ch_srv_accept hand their records the session's answer.
#ifndef CH_TEST_TCP_BLOCKING_LOOP_WIDEMUL_H
#define CH_TEST_TCP_BLOCKING_LOOP_WIDEMUL_H
#ifdef CH_WIDEMUL_RUNTIME

#include "widemul_runtime_count.h"

static void check_widemul_split(uint8_t client, uint8_t server) {
    int native = client == CH_WIDEMUL_CONSTANT_TIME || server == CH_WIDEMUL_CONSTANT_TIME;
    int decomposed = client == CH_WIDEMUL_NOT_STATED || server == CH_WIDEMUL_NOT_STATED;
    CHECK(native ? widemul_native_calls > 0 : widemul_native_calls == 0);
    CHECK(decomposed ? widemul_decomposed_calls > 0 : widemul_decomposed_calls == 0);
}

static void test_widemul_answers(void) {
    static const uint8_t values[4] = {0, CH_WIDEMUL_CONSTANT_TIME, CH_WIDEMUL_NOT_STATED, 3};
    static const int taken[4] = {0, 1, 1, 0};
    for (size_t i = 0; i < sizeof values; i++) {
        memset(&to_server, 0, sizeof to_server);
        memset(&to_client, 0, sizeof to_client);
        ch_cfg cfg;
        client_config(&cfg, read_to_client);
        cfg.widemul = values[i];
        static ch_tls probe;
        int rc = ch_connect(&probe, &cfg);
        if (taken[i]) {
            CHECK(rc != CH_EINVAL && to_server.len > 0);
        } else {
            CHECK(rc == CH_EINVAL && probe.state == CH_ST_FAILED && to_server.len == 0);
        }
        server_config(&cfg, read_to_server);
        cfg.widemul = values[i];
        CHECK((ch_srv_check(&cfg) == CH_OK) == taken[i]);
        rc = ch_srv_accept(&probe, &cfg);
        CHECK(taken[i] ? rc != CH_EINVAL : rc == CH_EINVAL && probe.state == CH_ST_FAILED);
        CHECK(taken[i] || to_client.len == 0);
    }
    static const uint8_t answers[2] = {CH_WIDEMUL_CONSTANT_TIME, CH_WIDEMUL_NOT_STATED};
    for (size_t c = 0; c < sizeof answers; c++) {
        for (size_t s = 0; s < sizeof answers; s++) {
            blocking_client_widemul = answers[c];
            blocking_server_widemul = answers[s];
            widemul_native_calls = 0;
            widemul_decomposed_calls = 0;
            client_reads_flight(0, 0);
            check_widemul_split(answers[c], answers[s]);
            widemul_native_calls = 0;
            widemul_decomposed_calls = 0;
            server_reads_client(0, 0);
            check_widemul_split(answers[c], answers[s]);
        }
    }
    blocking_client_widemul = TEST_WIDEMUL;
    blocking_server_widemul = TEST_WIDEMUL;
}

#endif // CH_WIDEMUL_RUNTIME
#endif
