// The WIDEMUL=runtime rows of the tcp-nonblocking loop (docs/decisions.md
// 87): test/tcp_nonblocking_loop_test.c built as
// bin/tcp_nonblocking_loop_widemul, a ROLE=both WIDEMUL=runtime object
// whose client half is the raw client, with the files built on the
// widening multiply compiled under test/widemul_runtime_count.h's counts.
// Every other case of that file runs in the same binary with both ends
// answering TEST_WIDEMUL, CH_WIDEMUL_CONSTANT_TIME, which server_config and
// client_config write. In any other build test_widemul_answers does
// nothing.
//
// What the rows hold: ch_record_init and ch_srv_record_init refuse
// ch_cfg.widemul at 0, the value a caller that never set it leaves, and at
// 3, the first value past the two answers, with CH_EINVAL, a failed
// session and nothing to send, and take each answer. In a whole handshake
// each end runs every operation on the copy its own answer names, and no
// operation on the other copy, for each of the four pairs of answers.
#ifndef CH_TEST_TCP_NONBLOCKING_LOOP_WIDEMUL_H
#define CH_TEST_TCP_NONBLOCKING_LOOP_WIDEMUL_H
#ifdef CH_WIDEMUL_RUNTIME

#include "widemul_runtime_count.h"

// run_handshake, with each end's calls counted around that end's own
// calls: ch_record_init and ch_record_in for the client, and
// ch_srv_record_init and ch_srv_record_in for the server.
// client_to_server calls the client's ch_record_out before the server's
// ch_srv_record_in, and ch_record_out copies staged bytes alone, so the
// calls counted around client_to_server are the server's.
static void widemul_counted_handshake(uint8_t client_answer, uint8_t server_answer) {
    static ch_record client;
    static ch_record server;
    ch_cfg ccfg;
    ch_cfg scfg;
    server_config(&scfg);
    client_config(&ccfg);
    scfg.widemul = server_answer;
    ccfg.widemul = client_answer;
    to_client.len = 0;
    records_pushed = 0;
    logged_count = 0;
    widemul_end_calls client_calls = {0, 0};
    widemul_end_calls server_calls = {0, 0};
    widemul_native_calls = 0;
    widemul_decomposed_calls = 0;
    CHECK(ch_srv_record_init(&server, &scfg) == CH_OK);
    widemul_take_calls(&server_calls);
    CHECK(ch_record_init(&client, &ccfg) == CH_OK);
    widemul_take_calls(&client_calls);
    for (int rounds = 0; rounds < 4; rounds++) {
        int moved = client_to_server(&client, &server);
        widemul_take_calls(&server_calls);
        if (!moved || (ch_record_state(&client) == CH_ST_CONNECTED &&
                       ch_record_state(&server) == CH_ST_CONNECTED)) {
            break;
        }
        moved = server_to_client(&client);
        widemul_take_calls(&client_calls);
        if (!moved) {
            break;
        }
    }
    CHECK(ch_record_state(&client) == CH_ST_CONNECTED);
    CHECK(ch_record_state(&server) == CH_ST_CONNECTED);
    CHECK(widemul_ran_own_copy(&client_calls, client_answer));
    CHECK(widemul_ran_own_copy(&server_calls, server_answer));
}

static void test_widemul_answers(void) {
    static const uint8_t values[4] = {0, CH_WIDEMUL_CONSTANT_TIME, CH_WIDEMUL_NOT_STATED, 3};
    static const int taken[4] = {0, 1, 1, 0};
    for (size_t i = 0; i < sizeof values; i++) {
        static ch_record probe;
        uint8_t wire[WIRE_MAX];
        size_t n = 0;
        ch_cfg cfg;
        client_config(&cfg);
        cfg.widemul = values[i];
        int rc = ch_record_init(&probe, &cfg);
        if (taken[i]) {
            CHECK(rc == CH_OK && ch_record_out(&probe, wire, sizeof wire, &n) == CH_OK && n > 0);
        } else {
            CHECK(rc == CH_EINVAL && ch_record_state(&probe) == CH_ST_FAILED);
            CHECK(ch_record_out(&probe, wire, sizeof wire, &n) == CH_EINVAL);
        }
        server_config(&cfg);
        cfg.widemul = values[i];
        rc = ch_srv_record_init(&probe, &cfg);
        if (taken[i]) {
            CHECK(rc == CH_OK && ch_record_state(&probe) != CH_ST_FAILED);
        } else {
            CHECK(rc == CH_EINVAL && ch_record_state(&probe) == CH_ST_FAILED);
            CHECK(ch_record_out(&probe, wire, sizeof wire, &n) == CH_EINVAL);
        }
    }
    static const uint8_t answers[2] = {CH_WIDEMUL_CONSTANT_TIME, CH_WIDEMUL_NOT_STATED};
    for (size_t c = 0; c < sizeof answers; c++) {
        for (size_t s = 0; s < sizeof answers; s++) {
            widemul_counted_handshake(answers[c], answers[s]);
        }
    }
}

#else

static void test_widemul_answers(void) {
}

#endif // CH_WIDEMUL_RUNTIME
#endif
