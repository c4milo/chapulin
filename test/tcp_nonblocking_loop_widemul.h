// The host object's multiply rows of the tcp-nonblocking loop
// (docs/decisions.md 87 and 89): test/tcp_nonblocking_loop_test.c built as
// bin/tcp_nonblocking_loop_host, a ROLE=both host object whose client
// half is the raw client, with the files built on the widening multiply
// compiled under test/widemul_runtime_count.h's counts, which the binary
// says with -DTEST_WIDEMUL_COUNTED. Every other case of that file runs in
// the same binary with both ends describing the CPU as TEST_CPU, which
// holds CH_CPU_CONSTANT_TIME_MULTIPLY and which server_config and
// client_config write. In any other build test_multiply_bit does nothing.
//
// What the rows hold: in a whole handshake each end runs every operation
// on the copy its own ch_cfg.cpu names, the native copies with
// CH_CPU_CONSTANT_TIME_MULTIPLY and the files under their own names
// without it, and no operation on the other copy, for each of the four
// pairs of values.
#ifndef CH_TEST_TCP_NONBLOCKING_LOOP_WIDEMUL_H
#define CH_TEST_TCP_NONBLOCKING_LOOP_WIDEMUL_H
#ifdef TEST_WIDEMUL_COUNTED

#include "widemul_runtime_count.h"

// run_handshake, with each end's calls counted around that end's own
// calls: ch_record_init and ch_record_in for the client, and
// ch_srv_record_init and ch_srv_record_in for the server.
// client_to_server calls the client's ch_record_out before the server's
// ch_srv_record_in, and ch_record_out copies staged bytes alone, so the
// calls counted around client_to_server are the server's.
static void widemul_counted_handshake(int client_stated, int server_stated) {
    static ch_record client;
    static ch_record server;
    ch_cfg ccfg;
    ch_cfg scfg;
    server_config(&scfg);
    client_config(&ccfg);
    scfg.cpu = widemul_row_cpu(scfg.cpu, server_stated);
    ccfg.cpu = widemul_row_cpu(ccfg.cpu, client_stated);
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
    CHECK(widemul_ran_own_copy(&client_calls, ccfg.cpu));
    CHECK(widemul_ran_own_copy(&server_calls, scfg.cpu));
}

static void test_multiply_bit(void) {
    for (int client_stated = 0; client_stated < 2; client_stated++) {
        for (int server_stated = 0; server_stated < 2; server_stated++) {
            widemul_counted_handshake(client_stated, server_stated);
        }
    }
}

#else

static void test_multiply_bit(void) {
}

#endif // TEST_WIDEMUL_COUNTED
#endif
