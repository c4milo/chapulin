// The host object's multiply rows of the blocking loop (docs/decisions.md
// 87 and 89): test/tcp_blocking_loop_test.c built as
// bin/tcp_blocking_loop_host, a ROLE=both host object whose client half
// is the raw client, with the files built on the widening multiply
// compiled under test/widemul_runtime_count.h's counts, which the binary
// says with -DTEST_WIDEMUL_COUNTED. Every other case of that file runs in
// the same binary with both ends describing the CPU as TEST_CPU, which
// holds CH_CPU_CONSTANT_TIME_MULTIPLY.
//
// What the rows hold: each driver's whole handshake, against the other
// role's handlers, runs every operation on the copy its own end's
// ch_cfg.cpu names: the native copies alone when both ends hold
// CH_CPU_CONSTANT_TIME_MULTIPLY, the files under their own names alone
// when neither does, and both when the values differ. The handlers'
// session is set up as its driver's init sets it up (peer_state), so the
// driver half of each handshake is what shows that ch_connect and
// ch_srv_accept hand their records the answer the session's ch_cfg.cpu
// gives.
#ifndef CH_TEST_TCP_BLOCKING_LOOP_WIDEMUL_H
#define CH_TEST_TCP_BLOCKING_LOOP_WIDEMUL_H
#ifdef TEST_WIDEMUL_COUNTED

#include "widemul_runtime_count.h"

static void check_widemul_split(int client_stated, int server_stated) {
    int native = client_stated || server_stated;
    int decomposed = !client_stated || !server_stated;
    CHECK(native ? widemul_native_calls > 0 : widemul_native_calls == 0);
    CHECK(decomposed ? widemul_decomposed_calls > 0 : widemul_decomposed_calls == 0);
}

static void test_multiply_bit(void) {
    for (int client_stated = 0; client_stated < 2; client_stated++) {
        for (int server_stated = 0; server_stated < 2; server_stated++) {
            blocking_client_cpu = widemul_row_cpu(TEST_CPU, client_stated);
            blocking_server_cpu = widemul_row_cpu(TEST_CPU, server_stated);
            widemul_native_calls = 0;
            widemul_decomposed_calls = 0;
            client_reads_flight(0, 0);
            check_widemul_split(client_stated, server_stated);
            widemul_native_calls = 0;
            widemul_decomposed_calls = 0;
            server_reads_client(0, 0);
            check_widemul_split(client_stated, server_stated);
        }
    }
    blocking_client_cpu = TEST_CPU;
    blocking_server_cpu = TEST_CPU;
}

#endif // TEST_WIDEMUL_COUNTED
#endif
