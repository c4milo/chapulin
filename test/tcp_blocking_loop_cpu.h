// The host object's rows of the blocking loop (docs/decisions.md 89):
// test/tcp_blocking_loop_test.c built as bin/tcp_blocking_loop_host, a
// ROLE=both host object whose client half is the raw client. Every other
// case of that file runs in the same binary with both ends describing the
// CPU as TEST_CPU, which test_cfg_clear writes (test/test_cpu.h).
//
// What the rows hold: ch_connect, ch_srv_accept and ch_srv_check refuse
// each value test_cpu_taken rejects with CH_EINVAL, a failed session and
// nothing sent, and take the others.
#ifndef CH_TEST_TCP_BLOCKING_LOOP_CPU_H
#define CH_TEST_TCP_BLOCKING_LOOP_CPU_H
#ifdef CH_CPU_RUNTIME

#include "test_cpu.h"

static void test_cpu_values_at_init(void) {
    for (size_t i = 0; i < TEST_CPU_VALUES; i++) {
        int taken = test_cpu_taken(i);
        memset(&to_server, 0, sizeof to_server);
        memset(&to_client, 0, sizeof to_client);
        ch_cfg cfg;
        client_config(&cfg, read_to_client);
        cfg.cpu = test_cpu_values[i];
        static ch_tls probe;
        int rc = ch_connect(&probe, &cfg);
        if (taken) {
            CHECK(rc != CH_EINVAL && to_server.len > 0);
        } else {
            CHECK(rc == CH_EINVAL && probe.state == CH_ST_FAILED && to_server.len == 0);
        }
        server_config(&cfg, read_to_server);
        cfg.cpu = test_cpu_values[i];
        CHECK((ch_srv_check(&cfg) == CH_OK) == taken);
        rc = ch_srv_accept(&probe, &cfg);
        CHECK(taken ? rc != CH_EINVAL : rc == CH_EINVAL && probe.state == CH_ST_FAILED);
        CHECK(taken || to_client.len == 0);
    }
}

#endif // CH_CPU_RUNTIME
#endif
