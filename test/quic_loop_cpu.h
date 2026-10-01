// The host object's rows of the QUIC loop (docs/decisions.md 89):
// test/quic_loop_test.c built as bin/quic_loop_host, the ROLE=both
// TRUST=webpki host object. Every other row of that file runs in the same
// binary with both ends describing the CPU as TEST_CPU, which
// test_cfg_clear writes (test/test_cpu.h).
//
// What the rows hold: ch_quic_init, ch_srv_quic_init and ch_srv_check
// refuse each value test_cpu_taken rejects, the two init calls with
// CH_EINVAL and a failed session, and take the others.
#ifndef CH_TEST_QUIC_LOOP_CPU_H
#define CH_TEST_QUIC_LOOP_CPU_H
#ifdef CH_CPU_RUNTIME

#include "srv.h"

static void test_quic_cpu_values(void) {
    static ch_quic probe;
    for (size_t i = 0; i < TEST_CPU_VALUES; i++) {
        int taken = test_cpu_taken(i);
        ch_cfg cfg;
        webpki_client(&cfg, webpki_corpus_anchors_root_p384, "s3.example.test");
        cfg.cpu = test_cpu_values[i];
        int rc = ch_quic_init(&probe, &cfg);
        CHECK(taken ? rc == CH_OK : rc == CH_EINVAL && ch_quic_state(&probe) == CH_ST_FAILED);
        ch_quic_close(&probe);
        webpki_server(&cfg, ticket_key);
        cfg.cpu = test_cpu_values[i];
        CHECK((ch_srv_check(&cfg) == CH_OK) == taken);
        rc = ch_srv_quic_init(&probe, &cfg);
        CHECK(taken ? rc == CH_OK : rc == CH_EINVAL && ch_quic_state(&probe) == CH_ST_FAILED);
        ch_quic_close(&probe);
    }
}

#endif // CH_CPU_RUNTIME
#endif
