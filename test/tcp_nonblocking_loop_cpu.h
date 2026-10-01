// The host object's rows of the tcp-nonblocking loop (docs/decisions.md
// 89): test/tcp_nonblocking_loop_test.c built as
// bin/tcp_nonblocking_loop_host, a ROLE=both host object whose client half
// is the raw client. Every other case of that file runs in the same binary
// with both ends describing the CPU as TEST_CPU, which test_cfg_clear
// writes (test/test_cpu.h). In any other build test_cpu_values_at_init
// does nothing.
//
// What the rows hold: ch_record_init and ch_srv_record_init refuse each
// value test_cpu_taken rejects with CH_EINVAL, a failed session and
// nothing to send, and take the others.
#ifndef CH_TEST_TCP_NONBLOCKING_LOOP_CPU_H
#define CH_TEST_TCP_NONBLOCKING_LOOP_CPU_H
#ifdef CH_CPU_RUNTIME

static void test_cpu_values_at_init(void) {
    for (size_t i = 0; i < TEST_CPU_VALUES; i++) {
        int taken = test_cpu_taken(i);
        static ch_record probe;
        uint8_t wire[WIRE_MAX];
        size_t n = 0;
        ch_cfg cfg;
        client_config(&cfg);
        cfg.cpu = test_cpu_values[i];
        int rc = ch_record_init(&probe, &cfg);
        if (taken) {
            CHECK(rc == CH_OK && ch_record_out(&probe, wire, sizeof wire, &n) == CH_OK && n > 0);
        } else {
            CHECK(rc == CH_EINVAL && ch_record_state(&probe) == CH_ST_FAILED);
            CHECK(ch_record_out(&probe, wire, sizeof wire, &n) == CH_EINVAL);
        }
        server_config(&cfg);
        cfg.cpu = test_cpu_values[i];
        rc = ch_srv_record_init(&probe, &cfg);
        if (taken) {
            CHECK(rc == CH_OK && ch_record_state(&probe) != CH_ST_FAILED);
        } else {
            CHECK(rc == CH_EINVAL && ch_record_state(&probe) == CH_ST_FAILED);
            CHECK(ch_record_out(&probe, wire, sizeof wire, &n) == CH_EINVAL);
        }
    }
}

#else

static void test_cpu_values_at_init(void) {
}

#endif // CH_CPU_RUNTIME
#endif
