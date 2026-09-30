// The AES=runtime rows of the blocking loop (docs/decisions.md 81):
// test/tcp_blocking_loop_test.c built as bin/tcp_blocking_loop_aes_runtime,
// a ROLE=both SUITE=aesgcm AES=runtime object whose client half is the raw
// client, so ch_connect runs the raw and ca configuration rules
// (tls.c) and ch_srv_accept the server's (srv.c). Every other case of that
// file runs in the same binary with both ends answering that the AES
// instructions are present.
//
// What the rows hold: both calls refuse ch_cfg.aes_instructions at 0, the
// value a caller that never set it leaves, and at 3, the first value past
// the two answers, with CH_EINVAL, a failed session and nothing sent, and
// take each answer; and a whole handshake runs with both ends answering
// that the instructions are absent.
#ifndef CH_TEST_TCP_BLOCKING_LOOP_RUNTIME_H
#define CH_TEST_TCP_BLOCKING_LOOP_RUNTIME_H
#ifdef CH_AES_RUNTIME

static void test_runtime_answers(void) {
    static const uint8_t values[4] = {0, CH_AES_INSTRUCTIONS_PRESENT, CH_AES_INSTRUCTIONS_ABSENT,
                                      3};
    static const int taken[4] = {0, 1, 1, 0};
    for (size_t i = 0; i < sizeof values; i++) {
        memset(&to_server, 0, sizeof to_server);
        memset(&to_client, 0, sizeof to_client);
        ch_cfg cfg;
        client_config(&cfg, read_to_client);
        cfg.aes_instructions = values[i];
        static ch_tls probe;
        int rc = ch_connect(&probe, &cfg);
        if (taken[i]) {
            CHECK(rc != CH_EINVAL && to_server.len > 0);
        } else {
            CHECK(rc == CH_EINVAL && probe.state == CH_ST_FAILED && to_server.len == 0);
        }
        server_config(&cfg, read_to_server);
        cfg.aes_instructions = values[i];
        rc = ch_srv_accept(&probe, &cfg);
        CHECK(taken[i] ? rc != CH_EINVAL : rc == CH_EINVAL && probe.state == CH_ST_FAILED);
    }
    // A whole handshake with both ends answering that the instructions are
    // absent: the raw client offers ChaCha20 alone in every build, and the
    // server's default order under that answer holds nothing else.
    blocking_aes_answer = CH_AES_INSTRUCTIONS_ABSENT;
    client_reads_flight(0, 0);
    blocking_aes_answer = CH_AES_INSTRUCTIONS_PRESENT;
}

#endif // CH_AES_RUNTIME
#endif
