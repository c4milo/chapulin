// The AES=runtime rows over TCP (docs/decisions.md 81): this tree's
// tcp-nonblocking client against its tcp-nonblocking server in the ROLE=both
// TRUST=webpki SUITE=aesgcm AES=runtime object, bin/webpki_loop_aes_runtime,
// with each end's ch_cfg.aes_instructions set by the row through
// test/webpki_loop_test.c's server_aes and client_aes. A TCP object holds
// no table, so the answer chooses the suites alone: an end with the
// instructions holds all three in docs/decisions.md 80's order, and one
// without them holds ChaCha20 alone and runs no AES instruction.
//
// What the rows hold: ch_record_init and ch_srv_record_init refuse a
// field that states neither answer, at 0 and at 3, and take each answer;
// each pair of answers runs a whole handshake at the suite both ends
// hold; a server without the instructions selects no AES-GCM suite, even
// from a client that offers nothing else; and an end without them refuses
// a suite list that names one.
//
// With "absent" as its argument the binary runs check_runtime_absent alone,
// which test/aes-runtime-qemu.sh does on a CPU model without the AES
// instructions and the carry-less multiply.
#ifndef CH_TEST_WEBPKI_LOOP_RUNTIME_H
#define CH_TEST_WEBPKI_LOOP_RUNTIME_H
#ifdef CH_AES_RUNTIME

// Both init calls at each edge of the field: 0, the value a caller that
// never set it leaves, each answer, and 3, the first value past them.
static void check_runtime_edges(void) {
    static const uint8_t values[4] = {0, CH_AES_INSTRUCTIONS_PRESENT, CH_AES_INSTRUCTIONS_ABSENT,
                                      3};
    static const int taken[4] = {0, 1, 1, 0};
    static ch_record probe;
    for (size_t i = 0; i < sizeof values; i++) {
        ch_cfg cfg;
        client_config(&cfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
        cfg.aes_instructions = values[i];
        int rc = ch_record_init(&probe, &cfg);
        CHECK(taken[i] ? rc == CH_OK : rc == CH_EINVAL && ch_record_state(&probe) == CH_ST_FAILED);
        ch_record_close(&probe);
        server_config(&cfg, ticket_key);
        cfg.aes_instructions = values[i];
        rc = ch_srv_record_init(&probe, &cfg);
        CHECK(taken[i] ? rc == CH_OK : rc == CH_EINVAL && ch_record_state(&probe) == CH_ST_FAILED);
        ch_record_close(&probe);
    }
}

// One whole handshake under each end's answer, at the suite want.
static void check_runtime_answers(uint8_t client_answer, uint8_t server_answer, uint16_t want) {
    ch_cfg scfg;
    ch_cfg ccfg;
    client_aes = client_answer;
    server_aes = server_answer;
    server_config(&scfg, ticket_key);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.suite == want && server.t.suite == want);
    client_aes = CH_AES_INSTRUCTIONS_PRESENT;
    server_aes = CH_AES_INSTRUCTIONS_PRESENT;
}

// A server without the instructions, and a client that offers AES-128-GCM
// alone: the server selects nothing and answers handshake_failure.
static void check_runtime_server_without_aes(void) {
    static const uint16_t aes128[] = {SUITE_AES_128_GCM_SHA256};
    ch_cfg scfg;
    ch_cfg ccfg;
    server_aes = CH_AES_INSTRUCTIONS_ABSENT;
    server_config(&scfg, ticket_key);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    ccfg.cipher_suites = aes128;
    ccfg.cipher_suite_count = 1;
    CHECK(!run(&ccfg, &scfg));
    CHECK(ch_record_state(&server) == CH_ST_FAILED &&
          ch_alert_sent(&server.t) == ALERT_HANDSHAKE_FAILURE);
    server_aes = CH_AES_INSTRUCTIONS_PRESENT;
}

// Whether both ends take a suite list under answer: the client's
// ch_cfg.cipher_suites and the server's ch_srv_cfg.cipher_suites, each
// refused or taken alike.
static int runtime_list_taken(uint8_t answer, const uint16_t *list, size_t count) {
    static ch_record probe;
    ch_cfg cfg;
    client_aes = answer;
    server_aes = answer;
    client_config(&cfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    cfg.cipher_suites = list;
    cfg.cipher_suite_count = count;
    int client_rc = ch_record_init(&probe, &cfg);
    ch_record_close(&probe);
    server_config(&cfg, ticket_key);
    cfg.srv.cipher_suites = list;
    cfg.srv.cipher_suite_count = count;
    int server_rc = ch_srv_record_init(&probe, &cfg);
    ch_record_close(&probe);
    client_aes = CH_AES_INSTRUCTIONS_PRESENT;
    server_aes = CH_AES_INSTRUCTIONS_PRESENT;
    CHECK(client_rc == server_rc);
    return client_rc == CH_OK;
}

// Each list that names an AES-GCM suite is refused without the
// instructions and taken with them; ChaCha20 alone is taken with both.
static void check_runtime_lists(void) {
    static const uint16_t aes128[] = {SUITE_AES_128_GCM_SHA256};
    static const uint16_t aes256[] = {SUITE_AES_256_GCM_SHA384};
    static const uint16_t chacha_then_aes[] = {SUITE_CHACHA20_POLY1305_SHA256,
                                               SUITE_AES_256_GCM_SHA384};
    static const uint16_t chacha[] = {SUITE_CHACHA20_POLY1305_SHA256};
    CHECK(!runtime_list_taken(CH_AES_INSTRUCTIONS_ABSENT, aes128, 1));
    CHECK(!runtime_list_taken(CH_AES_INSTRUCTIONS_ABSENT, aes256, 1));
    CHECK(!runtime_list_taken(CH_AES_INSTRUCTIONS_ABSENT, chacha_then_aes, 2));
    CHECK(runtime_list_taken(CH_AES_INSTRUCTIONS_ABSENT, chacha, 1));
    CHECK(runtime_list_taken(CH_AES_INSTRUCTIONS_PRESENT, aes128, 1));
    CHECK(runtime_list_taken(CH_AES_INSTRUCTIONS_PRESENT, aes256, 1));
    CHECK(runtime_list_taken(CH_AES_INSTRUCTIONS_PRESENT, chacha_then_aes, 2));
    CHECK(runtime_list_taken(CH_AES_INSTRUCTIONS_PRESENT, chacha, 1));
}

// Both ends answer that the instructions are absent, through a full
// handshake, its ticket resumed, the pins-alone rows and the pair of absent
// answers above, all on ChaCha20. On a CPU where either instruction traps,
// a row that ran one would end the process with SIGILL.
static int check_runtime_absent(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    client_aes = CH_AES_INSTRUCTIONS_ABSENT;
    server_aes = CH_AES_INSTRUCTIONS_ABSENT;
    server_config(&scfg, ticket_key);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    CHECK(run(&ccfg, &scfg));
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 1);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 1 && client.t.suite == SUITE_CHACHA20_POLY1305_SHA256);
    test_pins_alone();
    check_runtime_answers(CH_AES_INSTRUCTIONS_ABSENT, CH_AES_INSTRUCTIONS_ABSENT,
                          SUITE_CHACHA20_POLY1305_SHA256);
    if (failures == 0) {
        (void)printf("webpki_loop: with both ends answering that the AES instructions are absent,"
                     " every handshake ran on ChaCha20\n");
    }
    return failures != 0;
}

static void check_runtime(void) {
    check_runtime_edges();
    check_runtime_answers(CH_AES_INSTRUCTIONS_PRESENT, CH_AES_INSTRUCTIONS_PRESENT,
                          SUITE_AES_256_GCM_SHA384);
    check_runtime_answers(CH_AES_INSTRUCTIONS_ABSENT, CH_AES_INSTRUCTIONS_PRESENT,
                          SUITE_CHACHA20_POLY1305_SHA256);
    check_runtime_answers(CH_AES_INSTRUCTIONS_PRESENT, CH_AES_INSTRUCTIONS_ABSENT,
                          SUITE_CHACHA20_POLY1305_SHA256);
    check_runtime_answers(CH_AES_INSTRUCTIONS_ABSENT, CH_AES_INSTRUCTIONS_ABSENT,
                          SUITE_CHACHA20_POLY1305_SHA256);
    check_runtime_server_without_aes();
    check_runtime_lists();
}

#endif // CH_AES_RUNTIME
#endif
