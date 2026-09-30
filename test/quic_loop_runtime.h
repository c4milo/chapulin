// The AES=runtime rows (docs/decisions.md 81): this tree's QUIC client
// against its QUIC server in the ROLE=both TRUST=webpki SUITE=aesgcm
// AES=runtime object, bin/quic_loop_aes_runtime, with each end's
// ch_cfg.aes_instructions set by the row through test/quic_loop_test.c's
// server_aes and client_aes. Every other row of that file runs in the
// same binary with both ends answering that the instructions are present.
//
// What the rows hold:
//   - ch_quic_init and ch_srv_quic_init refuse a field that states neither
//     answer, at 0 and at 3, and take each answer.
//   - Each pair of answers runs a whole handshake. Two ends with the
//     instructions run AES-256-GCM, the first suite of docs/decisions.md
//     80's order, and an end without them holds ChaCha20 alone, so the
//     pair runs ChaCha20. An end without them never selects AES-GCM, even
//     from a client that offers nothing else.
//   - Initial packets, which run on the table at an end without the
//     instructions and on them at an end with them, open at the other end
//     either way: the two ciphers compute the same packet.
//   - An end without the instructions refuses a suite list that names an
//     AES-GCM suite, and takes ChaCha20 alone; an end with them takes the
//     same lists.
//
// With "absent" as its argument the binary runs test_quic_runtime_absent
// alone, which test/aes-runtime-qemu.sh does on a CPU model without the AES
// instructions and the carry-less multiply.
#ifndef CH_TEST_QUIC_LOOP_RUNTIME_H
#define CH_TEST_QUIC_LOOP_RUNTIME_H
#ifdef CH_AES_RUNTIME

// Both init calls at each edge of the field: 0, the value a caller that
// never set it leaves, each answer, and 3, the first value past them.
static void check_quic_answer_edges(void) {
    static const uint8_t values[4] = {0, CH_AES_INSTRUCTIONS_PRESENT, CH_AES_INSTRUCTIONS_ABSENT,
                                      3};
    static const int taken[4] = {0, 1, 1, 0};
    static ch_quic probe;
    for (size_t i = 0; i < sizeof values; i++) {
        ch_cfg cfg;
        webpki_client(&cfg, webpki_corpus_anchors_root_p384, "s3.example.test");
        cfg.aes_instructions = values[i];
        int rc = ch_quic_init(&probe, &cfg);
        CHECK(taken[i] ? rc == CH_OK : rc == CH_EINVAL && ch_quic_state(&probe) == CH_ST_FAILED);
        ch_quic_close(&probe);
        webpki_server(&cfg, ticket_key);
        cfg.aes_instructions = values[i];
        rc = ch_srv_quic_init(&probe, &cfg);
        CHECK(taken[i] ? rc == CH_OK : rc == CH_EINVAL && ch_quic_state(&probe) == CH_ST_FAILED);
        ch_quic_close(&probe);
    }
}

// An Initial packet the client seals opens at the server, and one the
// server seals opens at the client, whichever cipher each end runs. The
// header is a version 1 long header with a two-byte packet number, whose
// low byte-0 bits say so; chapulin reads no other header field.
static void check_initial_agree(void) {
    static const uint8_t dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    static const uint8_t hdr[20] = {0xc1, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0,
                                    0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x40, 0x2a, 0x00, 0x07};
    static const uint8_t pt[24] = {'i', 'n', 'i', 't', 'i', 'a', 'l'};
    ch_quic *ends[2][2] = {
        {&client, &server},
        {&server, &client}
    };
    CHECK(ch_quic_initial_keys(&client, dcid, sizeof dcid) == CH_OK);
    CHECK(ch_quic_initial_keys(&server, dcid, sizeof dcid) == CH_OK);
    for (size_t i = 0; i < 2; i++) {
        uint8_t pkt[sizeof hdr + sizeof pt + GCM_TAG];
        size_t pkt_len = 0;
        CHECK(ch_quic_seal(ends[i][0], CH_LEVEL_INITIAL, CH_QUIC_VERSION_1, 7, 2, hdr, sizeof hdr,
                           pt, sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);
        uint8_t key_set = 0;
        uint64_t pn = 0;
        size_t pt_len = 0;
        CHECK(ch_quic_open(ends[i][1], CH_LEVEL_INITIAL, CH_QUIC_VERSION_1, pkt, pkt_len,
                           sizeof hdr - 2, 0, 0, &key_set, &pn, &pt_len) == CH_OK);
        CHECK(pn == 7 && pt_len == sizeof pt && memcmp(&pkt[sizeof hdr], pt, sizeof pt) == 0);
    }
}

// One whole handshake under each end's answer: the suite both ends run,
// 1-RTT and Initial packets that open across, and the answers put back.
static void check_quic_answers(uint8_t client_answer, uint8_t server_answer, uint16_t want) {
    ch_cfg scfg;
    ch_cfg ccfg;
    client_aes = client_answer;
    server_aes = server_answer;
    webpki_server(&scfg, ticket_key);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.suite == want && server.t.suite == want);
    check_keys_agree();
    check_initial_agree();
    client_aes = CH_AES_INSTRUCTIONS_PRESENT;
    server_aes = CH_AES_INSTRUCTIONS_PRESENT;
}

// A server without the instructions selects no AES-GCM suite, even for a
// client that offers AES-128-GCM alone: the handshake fails with
// handshake_failure, which RFC 9001 §4.8 carries as 0x0100 plus the alert.
static void check_quic_server_without_aes(void) {
    static const uint16_t aes128[] = {SUITE_AES_128_GCM_SHA256};
    ch_cfg scfg;
    ch_cfg ccfg;
    server_aes = CH_AES_INSTRUCTIONS_ABSENT;
    webpki_server(&scfg, ticket_key);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    ccfg.cipher_suites = aes128;
    ccfg.cipher_suite_count = 1;
    CHECK(!run_quic(&ccfg, &scfg));
    CHECK(ch_quic_error_code(&server) == 0x0100U + ALERT_HANDSHAKE_FAILURE);
    server_aes = CH_AES_INSTRUCTIONS_PRESENT;
}

// Whether each end takes a suite list under answer: the client's
// ch_cfg.cipher_suites and the server's ch_srv_cfg.cipher_suites.
static int quic_list_taken(uint8_t answer, const uint16_t *list, size_t count) {
    static ch_quic probe;
    ch_cfg cfg;
    client_aes = answer;
    server_aes = answer;
    webpki_client(&cfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    cfg.cipher_suites = list;
    cfg.cipher_suite_count = count;
    int client_rc = ch_quic_init(&probe, &cfg);
    ch_quic_close(&probe);
    webpki_server(&cfg, ticket_key);
    cfg.srv.cipher_suites = list;
    cfg.srv.cipher_suite_count = count;
    int server_rc = ch_srv_quic_init(&probe, &cfg);
    ch_quic_close(&probe);
    client_aes = CH_AES_INSTRUCTIONS_PRESENT;
    server_aes = CH_AES_INSTRUCTIONS_PRESENT;
    CHECK(client_rc == server_rc);
    return client_rc == CH_OK;
}

// Each list that names an AES-GCM suite is refused without the
// instructions and taken with them; ChaCha20 alone is taken with both.
static void check_quic_lists(void) {
    static const uint16_t aes128[] = {SUITE_AES_128_GCM_SHA256};
    static const uint16_t aes256[] = {SUITE_AES_256_GCM_SHA384};
    static const uint16_t chacha_then_aes[] = {SUITE_CHACHA20_POLY1305_SHA256,
                                               SUITE_AES_128_GCM_SHA256};
    static const uint16_t chacha[] = {SUITE_CHACHA20_POLY1305_SHA256};
    CHECK(!quic_list_taken(CH_AES_INSTRUCTIONS_ABSENT, aes128, 1));
    CHECK(!quic_list_taken(CH_AES_INSTRUCTIONS_ABSENT, aes256, 1));
    CHECK(!quic_list_taken(CH_AES_INSTRUCTIONS_ABSENT, chacha_then_aes, 2));
    CHECK(quic_list_taken(CH_AES_INSTRUCTIONS_ABSENT, chacha, 1));
    CHECK(quic_list_taken(CH_AES_INSTRUCTIONS_PRESENT, aes128, 1));
    CHECK(quic_list_taken(CH_AES_INSTRUCTIONS_PRESENT, aes256, 1));
    CHECK(quic_list_taken(CH_AES_INSTRUCTIONS_PRESENT, chacha_then_aes, 2));
    CHECK(quic_list_taken(CH_AES_INSTRUCTIONS_PRESENT, chacha, 1));
}

// Both ends answer that the instructions are absent, through the web PKI
// rows, the ticket version rows and the pair of absent answers above: full
// and resumed handshakes whose Initial packets run on the table and whose
// traffic runs on ChaCha20. On a CPU where either instruction traps, a row
// that ran one would end the process with SIGILL.
static int test_quic_runtime_absent(void) {
    client_aes = CH_AES_INSTRUCTIONS_ABSENT;
    server_aes = CH_AES_INSTRUCTIONS_ABSENT;
    test_webpki_resumption();
    test_webpki_pins();
    test_ticket_versions();
    check_quic_answers(CH_AES_INSTRUCTIONS_ABSENT, CH_AES_INSTRUCTIONS_ABSENT,
                       SUITE_CHACHA20_POLY1305_SHA256);
    if (failures == 0) {
        (void)printf("quic_loop: with both ends answering that the AES instructions are absent,"
                     " every handshake ran on ChaCha20 and the table\n");
    }
    return failures != 0;
}

static void test_quic_runtime(void) {
    check_quic_answer_edges();
    check_quic_answers(CH_AES_INSTRUCTIONS_PRESENT, CH_AES_INSTRUCTIONS_PRESENT,
                       SUITE_AES_256_GCM_SHA384);
    check_quic_answers(CH_AES_INSTRUCTIONS_ABSENT, CH_AES_INSTRUCTIONS_PRESENT,
                       SUITE_CHACHA20_POLY1305_SHA256);
    check_quic_answers(CH_AES_INSTRUCTIONS_PRESENT, CH_AES_INSTRUCTIONS_ABSENT,
                       SUITE_CHACHA20_POLY1305_SHA256);
    check_quic_answers(CH_AES_INSTRUCTIONS_ABSENT, CH_AES_INSTRUCTIONS_ABSENT,
                       SUITE_CHACHA20_POLY1305_SHA256);
    check_quic_server_without_aes();
    check_quic_lists();
}

#endif // CH_AES_RUNTIME
#endif
