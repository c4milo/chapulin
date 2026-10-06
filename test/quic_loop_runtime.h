// The rows of the CH_CPU_CONSTANT_TIME_AES bit (docs/decisions.md 81 and
// 89): this tree's QUIC client against its QUIC server in the ROLE=both
// TRUST=webpki SUITE=aesgcm host object colibri links, bin/quic_loop_aes,
// with each end's ch_cfg.cpu set by the row through
// test/quic_loop_test.c's server_cpu and client_cpu. Every other row of
// that file runs in the same binary with both ends stating the AES
// instructions, TEST_CPU in a suite build (test/test_cpu.h).
//
// What the rows hold:
//   - Each pair of values runs a whole handshake. Two ends with the bit
//     run AES-256-GCM, the first suite of docs/decisions.md 80's order,
//     and an end without it holds ChaCha20 alone, so the pair runs
//     ChaCha20. An end without it never selects AES-GCM, even from a
//     client that offers nothing else.
//   - Initial packets, which run on the table at an end without the bit
//     and on the instructions at an end with it, open at the other end
//     either way: the two ciphers compute the same packet.
//   - An end without the bit refuses a suite list that names an AES-GCM
//     suite, and takes ChaCha20 alone; an end with it takes the same
//     lists.
//   - An end that states the hash instructions and one that does not
//     complete a handshake and hold the same keys, under either suite
//     (check_quic_hash_bits).
//
// test/quic_loop_cpu.h holds the values every init call refuses. With
// "absent" as its argument the binary runs test_quic_runtime_absent
// alone, which test/aes-runtime-qemu.sh does on a CPU model without the AES
// instructions and the carry-less multiply. With "cpu" and two values it
// runs test_quic_runtime_values alone, one handshake with each end
// stating a value, which that script does with values that name the
// x86-64 kernels.
#ifndef CH_TEST_QUIC_LOOP_RUNTIME_H
#define CH_TEST_QUIC_LOOP_RUNTIME_H
#if defined(CH_CPU_RUNTIME) && defined(CH_SUITE_AES_GCM)

// The two values the rows give an end: the AES instructions stated, and
// the probe's bit alone.
#define RUNTIME_PRESENT (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES)
#define RUNTIME_ABSENT CH_CPU_PROBED

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

// One whole handshake under each end's ch_cfg.cpu: the suite both ends
// run, 1-RTT and Initial packets that open across, and the values put
// back.
static void check_quic_bits(uint32_t client_bits, uint32_t server_bits, uint16_t want) {
    ch_cfg scfg;
    ch_cfg ccfg;
    client_cpu = client_bits;
    server_cpu = server_bits;
    webpki_server(&scfg, ticket_key);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.suite == want && server.t.suite == want);
    check_keys_agree();
    check_initial_agree();
    client_cpu = TEST_CPU;
    server_cpu = TEST_CPU;
}

// A server without the AES bit selects no AES-GCM suite, even for a
// client that offers AES-128-GCM alone: the handshake fails with
// handshake_failure, which RFC 9001 §4.8 carries as 0x0100 plus the alert.
static void check_quic_server_without_aes(void) {
    static const uint16_t aes128[] = {SUITE_AES_128_GCM_SHA256};
    ch_cfg scfg;
    ch_cfg ccfg;
    server_cpu = RUNTIME_ABSENT;
    webpki_server(&scfg, ticket_key);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    ccfg.cipher_suites = aes128;
    ccfg.cipher_suite_count = 1;
    CHECK(!run_quic(&ccfg, &scfg));
    CHECK(ch_quic_error_code(&server) == 0x0100U + ALERT_HANDSHAKE_FAILURE);
    server_cpu = TEST_CPU;
}

// Whether each end takes a suite list under bits: the client's
// ch_cfg.cipher_suites and the server's ch_srv_cfg.cipher_suites.
static int quic_list_taken(uint32_t bits, const uint16_t *list, size_t count) {
    static ch_quic probe;
    ch_cfg cfg;
    client_cpu = bits;
    server_cpu = bits;
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
    client_cpu = TEST_CPU;
    server_cpu = TEST_CPU;
    CHECK(client_rc == server_rc);
    return client_rc == CH_OK;
}

// Each list that names an AES-GCM suite is refused without the AES bit
// and taken with it; ChaCha20 alone is taken either way.
static void check_quic_lists(void) {
    static const uint16_t aes128[] = {SUITE_AES_128_GCM_SHA256};
    static const uint16_t aes256[] = {SUITE_AES_256_GCM_SHA384};
    static const uint16_t chacha_then_aes[] = {SUITE_CHACHA20_POLY1305_SHA256,
                                               SUITE_AES_128_GCM_SHA256};
    static const uint16_t chacha[] = {SUITE_CHACHA20_POLY1305_SHA256};
    CHECK(!quic_list_taken(RUNTIME_ABSENT, aes128, 1));
    CHECK(!quic_list_taken(RUNTIME_ABSENT, aes256, 1));
    CHECK(!quic_list_taken(RUNTIME_ABSENT, chacha_then_aes, 2));
    CHECK(quic_list_taken(RUNTIME_ABSENT, chacha, 1));
    CHECK(quic_list_taken(RUNTIME_PRESENT, aes128, 1));
    CHECK(quic_list_taken(RUNTIME_PRESENT, aes256, 1));
    CHECK(quic_list_taken(RUNTIME_PRESENT, chacha_then_aes, 2));
    CHECK(quic_list_taken(RUNTIME_PRESENT, chacha, 1));
}

// Both ends state the probe's bit alone, through the web PKI rows, the
// ticket version rows and the pair of such values above: full and resumed
// handshakes whose Initial packets run on the table and whose traffic runs
// on ChaCha20. On a CPU where either instruction traps, a row that ran one
// would end the process with SIGILL.
static int test_quic_runtime_absent(void) {
    client_cpu = RUNTIME_ABSENT;
    server_cpu = RUNTIME_ABSENT;
    test_webpki_resumption();
    test_webpki_pins();
    test_ticket_versions();
    check_quic_bits(RUNTIME_ABSENT, RUNTIME_ABSENT, SUITE_CHACHA20_POLY1305_SHA256);
    if (failures == 0) {
        (void)printf("quic_loop: with both ends stating no AES instructions, every handshake ran"
                     " on ChaCha20 and the table\n");
    }
    return failures != 0;
}

// One whole handshake with the client stating one ch_cfg.cpu value and the
// server another, each a number such as 0x1f, at the suite both can run:
// AES-256-GCM where both state the AES instructions, and ChaCha20 where
// either does not. On a CPU without the instructions of a kernel a value
// names, the end that states it dies of SIGILL at the kernel's first
// instruction, as a session whose caller described the CPU wrongly does.
static int test_quic_runtime_values(const char *client_text, const char *server_text) {
    uint32_t client_bits = (uint32_t)strtoul(client_text, NULL, 0);
    uint32_t server_bits = (uint32_t)strtoul(server_text, NULL, 0);
    int both_aes = (client_bits & server_bits & CH_CPU_CONSTANT_TIME_AES) != 0;
    check_quic_bits(client_bits, server_bits,
                    both_aes ? SUITE_AES_256_GCM_SHA384 : SUITE_CHACHA20_POLY1305_SHA256);
    if (failures == 0) {
        (void)printf("quic_loop: a handshake ran with the client stating ch_cfg.cpu 0x%x and the"
                     " server 0x%x\n",
                     (unsigned)client_bits, (unsigned)server_bits);
    }
    return failures != 0;
}

// The hash bits (docs/decisions.md 93). One end hashes its transcript and
// derives its keys on the CPU's hash instructions and the other on the
// portable code, in both orders, and then both do: under ChaCha20, whose
// key schedule runs SHA-256, and under AES-256-GCM, whose key schedule runs
// SHA-384 beside a transcript that takes both hashes. A handshake completes
// and its 1-RTT keys agree only where the two paths compute the same
// hashes. ML-KEM's hashes run on the instructions too in an object that
// holds Keccak on them (docs/decisions.md 99), so there the hybrid's
// shared secret agrees only where the two Keccaks do. The rows state the
// bits whose instructions this CPU has (test_cpu_hash_bits), and skip on a
// CPU with none.
static void check_quic_hash_bits(void) {
    uint32_t hash = test_cpu_hash_bits();
    if (hash == 0) {
        (void)printf("quic_loop: SKIP the rows on the hash instructions: this CPU has none\n");
        return;
    }
    check_quic_bits(RUNTIME_ABSENT | hash, RUNTIME_ABSENT, SUITE_CHACHA20_POLY1305_SHA256);
    check_quic_bits(RUNTIME_ABSENT, RUNTIME_ABSENT | hash, SUITE_CHACHA20_POLY1305_SHA256);
    check_quic_bits(RUNTIME_PRESENT | hash, RUNTIME_PRESENT, SUITE_AES_256_GCM_SHA384);
    check_quic_bits(RUNTIME_PRESENT, RUNTIME_PRESENT | hash, SUITE_AES_256_GCM_SHA384);
    check_quic_bits(RUNTIME_PRESENT | hash, RUNTIME_PRESENT | hash, SUITE_AES_256_GCM_SHA384);
}

static void test_quic_runtime(void) {
    check_quic_bits(RUNTIME_PRESENT, RUNTIME_PRESENT, SUITE_AES_256_GCM_SHA384);
    check_quic_bits(RUNTIME_ABSENT, RUNTIME_PRESENT, SUITE_CHACHA20_POLY1305_SHA256);
    check_quic_bits(RUNTIME_PRESENT, RUNTIME_ABSENT, SUITE_CHACHA20_POLY1305_SHA256);
    check_quic_bits(RUNTIME_ABSENT, RUNTIME_ABSENT, SUITE_CHACHA20_POLY1305_SHA256);
    check_quic_server_without_aes();
    check_quic_lists();
    check_quic_hash_bits();
}

#endif // CH_CPU_RUNTIME && CH_SUITE_AES_GCM
#endif
