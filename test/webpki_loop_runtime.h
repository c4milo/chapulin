// The rows of the CH_CPU_CONSTANT_TIME_AES bit over TCP (docs/decisions.md
// 81 and 89): this tree's tcp-nonblocking client against its
// tcp-nonblocking server in the ROLE=both TRUST=webpki SUITE=aesgcm host
// object, bin/webpki_loop_aes, with each end's ch_cfg.cpu set by the row
// through test/webpki_loop_test.c's server_cpu and client_cpu. A TCP
// object holds no table, so the bit chooses the suites alone: an end with
// it holds all three in docs/decisions.md 80's order, and one without it
// holds ChaCha20 alone and runs no AES instruction.
//
// What the rows hold: ch_record_init and ch_srv_record_init refuse each
// value of test/test_cpu.h's that every init call refuses, and take the
// others; each pair of values runs a whole handshake at the suite both
// ends hold; a server without the bit selects no AES-GCM suite, even from
// a client that offers nothing else; an end without it refuses a suite
// list that names one; and an end that states the hash instructions and
// one that does not complete a handshake under either suite
// (check_runtime_hash_bits).
//
// With "absent" as its argument the binary runs check_runtime_absent alone,
// which test/aes-runtime-qemu.sh does on a CPU model without the AES
// instructions and the carry-less multiply. With "cpu" and two values it
// runs check_runtime_values alone, one handshake with each end stating a
// value, which that script does with values that name the x86-64
// kernels.
#ifndef CH_TEST_WEBPKI_LOOP_RUNTIME_H
#define CH_TEST_WEBPKI_LOOP_RUNTIME_H
#if defined(CH_CPU_RUNTIME) && defined(CH_SUITE_AES_GCM)

// The two values the rows give an end: the AES instructions stated, and
// the probe's bit alone.
#define RUNTIME_PRESENT (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES)
#define RUNTIME_ABSENT CH_CPU_PROBED

// Both init calls over test/test_cpu.h's values, in the suite object.
static void check_runtime_edges(void) {
    static ch_record probe;
    for (size_t i = 0; i < TEST_CPU_VALUES; i++) {
        int taken = test_cpu_taken(i);
        ch_cfg cfg;
        client_config(&cfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
        cfg.cpu = test_cpu_value(i);
        int rc = ch_record_init(&probe, &cfg);
        CHECK(taken ? rc == CH_OK : rc == CH_EINVAL && ch_record_state(&probe) == CH_ST_FAILED);
        ch_record_close(&probe);
        server_config(&cfg, ticket_key);
        cfg.cpu = test_cpu_value(i);
        rc = ch_srv_record_init(&probe, &cfg);
        CHECK(taken ? rc == CH_OK : rc == CH_EINVAL && ch_record_state(&probe) == CH_ST_FAILED);
        ch_record_close(&probe);
    }
}

// One whole handshake under each end's ch_cfg.cpu, at the suite want.
static void check_runtime_bits(uint32_t client_bits, uint32_t server_bits, uint16_t want) {
    ch_cfg scfg;
    ch_cfg ccfg;
    client_cpu = client_bits;
    server_cpu = server_bits;
    server_config(&scfg, ticket_key);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.suite == want && server.t.suite == want);
    client_cpu = TEST_CPU;
    server_cpu = TEST_CPU;
}

// A server without the AES bit, and a client that offers AES-128-GCM
// alone: the server selects nothing and answers handshake_failure.
static void check_runtime_server_without_aes(void) {
    static const uint16_t aes128[] = {SUITE_AES_128_GCM_SHA256};
    ch_cfg scfg;
    ch_cfg ccfg;
    server_cpu = RUNTIME_ABSENT;
    server_config(&scfg, ticket_key);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    ccfg.cipher_suites = aes128;
    ccfg.cipher_suite_count = 1;
    CHECK(!run(&ccfg, &scfg));
    CHECK(ch_record_state(&server) == CH_ST_FAILED &&
          ch_alert_sent(&server.t) == ALERT_HANDSHAKE_FAILURE);
    server_cpu = TEST_CPU;
}

// Whether both ends take a suite list under bits: the client's
// ch_cfg.cipher_suites and the server's ch_srv_cfg.cipher_suites, each
// refused or taken alike.
static int runtime_list_taken(uint32_t bits, const uint16_t *list, size_t count) {
    static ch_record probe;
    ch_cfg cfg;
    client_cpu = bits;
    server_cpu = bits;
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
    client_cpu = TEST_CPU;
    server_cpu = TEST_CPU;
    CHECK(client_rc == server_rc);
    return client_rc == CH_OK;
}

// Each list that names an AES-GCM suite is refused without the AES bit
// and taken with it; ChaCha20 alone is taken either way.
static void check_runtime_lists(void) {
    static const uint16_t aes128[] = {SUITE_AES_128_GCM_SHA256};
    static const uint16_t aes256[] = {SUITE_AES_256_GCM_SHA384};
    static const uint16_t chacha_then_aes[] = {SUITE_CHACHA20_POLY1305_SHA256,
                                               SUITE_AES_256_GCM_SHA384};
    static const uint16_t chacha[] = {SUITE_CHACHA20_POLY1305_SHA256};
    CHECK(!runtime_list_taken(RUNTIME_ABSENT, aes128, 1));
    CHECK(!runtime_list_taken(RUNTIME_ABSENT, aes256, 1));
    CHECK(!runtime_list_taken(RUNTIME_ABSENT, chacha_then_aes, 2));
    CHECK(runtime_list_taken(RUNTIME_ABSENT, chacha, 1));
    CHECK(runtime_list_taken(RUNTIME_PRESENT, aes128, 1));
    CHECK(runtime_list_taken(RUNTIME_PRESENT, aes256, 1));
    CHECK(runtime_list_taken(RUNTIME_PRESENT, chacha_then_aes, 2));
    CHECK(runtime_list_taken(RUNTIME_PRESENT, chacha, 1));
}

// Both ends state the probe's bit alone, through a full handshake, its
// ticket resumed, the pins-alone rows and the pair of such values above,
// all on ChaCha20. On a CPU where either instruction traps, a row that ran
// one would end the process with SIGILL.
static int check_runtime_absent(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    client_cpu = RUNTIME_ABSENT;
    server_cpu = RUNTIME_ABSENT;
    server_config(&scfg, ticket_key);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    CHECK(run(&ccfg, &scfg));
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 1);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 1 && client.t.suite == SUITE_CHACHA20_POLY1305_SHA256);
    test_pins_alone();
    check_runtime_bits(RUNTIME_ABSENT, RUNTIME_ABSENT, SUITE_CHACHA20_POLY1305_SHA256);
    if (failures == 0) {
        (void)printf("webpki_loop: with both ends stating no AES instructions, every handshake"
                     " ran on ChaCha20\n");
    }
    return failures != 0;
}

// One whole handshake with the client stating one ch_cfg.cpu value and the
// server another, each a number such as 0x1f, at the suite both can run:
// AES-256-GCM where both state the AES instructions, and ChaCha20 where
// either does not. On a CPU without the instructions of a kernel a value
// names, the end that states it dies of SIGILL at the kernel's first
// instruction, as a session whose caller described the CPU wrongly does.
static int check_runtime_values(const char *client_text, const char *server_text) {
    uint32_t client_bits = (uint32_t)strtoul(client_text, NULL, 0);
    uint32_t server_bits = (uint32_t)strtoul(server_text, NULL, 0);
    int both_aes = (client_bits & server_bits & CH_CPU_CONSTANT_TIME_AES) != 0;
    check_runtime_bits(client_bits, server_bits,
                       both_aes ? SUITE_AES_256_GCM_SHA384 : SUITE_CHACHA20_POLY1305_SHA256);
    if (failures == 0) {
        (void)printf("webpki_loop: a handshake ran with the client stating ch_cfg.cpu 0x%x and"
                     " the server 0x%x\n",
                     (unsigned)client_bits, (unsigned)server_bits);
    }
    return failures != 0;
}

// The hash bits (docs/decisions.md 93). One end hashes its transcript and
// derives its keys on the CPU's hash instructions and the other on the
// portable code, in both orders, and then both do: under ChaCha20, whose
// key schedule runs SHA-256, and under AES-256-GCM, whose key schedule runs
// SHA-384 beside a transcript that takes both hashes. A handshake completes
// only where the two paths compute the same hashes. ML-KEM's hashes run on
// the instructions too in an object that holds Keccak on them
// (docs/decisions.md 99), so there the hybrid's shared secret agrees only
// where the two Keccaks do. The rows state the bits whose instructions this
// CPU has (test_cpu_hash_bits), and skip on a CPU with none.
static void check_runtime_hash_bits(void) {
    uint32_t hash = test_cpu_hash_bits();
    if (hash == 0) {
        (void)printf("webpki_loop: SKIP the rows on the hash instructions: this CPU has none\n");
        return;
    }
    check_runtime_bits(RUNTIME_ABSENT | hash, RUNTIME_ABSENT, SUITE_CHACHA20_POLY1305_SHA256);
    check_runtime_bits(RUNTIME_ABSENT, RUNTIME_ABSENT | hash, SUITE_CHACHA20_POLY1305_SHA256);
    check_runtime_bits(RUNTIME_PRESENT | hash, RUNTIME_PRESENT, SUITE_AES_256_GCM_SHA384);
    check_runtime_bits(RUNTIME_PRESENT, RUNTIME_PRESENT | hash, SUITE_AES_256_GCM_SHA384);
    check_runtime_bits(RUNTIME_PRESENT | hash, RUNTIME_PRESENT | hash, SUITE_AES_256_GCM_SHA384);
}

static void check_runtime(void) {
    check_runtime_edges();
    check_runtime_bits(RUNTIME_PRESENT, RUNTIME_PRESENT, SUITE_AES_256_GCM_SHA384);
    check_runtime_bits(RUNTIME_ABSENT, RUNTIME_PRESENT, SUITE_CHACHA20_POLY1305_SHA256);
    check_runtime_bits(RUNTIME_PRESENT, RUNTIME_ABSENT, SUITE_CHACHA20_POLY1305_SHA256);
    check_runtime_bits(RUNTIME_ABSENT, RUNTIME_ABSENT, SUITE_CHACHA20_POLY1305_SHA256);
    check_runtime_server_without_aes();
    check_runtime_lists();
    check_runtime_hash_bits();
}

#endif // CH_CPU_RUNTIME && CH_SUITE_AES_GCM
#endif
