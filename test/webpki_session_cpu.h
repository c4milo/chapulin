// The host object's rows of the TRUST=webpki session test
// (docs/decisions.md 89): test/webpki_session_test.c built as
// bin/webpki_session_host, the webpki client's sources in a host object.
// Every other case of that file runs in the same binary with the client
// describing the CPU as TEST_CPU, which valid_cfg writes. In any other
// build test_webpki_cpu_values does nothing.
//
// What the rows hold: this ch_connect, the webpki client's own, refuses
// each value test_cpu_taken rejects with CH_EINVAL before a byte leaves,
// and takes the others.
#ifndef CH_TEST_WEBPKI_SESSION_CPU_H
#define CH_TEST_WEBPKI_SESSION_CPU_H
#ifdef CH_CPU_RUNTIME

static void test_webpki_cpu_values(void) {
    for (size_t i = 0; i < TEST_CPU_VALUES; i++) {
        mock_server s;
        ch_cfg cfg = valid_cfg(&s);
        cfg.cpu = test_cpu_value(i);
        CHECK(test_cpu_taken(i) ? sends_client_hello(&cfg) : refused(&cfg));
    }
}

#else

static void test_webpki_cpu_values(void) {
}

#endif // CH_CPU_RUNTIME
#endif
