// The host object's rows of the TRUST=webpki session test
// (docs/decisions.md 89): test/webpki_session_test.c built as
// bin/webpki_session_host, the webpki client's sources in a host object.
// Every other case of that file runs in the same binary with the client
// describing the CPU as TEST_CPU, which valid_cfg writes. In any other
// build test_webpki_cpu_values does nothing.
//
// What the rows hold: this ch_connect, the webpki client's own, refuses
// each value test_cpu_taken rejects with CH_EINVAL before a byte leaves,
// and takes the others. test/webpki_ticket_rows.h's rows over ch_connect
// run in every build. They hold which configurations hash their anchors
// at init, and on which path (docs/decisions.md 132).
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

// ch_connect under test/webpki_ticket_rows.h's rows, in every build. The
// mock fails recv at once. So ch_connect accepts a configuration when it
// sends a ClientHello and then answers CH_EIO.
static int ticket_rows_init(const ch_cfg *cfg, uint8_t stored[SHA256_LEN]) {
    static ch_tls t;
    mock_server *s = cfg->io;
    s->hello_len = 0;
    s->sends = 0;
    int rc = ch_connect(&t, cfg);
    memcpy(stored, t.ticket_config_hash, SHA256_LEN);
    return rc == CH_EIO && s->hello_len > 0;
}

#include "webpki_ticket_rows.h"

static void ignore_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    (void)ticket;
}

static void test_webpki_ticket_hash(void) {
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    cfg.on_ticket = ignore_ticket;
    check_ticket_rows(&cfg);
}

#endif
