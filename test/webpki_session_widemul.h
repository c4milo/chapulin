// The host object's multiply rows of the TRUST=webpki session test
// (docs/decisions.md 87 and 89): test/webpki_session_test.c built as
// bin/webpki_session_host, the webpki client's sources in a host object,
// with the files built on the widening multiply compiled under
// test/widemul_runtime_count.h's counts, which the binary says with
// -DTEST_WIDEMUL_COUNTED. Every other case of that file runs in the same
// binary with the client describing the CPU as TEST_CPU, which holds
// CH_CPU_CONSTANT_TIME_MULTIPLY, and the mock server on the native copies.
// In any other build test_webpki_multiply_bit does nothing.
//
// What the rows hold: the mock answers every hello on the native copies,
// so in a handshake the client runs to its Certificate a call to a file
// under its own names is the client's: none when the client's ch_cfg.cpu
// holds CH_CPU_CONSTANT_TIME_MULTIPLY, and some when it does not. The
// client opens the server's EncryptedExtensions and Certificate records
// under its answer, so this is the row that shows ch_connect hands its
// records the answer the session's ch_cfg.cpu gives.
#ifndef CH_TEST_WEBPKI_SESSION_WIDEMUL_H
#define CH_TEST_WEBPKI_SESSION_WIDEMUL_H
#ifdef TEST_WIDEMUL_COUNTED

#include "widemul_runtime_count.h"

// The client's calls over one handshake that fails at its Certificate,
// the chain walk's refusal, under ch_cfg.cpu's multiply bit set or clear.
static widemul_end_calls webpki_widemul_handshake(int stated) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    cfg.cpu = widemul_row_cpu(cfg.cpu, stated);
    s.answer = 1;
    widemul_end_calls calls = {0, 0};
    widemul_native_calls = 0;
    widemul_decomposed_calls = 0;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);
    widemul_take_calls(&calls);
    return calls;
}

static void test_webpki_multiply_bit(void) {
    widemul_end_calls calls = webpki_widemul_handshake(1);
    CHECK(calls.native > 0 && calls.decomposed == 0);
    calls = webpki_widemul_handshake(0);
    CHECK(calls.decomposed > 0);
}

#else

static void test_webpki_multiply_bit(void) {
}

#endif // TEST_WIDEMUL_COUNTED
#endif
