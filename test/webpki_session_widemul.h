// The WIDEMUL=runtime rows of the TRUST=webpki session test
// (docs/decisions.md 87): test/webpki_session_test.c built as
// bin/webpki_session_widemul, the webpki client's sources in a
// WIDEMUL=runtime object, with the files built on the widening multiply
// compiled under test/widemul_runtime_count.h's counts. Every other case
// of that file runs in the same binary with the client and the mock
// server answering TEST_WIDEMUL, CH_WIDEMUL_CONSTANT_TIME.
//
// What the rows hold: this ch_connect, the webpki client's own, refuses
// ch_cfg.widemul at 0, the value a caller that never set it leaves, and at
// 3, the first value past the two answers, with CH_EINVAL before a byte
// leaves, and takes each answer. The mock answers every hello on the
// native copies, so in a handshake the client runs to its Certificate a
// call to a file under its own names is the client's: none when the
// client answers CH_WIDEMUL_CONSTANT_TIME, and some when it answers
// CH_WIDEMUL_NOT_STATED. The client opens the server's
// EncryptedExtensions and Certificate records under its answer, so this
// is the row that shows ch_connect hands its records the session's
// answer.
#ifndef CH_TEST_WEBPKI_SESSION_WIDEMUL_H
#define CH_TEST_WEBPKI_SESSION_WIDEMUL_H
#ifdef CH_WIDEMUL_RUNTIME

#include "widemul_runtime_count.h"

// The client's calls over one handshake that fails at its Certificate,
// the chain walk's refusal, under answer.
static widemul_end_calls webpki_widemul_handshake(uint8_t answer) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    cfg.widemul = answer;
    s.answer = 1;
    widemul_end_calls calls = {0, 0};
    widemul_native_calls = 0;
    widemul_decomposed_calls = 0;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);
    widemul_take_calls(&calls);
    return calls;
}

static void test_webpki_widemul_answers(void) {
    static const uint8_t values[4] = {0, CH_WIDEMUL_CONSTANT_TIME, CH_WIDEMUL_NOT_STATED, 3};
    static const int taken[4] = {0, 1, 1, 0};
    for (size_t i = 0; i < sizeof values; i++) {
        mock_server s;
        ch_cfg cfg = valid_cfg(&s);
        cfg.widemul = values[i];
        CHECK(taken[i] ? sends_client_hello(&cfg) : refused(&cfg));
    }
    widemul_end_calls calls = webpki_widemul_handshake(CH_WIDEMUL_CONSTANT_TIME);
    CHECK(calls.native > 0 && calls.decomposed == 0);
    calls = webpki_widemul_handshake(CH_WIDEMUL_NOT_STATED);
    CHECK(calls.decomposed > 0);
}

#endif // CH_WIDEMUL_RUNTIME
#endif
