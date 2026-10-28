// ch_fail (tls.h) on a TRANSPORT=tcp-blocking client that the mock server
// connected. Included by test/handshake_sequence_test.c only, after
// run_case, whose session and mock server it reads.
#ifndef CH_HANDSHAKE_SEQUENCE_FAIL_TESTS_H
#define CH_HANDSHAKE_SEQUENCE_FAIL_TESTS_H

// A description that is not an error alert of RFC 9846 §6.2 returns
// CH_EINVAL and sends nothing. record_overflow goes out once, sealed
// under the client's application write key, which the mock server opens,
// and the session fails. A second call, and a call after ch_close, return
// CH_EPROTO and send nothing.
static void test_caller_failure(void) {
    CHECK(run_case("SEF", 3, 1) == 1 && client_session.state == CH_ST_CONNECTED);
    CHECK(ch_fail(&client_session, ALERT_CLOSE_NOTIFY) == CH_EINVAL);
    CHECK(ch_fail(&client_session, ALERT_USER_CANCELED) == CH_EINVAL);
    CHECK(srv.alerts == 0 && client_session.state == CH_ST_CONNECTED);
    CHECK(ch_fail(&client_session, ALERT_RECORD_OVERFLOW) == CH_OK);
    CHECK(srv.alerts == 1 && srv.last_alert == ALERT_RECORD_OVERFLOW);
    CHECK(client_session.state == CH_ST_FAILED);
    CHECK(ch_alert_sent(&client_session) == ALERT_RECORD_OVERFLOW);
    CHECK(ch_fail(&client_session, ALERT_RECORD_OVERFLOW) == CH_EPROTO && srv.alerts == 1);

    CHECK(run_case("SEF", 3, 1) == 1);
    ch_close(&client_session);
    CHECK(ch_fail(&client_session, ALERT_DECODE_ERROR) == CH_EPROTO && srv.alerts == 0);
    CHECK(ch_alert_sent(&client_session) == 0);
}

#endif
