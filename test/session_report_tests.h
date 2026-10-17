// session_report.h's read calls: each one answers its own field of ch_tls and no other. The
// test writes a different value into every field a call reads, so a call that read a
// neighbour's field answers that neighbour's value. Included by test/unit_test.c, the webpki
// session test, the server flight test and the QUIC driver test, so every arm of the header
// runs under a build that declares it. Each includer defines CHECK.
#ifndef CH_TEST_SESSION_REPORT_TESTS_H
#define CH_TEST_SESSION_REPORT_TESTS_H

#include <string.h>

#include "session_report.h"

static void test_session_report(void) {
    static ch_tls t;
    memset(&t, 0, sizeof t);
    t.state = CH_ST_CONNECTED;
    t.group = CH_GROUP_X25519MLKEM768;
    t.psk_selected = 1;
    t.pin_slot = 2;
    t.epoch = 101;
    t.epoch_seen = 102;
    t.epoch_status = CH_EPOCH_AHEAD;
    t.epoch_store_failed = 1;
    CHECK(ch_state(&t) == CH_ST_CONNECTED);
    CHECK(ch_group(&t) == CH_GROUP_X25519MLKEM768);
    CHECK(ch_psk_selected(&t) == 1);
    CHECK(ch_pin_slot(&t) == 2);
    CHECK(ch_epoch(&t) == 101);
    CHECK(ch_epoch_seen(&t) == 102);
    CHECK(ch_epoch_status(&t) == CH_EPOCH_AHEAD);
    CHECK(ch_epoch_store_failed(&t) == 1);
#ifdef CH_SUITE_AES_GCM
    t.suite = CH_TLS_AES_256_GCM_SHA384;
    CHECK(ch_suite(&t) == CH_TLS_AES_256_GCM_SHA384);
#else
    CHECK(ch_suite(&t) == CH_TLS_CHACHA20_POLY1305_SHA256);
#endif
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_ROLE_SERVER)
    t.alpn_selected = 3;
    CHECK(ch_alpn_selected(&t) == 3);
#endif
#ifdef CH_TRUST_WEBPKI
    t.server_cert_type = CH_CERT_TYPE_RAW_PUBLIC_KEY;
    CHECK(ch_server_cert_type(&t) == CH_CERT_TYPE_RAW_PUBLIC_KEY);
#endif
#ifdef CH_ROLE_SERVER
    t.sni_len = 17;
    CHECK(ch_sni_len(&t) == 17);
#endif
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
    t.read_closed = 1;
    t.peer_limit = 1000;
    CHECK(ch_read_closed(&t) == 1);
    CHECK(ch_peer_limit(&t) == 1000);
#endif
}

#endif
