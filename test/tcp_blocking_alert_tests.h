// The peer's alert in a tcp-blocking handshake, read by each driver: the
// client's ch_connect and the server's ch_srv_accept (RFC 9846 §5.1, §6
// and §6.2). The peer is the test's own calls, made from inside the
// driver's recv callback, as in the rest of test/tcp_blocking_loop_test.c.
//
// A fatal alert ends the handshake with CH_EPROTO and gets no answer: the
// driver sends nothing after it, and ch_alert_received names it, whether
// it came in the clear or protected. The server reads one in the clear
// even after its flight has installed its read key, because a client that
// could not use the ServerHello has no key to protect it with. An alert
// record of three bytes is not one alert, and the driver answers it with
// decode_error, which ch_alert_sent names. Included by
// test/tcp_blocking_loop_test.c after its wire and both configurations.
#ifndef CH_TEST_TCP_BLOCKING_ALERT_TESTS_H
#define CH_TEST_TCP_BLOCKING_ALERT_TESTS_H

// The alert record's plaintext the peer answers with, and how many bytes
// the driver under test had sent when it did.
static const uint8_t *peer_alert;
static size_t peer_alert_len;
static size_t sent_before_alert;

// Appends the alert record to w: in the clear, or sealed under secret at
// the sequence number the reader's first protected record has.
static void put_alert(wire *w, const uint8_t *secret) {
    uint8_t rec[REC_HDR + 8 + AEAD_TAG];
    size_t len = REC_HDR + peer_alert_len;
    if (secret != NULL) {
        rec_dir d;
        rec_dir_init(&d, secret);
        CHECK(rec_seal(&d, REC_ALERT, peer_alert, peer_alert_len, rec, sizeof rec, &len) == 0);
    } else {
        const uint8_t hdr[REC_HDR] = {REC_ALERT, 0x03, 0x03, 0, (uint8_t)peer_alert_len};
        memcpy(rec, hdr, REC_HDR);
        memcpy(rec + REC_HDR, peer_alert, peer_alert_len);
    }
    CHECK(put(w, rec, len) == 0);
}

// Whether the server answers the ClientHello with the alert in the clear,
// or with a ServerHello and then the alert under the key it installs.
static int alert_after_server_hello;

static int alert_client_recv(void *io, uint8_t *p, size_t n) {
    if (to_client.off == to_client.len && !served) {
        served = 1;
        sent_before_alert = to_server.len;
        if (!alert_after_server_hello) {
            put_alert(&to_client, NULL);
            return read_to_client(io, p, n);
        }
        client_hello ch;
        selection sel;
        memset(&ch, 0, sizeof ch);
        memset(&sel, 0, sizeof sel);
        srv_begin(&srv_h);
        int rc = srv_read_client_hello(&srv_h, &ch);
        if (rc == CH_OK) {
            rc = srv_select(&srv_h, &ch, &sel);
        }
        if (rc == CH_OK) {
            rc = srv_send_server_hello(&srv_h, &ch, &sel);
        }
        if (rc == CH_OK) {
            srv_store_selection(&srv_t, &ch, &sel);
            rc = srv_derive_handshake_secrets(&srv_h, &ch, &sel);
        }
        if (rc != CH_OK) {
            return -1;
        }
        put_alert(&to_client, srv_h.s_hs);
    }
    return read_to_client(io, p, n);
}

// ch_connect against a server that answers with the alert of n bytes.
static void client_reads_alert(int after_server_hello, const uint8_t *alert, size_t n) {
    memset(&to_server, 0, sizeof to_server);
    memset(&to_client, 0, sizeof to_client);
    ch_cfg scfg;
    server_config(&scfg, read_to_server);
    peer_state(&srv_t, &srv_h, &scfg);
    served = 0;
    peer_alert = alert;
    peer_alert_len = n;
    alert_after_server_hello = after_server_hello;
    ch_cfg ccfg;
    client_config(&ccfg, alert_client_recv);
    static ch_tls client;
    CHECK(ch_connect(&client, &ccfg) == CH_EPROTO);
    CHECK(client.state == CH_ST_FAILED && client.keys == 0);
    if (n == 2) {
        CHECK(ch_alert_received(&client) == alert[1] && ch_alert_sent(&client) == 0);
        CHECK(to_server.len == sent_before_alert);
        return;
    }
    // decode_error, in the clear before the client's keys and protected
    // after them.
    CHECK(ch_alert_received(&client) == 0 && ch_alert_sent(&client) == ALERT_DECODE_ERROR);
    size_t want = after_server_hello ? CH_ALERT_RECORD_LEN : REC_HDR + 2;
    CHECK(to_server.len - sent_before_alert == want);
}

// How the client answers the server's flight: 1 for the alert in the
// clear, as a client that could not use the ServerHello sends it, and 2
// for the alert under its handshake write key.
static int client_answer;

static int alert_server_recv(void *io, uint8_t *p, size_t n) {
    if (to_server.off == to_server.len && !answered) {
        answered = 1;
        sent_before_alert = to_client.len;
        if (client_answer == 1) {
            put_alert(&to_server, NULL);
            return read_to_server(io, p, n);
        }
        server_hello_info info;
        int rc = hsf_read_server_hello(&cli_h, &info);
        if (rc == CH_OK) {
            rc = hsf_accept_server_hello(&cli_h, &info);
        }
        if (rc == CH_OK) {
            rc = hsf_derive_handshake_secrets(&cli_h, &info);
        }
        if (rc != CH_OK) {
            return -1;
        }
        put_alert(&to_server, cli_h.c_hs);
    }
    return read_to_server(io, p, n);
}

// ch_srv_accept against a client that sends the alert of n bytes in place
// of its ClientHello (answer 0) or in answer to the flight (1 and 2).
static void server_reads_alert(int answer, const uint8_t *alert, size_t n) {
    memset(&to_server, 0, sizeof to_server);
    memset(&to_client, 0, sizeof to_client);
    peer_alert = alert;
    peer_alert_len = n;
    client_answer = answer;
    answered = answer == 0;
    sent_before_alert = 0;
    if (answer == 0) {
        put_alert(&to_server, NULL);
    } else {
        queue_client_hello(0);
    }
    ch_cfg scfg;
    server_config(&scfg, alert_server_recv);
    static ch_tls server;
    CHECK(ch_srv_accept(&server, &scfg) == CH_EPROTO);
    CHECK(server.state == CH_ST_FAILED && server.keys == 0);
    if (n == 2) {
        CHECK(ch_alert_received(&server) == alert[1] && ch_alert_sent(&server) == 0);
        CHECK(to_client.len == sent_before_alert);
        return;
    }
    CHECK(ch_alert_received(&server) == 0 && ch_alert_sent(&server) == ALERT_DECODE_ERROR);
    size_t want = answer == 0 ? REC_HDR + 2 : CH_ALERT_RECORD_LEN;
    CHECK(to_client.len - sent_before_alert == want);
}

static void test_handshake_alerts(void) {
    static const uint8_t alert[3] = {2, ALERT_HANDSHAKE_FAILURE, 0};
    for (size_t n = 2; n <= 3; n++) {
        client_reads_alert(0, alert, n);
        client_reads_alert(1, alert, n);
        server_reads_alert(0, alert, n);
        server_reads_alert(1, alert, n);
        server_reads_alert(2, alert, n);
    }
}

#endif
