// The TRUST=raw-ecdsa half of test/quic_loop_test.c: a full handshake
// against a pinned P-256 key, the ticket at the 1-RTT level, and the
// resumed handshake with no Certificate. Included by that file, whose
// helpers it reads.
#ifndef CH_TEST_QUIC_LOOP_RAW_H
#define CH_TEST_QUIC_LOOP_RAW_H

static void test_raw_resumption(void) {
    ch_cfg scfg;
    ch_cfg ccfg;

    // The full handshake: the client pins the server's key, and the server
    // sends EncryptedExtensions, Certificate, CertificateVerify and
    // Finished, then one ticket at the 1-RTT level.
    server_config(&scfg);
    client_config(&ccfg, &server_alpn[0]);
    ccfg.server_pubkey = p256_sign_vectors[0].pub;
    ccfg.server_pubkey_len = sizeof p256_sign_vectors[0].pub;
    memset(&kept, 0, sizeof kept);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(server.t.psk_selected == 0 && server.t.sigalg == SIGALG_ECDSA_P256_SHA256);
    CHECK(handshake_messages() == 4);
    // The client offers x25519 alone, so the server, which holds both
    // groups, selects x25519, and both ends report it.
    CHECK(server.t.group == CH_GROUP_X25519 && client.t.group == CH_GROUP_X25519);
    take_ticket();
    CHECK(kept.count == 1 && kept.lifetime_s == SRV_TICKET_LIFETIME);
    CHECK(kept.identity_len == SRV_TICKET_LEN);
    check_keys_agree();

    // The resumed handshake: the client presents the ticket and pins
    // nothing, the server sends EncryptedExtensions and Finished alone, and
    // a fresh ticket follows.
    client_config(&ccfg, &server_alpn[0]);
    present_ticket(&ccfg);
    scfg.srv.now_seconds = LOOP_NOW + 30;
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(server.t.psk_selected == 1 && server.t.sigalg == 0);
    CHECK(handshake_messages() == 2);
    CHECK(server.t.group == CH_GROUP_X25519 && client.t.group == CH_GROUP_X25519);
    check_keys_agree();
    take_ticket();
    CHECK(kept.count == 2 && kept.lifetime_s == SRV_TICKET_LIFETIME - 30);

    // The ticket was issued under hq-interop. A connection that selects h3
    // does not resume it: the server passes the ticket over, and a client
    // that offered no signature scheme gets missing_extension.
    client_config(&ccfg, &server_alpn[1]);
    present_ticket(&ccfg);
    CHECK(!run_quic(&ccfg, &scfg));
    CHECK(ch_quic_state(&server) == CH_ST_FAILED);
    CHECK(ch_quic_alert(&server) == ALERT_MISSING_EXTENSION);

    // No clock: the full handshake completes and no ticket follows.
    scfg.srv.now_seconds = 0;
    client_config(&ccfg, &server_alpn[0]);
    ccfg.server_pubkey = p256_sign_vectors[0].pub;
    ccfg.server_pubkey_len = sizeof p256_sign_vectors[0].pub;
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(from_server.len[CH_LEVEL_APPLICATION] == 0);
}

#endif
