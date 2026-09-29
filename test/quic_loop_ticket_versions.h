// The QUIC version a ticket belongs to, in both builds of
// test/quic_loop_test.c. RFC 9369 section 5 makes a ticket specific to the
// QUIC version of the connection that issued it, the negotiated one after
// compatible negotiation, and has a server pass over a ticket of another
// version for a full handshake (rfc9369.txt:268-284). The server records
// that version in each ticket, and the client records it in
// ch_ticket.quic_version and offers the ticket only in a connection that
// starts in it. Included by that file after quic_loop_close.h in the
// TRUST=raw-ecdsa build and after quic_loop_webpki.h in the TRUST=webpki
// one, whose clients and servers it reads.
#ifndef CH_TEST_QUIC_LOOP_TICKET_VERSIONS_H
#define CH_TEST_QUIC_LOOP_TICKET_VERSIONS_H

#ifdef CH_TRUST_WEBPKI
// This build's server, which signs with the r2 identity, and its client,
// which verifies the r2 chain. A resuming client presents the kept ticket
// beside that trust, so its hello offers the chain path too.
static void version_server(ch_cfg *cfg) {
    webpki_server(cfg, ticket_key);
}

static void version_client(ch_cfg *cfg) {
    webpki_client(cfg, webpki_corpus_anchors_root_p384, "s3.example.test");
}

static void version_resuming_client(ch_cfg *cfg) {
    version_client(cfg);
    present_ticket(cfg);
}
#else
// This build's server, and its client, which pins the server's P-256 key.
// A resuming client presents the kept ticket in place of the pin, so its
// hello offers the ticket alone.
static void version_server(ch_cfg *cfg) {
    server_config(cfg);
}

static void version_client(ch_cfg *cfg) {
    pinned_client_config(cfg, &server_alpn[0]);
}

static void version_resuming_client(ch_cfg *cfg) {
    client_config(cfg, &server_alpn[0]);
    present_ticket(cfg);
}
#endif

// The QUIC version the server sealed into the kept ticket, read by opening
// it under the server's ticket key, or 0xffffffff when it does not open.
static uint32_t kept_ticket_server_version(void) {
    srv_ticket_contents c;
    if (srv_ticket_open(ticket_key, kept.identity, kept.identity_len, &c) != CH_OK) {
        return 0xffffffffU;
    }
    return c.quic_version;
}

// A full handshake between this build's client and server, the server
// choosing version 2 when choose is set, and the one ticket the client
// took from it.
static void full_handshake_ticket(int choose) {
    ch_cfg scfg;
    ch_cfg ccfg;
    version_server(&scfg);
    scfg.srv.choose_version = choose ? choose_version_2 : NULL;
    version_client(&ccfg);
    memset(&kept, 0, sizeof kept);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 0 && server.t.psk_selected == 0);
    take_ticket();
    CHECK(kept.count == 1);
}

// What ch_quic_init refuses before it sends a byte: the kept ticket in a
// connection that starts in the other version, and the ticket presented
// without its version. In its own version it is taken.
static void check_client_refuses_other_version(uint32_t ticket_version) {
    static ch_quic probe;
    uint32_t other = ticket_version == CH_QUIC_VERSION_1 ? CH_QUIC_VERSION_2 : CH_QUIC_VERSION_1;
    ch_cfg ccfg;
    version_resuming_client(&ccfg);
    CHECK(ccfg.ticket_quic_version == ticket_version);
    ccfg.quic_original_version = ticket_version;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_OK);
    ch_quic_close(&probe);
    ccfg.quic_original_version = other;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL && ch_quic_state(&probe) == CH_ST_FAILED);
    ccfg.quic_original_version = ticket_version;
    ccfg.ticket_quic_version = 0;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
}

static void test_ticket_versions(void) {
    ch_cfg scfg;
    ch_cfg ccfg;

    // A version 1 client and a server that chooses version 2: the ticket
    // belongs to version 2 at both ends (rfc9369.txt:283-284).
    full_handshake_ticket(1);
    CHECK(kept.quic_version == CH_QUIC_VERSION_2);
    CHECK(kept_ticket_server_version() == CH_QUIC_VERSION_2);
    check_client_refuses_other_version(CH_QUIC_VERSION_2);

    // It resumes a connection that starts in version 2, whose server keeps
    // its original version, and the resumed handshake's own ticket belongs
    // to version 2 too.
    version_server(&scfg);
    scfg.quic_original_version = CH_QUIC_VERSION_2;
    version_resuming_client(&ccfg);
    ccfg.quic_original_version = CH_QUIC_VERSION_2;
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 1 && server.t.psk_selected == 1 && handshake_messages() == 2);
    check_keys_agree_in(CH_QUIC_VERSION_2);
    take_ticket();
    CHECK(kept.count == 2 && kept.quic_version == CH_QUIC_VERSION_2);

    // A connection that stays in version 1 ends with a version 1 ticket.
    full_handshake_ticket(0);
    CHECK(kept.quic_version == CH_QUIC_VERSION_1);
    CHECK(kept_ticket_server_version() == CH_QUIC_VERSION_1);
    check_client_refuses_other_version(CH_QUIC_VERSION_1);

    // The client offers it in a version 1 connection, and the server
    // chooses version 2 before it selects a ticket, so it passes this one
    // over (rfc9369.txt:276-281).
    version_server(&scfg);
    scfg.srv.choose_version = choose_version_2;
    version_resuming_client(&ccfg);
#ifdef CH_TRUST_WEBPKI
    // The webpki hello offered the chain path beside the ticket, so the
    // same connection completes as a full handshake that walks the chain,
    // in version 2 (docs/decisions.md 55).
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 0 && server.t.psk_selected == 0 && handshake_messages() == 4);
    check_keys_agree_in(CH_QUIC_VERSION_2);
#else
    // A raw hello offered the ticket alone, so nothing is left to
    // authenticate the server with, and the handshake fails closed.
    CHECK(!run_quic(&ccfg, &scfg));
    CHECK(ch_quic_state(&server) == CH_ST_FAILED);
    CHECK(ch_quic_alert(&server) == ALERT_MISSING_EXTENSION);
#endif

    // The same ticket still resumes when the server keeps version 1.
    version_server(&scfg);
    version_resuming_client(&ccfg);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 1 && server.t.psk_selected == 1);
    check_keys_agree_in(CH_QUIC_VERSION_1);
}

#endif
