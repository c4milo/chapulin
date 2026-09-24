// The TRUST=webpki half of test/quic_loop_test.c. Included by that file,
// whose helpers it reads.
//
// The ticket comes from srv_ticket_seal under the server's own ticket key,
// carrying a PSK chosen here, and the client presents it with the binding
// webpki_ticket.h computes over its hostname and anchors. That is the
// ticket on_ticket would have handed a TCP client after a full handshake,
// which this build cannot run for want of a chain with its private key.
// Everything after the ticket is real: ch_quic_init's rules, the resumed
// handshake with no Certificate, and the ticket the server issues at its
// end, whose binding shows ch_quic_init took the configuration hash.
#ifndef CH_TEST_QUIC_LOOP_WEBPKI_H
#define CH_TEST_QUIC_LOOP_WEBPKI_H

// One anchor. A resumed handshake walks no chain, so its bytes are never
// read; webpki_ticket.h hashes them into the binding all the same.
static const uint8_t anchor_name[3] = {0x30, 0x01, 0x00};
static const uint8_t anchor_spki[3] = {0x30, 0x01, 0x01};
static const ch_trust_anchor anchors[1] = {
    {anchor_name, sizeof anchor_name, anchor_spki, sizeof anchor_spki}
};
static const uint8_t host[14] = {'s', 'e', 'r', 'v', 'e', 'r', '.',
                                 'e', 'x', 'a', 'm', 'p', 'l', 'e'};
static const uint8_t other_host[5] = {'o', 't', 'h', 'e', 'r'};

// Mints the ticket a full handshake under hq-interop would have left,
// into kept, bound to cfg's hostname and anchors.
static void mint_ticket(const ch_cfg *cfg) {
    srv_ticket_contents c;
    memset(&c, 0, sizeof c);
    c.auth_seconds = LOOP_NOW;
    c.suite = SUITE_CHACHA20_POLY1305_SHA256;
    c.alpn_len = sizeof alpn_interop;
    memcpy(c.alpn, alpn_interop, sizeof alpn_interop);
    for (size_t i = 0; i < SHA256_LEN; i++) {
        c.psk[i] = (uint8_t)(0x20 + i);
    }
    static const uint8_t nonce[AEAD_NONCE] = {3};
    memset(&kept, 0, sizeof kept);
    CHECK(srv_ticket_seal(ticket_key, nonce, &c, kept.identity, sizeof kept.identity) ==
          SRV_TICKET_LEN);
    kept.identity_len = SRV_TICKET_LEN;
    memcpy(kept.psk, c.psk, SHA256_LEN);
    uint8_t config_hash[SHA256_LEN];
    webpki_ticket_config_hash(cfg, config_hash);
    webpki_ticket_binding(kept.psk, config_hash, kept.binding);
}

// The client configuration this build resumes with: anchors, a hostname
// and a clock, as a full handshake would need, and the kept ticket.
static void webpki_client(ch_cfg *cfg, const uint8_t *name, size_t name_len) {
    client_config(cfg, &server_alpn[0]);
    cfg->anchors = anchors;
    cfg->anchor_count = 1;
    cfg->hostname = name;
    cfg->hostname_len = name_len;
    cfg->now_seconds = LOOP_NOW;
}

static void test_webpki_resumption(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    static ch_quic probe;

    // A bound ticket resumes over QUIC: EncryptedExtensions and Finished
    // alone, and keys that agree.
    server_config(&scfg);
    webpki_client(&ccfg, host, sizeof host);
    mint_ticket(&ccfg);
    present_ticket(&ccfg);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(server.t.psk_selected == 1 && server.t.sigalg == 0);
    CHECK(handshake_messages() == 2);
    check_keys_agree();

    // The ticket the server issues at the end carries a binding to this
    // hostname and these anchors, which is only true if ch_quic_init took
    // the configuration hash; and that ticket resumes in turn.
    take_ticket();
    CHECK(kept.count == 1);
    uint8_t config_hash[SHA256_LEN];
    uint8_t want[SHA256_LEN];
    webpki_ticket_config_hash(&ccfg, config_hash);
    webpki_ticket_binding(kept.psk, config_hash, want);
    CHECK(memcmp(kept.binding, want, sizeof want) == 0);
    webpki_client(&ccfg, host, sizeof host);
    present_ticket(&ccfg);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(server.t.psk_selected == 1);

    // What ch_quic_init refuses, with CH_EINVAL and nothing sent: a binding
    // one bit off, the ticket under another hostname, a ticket with no
    // binding, and an external PSK, which has no hostname to bind.
    kept.binding[0] ^= 0x01;
    webpki_client(&ccfg, host, sizeof host);
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    kept.binding[0] ^= 0x01;
    webpki_client(&ccfg, other_host, sizeof other_host);
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    webpki_client(&ccfg, host, sizeof host);
    present_ticket(&ccfg);
    ccfg.ticket_binding = NULL;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    webpki_client(&ccfg, host, sizeof host);
    present_ticket(&ccfg);
    ccfg.resumption = 0;
    ccfg.ticket_binding = NULL;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    // And the configuration with no ticket at all still initializes.
    webpki_client(&ccfg, host, sizeof host);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_OK);
}

#endif
