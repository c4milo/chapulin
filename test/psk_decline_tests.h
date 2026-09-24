// hsf_accept_server_hello (handshake_flight.c) on a ServerHello that did
// not select the PSK this client offered, driven directly rather than
// through a server. One function serves every trust mode, and the mode
// decides what it expects: a raw or ca client fails closed with
// handshake_failure, because its hello offers the ticket alone, and a
// TRUST=webpki client goes on as a full handshake, with the early secret
// of no PSK in place of the PSK's (docs/decisions.md 55). Included by
// test/unit_test.c, which bin/unit, bin/unit_ca and bin/unit_pq build,
// and by test/webpki_resume_test.c. Include it after handshake_flight.h,
// keysched.h and the file's CHECK.
#ifndef CH_TEST_PSK_DECLINE_TESTS_H
#define CH_TEST_PSK_DECLINE_TESTS_H

// A session that offered psk as a resumption PSK, with the early secret
// and binder key hsf_begin derives from it, and a ServerHello whose one
// key share was accepted.
static ch_tls decline_session;

static void offer_psk(handshake_state *h, server_hello_info *info, const uint8_t psk[SHA256_LEN]) {
    memset(&decline_session, 0, sizeof decline_session);
    memset(h, 0, sizeof *h);
    memset(info, 0, sizeof *info);
    h->t = &decline_session;
    decline_session.cfg.psk = psk;
    decline_session.cfg.psk_len = SHA256_LEN;
    decline_session.cfg.resumption = 1;
    ks_early(SHA256_LEN, psk, SHA256_LEN, 1, h->early, h->binder_key);
    info->have_share = 1;
    info->group = CH_GROUP_X25519;
}

static void test_decline_handler(void) {
    static const uint8_t psk[SHA256_LEN] = {0x5a, 0xa5};
    static const uint8_t zero[SHA256_LEN] = {0};
    uint8_t psk_early[SHA256_LEN];
    uint8_t psk_binder_key[SHA256_LEN];
    uint8_t no_psk_early[SHA256_LEN];
    uint8_t unused[SHA256_LEN];
    ks_early(SHA256_LEN, psk, sizeof psk, 1, psk_early, psk_binder_key);
    ks_early(SHA256_LEN, zero, sizeof zero, 0, no_psk_early, unused);
    handshake_state h;
    server_hello_info info;

    // Selected: pre_shared_key naming identity 0. The PSK's early secret
    // stays, and the session reports the resumption.
    offer_psk(&h, &info, psk);
    info.psk_ok = 1;
    info.seen = HSP_SEEN_PRE_SHARED_KEY;
    CHECK(hsf_accept_server_hello(&h, &info) == CH_OK);
    CHECK(decline_session.psk_selected == 1);
    CHECK(memcmp(h.early, psk_early, SHA256_LEN) == 0);

    // Declined: no pre_shared_key at all.
    offer_psk(&h, &info, psk);
    int rc = hsf_accept_server_hello(&h, &info);
    CHECK(decline_session.psk_selected == 0);
#ifdef CH_TRUST_WEBPKI
    // The full handshake goes on from the early secret of no PSK, and
    // nothing the PSK derived is left behind.
    CHECK(rc == CH_OK);
    CHECK(memcmp(h.early, no_psk_early, SHA256_LEN) == 0);
    CHECK(memcmp(h.binder_key, zero, SHA256_LEN) == 0);
#else
    CHECK(rc == CH_EAUTH && h.alert == ALERT_HANDSHAKE_FAILURE);
#endif

    // An identity this client never offered: no decline. RFC 9846
    // §4.3.11 makes it illegal_parameter (rfc9846.txt:2551-2557), and a
    // raw or ca client answers it as it answers a decline.
    offer_psk(&h, &info, psk);
    info.seen = HSP_SEEN_PRE_SHARED_KEY;
    rc = hsf_accept_server_hello(&h, &info);
    CHECK(decline_session.psk_selected == 0);
#ifdef CH_TRUST_WEBPKI
    CHECK(rc == CH_EPROTO && h.alert == ALERT_ILLEGAL_PARAMETER);
#else
    CHECK(rc == CH_EAUTH && h.alert == ALERT_HANDSHAKE_FAILURE);
#endif

    // No PSK offered: a full handshake, and no resumption to report.
    offer_psk(&h, &info, psk);
    decline_session.cfg.psk = NULL;
    CHECK(hsf_accept_server_hello(&h, &info) == CH_OK);
    CHECK(decline_session.psk_selected == 0);
}

#endif
