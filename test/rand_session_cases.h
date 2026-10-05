// The checks a RAND=session build of each loop test runs over the
// sources test/rand_session.h hands out (docs/decisions.md 77, INV-4).
// The loop test defines, before it includes this header, what differs
// by transport:
//
//   run_seeded(client_seed, server_seed, out)
//       one handshake from fresh sessions whose sources start at the two
//       seeds, with every byte each side sent written into out; 1 when
//       both ends are connected
//   SESSION_CLIENT_DRAWS, SESSION_SERVER_DRAWS
//       the draws each side of that handshake makes
//   SESSION_SERVER_RANDOM_DRAW
//       which server draw is the ServerHello random
//   SESSION_RANDOM_OFF
//       where the random sits in the first message each side sends: 11
//       over TCP, after a record header, a handshake header and
//       legacy_version, and 6 over QUIC, which sends no record header
//
// and the CHECK macro every loop test has.
#ifndef CH_TEST_RAND_SESSION_CASES_H
#define CH_TEST_RAND_SESSION_CASES_H

#include "rand_session.h"
#include "rsa.h"
#include "rsa_sign.h"
#include "rsa_sign_key.h"
#include "srv.h"
#include "srv_auth.h"

// The random length both hellos carry (RFC 9846 §4.2.2 and §4.2.3,
// rfc9846.txt:1256 and 1358).
#define SESSION_RANDOM_LEN 32

// Every draw of one handshake went to the source its session's ch_cfg
// names, as many times as that side draws, and none to the hook or to no
// source. The client and the server are two sessions whose calls
// interleave, and neither drew from the other's source: the client's
// hello random is its own source's second draw, and the server's its own
// source's SESSION_SERVER_RANDOM_DRAW.
static void check_session_draws(void) {
    static crossed wire;
    stray_draws = 0;
    hook_draws = 0;
    CHECK(run_seeded(0x11, 0x22, &wire));
    CHECK(client_source.calls == SESSION_CLIENT_DRAWS);
    CHECK(server_source.calls == SESSION_SERVER_DRAWS);
    CHECK(stray_draws == 0 && hook_draws == 0);
    CHECK(wire.to_server_len >= SESSION_RANDOM_OFF + SESSION_RANDOM_LEN &&
          drawn_is(&client_source, 1, wire.to_server + SESSION_RANDOM_OFF, SESSION_RANDOM_LEN));
    CHECK(wire.to_client_len >= SESSION_RANDOM_OFF + SESSION_RANDOM_LEN &&
          drawn_is(&server_source, SESSION_SERVER_RANDOM_DRAW, wire.to_client + SESSION_RANDOM_OFF,
                   SESSION_RANDOM_LEN));
}

// Whether one direction of two crossings carried the same bytes.
static int same_direction(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
    return a_len == b_len && memcmp(a, b, a_len) == 0;
}

// Two handshakes from the same two seeds send the same bytes in both
// directions: the seeds are all a replay needs. A different seed on
// either side changes both directions. The client's changes its hello
// and every key the server derives from it, and the server's changes its
// random, so every key and the client's Finished with it.
static void check_session_replay(void) {
    static crossed first;
    static crossed again;
    static crossed other_client;
    static crossed other_server;
    CHECK(run_seeded(0x11, 0x22, &first));
    CHECK(run_seeded(0x11, 0x22, &again));
    CHECK(
        same_direction(first.to_server, first.to_server_len, again.to_server, again.to_server_len));
    CHECK(
        same_direction(first.to_client, first.to_client_len, again.to_client, again.to_client_len));
    CHECK(run_seeded(0x33, 0x22, &other_client));
    CHECK(!same_direction(first.to_server, first.to_server_len, other_client.to_server,
                          other_client.to_server_len));
    CHECK(!same_direction(first.to_client, first.to_client_len, other_client.to_client,
                          other_client.to_client_len));
    CHECK(run_seeded(0x11, 0x44, &other_server));
    CHECK(!same_direction(first.to_server, first.to_server_len, other_server.to_server,
                          other_server.to_server_len));
    CHECK(!same_direction(first.to_client, first.to_client_len, other_server.to_client,
                          other_server.to_client_len));
    CHECK(hook_draws == 0 && stray_draws == 0);
}

// A configuration holding one RSA-PSS identity, the 2048-bit key of
// test/rsa_sign_vectors.h behind a chain of one entry no line here
// parses, and no source.
static const uint8_t salt_cert_der[4] = {0x30, 0x02, 0x05, 0x00};
static const ch_cert salt_chain[1] = {
    {salt_cert_der, sizeof salt_cert_der}
};
static ch_rsa_priv salt_key;

static void rsa_identity_config(ch_cfg *cfg) {
    test_rsa_sign_key_2048(&salt_key);
    memset(cfg, 0, sizeof *cfg);
    cfg->srv.rsa_pss.chain = salt_chain;
    cfg->srv.rsa_pss.chain_count = 1;
    cfg->srv.rsa_pss.priv = &salt_key;
    cfg->srv.rsa_pss.priv_len = sizeof salt_key;
    cfg->srv.rsa_pss.pub = rsa_sign_2048_n;
    cfg->srv.rsa_pss.pub_len = sizeof rsa_sign_2048_n;
}

// An RSA-PSS server signature's salt is its session source's draw. The
// CertificateVerify signature srv_sign_certificate_verify returns is the
// one rsa_pss_sign computes over the 32 bytes the server's source handed
// out, and a second seed gives a second signature that verifies too. A
// salt from anywhere else signs over other bytes. ch_srv_check's boot
// signature draws its salt from the same source, and without a source
// ch_srv_check refuses before it signs.
static void check_pss_salt_from_source(void) {
    ch_cfg cfg;
    rsa_identity_config(&cfg);
    attach_source(&cfg, &server_source);
    uint8_t transcript_hash[SHA256_LEN];
    memset(transcript_hash, 0x33, sizeof transcript_hash);
    uint8_t digest[SHA256_LEN];
    srv_hash_signed_content(SIGALG_RSA_PSS_RSAE_SHA256, transcript_hash, sizeof transcript_hash,
                            digest);
    static uint8_t sigs[2][SRV_SIG_MAX];
    for (size_t k = 0; k < 2; k++) {
        seed_source(&server_source, 0x5a17 + k);
        hook_draws = 0;
        size_t sig_len = 0;
        uint8_t alert = 0;
        CHECK(srv_sign_certificate_verify(&cfg, SIGALG_RSA_PSS_RSAE_SHA256, transcript_hash,
                                          sizeof transcript_hash, sigs[k], sizeof sigs[k], &sig_len,
                                          &alert) == CH_OK);
        CHECK(sig_len == sizeof rsa_sign_2048_n);
        CHECK(server_source.calls == 1 && hook_draws == 0 && server_source.logged == 1);
        CHECK(server_source.draw_len[0] == RSA_PSS_SALT_LEN);
        uint8_t expected[SRV_SIG_MAX];
        size_t expected_len = 0;
        CHECK(rsa_pss_sign(&salt_key, digest, server_source.log, expected, sizeof expected,
                           &expected_len) == 1);
        CHECK(expected_len == sig_len && memcmp(expected, sigs[k], sig_len) == 0);
        CHECK(rsa_pss_verify(rsa_sign_2048_n, sizeof rsa_sign_2048_n, digest, sigs[k], sig_len) ==
              1);
    }
    CHECK(memcmp(sigs[0], sigs[1], sizeof rsa_sign_2048_n) != 0);

    seed_source(&server_source, 0x5a17);
    CHECK(ch_srv_check(&cfg) == CH_OK);
    CHECK(server_source.calls == 1 && hook_draws == 0);
    cfg.rand_bytes = NULL;
    seed_source(&server_source, 0x5a17);
    CHECK(ch_srv_check(&cfg) == CH_EINVAL);
    CHECK(server_source.calls == 0 && hook_draws == 0);
}

#endif
