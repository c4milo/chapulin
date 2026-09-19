// Every function of the ROLE=server mode is a stub today, and this binary holds the two
// rules that make a stubbed role safe to link: no call reports success, and no call writes
// through an out-parameter.
//
// Why it exists. The Makefile's ROLE axis packages these sources into an object a caller
// can link before one line of the role is implemented. A stub that answered CH_OK would
// hand that caller a session no handshake ever brought up. So each stub returns the
// refusal its header documents, and this binary calls every one of them and requires it.
// docs/server.md, "Stubs first", states the rules; it is the same shape
// test/quic_stub_test.c already runs for the other axis.
//
// Every buffer and every struct below is filled with POISON before the call and compared
// against POISON after it, so "writes nothing" is measured rather than assumed. A function
// leaves this file when it is implemented, in the commit that implements it.
//
// One definition here is not a stub, so this file checks its value instead of its refusal:
// srv_hrr_random holds the 32 bytes RFC 9846 §4.1.3 fixes for a HelloRetryRequest, and the
// vector below is a second transcription of them.
#include <stdio.h>
#include <string.h>

#include "srv.h"
#include "srv_flight.h"
#include "srv_handshake.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// The byte no stub may replace. 0xa5 is neither 0 nor 0xff, so a wipe and a fill both show.
#define POISON 0xa5

// One scratch buffer, larger than any message these calls are handed.
#define SCRATCH 256

// True when every byte of p is still POISON.
static int untouched(const void *p, size_t n) {
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) {
        if (b[i] != POISON) {
            return 0;
        }
    }
    return 1;
}

// The out-parameters most calls share, refilled before each call.
static uint8_t out[SCRATCH];
static size_t out_len;

static void fill_out(void) {
    memset(out, POISON, sizeof out);
    memset(&out_len, POISON, sizeof out_len);
}

static int out_untouched(void) {
    return untouched(out, sizeof out) && untouched(&out_len, sizeof out_len);
}

// The session and the handshake state, out of the frame because a ch_tls is over a
// kilobyte. Both are refilled before every call that takes one.
static ch_tls session;
static handshake_state hs;
static ch_cfg cfg;

static void fill_state(void) {
    memset(&session, POISON, sizeof session);
    memset(&hs, POISON, sizeof hs);
}

static int state_untouched(void) {
    return untouched(&session, sizeof session) && untouched(&hs, sizeof hs);
}

static void test_hrr_random(void) {
    static const uint8_t want[SRV_RANDOM] = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
                                             0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                             0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
                                             0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    CHECK(memcmp(srv_hrr_random, want, sizeof want) == 0);
}

static void test_parser(void) {
    client_hello ch;
    uint8_t alert;
    uint8_t body[SCRATCH];

    memset(body, POISON, sizeof body);
    CHECK(srv_ext_known(EXT_SUPPORTED_VERSIONS) == 0);
    CHECK(srv_ext_known(0x0a0a) == 0);
    CHECK(srv_ext_duplicate(body, sizeof body) == 0);

    memset(&ch, POISON, sizeof ch);
    memset(&alert, POISON, sizeof alert);
    CHECK(srv_parse_client_hello(body, sizeof body, &ch, NULL, 0, &alert) == CH_EPROTO);
    CHECK(untouched(&ch, sizeof ch) && untouched(&alert, sizeof alert));
}

static void test_message_builders(void) {
    selection sel;
    uint8_t rnd[SRV_RANDOM];
    uint8_t id[SRV_SESSION_ID_MAX];
    uint8_t share[SCRATCH / 4];

    memset(&sel, POISON, sizeof sel);
    memset(rnd, POISON, sizeof rnd);
    memset(id, POISON, sizeof id);
    memset(share, POISON, sizeof share);

    fill_out();
    CHECK(srv_build_server_hello(out, sizeof out, &sel, rnd, id, sizeof id, share, sizeof share) ==
          0);
    CHECK(untouched(out, sizeof out));

    fill_out();
    CHECK(srv_build_hello_retry_request(out, sizeof out, &sel, id, sizeof id, share,
                                        sizeof share) == 0);
    CHECK(untouched(out, sizeof out));

    fill_out();
    CHECK(srv_build_compat_ccs(out, sizeof out) == 0);
    CHECK(untouched(out, sizeof out));

    fill_out();
    CHECK(srv_build_encrypted_extensions(out, sizeof out, 512, NULL) == 0);
    CHECK(untouched(out, sizeof out));

    fill_out();
    CHECK(srv_build_certificate_verify(out, sizeof out, SIGALG_ECDSA_P256_SHA256, share,
                                       sizeof share) == 0);
    CHECK(untouched(out, sizeof out));

    fill_out();
    CHECK(srv_build_finished(out, sizeof out, share, SHA256_LEN) == 0);
    CHECK(untouched(out, sizeof out));

    fill_out();
    CHECK(srv_build_key_update(out, sizeof out, 0) == 0);
    CHECK(untouched(out, sizeof out));
}

static void test_certificate_framing(void) {
    ch_cert cert = {NULL, 0};
    ch_identity id = {&cert, 1, NULL, 0, NULL, 0};

    CHECK(srv_certificate_message_len(&id) == 0);

    fill_out();
    CHECK(srv_build_certificate_header(out, sizeof out, &id) == 0);
    CHECK(untouched(out, sizeof out));

    fill_out();
    CHECK(srv_build_certificate_entry_prefix(out, sizeof out, 7) == 0);
    CHECK(untouched(out, sizeof out));

    fill_out();
    CHECK(srv_build_certificate_entry_suffix(out, sizeof out) == 0);
    CHECK(untouched(out, sizeof out));
}

static void test_cookie(void) {
    uint8_t key[SRV_COOKIE_KEY_LEN];
    uint8_t ch1_hash[SRV_COOKIE_HASH_MAX];
    uint8_t frozen[SHA256_LEN];
    uint16_t suite;
    uint16_t group;
    size_t hash_len;

    memset(key, POISON, sizeof key);
    memset(ch1_hash, POISON, sizeof ch1_hash);
    memset(frozen, POISON, sizeof frozen);

    fill_out();
    CHECK(srv_cookie_mint(key, SUITE_CHACHA20_POLY1305_SHA256, CH_KEX_GROUP, ch1_hash, SHA256_LEN,
                          frozen, out, sizeof out) == 0);
    CHECK(untouched(out, sizeof out));

    memset(&suite, POISON, sizeof suite);
    memset(&group, POISON, sizeof group);
    memset(&hash_len, POISON, sizeof hash_len);
    CHECK(srv_cookie_open(key, out, sizeof out, &suite, &group, ch1_hash, &hash_len, frozen) ==
          CH_EPROTO);
    CHECK(untouched(&suite, sizeof suite) && untouched(&group, sizeof group) &&
          untouched(&hash_len, sizeof hash_len));
    CHECK(untouched(ch1_hash, sizeof ch1_hash) && untouched(frozen, sizeof frozen));
}

static void test_auth(void) {
    uint8_t transcript[SHA256_LEN];
    uint8_t digest[SHA256_LEN];
    uint8_t alert;

    memset(&cfg, POISON, sizeof cfg);
    memset(transcript, POISON, sizeof transcript);

    CHECK(srv_identity_live(&cfg) == 0);
    CHECK(srv_identity_for(&cfg, SIGALG_ECDSA_P256_SHA256) == NULL);
    CHECK(srv_identity_for(&cfg, SIGALG_RSA_PSS_RSAE_SHA256) == NULL);
    CHECK(srv_identity_for(&cfg, SIGALG_RSA_PKCS1_SHA256) == NULL);

    memset(digest, POISON, sizeof digest);
    srv_hash_signed_content(SIGALG_ECDSA_P256_SHA256, transcript, SHA256_LEN, digest);
    CHECK(untouched(digest, sizeof digest));

    fill_out();
    memset(&alert, POISON, sizeof alert);
    CHECK(srv_sign_certificate_verify(&cfg, SIGALG_ECDSA_P256_SHA256, transcript, SHA256_LEN, out,
                                      sizeof out, &out_len, &alert) == CH_EINVAL);
    CHECK(out_untouched() && untouched(&alert, sizeof alert));

    CHECK(srv_identity_check(&cfg, SIGALG_ECDSA_P256_SHA256) == CH_EINVAL);
    CHECK(srv_identity_check(&cfg, SIGALG_RSA_PSS_RSAE_SHA256) == CH_EINVAL);
}

static void test_flight(void) {
    client_hello ch;
    selection sel;

    memset(&ch, POISON, sizeof ch);
    memset(&sel, POISON, sizeof sel);

    fill_state();
    srv_begin(&hs);
    CHECK(state_untouched());

    fill_state();
    CHECK(srv_read_client_hello(&hs, &ch) == CH_EPROTO);
    CHECK(state_untouched() && untouched(&ch, sizeof ch));

    fill_state();
    CHECK(srv_select(&hs, &ch, &sel) == CH_EPROTO);
    CHECK(state_untouched() && untouched(&sel, sizeof sel));

    fill_state();
    CHECK(srv_send_hello_retry_request(&hs, &ch, &sel) == CH_EPROTO);
    CHECK(srv_send_compat_ccs(&hs, &ch) == CH_EPROTO);
    CHECK(srv_check_retry_hello(&hs, &ch, &sel) == CH_EPROTO);
    CHECK(srv_send_server_hello(&hs, &ch, &sel) == CH_EPROTO);
    CHECK(srv_derive_handshake_secrets(&hs, &ch, &sel) == CH_EPROTO);
    CHECK(state_untouched() && untouched(&sel, sizeof sel) && untouched(&ch, sizeof ch));

    fill_state();
    CHECK(srv_send_encrypted_extensions(&hs, &sel) == CH_EPROTO);
    CHECK(srv_send_certificate(&hs, &sel) == CH_EPROTO);
    CHECK(srv_send_certificate_verify(&hs, &sel) == CH_EPROTO);
    CHECK(srv_send_finished(&hs) == CH_EPROTO);
    CHECK(srv_read_client_finished(&hs) == CH_EPROTO);
    srv_complete(&hs);
    CHECK(state_untouched() && untouched(&sel, sizeof sel));
}

static void test_public_entries(void) {
    fill_state();
    CHECK(srv_handshake(&session) == CH_EPROTO);
    CHECK(state_untouched());

    memset(&cfg, POISON, sizeof cfg);
    fill_state();
    CHECK(ch_srv_accept(&session, &cfg) == CH_EINVAL);
    CHECK(state_untouched() && untouched(&cfg, sizeof cfg));

    CHECK(ch_srv_check(&cfg) == CH_EINVAL);
    CHECK(untouched(&cfg, sizeof cfg));
}

int main(void) {
    test_hrr_random();
    test_parser();
    test_message_builders();
    test_certificate_framing();
    test_cookie();
    test_auth();
    test_flight();
    test_public_entries();
    if (failures == 0) {
        (void)printf("srv_stub: every stub refuses and writes nothing\n");
    }
    return failures != 0;
}
