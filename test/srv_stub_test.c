// The ROLE=server functions that are still stubs, and the two rules that make a stubbed
// role safe to link: no call reports success, and no call writes through an out-parameter.
//
// Why it exists. The Makefile's ROLE axis packages these sources into an object a caller
// can link before one line of the role is implemented. A stub that answered CH_OK would
// hand that caller a session no handshake ever brought up. So each stub returns the
// refusal its header documents, and this binary calls every one of them and requires it.
// docs/server.md, "Stubs first", states the rules; it is the shape
// test/quic_stub_test.c ran for the TRANSPORT=quic axis until that mode was implemented.
//
// Every buffer and every struct below is filled with POISON before the call and compared
// against POISON after it, so "writes nothing" is measured rather than assumed. A function
// leaves this file when it is implemented, in the commit that implements it.
//
// Some definitions here are not stubs, so this file checks what they answer instead of
// their refusal. srv_hrr_random holds the 32 bytes RFC 9846 §4.1.3 fixes for a
// HelloRetryRequest, and the vector below is a second transcription of them. srv_auth.c is
// implemented, so test_signed_content pins the CertificateVerify signed content of §4.4.3
// and test_identity pins the slot predicates; its two signers are still absent, so the two
// calls that need one still refuse and this file requires that too.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "srv.h"
#include "srv_flight.h"
#include "srv_handshake.h"

// hkdf.c and srv_auth.c seed CH_ASSERT at their contract points, and srv_cookie.c and
// srv_auth.c call them now that both are implemented, so this binary links the handler
// every other test main defines.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

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

// The session and the handshake state, out of the frame because a ch_tls is over a
// kilobyte. Both are refilled before every call that takes one.
static ch_tls session;
static handshake_state hs;

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

// srv_hash_signed_content is implemented, so this checks its value too.
// The two vectors pin the exact bytes RFC 9846 §4.4.3 puts in front of
// the transcript hash: 64 bytes of 0x20, the context string "TLS 1.3,
// server CertificateVerify", and one 0x00 separator. A wrong pad
// length, a wrong context string or a missing separator moves the
// digest. The transcript hash is 0x00 up, and the two lengths are the
// ends of the range srv_auth.h admits: SHA256_LEN, which is what this
// build's one cipher suite gives, and SRV_COOKIE_HASH_MAX, which is the
// longest any suite in §9.1 gives. The expected digests come from
// hashing those two 130-byte and 146-byte strings outside this tree.
static void test_signed_content(void) {
    static const uint8_t want32[SHA256_LEN] = {0xff, 0xf8, 0xad, 0x38, 0x56, 0x4d, 0xc7, 0x41,
                                               0x84, 0x29, 0x17, 0x0b, 0x33, 0xd8, 0x50, 0xb8,
                                               0xd3, 0xef, 0x09, 0xa7, 0x2f, 0x89, 0x4e, 0xb1,
                                               0x9d, 0x19, 0x07, 0x17, 0x6d, 0x29, 0x0c, 0xdf};
    static const uint8_t want48[SHA256_LEN] = {0xca, 0xf6, 0x84, 0xa5, 0xd6, 0x70, 0xdb, 0x29,
                                               0x1b, 0x7a, 0x85, 0xa7, 0xb6, 0x2f, 0x0b, 0x97,
                                               0x4c, 0xae, 0x6f, 0xd8, 0x0f, 0xa7, 0xcc, 0xa7,
                                               0x3a, 0x91, 0xf1, 0x9e, 0xa9, 0xe3, 0x42, 0x3e};
    uint8_t transcript[SRV_COOKIE_HASH_MAX];
    uint8_t digest[SHA256_LEN];

    for (size_t i = 0; i < sizeof transcript; i++) {
        transcript[i] = (uint8_t)i;
    }

    // Both schemes name SHA-256 over the content, so both reach the
    // same digest for one transcript.
    srv_hash_signed_content(SIGALG_ECDSA_P256_SHA256, transcript, SHA256_LEN, digest);
    CHECK(memcmp(digest, want32, sizeof want32) == 0);

    memset(digest, POISON, sizeof digest);
    srv_hash_signed_content(SIGALG_RSA_PSS_RSAE_SHA256, transcript, SHA256_LEN, digest);
    CHECK(memcmp(digest, want32, sizeof want32) == 0);

    memset(digest, POISON, sizeof digest);
    srv_hash_signed_content(SIGALG_ECDSA_P256_SHA256, transcript, SRV_COOKIE_HASH_MAX, digest);
    CHECK(memcmp(digest, want48, sizeof want48) == 0);
}

// The identity predicates over a configuration the caller filled in.
// srv_identity_live and srv_identity_for are implemented, so this checks
// what they answer; srv_sign_certificate_verify and srv_identity_check
// still refuse, because the two signers srv_auth.h names are not in this
// tree.
static void test_identity(void) {
    static const uint8_t key[SHA256_LEN] = {0};
    static const ch_cert chain[1] = {
        {key, sizeof key}
    };
    ch_cfg live;
    uint8_t sig[SRV_SIG_MAX];
    size_t sig_len;
    uint8_t alert;
    uint8_t transcript[SHA256_LEN];

    memset(&live, 0, sizeof live);
    CHECK(srv_identity_live(&live) == 0);
    CHECK(srv_identity_for(&live, SIGALG_ECDSA_P256_SHA256) == NULL);

    live.srv.rsa_pss.chain = chain;
    live.srv.rsa_pss.chain_count = 1;
    live.srv.rsa_pss.priv = key;
    live.srv.rsa_pss.priv_len = sizeof key;
    live.srv.rsa_pss.pub = key;
    live.srv.rsa_pss.pub_len = sizeof key;

    CHECK(srv_identity_live(&live) == SRV_IDENTITY_RSA_PSS);
    CHECK(srv_identity_for(&live, SIGALG_RSA_PSS_RSAE_SHA256) == &live.srv.rsa_pss);
    CHECK(srv_identity_for(&live, SIGALG_ECDSA_P256_SHA256) == NULL);
    // RFC 9846 §4.3.3 leaves the PKCS#1 v1.5 code points undefined for
    // signed handshake messages, so no slot answers for them.
    CHECK(srv_identity_for(&live, SIGALG_RSA_PKCS1_SHA256) == NULL);

    // A chain_count of 0 unprovisions the slot whatever the keys hold.
    live.srv.rsa_pss.chain_count = 0;
    CHECK(srv_identity_live(&live) == 0);
    CHECK(srv_identity_for(&live, SIGALG_RSA_PSS_RSAE_SHA256) == NULL);
    live.srv.rsa_pss.chain_count = 1;

    memset(transcript, 0, sizeof transcript);
    memset(sig, POISON, sizeof sig);
    sig_len = POISON;
    alert = 0;
    // The signer is absent, so a provisioned slot gets the local fault
    // srv_auth.h documents rather than a signature. That path clears the
    // staging buffer and reports a zero length.
    CHECK(srv_sign_certificate_verify(&live, SIGALG_RSA_PSS_RSAE_SHA256, transcript, SHA256_LEN,
                                      sig, sizeof sig, &sig_len, &alert) == CH_EINVAL);
    CHECK(alert == ALERT_INTERNAL_ERROR);
    CHECK(sig_len == 0);
    int cleared = 1;
    for (size_t i = 0; i < sizeof sig; i++) {
        cleared = cleared && sig[i] == 0;
    }
    CHECK(cleared);

    // A cap below the longest signature the scheme can produce is
    // refused before any signing is attempted, and that refusal writes
    // neither output.
    memset(sig, POISON, sizeof sig);
    memset(&sig_len, POISON, sizeof sig_len);
    alert = 0;
    CHECK(srv_sign_certificate_verify(&live, SIGALG_RSA_PSS_RSAE_SHA256, transcript, SHA256_LEN,
                                      sig, sizeof sig - 1, &sig_len, &alert) == CH_ECAP);
    CHECK(alert == ALERT_INTERNAL_ERROR);
    CHECK(untouched(sig, sizeof sig) && untouched(&sig_len, sizeof sig_len));

    CHECK(srv_identity_check(&live, SIGALG_RSA_PSS_RSAE_SHA256) == CH_EINVAL);
    CHECK(srv_identity_check(&live, SIGALG_ECDSA_P256_SHA256) == CH_EINVAL);
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

int main(void) {
    test_hrr_random();
    test_signed_content();
    test_identity();
    test_parser();
    test_flight();
    if (failures == 0) {
        (void)printf("srv_stub: every stub refuses and writes nothing\n");
    }
    return failures != 0;
}
