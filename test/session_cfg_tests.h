// ch_connect's config validation: the auth-mode, pin-length, buffer-size
// and revocation-epoch checks, all decided before the handshake sends a
// byte. Included by session_tests.h after the mock helpers exist; not a
// standalone translation unit.
#ifndef CH_SESSION_CFG_TESTS_H
#define CH_SESSION_CFG_TESTS_H

#include "hello_exts.h"

// ch_connect's config validation: exactly one auth mode, sane buffer. A
// case that passes validation reaches I/O and dies there (empty queue
// gives CH_EIO), which distinguishes it from a rejected config (CH_EINVAL).
// The pin size the compiled build accepts: a P-256 point or an RSA-3072
// modulus. Boundary checks below use it plus each mode's exact limits.
#ifdef CH_PIN_ECDSA
#define TEST_PIN_LEN 64
#else
#define TEST_PIN_LEN 384
#endif

// The revocation epoch's config checks (docs/ca.md), all of which
// must decide before the handshake sends a byte. mock_recv failing
// the connect with CH_EIO marks the cases that got past them.
static uint32_t epoch_mark;
static int epoch_load_rc;
static int epoch_stores;

static int test_epoch_load(void *io, uint32_t *value) {
    (void)io;
    *value = epoch_mark;
    return epoch_load_rc;
}

static int test_epoch_store(void *io, uint32_t value) {
    (void)io;
    (void)value;
    epoch_stores++;
    return 0;
}

static void test_epoch_cfg(void) {
    static uint8_t rxbuf[CH_MIN_RXBUF + 88];
    uint8_t pin[TEST_PIN_LEN] = {2};
    pin[TEST_PIN_LEN - 1] = 1;
    mock_io m = {0};
    ch_cfg cfg = {0};
    ch_tls t;
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &m;
    cfg.server_pubkey = pin;
    cfg.server_pubkey_len = sizeof pin;

    epoch_mark = 0;
    epoch_load_rc = 0;
    epoch_stores = 0;

    // One callback alone is a provisioning mistake either way round.
    cfg.epoch_load = test_epoch_load;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    cfg.epoch_load = NULL;
    cfg.epoch_store = test_epoch_store;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    cfg.epoch_load = test_epoch_load;

#ifdef CH_TRUST_CA
    // The pair configured: storage that answers in range lets
    // the connect through to I/O, and the session holds the epoch.
    epoch_mark = 12;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    CHECK(t.epoch == 12);
    CHECK(t.epoch_store_failed == 0);
    CHECK(epoch_stores == 0); // only an authenticated handshake writes
    // No certificate was judged, so the caller is told nothing.
    CHECK(t.epoch_status == CH_EPOCH_NONE);
    CHECK(t.epoch_seen == 0);

    // The last in-range value passes; the first one past it does not.
    epoch_mark = CH_EPOCH_MAX;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    epoch_mark = CH_EPOCH_MAX + 1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    epoch_mark = 0xffffffff; // an erased flash word
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);

    // Storage that cannot answer fails closed.
    epoch_mark = 3;
    epoch_load_rc = -1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    epoch_load_rc = 0;

    // Resumption carries no certificate, so the ticket's own epoch is
    // the only revocation check left: a ticket below the stored epoch
    // was retired by the bump that raised it, and one at or above it
    // still resumes.
    static uint8_t psk[32] = {1};
    cfg.server_pubkey = NULL;
    cfg.server_pubkey_len = 0;
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = (const uint8_t *)"d";
    cfg.psk_id_len = 1;
    cfg.resumption = 1;
    epoch_mark = 10;
    cfg.ticket_epoch = 9;
    CHECK(ch_connect(&t, &cfg) == CH_EAUTH);
    // The caller sees the verdict on the failing path too.
    CHECK(t.epoch_status == CH_EPOCH_REVOKED);
    CHECK(t.epoch_seen == 9);
    cfg.ticket_epoch = 10;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    CHECK(t.epoch_status == CH_EPOCH_MATCHED);
    // A ticket above the stored epoch says that epoch went backwards.
    cfg.ticket_epoch = 11;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    CHECK(t.epoch_status == CH_EPOCH_AHEAD);
    cfg.ticket_epoch = CH_EPOCH_MAX + 1; // corrupt ticket storage
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);

    // A fresh external PSK carries no ticket epoch to screen.
    cfg.resumption = 0;
    cfg.ticket_epoch = 0;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
#else
    // Without CA mode there is no epoch to enforce, so a config that
    // asks for one is refused rather than quietly ignored.
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
#endif
}

// The ClientHello staging boundary
// (https://github.com/c4milo/chapulin/issues/46). CH_TX_STAGE must hold the
// largest hello this build can emit, and CH_HELLO_MAX is that size, so the
// pair below is exact: at CH_HELLO_MAX the worst reachable hello — a
// resumption carrying a CH_TICKET_ID_MAX identity that then answers a
// HelloRetryRequest with an HSP_COOKIE_MAX cookie — is built whole, and one
// byte less refuses. Before the classic build covered its own hello this
// second case was what a device met mid-handshake, as CH_ECAP.
static void test_hello_staging_boundary(void) {
    static uint8_t out[CH_HELLO_MAX];
    static uint8_t identity[CH_TICKET_ID_MAX];
    static uint8_t cookie[HSP_COOKIE_MAX];
    uint8_t pub[32] = {0};
    uint8_t random32[32] = {0};
#ifdef CH_KEX_PQ
    static uint8_t ek[MLKEM_EK_LEN];
#endif
    ch_cfg cfg = {0};
    cfg.psk = identity; // any non-NULL selects the PSK arm
    cfg.psk_id = identity;
    cfg.psk_id_len = sizeof identity;
    cfg.resumption = 1;
    cfg.obfuscated_age = 0xffffffffU;

#ifdef CH_KEX_PQ
#define BUILD_HELLO(cap)                                                                           \
    hs_build_client_hello(out, (cap), &cfg, ek, pub, random32, 0xffff, cookie, sizeof cookie)
#else
#define BUILD_HELLO(cap)                                                                           \
    hs_build_client_hello(out, (cap), &cfg, pub, random32, 0xffff, cookie, sizeof cookie)
#endif
    // The last valid capacity builds it, and fills the array exactly:
    // CH_HELLO_MAX is the size of the worst hello, not an over-estimate.
    CHECK(BUILD_HELLO(CH_HELLO_MAX) == CH_HELLO_MAX);
    // One byte less refuses rather than truncating.
    CHECK(BUILD_HELLO(CH_HELLO_MAX - 1) == 0);
#undef BUILD_HELLO

    // The staging array is sized from that bound, so a session can
    // always hold what the builder can emit. Pin the per-build numbers
    // too, so a constant regression fails here, not a live handshake.
    CHECK(CH_TX_STAGE >= CH_HELLO_MAX);
#ifdef CH_KEX_PQ
    CHECK(CH_HELLO_MAX == 1801);
#else
    CHECK(CH_HELLO_MAX == 617);
#endif
}

static void test_connect_cfg(void) {
    // Sized to the compiled build's floor plus slack: 512 in classic
    // raw-pin builds, the ServerHello-derived floor in hybrid builds,
    // the certificate-derived floor in CA builds (cfg.h). The floor
    // boundary pair below therefore runs against whichever floor this
    // build derives.
    static uint8_t rxbuf[CH_MIN_RXBUF + 88];
    uint8_t psk[32] = {1};
    uint8_t pin[TEST_PIN_LEN] = {2};
    pin[TEST_PIN_LEN - 1] = 1; // a real RSA modulus is odd
    uint8_t pin2[TEST_PIN_LEN] = {4};
    pin2[TEST_PIN_LEN - 1] = 3; // slot B must be odd too
    mock_io m = {0};
    ch_cfg cfg = {0};
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &m;
    ch_tls t;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // no auth mode at all
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // psk without identity
    cfg.psk_id = (const uint8_t *)"d";
    cfg.psk_id_len = 1;
    cfg.server_pubkey = pin;
    cfg.server_pubkey_len = sizeof pin;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // both modes set
    cfg.server_pubkey = NULL;
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // valid PSK config reaches I/O
    cfg.psk = NULL;
    cfg.psk_len = 0;
    cfg.psk_id = NULL;
    cfg.psk_id_len = 0;
    cfg.server_pubkey = pin;
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // valid pinned config reaches I/O
    CHECK(t.group == 0);                   // no ServerHello arrived, so no group
#ifdef CH_PIN_ECDSA
    cfg.server_pubkey_len = 63;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // P-256 pin must be exactly 64
    cfg.server_pubkey_len = 65;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
#else
    cfg.server_pubkey_len = 256;
    pin[255] = 1; // the low byte the shorter length exposes must be odd too
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // RSA-2048, the smallest pin
    cfg.server_pubkey_len = 248;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // below the floor
    cfg.server_pubkey_len = 392;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // above RSA-3072
    cfg.server_pubkey_len = 260;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // not a multiple of 8 bytes
#endif
    cfg.server_pubkey_len = sizeof pin;
    cfg.buf_len = CH_MIN_RXBUF - 1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // first size below the floor
    cfg.buf_len = CH_MIN_RXBUF;
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // the floor itself reaches I/O
    cfg.buf_len = sizeof rxbuf;
#ifdef CH_TRUST_CA
    // CA builds reuse both key slots as CA keys, and ch_connect applies
    // the pin validation to them unchanged — every length and oddness
    // case in this test doubles as the CA-key rule set. What is
    // CA-specific is the floor: cfg.h derives it from the certificate
    // cap, and the boundary pair above just ran against that derived
    // value. Pin the derivation and the per-PIN number here so a cfg.h
    // regression fails this test, not a live handshake.
    CHECK(CH_MIN_RXBUF == 2 * (CH_X509_MAX + 5) + 8 + REC_OVERHEAD);
#ifdef CH_PIN_ECDSA
    CHECK(CH_MIN_RXBUF == 1576);
#else
    CHECK(CH_MIN_RXBUF == 3112);
#endif
#endif
#if defined(CH_KEX_PQ) && !defined(CH_TRUST_CA)
    // The hybrid build's floor: cfg.h derives it from the plaintext
    // ServerHello record — 5-byte record header, 4-byte message header,
    // 40-byte fixed body, then the supported_versions (6), key_share
    // (2 + 2 + 2 + 2 + 1120 = 1128), and pre_shared_key (6) replies.
    // The boundary pair above just ran against this value. Pin the
    // derivation and the number here so a cfg.h regression fails this
    // test, not a live handshake.
    CHECK(CH_MIN_RXBUF == 5 + 4 + 40 + 6 + 1128 + 6);
    CHECK(CH_MIN_RXBUF == 1189);
#endif

    // require_pq (docs/decisions.md 12): a classic build offers x25519
    // alone and cannot satisfy it, so ch_connect refuses the config
    // before it sends a byte; a hybrid build offers X25519MLKEM768
    // alone, so the flag passes validation and the handshake checks it
    // once parse_key_share accepts the ServerHello's key_share. No
    // ServerHello arrives here either way, so the reported group stays
    // 0.
    cfg.require_pq = 1;
#ifdef CH_KEX_PQ
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
#else
    int sends_before = m.sends;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    CHECK(m.sends == sends_before); // refused at config time: nothing left the client
#endif
    CHECK(t.group == 0);
    cfg.require_pq = 0;

    // Slot B (key rotation): optional, but bound to every slot-A rule.
    cfg.server_pubkey2 = pin2;
    cfg.server_pubkey2_len = sizeof pin2;
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // both slots valid reaches I/O
    CHECK(t.pin_slot == 0);                // no pin matched anything yet
    cfg.server_pubkey2_len = TEST_PIN_LEN - 1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // bad slot-B length
    cfg.server_pubkey2_len = sizeof pin2;
    cfg.server_pubkey = NULL;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // slot B never stands alone
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = (const uint8_t *)"d";
    cfg.psk_id_len = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // ... not even beside a PSK
    cfg.psk = NULL;
    cfg.psk_len = 0;
    cfg.psk_id = NULL;
    cfg.psk_id_len = 0;
    cfg.server_pubkey = pin;
#ifndef CH_PIN_ECDSA
    pin2[TEST_PIN_LEN - 1] = 2; // even slot B: same corruption check as A
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    cfg.server_pubkey2 = NULL;
    cfg.server_pubkey2_len = 0;
    pin[TEST_PIN_LEN - 1] = 2; // even low byte: provisioning corruption
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
#endif
}

// The hello a raw or ca build sends. Its ClientHello carries no
// server_name, its signature_algorithms lists the one scheme the pin can
// be, and its key_share carries one entry, for the build's one group
// (docs/decisions.md entry 12). A TRUST=webpki build sends all three
// differently, and test/webpki_session_cases.h and
// test/webpki_groups_cases.h check that hello.
static void test_pinned_hello_extensions(void) {
    static uint8_t rxbuf[CH_MIN_RXBUF + 88];
    uint8_t pin[TEST_PIN_LEN] = {2};
    pin[TEST_PIN_LEN - 1] = 1;
    mock_io m = {0};
    ch_cfg cfg = {0};
    ch_tls t;
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &m;
    cfg.server_pubkey = pin;
    cfg.server_pubkey_len = sizeof pin;

    // The first record the client sent is the plaintext hello; the
    // alert that follows it when recv fails is not read.
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    CHECK(m.sends >= 1 && m.tx_len > REC_HDR && m.tx[0] == REC_HANDSHAKE);
    const uint8_t *hello = m.tx + REC_HDR;
    size_t hello_len = ((size_t)m.tx[3] << 8) | m.tx[4];
    CHECK(REC_HDR + hello_len <= m.tx_len);
    size_t ext_len = 0;
    CHECK(hello_first_ext(hello, hello_len) == EXT_SUPPORTED_VERSIONS);
    CHECK(hello_ext(hello, hello_len, EXT_SERVER_NAME, &ext_len) == NULL);
    uint16_t schemes[8] = {0};
    CHECK(hello_sigalgs(hello, hello_len, schemes, 8) == 1);
    CHECK(schemes[0] == CH_PIN_SIGALG);
    hello_share_entry shares[2] = {{0}};
    size_t key_len = 0;
    CHECK(hello_key_shares(hello, hello_len, shares, 2) == 1);
    CHECK(hello_key_share(hello, hello_len, CH_KEX_GROUP, &key_len) != NULL &&
          key_len == CH_KEX_CLIENT_SHARE);
}

// The PSK hello a raw or ca client sends, byte for byte. A TRUST=webpki
// hello offers the certificate path beside the ticket
// (docs/decisions.md 55), and this build's must not: its hello offers the
// ticket alone, with no signature_algorithms, and pre_shared_key last.
// want is SHA-256 of the hello hs_build_client_hello wrote over these
// inputs at e82ed51, the commit before that change, in each group this
// main links; the change left both digests as they were.
static void test_psk_hello_bytes(void) {
    static const uint8_t identity[8] = {'t', 'i', 'c', 'k', 'e', 't', '-', '1'};
    static const uint8_t psk[SHA256_LEN] = {1};
    static uint8_t out[CH_HELLO_MAX];
    uint8_t pub[32];
    uint8_t random32[32];
    for (int i = 0; i < 32; i++) {
        pub[i] = (uint8_t)(0x20 + i);
        random32[i] = (uint8_t)(0x60 + i);
    }
    ch_cfg cfg = {0};
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = identity;
    cfg.psk_id_len = sizeof identity;
    cfg.resumption = 1;
    cfg.obfuscated_age = 0x01020304;
#ifdef CH_KEX_PQ
    static uint8_t ek[MLKEM_EK_LEN];
    for (size_t i = 0; i < sizeof ek; i++) {
        ek[i] = (uint8_t)i;
    }
    size_t n = hs_build_client_hello(out, sizeof out, &cfg, ek, pub, random32, 0x4001, NULL, 0);
    static const size_t want_len = 1355;
    static const uint8_t want[SHA256_LEN] = {0x63, 0x69, 0x41, 0x4d, 0x2c, 0xbb, 0x9d, 0x7e,
                                             0x40, 0x4f, 0xc1, 0x72, 0xf0, 0xe3, 0xd5, 0x35,
                                             0x50, 0xa0, 0x47, 0x5a, 0xc4, 0x59, 0x91, 0x29,
                                             0x82, 0xb5, 0x42, 0xf5, 0x9c, 0xfb, 0x60, 0x5b};
#else
    size_t n = hs_build_client_hello(out, sizeof out, &cfg, pub, random32, 0x4001, NULL, 0);
    static const size_t want_len = 171;
    static const uint8_t want[SHA256_LEN] = {0x03, 0x45, 0xe8, 0x24, 0x81, 0x46, 0x50, 0x13,
                                             0x15, 0xf2, 0x47, 0x39, 0xab, 0x6d, 0x88, 0xc1,
                                             0x21, 0x58, 0x6e, 0xfe, 0x66, 0x02, 0x94, 0x24,
                                             0xab, 0xf7, 0xfd, 0x7d, 0xa0, 0x1d, 0x1f, 0x8a};
#endif
    uint8_t digest[SHA256_LEN];
    sha256_of(out, n, digest);
    CHECK(n == want_len && memcmp(digest, want, sizeof want) == 0);
    int count = 0;
    CHECK(hello_ext_index(out, n, EXT_PRE_SHARED_KEY, &count) == count - 1 && count > 0);
    CHECK(hello_ext_index(out, n, EXT_SIGNATURE_ALGORITHMS, NULL) == -1);
}

#endif
