// ch_connect's config validation: the auth-mode, pin-length, buffer-size
// and revocation-epoch gates, all decided before the handshake sends a
// byte. Included by session_tests.h after the mock helpers exist; not a
// standalone translation unit.
#ifndef CH_SESSION_CFG_TESTS_H
#define CH_SESSION_CFG_TESTS_H

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

// The revocation epoch's config gates (docs/ca.md), all of which
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

// The ClientHello staging boundary (#46). CH_TX_STAGE must hold the
// largest hello this build can emit, and CH_HELLO_MAX is that size, so
// the pair below is exact: at CH_HELLO_MAX the worst reachable hello —
// a resumption carrying a CH_TICKET_ID_MAX identity that then answers a
// HelloRetryRequest with an HSP_COOKIE_MAX cookie — is built whole, and
// one byte less refuses. Before the classic build covered its own hello
// this second case was what a device met mid-handshake, as CH_ECAP.
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
    cfg.obfuscated_age = 0xffffffffu;

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
    CHECK(CH_MIN_RXBUF == 2 * (CH_X509_MAX + 5) + 16);
#ifdef CH_PIN_ECDSA
    CHECK(CH_MIN_RXBUF == 1562);
#else
    CHECK(CH_MIN_RXBUF == 3098);
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

#endif
