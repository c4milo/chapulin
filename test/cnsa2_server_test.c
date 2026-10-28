// The PROFILE=cnsa2 server's own rules (docs/decisions.md 162, INV-64),
// each held at its boundary in one process over the profile server's
// sources:
//  - the identity: priv_len 4896 and pub_len 2592 pass, one byte less of
//    either is refused, and ch_srv_check signs and verifies a real key;
//  - the CPU: a ch_cfg.cpu without CH_CPU_CONSTANT_TIME_AES is refused by
//    the configuration check and by ch_srv_check, and one with it passes;
//  - the selection: ML-KEM-1024 alone, TLS_AES_256_GCM_SHA384 alone and
//    mldsa87 alone, a retry for a hello that lists ML-KEM-1024 without a
//    share, and handshake_failure for one that does not list it;
//  - the cookie: 133 bytes under HMAC-SHA-384, which the test computes
//    again over the body, and a cookie one byte short or long refused;
//  - the ticket: 124 bytes under AES-256-GCM, which the test opens again
//    with gcm_traffic_open on a key it expands itself.
// e2e runs the server against OpenSSL and this tree's client.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_traffic_key.h"
#include "ch_assert.h"
#include "gcm.h"
#include "hkdf.h"
#include "mldsa_signer.h"
#include "srv.h"
#include "srv_cookie.h"
#include "srv_flight.h"
#include "srv_parser.h"
#include "srv_ticket.h"
#include "suite.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// A counter, not entropy: every draw differs, and a failure replays.
void ch_rand_bytes(uint8_t *p, size_t n) {
    static uint8_t counter = 1;
    for (size_t i = 0; i < n; i++) {
        p[i] = counter++;
    }
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

#define CPU_WITH_AES (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES)

static uint8_t sk[MLDSA87_SK_LEN];
static uint8_t pk[MLDSA87_PK_LEN];
static const uint8_t cert_der[64] = {0x30, 0x3e};
static ch_cert chain[1];
static uint8_t cookie_key[CH_SRV_COOKIE_KEY_LEN];
static uint8_t ticket_key[CH_SRV_TICKET_KEY_LEN];
static uint8_t rxbuf[16384];

static int io_none(void *io, uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return -1;
}

static int io_none_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return -1;
}

static void base_cfg(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    chain[0].der = cert_der;
    chain[0].len = sizeof cert_der;
    cfg->srv.mldsa87.chain = chain;
    cfg->srv.mldsa87.chain_count = 1;
    cfg->srv.mldsa87.priv = sk;
    cfg->srv.mldsa87.priv_len = sizeof sk;
    cfg->srv.mldsa87.pub = pk;
    cfg->srv.mldsa87.pub_len = sizeof pk;
    cfg->srv.cookie_key = cookie_key;
    cfg->srv.ticket_key = ticket_key;
    cfg->buf = rxbuf;
    cfg->buf_len = sizeof rxbuf;
    cfg->send = io_none_send;
    cfg->recv = io_none;
    cfg->cpu = CPU_WITH_AES;
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    cfg->srv.on_record_out = NULL;
#endif
}

static void test_identity_and_cpu(void) {
    ch_cfg cfg;
    base_cfg(&cfg);
    CHECK(ch_srv_check(&cfg) == CH_OK);
    CHECK(srv_config_ok(&cfg) == 1);
    // The CPU: the AES bit is what the profile requires.
    cfg.cpu = CH_CPU_PROBED;
    CHECK(ch_srv_check(&cfg) == CH_EINVAL);
    CHECK(srv_config_ok(&cfg) == 0);
    // The key lengths, one byte short of each.
    base_cfg(&cfg);
    cfg.srv.mldsa87.priv_len = MLDSA87_SK_LEN - 1;
    CHECK(ch_srv_check(&cfg) == CH_EINVAL);
    CHECK(srv_config_ok(&cfg) == 0);
    base_cfg(&cfg);
    cfg.srv.mldsa87.pub_len = MLDSA87_PK_LEN - 1;
    CHECK(ch_srv_check(&cfg) == CH_EINVAL);
    CHECK(srv_config_ok(&cfg) == 0);
    // A public key that is not the secret key's fails the boot check,
    // because the signer checks each signature under it.
    base_cfg(&cfg);
    static uint8_t other_pk[MLDSA87_PK_LEN];
    memcpy(other_pk, pk, sizeof other_pk);
    other_pk[100] ^= 1;
    cfg.srv.mldsa87.pub = other_pk;
    CHECK(ch_srv_check(&cfg) == CH_EINVAL);
    // The receive floor: the profile client's largest ClientHello, 2174
    // bytes, behind its record header. The floor passes and one byte less
    // is refused.
    CHECK(CH_MIN_RXBUF == 5 + 2174);
    base_cfg(&cfg);
    cfg.buf_len = CH_MIN_RXBUF;
    CHECK(srv_config_ok(&cfg) == 1);
    cfg.buf_len = CH_MIN_RXBUF - 1;
    CHECK(srv_config_ok(&cfg) == 0);
    // A suite list may name the profile's suite alone.
    base_cfg(&cfg);
    static const uint16_t only_256[1] = {SUITE_AES_256_GCM_SHA384};
    static const uint16_t chacha[1] = {SUITE_CHACHA20_POLY1305_SHA256};
    cfg.srv.cipher_suites = only_256;
    cfg.srv.cipher_suite_count = 1;
    CHECK(srv_config_ok(&cfg) == 1);
    cfg.srv.cipher_suites = chacha;
    CHECK(srv_config_ok(&cfg) == 0);
}

// A ClientHello body with the three lists the profile reads and, when
// share is set, an ML-KEM-1024 key share of the right length.
static size_t build_hello(uint8_t *out, size_t cap, uint16_t suite, uint16_t group, uint16_t sigalg,
                          int share) {
    size_t n = 0;
#define PUT8(v) (out[n++] = (uint8_t)(v))
#define PUT16(v) (PUT8((v) >> 8), PUT8(v))
    PUT16(0x0303);
    for (int i = 0; i < 32; i++) {
        PUT8(i);
    }
    PUT8(0);
    PUT16(2);
    PUT16(suite);
    PUT8(1);
    PUT8(0);
    size_t ext_at = n;
    PUT16(0);
    PUT16(0x002b); // supported_versions: TLS 1.3
    PUT16(3);
    PUT8(2);
    PUT16(0x0304);
    PUT16(0x000a); // supported_groups
    PUT16(4);
    PUT16(2);
    PUT16(group);
    PUT16(0x000d); // signature_algorithms
    PUT16(4);
    PUT16(2);
    PUT16(sigalg);
    PUT16(0x0033); // key_share
    if (share) {
        PUT16(2 + 4 + MLKEM_EK_LEN);
        PUT16(4 + MLKEM_EK_LEN);
        PUT16(group);
        PUT16(MLKEM_EK_LEN);
        memset(out + n, 0, MLKEM_EK_LEN);
        n += MLKEM_EK_LEN;
    } else {
        PUT16(2);
        PUT16(0);
    }
    size_t ext_len = n - ext_at - 2;
    out[ext_at] = (uint8_t)(ext_len >> 8);
    out[ext_at + 1] = (uint8_t)ext_len;
#undef PUT8
#undef PUT16
    CHECK(n <= cap);
    return n;
}

static int select_for(uint16_t suite, uint16_t group, uint16_t sigalg, int share, selection *sel) {
    static uint8_t body[4096];
    size_t n = build_hello(body, sizeof body, suite, group, sigalg, share);
    client_hello ch;
    memset(&ch, 0, sizeof ch);
    uint8_t alert = 0;
    if (srv_parse_client_hello(CPU_WITH_AES, body, n, &ch, NULL, 0, &alert) != CH_OK) {
        return -1;
    }
    static ch_tls t;
    memset(&t, 0, sizeof t);
    base_cfg(&t.cfg);
    handshake_state h;
    memset(&h, 0, sizeof h);
    h.t = &t;
    return srv_select(&h, &ch, sel);
}

static void test_selection(void) {
    selection sel;
    // The profile's three, with a share: selected in one round trip.
    CHECK(select_for(SUITE_AES_256_GCM_SHA384, CH_GROUP_MLKEM1024, SIGALG_MLDSA87, 1, &sel) ==
          CH_OK);
    CHECK(sel.suite == SUITE_AES_256_GCM_SHA384 && sel.group == CH_GROUP_MLKEM1024 &&
          sel.sigalg == SIGALG_MLDSA87 && sel.need_retry == 0 && sel.hash_len == SHA384_LEN);
    // Listed without a share: a HelloRetryRequest asks for it.
    CHECK(select_for(SUITE_AES_256_GCM_SHA384, CH_GROUP_MLKEM1024, SIGALG_MLDSA87, 0, &sel) ==
          CH_OK);
    CHECK(sel.need_retry == 1 && sel.group == CH_GROUP_MLKEM1024);
    // Every other group, suite and scheme shares nothing with the profile.
    CHECK(select_for(SUITE_AES_256_GCM_SHA384, CH_GROUP_X25519MLKEM768, SIGALG_MLDSA87, 0, &sel) ==
          CH_EPROTO);
    CHECK(select_for(SUITE_AES_256_GCM_SHA384, CH_GROUP_X25519, SIGALG_MLDSA87, 0, &sel) ==
          CH_EPROTO);
    CHECK(select_for(SUITE_AES_128_GCM_SHA256, CH_GROUP_MLKEM1024, SIGALG_MLDSA87, 1, &sel) ==
          CH_EPROTO);
    CHECK(select_for(SUITE_CHACHA20_POLY1305_SHA256, CH_GROUP_MLKEM1024, SIGALG_MLDSA87, 1, &sel) ==
          CH_EPROTO);
    CHECK(select_for(SUITE_AES_256_GCM_SHA384, CH_GROUP_MLKEM1024, SIGALG_ECDSA_P256_SHA256, 1,
                     &sel) == CH_EPROTO);
}

static void test_cookie(void) {
    uint8_t ch1[SHA384_LEN];
    uint8_t frozen[SHA256_LEN];
    memset(ch1, 0x11, sizeof ch1);
    memset(frozen, 0x22, sizeof frozen);
    uint8_t cookie[SRV_COOKIE_MAX + 1];
    CHECK(SRV_COOKIE_MAX == 133 && HSP_COOKIE_MAX == 133);
    size_t n = srv_cookie_mint(cookie_key, SUITE_AES_256_GCM_SHA384, CH_GROUP_MLKEM1024, ch1,
                               sizeof ch1, frozen, cookie, sizeof cookie);
    CHECK(n == 133);
    // The MAC is HMAC-SHA-384 over every byte before it.
    uint8_t want[SHA384_LEN];
    hmac_sha384(cookie_key, sizeof cookie_key, cookie, n - SHA384_LEN, want);
    CHECK(memcmp(want, cookie + n - SHA384_LEN, SHA384_LEN) == 0);
    uint16_t suite = 0;
    uint16_t group = 0;
    uint8_t got_hash[SRV_COOKIE_HASH_MAX];
    size_t hash_len = 0;
    uint8_t got_frozen[SHA256_LEN];
    CHECK(srv_cookie_open(cookie_key, cookie, n, &suite, &group, got_hash, &hash_len, got_frozen) ==
          CH_OK);
    CHECK(suite == SUITE_AES_256_GCM_SHA384 && group == CH_GROUP_MLKEM1024 &&
          hash_len == SHA384_LEN);
    // One byte short and one byte long are refused before the MAC runs.
    CHECK(srv_cookie_open(cookie_key, cookie, n - 1, &suite, &group, got_hash, &hash_len,
                          got_frozen) == CH_EPROTO);
    cookie[n] = 0;
    CHECK(srv_cookie_open(cookie_key, cookie, n + 1, &suite, &group, got_hash, &hash_len,
                          got_frozen) == CH_EPROTO);
    // The last MAC byte changed.
    cookie[n - 1] ^= 1;
    CHECK(srv_cookie_open(cookie_key, cookie, n, &suite, &group, got_hash, &hash_len, got_frozen) ==
          CH_EPROTO);
    // A cap one byte short of the cookie writes nothing.
    CHECK(srv_cookie_mint(cookie_key, SUITE_AES_256_GCM_SHA384, CH_GROUP_MLKEM1024, ch1, sizeof ch1,
                          frozen, cookie, 132) == 0);
}

static void test_ticket(void) {
    srv_ticket_contents c;
    memset(&c, 0, sizeof c);
    c.auth_seconds = 1000;
    c.suite = SUITE_AES_256_GCM_SHA384;
    memset(c.psk, 0x5a, sizeof c.psk);
    uint8_t nonce[AEAD_NONCE];
    memset(nonce, 7, sizeof nonce);
    uint8_t ticket[SRV_TICKET_LEN];
    CHECK(SRV_TICKET_LEN == 124);
    CHECK(srv_ticket_seal(0, ticket_key, nonce, &c, ticket, sizeof ticket) == SRV_TICKET_LEN);
    // The body opens under AES-256-GCM on a key this test expands itself,
    // with the version byte as associated data.
    aes_traffic_key k;
    aes_traffic_key_init(&k, ticket_key, sizeof ticket_key);
    uint8_t body[SRV_TICKET_BODY_LEN];
    CHECK(gcm_traffic_open(&k, ticket + 1, ticket, 1, ticket + 1 + AEAD_NONCE, sizeof body,
                           ticket + 1 + AEAD_NONCE + sizeof body, body) == 1);
    CHECK(body[8] == 0x13 && body[9] == 0x02);
    srv_ticket_contents got;
    CHECK(srv_ticket_open(0, ticket_key, ticket, sizeof ticket, &got) == CH_OK);
    CHECK(got.suite == SUITE_AES_256_GCM_SHA384 && memcmp(got.psk, c.psk, sizeof c.psk) == 0);
    // The profile's tickets are version 3. A version-2 ticket, the
    // ChaCha20-Poly1305 layout of every other server, is refused on its
    // first byte, before the AEAD runs.
    CHECK(SRV_TICKET_VERSION == 3 && ticket[0] == 3);
    ticket[0] = 2;
    CHECK(srv_ticket_open(0, ticket_key, ticket, sizeof ticket, &got) == CH_EAUTH);
    ticket[0] = 3;
    CHECK(srv_ticket_open(0, ticket_key, ticket, sizeof ticket, &got) == CH_OK);
    ticket[sizeof ticket - 1] ^= 1;
    CHECK(srv_ticket_open(0, ticket_key, ticket, sizeof ticket, &got) == CH_EAUTH);
}

int main(void) {
    uint8_t seed[MLDSA87_SEED_LEN];
    memset(seed, 3, sizeof seed);
    if (!mldsa87_keygen(sk, pk, seed)) {
        (void)fprintf(stderr, "FAIL: key generation\n");
        return 1;
    }
    memset(cookie_key, 0x31, sizeof cookie_key);
    memset(ticket_key, 0x42, sizeof ticket_key);
    test_identity_and_cpu();
    test_selection();
    test_cookie();
    test_ticket();
    if (failures != 0) {
        (void)fprintf(stderr, "cnsa2_server_test: %d failures\n", failures);
        return 1;
    }
    (void)printf("cnsa2_server_test: identity, cpu, selection, cookie and ticket ok\n");
    return 0;
}
