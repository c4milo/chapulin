// The ML-DSA-87 identity of a host server outside PROFILE=cnsa2
// (docs/decisions.md 180), each rule held at its boundary in one process
// over the sources the host server object packages:
//  - the boot check: a real key pair passes ch_srv_check, priv_len 4896
//    and pub_len 2592 pass, one byte less of either is refused, and a
//    public key that is not the secret key's fails;
//  - the selection: mldsa87 first whenever the client offers it and the
//    slot is provisioned, ECDSA P-256 then RSA-PSS otherwise, and no
//    scheme when the client offers mldsa87 alone to a server without the
//    slot;
//  - the slot set beside the other two: srv_identity_live reports all
//    three bits, and srv_identity_for names each slot.
// test/e2e.sh runs the CertificateVerify against OpenSSL under each suite.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "handshake_message.h"
#include "mldsa_signer.h"
#include "srv.h"
#include "srv_auth.h"
#include "srv_flight.h"
#include "srv_parser.h"

#if !defined(CH_SIGN_MLDSA) || defined(CH_PROFILE_CNSA2)
#error "srv_mldsa_identity_test runs a host server outside PROFILE=cnsa2"
#endif

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

static uint8_t sk[MLDSA87_SK_LEN];
static uint8_t pk[MLDSA87_PK_LEN];
static const uint8_t cert_der[64] = {0x30, 0x3e};
static ch_cert chain[1];
static uint8_t cookie_key[CH_SRV_COOKIE_KEY_LEN];
static uint8_t rxbuf[16384];

// Key bytes for a slot this test provisions but never signs with. The
// selection reads pointers alone, and ch_srv_check runs on a
// configuration without them.
static const uint8_t placeholder[MLDSA87_SK_LEN] = {1};

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

static void set_slot(ch_identity *id, const void *priv, size_t priv_len, const uint8_t *pub,
                     size_t pub_len) {
    id->chain = chain;
    id->chain_count = 1;
    id->priv = priv;
    id->priv_len = priv_len;
    id->pub = pub;
    id->pub_len = pub_len;
}

// A configuration whose one identity is the ML-DSA-87 key pair.
static void base_cfg(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    chain[0].der = cert_der;
    chain[0].len = sizeof cert_der;
    set_slot(&cfg->srv.mldsa87, sk, sizeof sk, pk, sizeof pk);
    cfg->srv.cookie_key = cookie_key;
    cfg->buf = rxbuf;
    cfg->buf_len = sizeof rxbuf;
    cfg->send = io_none_send;
    cfg->recv = io_none;
    cfg->cpu = CH_CPU_PROBED;
}

static void test_boot_check(void) {
    ch_cfg cfg;
    base_cfg(&cfg);
    CHECK(srv_identity_live(&cfg) == SRV_IDENTITY_MLDSA87);
    CHECK(ch_srv_check(&cfg) == CH_OK);
    CHECK(srv_config_ok(&cfg) == 1);
    // The multiply bit, under which an arm64 object signs on
    // mldsa_vector.c's lanes (docs/decisions.md 172).
    cfg.cpu = CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY;
    CHECK(ch_srv_check(&cfg) == CH_OK);
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
}

static void test_selection(void) {
    ch_cfg cfg;
    base_cfg(&cfg);
    set_slot(&cfg.srv.ecdsa_p256, placeholder, 32, placeholder, 64);
    set_slot(&cfg.srv.rsa_pss, placeholder, 32, placeholder, 256);
    const uint8_t all = SRV_SIGALG_MLDSA87 | SRV_SIGALG_ECDSA_P256 | SRV_SIGALG_RSA_PSS;
    CHECK(srv_identity_live(&cfg) ==
          (SRV_IDENTITY_MLDSA87 | SRV_IDENTITY_ECDSA_P256 | SRV_IDENTITY_RSA_PSS));
    // mldsa87 first whenever it is offered and provisioned.
    CHECK(srv_select_sigalg(&cfg, all) == SIGALG_MLDSA87);
    CHECK(srv_select_sigalg(&cfg, SRV_SIGALG_MLDSA87) == SIGALG_MLDSA87);
    CHECK(srv_select_sigalg(&cfg, SRV_SIGALG_ECDSA_P256 | SRV_SIGALG_RSA_PSS) ==
          SIGALG_ECDSA_P256_SHA256);
    CHECK(srv_select_sigalg(&cfg, SRV_SIGALG_RSA_PSS) == SIGALG_RSA_PSS_RSAE_SHA256);
    CHECK(srv_identity_for(&cfg, SIGALG_MLDSA87) == &cfg.srv.mldsa87);
    CHECK(srv_identity_for(&cfg, SIGALG_ECDSA_P256_SHA256) == &cfg.srv.ecdsa_p256);
    // Without the slot, an offer of mldsa87 alone names no scheme, and a
    // wider offer falls to the next slot.
    memset(&cfg.srv.mldsa87, 0, sizeof cfg.srv.mldsa87);
    CHECK(srv_select_sigalg(&cfg, SRV_SIGALG_MLDSA87) == 0);
    CHECK(srv_select_sigalg(&cfg, all) == SIGALG_ECDSA_P256_SHA256);
    CHECK(srv_identity_for(&cfg, SIGALG_MLDSA87) == NULL);
    // The other signers refuse mldsa87, which srv_mldsa.c signs.
    base_cfg(&cfg);
    uint8_t sig[SRV_SIG_MAX];
    size_t sig_len = 1;
    uint8_t alert = 0;
    static const uint8_t hash[SHA256_LEN] = {0};
    CHECK(srv_sign_certificate_verify(&cfg, SIGALG_MLDSA87, hash, sizeof hash, sig, sizeof sig,
                                      &sig_len, &alert) == CH_EAUTH);
    CHECK(alert == ALERT_INTERNAL_ERROR);
}

int main(void) {
    uint8_t seed[MLDSA87_SEED_LEN];
    memset(seed, 7, sizeof seed);
    if (!mldsa87_keygen(sk, pk, seed)) {
        (void)fprintf(stderr, "FAIL: key generation\n");
        return 1;
    }
    memset(cookie_key, 0x5a, sizeof cookie_key);
    test_boot_check();
    test_selection();
    if (failures != 0) {
        return 1;
    }
    (void)printf("srv_mldsa_identity: the host server's ML-DSA-87 slot checks at boot and "
                 "signs first when offered\n");
    return 0;
}
