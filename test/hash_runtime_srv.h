// The row of bin/hash_runtime_exporter_test that a server role alone
// holds: srv_hash_signed_content, the SHA-256 of a server's
// CertificateVerify signed content, which takes the session's ch_cfg.cpu
// (srv_auth.h). test/hash_runtime_test.c includes this file after the
// names its row reads: transcript_hash, output and row_hash_len.
//
// The Makefile links srv_auth.c into that binary with -DCH_ROLE_SERVER and
// none of the signers and verifiers srv_auth.c calls. The row calls none
// of them, so this file defines each one as a call that ends the test.
// The binary then links. A call of a stub reports its name and aborts.
// Outside a server role this file holds nothing.
#ifndef CH_TEST_HASH_RUNTIME_SRV_H
#define CH_TEST_HASH_RUNTIME_SRV_H
#ifdef CH_ROLE_SERVER

#include "p256.h"
#include "rand.h"
#include "rsa.h"
#include "rsa_sign.h"
#include "rsa_sign64.h"
#include "srv_auth.h"
#include "srv_message.h"

static noreturn void srv_stub_called(const char *name) {
    (void)fprintf(stderr, "hash runtime: the row called %s, which this binary does not hold\n",
                  name);
    abort();
}

void ch_rand_bytes(uint8_t *p, size_t n) {
    (void)p;
    (void)n;
    srv_stub_called("ch_rand_bytes");
}

int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    (void)pub;
    (void)msg_hash;
    (void)sig_der;
    (void)sig_len;
    srv_stub_called("p256_ecdsa_verify");
}

int rsa_pss_sign(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                 const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap, size_t *sig_len) {
    (void)k;
    (void)msg_hash;
    (void)salt;
    (void)sig;
    (void)cap;
    (void)sig_len;
    srv_stub_called("rsa_pss_sign");
}

int rsa_pss_verify_cpu(uint32_t cpu, const uint8_t *n, size_t n_len, const uint8_t msg_hash[32],
                       const uint8_t *sig, size_t sig_len) {
    (void)cpu;
    (void)n;
    (void)n_len;
    (void)msg_hash;
    (void)sig;
    (void)sig_len;
    srv_stub_called("rsa_pss_verify_cpu");
}

int rsa_sign64_key_ok(const ch_rsa_priv *k) {
    (void)k;
    srv_stub_called("rsa_sign64_key_ok");
}

int rsa_sign64_pss(uint32_t cpu, const ch_rsa_priv *k, const uint8_t msg_hash[32],
                   const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap,
                   size_t *sig_len) {
    (void)cpu;
    (void)k;
    (void)msg_hash;
    (void)salt;
    (void)sig;
    (void)cap;
    (void)sig_len;
    srv_stub_called("rsa_sign64_pss");
}

int srv_certificate_fits(const ch_identity *id) {
    (void)id;
    srv_stub_called("srv_certificate_fits");
}

// The signed content over a transcript hash of row_hash_len bytes, for
// the scheme ecdsa_secp256r1_sha256. The digest is SHA-256 at either
// transcript hash length.
static void row_srv_signed_content(uint32_t cpu) {
    srv_hash_signed_content(cpu, SIGALG_ECDSA_P256_SHA256, transcript_hash, row_hash_len, output);
}

#endif
#endif
