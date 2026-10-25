// The two rows of bin/hash_runtime_exporter_test that a server role alone
// holds. Each takes the session's ch_cfg.cpu:
//
//   - srv_hash_signed_content, the SHA-256 of a server's CertificateVerify
//     signed content (srv_auth.h);
//   - srv_parse_client_hello, whose frozen digest is a SHA-256 of the
//     ClientHello (srv_parser.h, docs/decisions.md 149).
//
// test/hash_runtime_test.c includes this file after the names the rows
// read: transcript_hash, output, row_hash_len and CHECK.
//
// The Makefile links srv_auth.c, srv_parser.c and srv_parser_ext.c into
// that binary with -DCH_ROLE_SERVER and none of the signers and verifiers
// srv_auth.c calls. The rows call none of them, so this file defines each
// one as a call that ends the test.
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
#include "srv_parser.h"

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

// A ClientHello body the parser accepts: the head with one suite, then
// supported_versions, supported_groups, signature_algorithms and one
// x25519 key_share. The digest covers the head and the first three
// extensions, so the row makes four updates and one final.
static const uint8_t srv_row_hello[] = {
    0x03, 0x03,                                     // legacy_version
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // random
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, //
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, //
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, //
    0x00,                                           // legacy_session_id, empty
    0x00, 0x02, 0x13, 0x03,                         // cipher_suites: ChaCha20-Poly1305
    0x01, 0x00,                                     // legacy_compression_methods: null
    0x00, 0x41,                                     // extensions, 65 bytes
    0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,       // supported_versions: TLS 1.3
    0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, // supported_groups: x25519
    0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03, // signature_algorithms: ECDSA P-256
    0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, // key_share: x25519, 32 bytes
    0x00, 0x20, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, //
    0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, //
    0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, //
    0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, //
    0x5e, 0x5f};

// The frozen digest of that hello. The row requires that the parser
// accepts it, so a refusal before the digest's final fails the row too.
static void row_srv_parse_client_hello(uint32_t cpu) {
    client_hello ch;
    memset(&ch, 0, sizeof ch);
    uint8_t alert = 0;
    CHECK(srv_parse_client_hello(cpu, srv_row_hello, sizeof srv_row_hello, &ch, NULL, 0, &alert) ==
          CH_OK);
    memcpy(output, ch.frozen, sizeof ch.frozen);
}

#endif
#endif
