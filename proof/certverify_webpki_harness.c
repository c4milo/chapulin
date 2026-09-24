// Proves the TRUST=webpki CertificateVerify arm of handshake_auth.c:
// the rule that binds the signature scheme to the leaf key's family,
// and the hash each scheme's signed content takes. Both run over every
// scheme value and every leaf key family, which the vectors in
// test/webpki_auth_vectors.h can only sample.
//
// What runs for real: check_certificate_verify, leaf_scheme,
// hash_signed_content and verify_leaf_signature, over the real
// CertificateVerify parser in handshake_parser.c.
//
// What is a stub, and where the real thing is proved: the record reader
// hsr_next_msg (handshake_record), the two hashes (sha256,
// sha512_compress) and the three signature verifiers (p256, p384,
// rsa_webpki). Each stub asserts the contract its caller must honour
// and returns unconstrained bytes, so the proof considers every answer
// the real function could give. The verifier stubs also record which
// one ran, which is how the asserts below read the dispatch.
//
// Narrow on purpose, like proof/epoch_harness.c: hsa_server_auth's
// other half calls webpki_verify_chain, and webpki_chain proves that
// walk at its own bound; under SPKI pins it calls webpki_verify_raw_key
// and webpki_path_pinned, and webpki_pin proves both. main never reaches
// that half, so cbmc needs no body for the two pin calls.
#define CH_TRUST_WEBPKI 1
#define CH_PROOF_STUB_SHA256

#include "harness.h"

#include <string.h>

#include "cfg.h"
#include "handshake_message.h"
#include "p256.h"
#include "p384.h"
#include "rsa.h"
#include "sha512.h"
#include "webpki.h"

// The CertificateVerify message the stubbed reader yields, header
// included. A launch line may set it; at the default the body holds a
// scheme, a length and up to four signature bytes, which is every shape
// the parser tells apart, since no verifier here reads the signature.
#ifndef CH_PROOF_VERIFY_MSG
#define CH_PROOF_VERIFY_MSG 12
#endif

int nondet_int(void);

// SHA-384 as its header's contract: sha512.c and sha512_compress.c have
// their own harnesses, and compressing 130 bytes symbolically here
// would prove the compression twice. sha384_finals counts the digests
// this arm took, so an assert below can say which hash ran.
static size_t sha384_finals;

void sha384_init(sha512 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha384_init: ctx writable");
    fill_nondet((uint8_t *)s, sizeof *s);
}

void sha512_update(sha512 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha512_update: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha512_update: input readable");
    fill_nondet((uint8_t *)s, sizeof *s);
}

void sha384_final(sha512 *s, uint8_t out[SHA384_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha384_final: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA384_LEN), "sha384_final: output writable");
    sha384_finals++;
    fill_nondet(out, SHA384_LEN);
}

// Which verifier the arm called: WEBPKI_KEY_* for a call, 0 for none.
static uint8_t verifier_ran;

int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(pub, 64), "p256 verify: key readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, 32), "p256 verify: digest readable");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig_der, sig_len),
                     "p256 verify: signature readable");
    verifier_ran = WEBPKI_KEY_P256;
    return nondet_int();
}

int p384_ecdsa_verify(const uint8_t pub[P384_PUB_LEN], const uint8_t msg_hash[P384_LEN],
                      const uint8_t *sig_der, size_t sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(pub, P384_PUB_LEN), "p384 verify: key readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, P384_LEN), "p384 verify: digest readable");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig_der, sig_len),
                     "p384 verify: signature readable");
    verifier_ran = WEBPKI_KEY_P384;
    return nondet_int();
}

int rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t sig_len) {
    __CPROVER_assert(n_len == 0 || __CPROVER_r_ok(n, n_len), "rsa verify: modulus readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, 32), "rsa verify: digest readable");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig, sig_len),
                     "rsa verify: signature readable");
    verifier_ran = WEBPKI_KEY_RSA;
    return nondet_int();
}

#include "handshake_auth.c"

// The message the arm reads. hsr_next_msg's own harness is
// handshake_record; here it yields any type, any length up to the
// bound, and any bytes, or fails.
static uint8_t message[CH_PROOF_VERIFY_MSG];

int hsr_next_msg(handshake_state *h, uint8_t *type, const uint8_t **raw, size_t *raw_len) {
    (void)h;
    if (nondet_u8()) {
        return CH_EIO;
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= 4 && n <= sizeof message); // the reader yields whole messages
    fill_nondet(message, sizeof message);
    *type = nondet_u8();
    *raw = message;
    *raw_len = n;
    return CH_OK;
}

int webpki_verify_chain(const uint8_t *list, size_t list_len, const ch_cfg *cfg,
                        webpki_leaf_info *leaf, uint8_t *alert) {
    (void)list;
    (void)list_len;
    (void)cfg;
    (void)leaf;
    (void)alert;
    return CH_EAUTH; // main drives check_certificate_verify, not the walk
}

int main(void) {
    ch_tls t;
    handshake_state h;
    memset(&t, 0, sizeof t);
    memset(&h, 0, sizeof h);
    h.t = &t;
    h.alert = nondet_u8();

    // The leaf webpki_verify_chain copied out: any family byte, and a
    // key as long as the bound admits. webpki_spki proves which bytes
    // reach these fields; every value they can hold is driven here.
    h.leaf.alg = nondet_u8();
    size_t key_len = nondet_size_t();
    __CPROVER_assume(key_len <= CH_WEBPKI_KEY_MAX);
    h.leaf.key_len = key_len;
    fill_nondet(h.leaf.key, sizeof h.leaf.key);

    uint8_t hash[SHA256_LEN];
    fill_nondet(hash, sizeof hash);
    sha384_finals = 0;
    verifier_ran = 0;

    int rc = check_certificate_verify(&h, hash);

    // The binding of RFC 9846 section 4.5.2: a signature is checked
    // only under the scheme the leaf key's family can produce, and the
    // verifier that ran is that family's own. Every alg byte that is
    // neither curve is an RSA key, which is what webpki_read_spki
    // leaves behind.
    uint8_t family = WEBPKI_KEY_RSA;
    if (h.leaf.alg == WEBPKI_KEY_P256 || h.leaf.alg == WEBPKI_KEY_P384) {
        family = h.leaf.alg;
    }
    __CPROVER_assert(verifier_ran == 0 || verifier_ran == family,
                     "certverify: the verifier that ran is the leaf key's own");
    // The hash the scheme names, both ways: SHA-384 runs for a P-384
    // leaf and for no other, so a P-256 or RSA signature is never
    // checked over 48 bytes of digest, and a P-384 one never over 32.
    __CPROVER_assert(sha384_finals == 0 || family == WEBPKI_KEY_P384,
                     "certverify: SHA-384 signs only a P-384 leaf's content");
    __CPROVER_assert(verifier_ran != WEBPKI_KEY_P384 || sha384_finals == 1,
                     "certverify: a P-384 leaf's content is signed with SHA-384");
    __CPROVER_assert(sha384_finals <= 1, "certverify: one signed content per message");
    // Accepting means a verifier ran and answered yes.
    __CPROVER_assert(rc != CH_OK || verifier_ran != 0,
                     "certverify: an accepted message went through a verifier");
    // Every refusal is one of the arm's own codes; nothing else escapes.
    __CPROVER_assert(rc == CH_OK || rc == CH_EIO || rc == CH_EPROTO || rc == CH_EAUTH,
                     "certverify: a refusal names one of the arm's codes");
    return 0;
}
