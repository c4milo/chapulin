// The TRUST=ca build variant of the handshake proof: the same driver,
// with server_auth routing the Certificate message through
// x509_verify_leaf and CertificateVerify checking the extracted leaf
// key. A proof name is one launch line, so the variant gets its own
// file, the x509der_ecdsa precedent.
//
// The chain verifier is a stub asserting its x509.h contract — its
// real body is proven in the x509parse harnesses. The object under
// proof stays the driver's own arithmetic and state.
// Status: no launch line yet. Both PIN variants leave kissat without
// a verdict in 25 minutes at the raw driver's bounds; a converging
// configuration is being measured, and the launch line lands with
// it. Until then the CA driver's assurance is the raw driver proof
// (the code is shared outside the CA arm), the x509parse proofs for
// the arm's parser, and the e2e and unit_ca suites.
#define CH_TRUST_CA 1
// Certificates reach this driver only in the pinned arm.
#define CH_PROOF_PIN 1

#include "harness.h"
#include "x509.h"

// Contract stub: inputs readable, outputs writable; the result stays
// inside the declared domain (a leaf key of at most CH_X509_KEY_MAX
// bytes, the chain anchored at pin slot 1 or 2) while every byte of
// it havocs — so the driver proves safe against any verdict the real
// verifier can return.
int x509_verify_leaf(const uint8_t *list, size_t list_len, const uint8_t *ca_key_a, size_t ca_a_len,
                     const uint8_t *ca_key_b, size_t ca_b_len, x509_leaf_info *out,
                     uint8_t *alert) {
    __CPROVER_assert(list_len == 0 || __CPROVER_r_ok(list, list_len), "x509: list readable");
    __CPROVER_assert(ca_a_len == 0 || __CPROVER_r_ok(ca_key_a, ca_a_len), "x509: slot A readable");
    __CPROVER_assert(ca_key_b == NULL || ca_b_len == 0 || __CPROVER_r_ok(ca_key_b, ca_b_len),
                     "x509: slot B readable");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "x509: leaf out writable");
    __CPROVER_assert(__CPROVER_w_ok(alert, sizeof *alert), "x509: alert writable");
    *alert = nondet_u8();
    fill_nondet(out->key, sizeof out->key);
    out->epoch = (uint32_t)nondet_size_t();
    out->epoch_ok = nondet_u8();
    size_t key_len = nondet_size_t();
    __CPROVER_assume(key_len <= CH_X509_KEY_MAX);
    out->key_len = key_len;
    out->ca_slot = (uint8_t)((nondet_u8() & 1) + 1);
    uint8_t verdict = nondet_u8();
    if (verdict == 0) {
        return CH_OK;
    }
    return (verdict & 1) ? CH_EPROTO : CH_EAUTH;
}

#include "handshake_harness.c"
