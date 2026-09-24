// Contract stubs for the two HKDF calls quic_aes.c makes, so
// quic_aes_harness proves the key schedule, the forward cipher and the
// constructors' own framing rather than re-deriving HMAC-SHA-256 inside
// that formula.
//
// Why this exists: hkdf_expand and hkdf_expand_label are slow-tier
// proofs of their own, 745 s and 747 s under kissat
// (proof/run.sh:337-343). aes_public_key_initial calls the label form
// four times and hkdf_extract once, so a concrete harness would carry
// five HMAC formulas on top of the cipher it exists to prove.
//
// WHAT THESE MODEL, and therefore what the harness still proves:
//
//   hkdf_extract       a 32-byte pseudorandom key whose bytes are
//                      unconstrained.
//   hkdf_expand_label  out_len unconstrained bytes.
//
// Both assert the contract hkdf.h states for their caller: every buffer
// readable or writable at the length passed, and the label present.
// Every output byte is havocked, so the harness proves the cipher and
// the schedule over every key HKDF could return rather than one CBMC
// picked.
//
// WHAT THIS NO LONGER PROVES: that hkdf.c meets those contracts. That
// moves to hkdf_harness, hkdf_expand_harness and
// hkdf_expand_label_harness, which prove the real functions over their
// own domains, and to the RFC 9001 Appendix A.1 vectors in
// test/quic_vectors.c, which check the whole derivation end to end.
#ifndef CH_QUIC_AES_STUBS_H
#define CH_QUIC_AES_STUBS_H

#include "hkdf.h"

void hkdf_extract(size_t hash_len, const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                  size_t ikm_len, uint8_t *prk) {
    __CPROVER_assert(hash_len == SHA256_LEN || hash_len == HKDF_HASH_MAX,
                     "hkdf_extract: hash_len names a hash this build holds");
    __CPROVER_assert(salt_len == 0 || __CPROVER_r_ok(salt, salt_len),
                     "hkdf_extract: salt readable");
    __CPROVER_assert(ikm_len == 0 || __CPROVER_r_ok(ikm, ikm_len), "hkdf_extract: ikm readable");
    __CPROVER_assert(__CPROVER_w_ok(prk, hash_len), "hkdf_extract: prk writable");
    fill_nondet(prk, hash_len);
}

void hkdf_expand_label(size_t hash_len, const uint8_t *secret, const char *label,
                       const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len) {
    __CPROVER_assert(hash_len == SHA256_LEN || hash_len == HKDF_HASH_MAX,
                     "hkdf_expand_label: hash_len names a hash this build holds");
    __CPROVER_assert(__CPROVER_r_ok(secret, hash_len), "hkdf_expand_label: secret readable");
    __CPROVER_assert(__CPROVER_r_ok(label, 1), "hkdf_expand_label: label present");
    __CPROVER_assert(ctx_len == 0 || __CPROVER_r_ok(ctx, ctx_len), "hkdf_expand_label: ctx "
                                                                   "readable");
    __CPROVER_assert(out_len > 0 && __CPROVER_w_ok(out, out_len), "hkdf_expand_label: output "
                                                                  "writable");
    fill_nondet(out, out_len);
}

#endif
