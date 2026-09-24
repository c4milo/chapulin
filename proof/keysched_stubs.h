// Contract stubs for the five key-schedule calls the client handshake
// makes, so the handshake harnesses prove the driver's framing rather than
// re-deriving HKDF inside that formula. keysched_harness proves the real
// functions over their own domain.
//
// WHAT THESE MODEL: each asserts the buffers keysched.h says it reads, at
// the hash length the caller passed, and that the length names a hash the
// build holds; each havocs every byte it writes, so the harness proves the
// driver over every secret the schedule could return.
//
// Included by proof/handshake_harness.c, which the handshake_psk,
// handshake_pin and handshake_ca harnesses include in turn, after
// keysched.h.
#ifndef CH_PROOF_KEYSCHED_STUBS_H
#define CH_PROOF_KEYSCHED_STUBS_H

#include "keysched.h"

void ks_early(size_t hash_len, const uint8_t *psk, size_t psk_len, int resumption, uint8_t *early,
              uint8_t *binder_key) {
    __CPROVER_assert(hash_len == SHA256_LEN || hash_len == HKDF_HASH_MAX,
                     "ks_early: hash_len names a hash this build holds");
    (void)resumption;
    __CPROVER_assert(psk_len == 0 || __CPROVER_r_ok(psk, psk_len), "ks: psk readable");
    fill_nondet(early, hash_len);
    fill_nondet(binder_key, hash_len);
}

void ks_verify_data(size_t hash_len, const uint8_t *key, const uint8_t *transcript, uint8_t *out) {
    __CPROVER_assert(hash_len == SHA256_LEN || hash_len == HKDF_HASH_MAX,
                     "ks_verify_data: hash_len names a hash this build holds");
    __CPROVER_assert(__CPROVER_r_ok(key, hash_len), "ks: key readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, hash_len), "ks: transcript readable");
    fill_nondet(out, hash_len);
}

void ks_handshake(size_t hash_len, const uint8_t *early, const uint8_t *ecdhe, size_t ecdhe_len,
                  const uint8_t *transcript, uint8_t *handshake_secret, uint8_t *c_hs,
                  uint8_t *s_hs) {
    __CPROVER_assert(hash_len == SHA256_LEN || hash_len == HKDF_HASH_MAX,
                     "ks_handshake: hash_len names a hash this build holds");
    __CPROVER_assert(__CPROVER_r_ok(early, hash_len), "ks: early readable");
    __CPROVER_assert(ecdhe_len == 0 || __CPROVER_r_ok(ecdhe, ecdhe_len), "ks: ecdhe readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, hash_len), "ks: transcript readable");
    fill_nondet(handshake_secret, hash_len);
    fill_nondet(c_hs, hash_len);
    fill_nondet(s_hs, hash_len);
}

void ks_master(size_t hash_len, const uint8_t *handshake_secret, const uint8_t *transcript,
               uint8_t *master, uint8_t *c_ap, uint8_t *s_ap) {
    __CPROVER_assert(hash_len == SHA256_LEN || hash_len == HKDF_HASH_MAX,
                     "ks_master: hash_len names a hash this build holds");
    __CPROVER_assert(__CPROVER_r_ok(handshake_secret, hash_len), "ks: handshake secret readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, hash_len), "ks: transcript readable");
    fill_nondet(master, hash_len);
    fill_nondet(c_ap, hash_len);
    fill_nondet(s_ap, hash_len);
}

void ks_res_master(size_t hash_len, const uint8_t *master, const uint8_t *transcript,
                   uint8_t *res_master) {
    __CPROVER_assert(hash_len == SHA256_LEN || hash_len == HKDF_HASH_MAX,
                     "ks_res_master: hash_len names a hash this build holds");
    __CPROVER_assert(__CPROVER_r_ok(master, hash_len), "ks: master readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, hash_len), "ks: transcript readable");
    fill_nondet(res_master, hash_len);
}

#endif
