#include "keysched.h"

#include "ct.h"
#include "hkdf.h"

// SHA256("") — the transcript hash of the empty context.
static const uint8_t empty_hash[SHA256_LEN] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

static const uint8_t zeros[SHA256_LEN] = {0};

void ks_early(const uint8_t *psk, size_t psk_len, int resumption, uint8_t early[SHA256_LEN],
              uint8_t binder_key[SHA256_LEN]) {
    hkdf_extract(zeros, SHA256_LEN, psk, psk_len, early);
    hkdf_derive_secret(early, resumption ? "res binder" : "ext binder", empty_hash, binder_key);
}

void ks_verify_data(const uint8_t key[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
                    uint8_t out[SHA256_LEN]) {
    uint8_t finished_key[SHA256_LEN];
    hkdf_expand_label(key, "finished", NULL, 0, finished_key, SHA256_LEN);
    hmac_sha256(finished_key, SHA256_LEN, transcript, SHA256_LEN, out);
    ct_wipe(finished_key, sizeof finished_key);
}

void ks_handshake(const uint8_t early[SHA256_LEN], const uint8_t ecdhe[32],
                  const uint8_t transcript[SHA256_LEN], uint8_t handshake_secret[SHA256_LEN],
                  uint8_t c_hs[SHA256_LEN], uint8_t s_hs[SHA256_LEN]) {
    uint8_t derived[SHA256_LEN];
    hkdf_derive_secret(early, "derived", empty_hash, derived);
    hkdf_extract(derived, SHA256_LEN, ecdhe, 32, handshake_secret);
    hkdf_derive_secret(handshake_secret, "c hs traffic", transcript, c_hs);
    hkdf_derive_secret(handshake_secret, "s hs traffic", transcript, s_hs);
    ct_wipe(derived, sizeof derived);
}

void ks_master(const uint8_t handshake_secret[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
               uint8_t master[SHA256_LEN], uint8_t c_ap[SHA256_LEN], uint8_t s_ap[SHA256_LEN]) {
    uint8_t derived[SHA256_LEN];
    hkdf_derive_secret(handshake_secret, "derived", empty_hash, derived);
    hkdf_extract(derived, SHA256_LEN, zeros, SHA256_LEN, master);
    hkdf_derive_secret(master, "c ap traffic", transcript, c_ap);
    hkdf_derive_secret(master, "s ap traffic", transcript, s_ap);
    ct_wipe(derived, sizeof derived);
}

void ks_res_master(const uint8_t master[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
                   uint8_t res_master[SHA256_LEN]) {
    hkdf_derive_secret(master, "res master", transcript, res_master);
}

void ks_res_psk(const uint8_t res_master[SHA256_LEN], const uint8_t *nonce, size_t nonce_len,
                uint8_t psk[SHA256_LEN]) {
    hkdf_expand_label(res_master, "resumption", nonce, nonce_len, psk, SHA256_LEN);
}
