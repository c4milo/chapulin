// TLS 1.3 key schedule (RFC 9846 §7.1), specialized to one PSK and
// SHA-256. Pure functions over 32-byte secrets; the handshake owns where
// they live and when they die.
#ifndef CH_KEYSCHED_H
#define CH_KEYSCHED_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

// early_secret = Extract(0, psk); binder_key = Derive-Secret(early,
// "ext binder" | "res binder", ""). resumption selects the label.
void ks_early(const uint8_t *psk, size_t psk_len, int resumption, uint8_t early[SHA256_LEN],
              uint8_t binder_key[SHA256_LEN]);

// binder/finished MAC: HMAC(Expand-Label(key, "finished"), transcript).
void ks_verify_data(const uint8_t key[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
                    uint8_t out[SHA256_LEN]);

// handshake_secret = Extract(Derive-Secret(early, "derived", ""), ecdhe);
// c/s handshake traffic secrets from the CH..SH transcript.
void ks_handshake(const uint8_t early[SHA256_LEN], const uint8_t ecdhe[32],
                  const uint8_t transcript[SHA256_LEN], uint8_t handshake_secret[SHA256_LEN],
                  uint8_t c_hs[SHA256_LEN], uint8_t s_hs[SHA256_LEN]);

// master = Extract(Derive-Secret(handshake_secret, "derived", ""), 0); c/s application
// traffic secrets from the CH..server-Finished transcript.
void ks_master(const uint8_t handshake_secret[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
               uint8_t master[SHA256_LEN], uint8_t c_ap[SHA256_LEN], uint8_t s_ap[SHA256_LEN]);

// resumption_master from the CH..client-Finished transcript; a ticket's
// PSK is Expand-Label(res_master, "resumption", ticket_nonce, 32).
void ks_res_master(const uint8_t master[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
                   uint8_t res_master[SHA256_LEN]);
void ks_res_psk(const uint8_t res_master[SHA256_LEN], const uint8_t *nonce, size_t nonce_len,
                uint8_t psk[SHA256_LEN]);

#endif
