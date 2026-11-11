// PBKDF2 with HMAC-SHA-256 (RFC 8018 section 5.2), which SCRAM-SHA-256
// calls Hi() (RFC 5802 section 2.2). scram.c forwards
// ch_pbkdf2_hmac_sha256 to it, and scram.h states the contract. Only a
// CH_SCRAM build holds it.
#ifndef CH_PBKDF2_H
#define CH_PBKDF2_H

#include <stddef.h>
#include <stdint.h>

#ifdef CH_SCRAM
int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt,
                       size_t salt_len, uint32_t iteration_count, uint8_t *out, size_t out_len);
#endif

#endif
