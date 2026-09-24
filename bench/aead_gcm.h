// Entries bench/aead.c needs that quic_gcm.c keeps static.
// bench/aead_gcm.c compiles quic_gcm.c with these added, so the bench can
// time the two halves of AES-128-GCM apart and build an AES-128-GCM seal
// on the prototype GHASH. None of this is library code.
#ifndef CH_BENCH_AEAD_GCM_H
#define CH_BENCH_AEAD_GCM_H

#include <stddef.h>
#include <stdint.h>

#include "ghash_clmul.h"
#include "quic_gcm.h"

// The counter-mode half of gcm_seal: quic_gcm.c's counter_mode from the
// counter block after the one nonce names, over n bytes of in into out.
void bench_gcm_counter_mode(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *in,
                            size_t n, uint8_t *out);

#ifdef GHASH_CLMUL_INSTRUCTION
// gcm_ghash with the prototype in place of quic_gcm.c's multiply: the
// hash subkey is one forward-cipher block under k, as gcm_ghash computes
// it, and ghash_clmul does the rest.
void bench_ghash_clmul(const aes_public_key *k, const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t n, uint8_t out[AES_BLOCK]);

// gcm_seal with the prototype GHASH: quic_gcm.c's counter mode and tag
// mask, and bench_ghash_clmul for the hash. Same arguments, same output.
void bench_gcm_seal_clmul(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                          size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                          uint8_t tag[GCM_TAG]);
#endif

#endif
