// The entry bench/aead.c needs that gcm.c keeps static.
// bench/aead_gcm.c compiles gcm.c with it added, so the bench can
// time the two halves of AES-128-GCM apart. None of this is library code.
#ifndef CH_BENCH_AEAD_GCM_H
#define CH_BENCH_AEAD_GCM_H

#include <stddef.h>
#include <stdint.h>

#include "gcm.h"

// The counter-mode half of gcm_seal: gcm.c's counter_mode from the
// counter block after the one nonce names, over n bytes of in into out.
void bench_gcm_counter_mode(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *in,
                            size_t n, uint8_t *out);

#endif
