// quic_gcm.c compiled with one more entry, for bench/aead.c only.
// counter_mode and first_counter_block are static in quic_gcm.c, so this
// file includes the source rather than linking its object, the way
// test/aes_equiv_hw.c includes quic_aes_hw.c. The bench links this object
// in place of quic_gcm.o, and quic_gcm.c itself is unchanged: gcm_seal,
// gcm_open and gcm_ghash compile from the same text the library does,
// with the GHASH the build's AES value picks.
#include "quic_gcm.c"

#include "aead_gcm.h"

void bench_gcm_counter_mode(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *in,
                            size_t n, uint8_t *out) {
    uint8_t counter[AES_BLOCK];
    first_counter_block(counter, nonce);
    counter_mode(&k->key, counter, in, n, out);
}
