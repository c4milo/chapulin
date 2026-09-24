// quic_gcm.c compiled with three more entries, for bench/aead.c only.
// counter_mode and first_counter_block are static in quic_gcm.c, so this
// file includes the source rather than linking its object, the way
// test/aes_equiv_hw.c includes quic_aes_hw.c. The bench links this object
// in place of quic_gcm.o, and quic_gcm.c itself is unchanged: gcm_seal,
// gcm_open and gcm_ghash compile from the same text the library does.
#include "quic_gcm.c"

#include "aead_gcm.h"

void bench_gcm_counter_mode(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *in,
                            size_t n, uint8_t *out) {
    uint8_t counter[AES_BLOCK];
    first_counter_block(counter, nonce);
    counter_mode(&k->key, counter, in, n, out);
}

#ifdef GHASH_CLMUL_INSTRUCTION
void bench_ghash_clmul(const aes_public_key *k, const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t n, uint8_t out[AES_BLOCK]) {
    uint8_t subkey[AES_BLOCK];
    aes_encrypt_schedule(&k->key, ZERO_BLOCK, subkey);
    ghash_clmul(subkey, aad, aad_len, ct, n, out);
    ct_wipe(subkey, sizeof subkey);
}

// seal_schedule and compute_tag with one call changed, so the two seals
// differ only in the multiply, wipes included.
void bench_gcm_seal_clmul(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                          size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                          uint8_t tag[GCM_TAG]) {
    uint8_t first_counter[AES_BLOCK];
    first_counter_block(first_counter, nonce);
    uint8_t counter[AES_BLOCK];
    memcpy(counter, first_counter, AES_BLOCK);
    counter_mode(&k->key, counter, pt, n, ct);

    uint8_t hashed[AES_BLOCK];
    bench_ghash_clmul(k, aad, aad_len, ct, n, hashed);
    uint8_t mask[AES_BLOCK];
    aes_encrypt_schedule(&k->key, first_counter, mask);
    for (size_t i = 0; i < GCM_TAG; i++) {
        tag[i] = (uint8_t)(hashed[i] ^ mask[i]);
    }
    ct_wipe(hashed, sizeof hashed);
    ct_wipe(mask, sizeof mask);
}
#endif
