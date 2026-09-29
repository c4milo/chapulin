// gcm.c compiled with two more entries, for bench/record.c only.
// counter_mode, compute_tag and first_counter_block are static in gcm.c, so
// this file includes the source, the way bench/aead_gcm.c does. The bench
// also links the library's own gcm.o, so this file first renames the
// external names gcm.c defines: the copy compiled here serves the two
// entries below, and nothing calls the renamed functions.
#define gcm_seal bench_gcm_copy_seal
#define gcm_open bench_gcm_copy_open
#define gcm_ghash bench_gcm_copy_ghash
#define gcm_traffic_seal bench_gcm_copy_traffic_seal
#define gcm_traffic_open bench_gcm_copy_traffic_open

#include "gcm.c"

#include "record_stages.h"

void bench_gcm_counter_mode(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                            const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t counter[AES_BLOCK];
    first_counter_block(counter, nonce);
    counter_mode(&k->key, counter, in, n, out);
}

void bench_gcm_compute_tag(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                           const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                           uint8_t tag[GCM_TAG]) {
    uint8_t first_counter[AES_BLOCK];
    first_counter_block(first_counter, nonce);
    compute_tag(&k->key, first_counter, aad, aad_len, ct, n, tag);
}
