// gcm.c compiled a second time with its forward cipher replaced, for
// bench/record.c only. The first #define renames every call gcm.c makes to
// aes_encrypt_schedule, and the declaration it reads from aes.h, to
// bench/record_stub.c's stub, which copies the counter block to the
// keystream and runs no round. counter_mode's own text is unchanged, so
// bench_gcm_counter_mode_without_aes times its counter increments, its
// calls and its keystream exclusive-or. The other renames keep this copy's
// external names apart from the library's gcm.o, which the bench also
// links.
#define aes_encrypt_schedule bench_stub_encrypt_schedule
#define gcm_seal bench_gcm_stub_seal
#define gcm_open bench_gcm_stub_open
#define gcm_ghash bench_gcm_stub_ghash
#define gcm_traffic_seal bench_gcm_stub_traffic_seal
#define gcm_traffic_open bench_gcm_stub_traffic_open

#include "gcm.c"

#include "record_stages.h"

void bench_gcm_counter_mode_without_aes(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                                        const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t counter[AES_BLOCK];
    first_counter_block(counter, nonce);
    counter_mode(&k->key, counter, in, n, out);
}
