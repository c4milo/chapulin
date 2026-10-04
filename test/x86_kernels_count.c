// The four entries of an x86-64 host object's kernels, each a count and a
// call to the 128-bit entry it stands beside (test/x86_kernels_count.h).
// chacha20_vector_xor computes the bytes chacha20_avx2_xor computes, and
// gcm_hw.c's three entries the bytes gcm_vaes.c's compute, under the same
// contracts, so a caller sees what it would see from the kernel. On any
// other target the kernels have no entry and this file holds nothing.
#include "x86_kernels_count.h"

#include "chacha20_avx2.h"
#include "chacha20_vector.h"
#include "gcm_hw.h"
#include "gcm_vaes.h"

#ifdef __x86_64__

unsigned long x86_avx2_calls;
unsigned long x86_vaes_seal_calls;
unsigned long x86_vaes_open_calls;
unsigned long x86_vaes_counter_calls;

void chacha20_avx2_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                       uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
    x86_avx2_calls++;
    chacha20_vector_xor(key, nonce, counter, in, out, n);
}

void gcm_counter_blocks_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                             const uint8_t *in, size_t blocks, uint8_t *out) {
    x86_vaes_counter_calls++;
    gcm_counter_blocks_hw(round_keys, rounds, counter, in, blocks, out);
}

void gcm_seal_passes_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                          uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *in, size_t passes, uint8_t *out) {
    x86_vaes_seal_calls++;
    gcm_seal_passes_hw(round_keys, rounds, counter, acc, subkey, in, passes, out);
}

void gcm_open_passes_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                          uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *in, size_t passes, uint8_t *out) {
    x86_vaes_open_calls++;
    gcm_open_passes_hw(round_keys, rounds, counter, acc, subkey, in, passes, out);
}

#endif // __x86_64__
