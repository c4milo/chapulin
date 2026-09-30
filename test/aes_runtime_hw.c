// aes_hw.c's four entries, ghash_hw.c's two and gcm_hw.c's three under
// second names, and the entries aes.c and gcm.c call in their place, each
// a count and a call (test/aes_runtime_count.h). test/aes_runtime_soft.c
// states why the #defines come before the includes.
//
// The files compile here as an AES=runtime build compiles them: with no
// instruction flag, each function turning the instructions on through its
// own target attribute. The entries below carry none, and call the
// renamed ones, so a count runs on any CPU, and an instruction runs only
// inside a call into the file that holds it. gcm_hw.c's one-pass seal and
// open run the AES instructions and the carry-less multiply both, so a
// call to either counts once for each.
#define aes_expand_round_keys instruction_expand_round_keys
#define aes_cipher_block instruction_cipher_block
#define aes_expand_round_keys_256 instruction_expand_round_keys_256
#define aes_cipher_block_256 instruction_cipher_block_256
#define gcm_counter_blocks_hw instruction_counter_blocks
#define gcm_seal_passes_hw instruction_seal_passes
#define gcm_open_passes_hw instruction_open_passes
#define gcm_multiply_by_subkey_hw clmul_multiply_by_subkey
#define gcm_hash_data_hw clmul_hash_data

#include "aes_hw.c"
#include "gcm_hw.c"
#include "ghash_hw.c"

#undef aes_expand_round_keys
#undef aes_cipher_block
#undef aes_expand_round_keys_256
#undef aes_cipher_block_256
#undef gcm_counter_blocks_hw
#undef gcm_seal_passes_hw
#undef gcm_open_passes_hw
#undef gcm_multiply_by_subkey_hw
#undef gcm_hash_data_hw

#include "aes_runtime_count.h"

unsigned long aes_runtime_instruction_calls;
unsigned long aes_runtime_clmul_calls;

// The declarations aes_block.h, gcm_hw.h and ghash_hw.h gave these under
// the names above, restated under the names aes.c and gcm.c call.
void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]);
void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]);
void aes_expand_round_keys_256(const uint8_t key[AES_256_KEY],
                               uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK]);
void aes_cipher_block_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                          const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]);
void gcm_counter_blocks_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                           const uint8_t *in, size_t blocks, uint8_t *out);
void gcm_seal_passes_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                        uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                        size_t passes, uint8_t *out);
void gcm_open_passes_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                        uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                        size_t passes, uint8_t *out);
void gcm_multiply_by_subkey_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]);
void gcm_hash_data_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *data,
                      size_t n);

void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    aes_runtime_instruction_calls++;
    instruction_expand_round_keys(key, round_keys);
}

void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    aes_runtime_instruction_calls++;
    instruction_cipher_block(round_keys, in, out);
}

void aes_expand_round_keys_256(const uint8_t key[AES_256_KEY],
                               uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK]) {
    aes_runtime_instruction_calls++;
    instruction_expand_round_keys_256(key, round_keys);
}

void aes_cipher_block_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                          const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    aes_runtime_instruction_calls++;
    instruction_cipher_block_256(round_keys, in, out);
}

void gcm_counter_blocks_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                           const uint8_t *in, size_t blocks, uint8_t *out) {
    aes_runtime_instruction_calls++;
    instruction_counter_blocks(round_keys, rounds, counter, in, blocks, out);
}

void gcm_seal_passes_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                        uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                        size_t passes, uint8_t *out) {
    aes_runtime_instruction_calls++;
    aes_runtime_clmul_calls++;
    instruction_seal_passes(round_keys, rounds, counter, acc, subkey, in, passes, out);
}

void gcm_open_passes_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                        uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                        size_t passes, uint8_t *out) {
    aes_runtime_instruction_calls++;
    aes_runtime_clmul_calls++;
    instruction_open_passes(round_keys, rounds, counter, acc, subkey, in, passes, out);
}

void gcm_multiply_by_subkey_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]) {
    aes_runtime_clmul_calls++;
    clmul_multiply_by_subkey(acc, subkey);
}

void gcm_hash_data_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *data,
                      size_t n) {
    aes_runtime_clmul_calls++;
    clmul_hash_data(acc, subkey, data, n);
}
