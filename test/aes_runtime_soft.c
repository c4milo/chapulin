// quic_aes_soft.c's two entries in a QUIC host object under second names, and the
// entries aes.c calls in their place, each a count and a call
// (test/aes_runtime_count.h). The #defines rewrite both the definitions in
// quic_aes_soft.c and the declarations it reads from aes_block.h, because
// they are in effect before that header is read, as test/aes_equiv_soft.c's
// are.
#define aes_soft_expand_round_keys table_expand_round_keys
#define aes_soft_cipher_block table_cipher_block

#include "quic_aes_soft.c"

#undef aes_soft_expand_round_keys
#undef aes_soft_cipher_block

#include "aes_runtime_count.h"

unsigned long aes_runtime_table_calls;

// The declarations aes_block.h gave these under the names above, restated
// under the names aes.c calls.
void aes_soft_expand_round_keys(const uint8_t key[AES_128_KEY],
                                uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]);
void aes_soft_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]);

void aes_soft_expand_round_keys(const uint8_t key[AES_128_KEY],
                                uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    aes_runtime_table_calls++;
    table_expand_round_keys(key, round_keys);
}

void aes_soft_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    aes_runtime_table_calls++;
    table_cipher_block(round_keys, in, out);
}
