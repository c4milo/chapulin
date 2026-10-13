// The fifteen entries of an x86-64 host object's kernels, each a count and a
// call to the code it stands beside (test/x86_kernels_count.h).
// chacha20_vector_xor computes the bytes chacha20_avx2_xor and
// chacha20_avx512_xor compute,
// gcm_hw.c's three entries the bytes gcm_vaes.c's compute, gcm_on_loops below
// the bytes gcm_avx512_kernel.c's four compute, mlkem.c's
// three session calls the bytes of mlkem_avx2.c's, and
// poly1305_vector_blocks_native the accumulator poly1305_avx2_blocks_native
// and poly1305_ifma_blocks_native compute, and sha512_compress_blocks the
// state sha512_avx2_compress_blocks computes, under the same contracts, so a caller sees what it
// would see from the kernel. On any other target the kernels have no entry and this file holds
// nothing.
// test/rsa_ifma_count.c stands beside rsa_ifma.c's entry the same way.
#include "x86_kernels_count.h"

#include "aes_block.h"
#include "chacha20_avx2.h"
#include "chacha20_avx512.h"
#include "chacha20_vector.h"
#include "gcm_avx512_kernel.h"
#include "gcm_hw.h"
#include "gcm_vaes.h"
#include "ghash_hw.h"
#include "mlkem.h"
#include "poly1305_avx2.h"
#include "poly1305_ifma.h"
#include "poly1305_vector.h"
#include "sha512_avx2.h"
#include "sha512_compress_blocks.h"

#ifdef __x86_64__

#include <string.h>

unsigned long x86_avx2_calls;
unsigned long x86_avx512_calls;
unsigned long x86_vaes_seal_calls;
unsigned long x86_vaes_open_calls;
unsigned long x86_vaes_counter_calls;
unsigned long x86_gcm_avx512_seal_calls;
unsigned long x86_gcm_avx512_open_calls;
unsigned long x86_mlkem_keygen_calls;
unsigned long x86_mlkem_encaps_calls;
unsigned long x86_mlkem_decaps_calls;
unsigned long x86_poly1305_avx2_calls;
unsigned long x86_poly1305_ifma_calls;
unsigned long x86_sha512_avx2_calls;

void chacha20_avx2_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                       uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
    x86_avx2_calls++;
    chacha20_vector_xor(key, nonce, counter, in, out, n);
}

void chacha20_avx512_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                         uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
    x86_avx512_calls++;
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

// One block through the forward cipher under round keys for rounds rounds.
static void cipher_block(const uint8_t *round_keys, size_t rounds, const uint8_t in[AES_BLOCK],
                         uint8_t out[AES_BLOCK]) {
#ifdef CH_AES_256
    if (rounds == AES_256_ROUNDS) {
        aes_cipher_block_256(round_keys, in, out);
        return;
    }
#else
    (void)rounds;
#endif
    aes_cipher_block(round_keys, in, out);
}

// SP 800-38D's GCM-AE, or GCM-AD without the comparison where seal is 0, on
// gcm_hw.c's counter mode and ghash_hw.c's GHASH: the bytes and the tag
// gcm_avx512_kernel.c's four functions write, under their contracts. The
// open hashes the ciphertext before it writes any plaintext, so in place
// and below works as it does there.
static void gcm_on_loops(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                         const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t n,
                         uint8_t *out, uint8_t tag[AES_BLOCK], int seal) {
    static const uint8_t zero[AES_BLOCK] = {0};
    uint8_t subkey[AES_BLOCK];
    uint8_t acc[AES_BLOCK] = {0};
    uint8_t counter[AES_BLOCK] = {0};
    uint8_t block[AES_BLOCK];
    cipher_block(round_keys, rounds, zero, subkey);
    gcm_hash_data_hw(acc, subkey, aad, aad_len);
    if (!seal) {
        gcm_hash_data_hw(acc, subkey, in, n);
    }
    memcpy(counter, nonce, AES_IV);
    counter[AES_BLOCK - 1] = 1;
    uint8_t first[AES_BLOCK];
    memcpy(first, counter, AES_BLOCK);
    size_t whole = n / AES_BLOCK * AES_BLOCK;
    gcm_counter_blocks_hw(round_keys, rounds, counter, in, n / AES_BLOCK, out);
    if (whole < n) {
        // The counter holds the last whole block's, and inc32 gives the
        // next: one more in its last four bytes, read big-endian, modulo
        // 2^32.
        uint32_t count = (uint32_t)counter[12] << 24 | (uint32_t)counter[13] << 16 |
                         (uint32_t)counter[14] << 8 | counter[15];
        count++;
        for (size_t i = 0; i < 4; i++) {
            counter[12 + i] = (uint8_t)(count >> (24 - 8 * i));
        }
        cipher_block(round_keys, rounds, counter, block);
        for (size_t i = whole; i < n; i++) {
            out[i] = (uint8_t)(in[i] ^ block[i - whole]);
        }
    }
    if (seal) {
        gcm_hash_data_hw(acc, subkey, out, n);
    }
    const uint64_t bits[2] = {(uint64_t)aad_len * 8U, (uint64_t)n * 8U};
    for (size_t i = 0; i < AES_BLOCK; i++) {
        acc[i] = (uint8_t)(acc[i] ^ (uint8_t)(bits[i / 8] >> (8 * (7 - i % 8))));
    }
    gcm_multiply_by_subkey_hw(acc, subkey);
    cipher_block(round_keys, rounds, first, block);
    for (size_t i = 0; i < AES_BLOCK; i++) {
        tag[i] = (uint8_t)(acc[i] ^ block[i]);
    }
}

void gcm_avx512_seal_128(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                         uint8_t tag[AES_BLOCK]) {
    x86_gcm_avx512_seal_calls++;
    gcm_on_loops(round_keys, AES_128_ROUNDS, nonce, aad, aad_len, pt, n, ct, tag, 1);
}

void gcm_avx512_open_128(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                         uint8_t want[AES_BLOCK]) {
    x86_gcm_avx512_open_calls++;
    gcm_on_loops(round_keys, AES_128_ROUNDS, nonce, aad, aad_len, ct, n, pt, want, 0);
}

#ifdef CH_AES_256
void gcm_avx512_seal_256(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                         uint8_t tag[AES_BLOCK]) {
    x86_gcm_avx512_seal_calls++;
    gcm_on_loops(round_keys, AES_256_ROUNDS, nonce, aad, aad_len, pt, n, ct, tag, 1);
}

void gcm_avx512_open_256(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                         uint8_t want[AES_BLOCK]) {
    x86_gcm_avx512_open_calls++;
    gcm_on_loops(round_keys, AES_256_ROUNDS, nonce, aad, aad_len, ct, n, pt, want, 0);
}
#endif

void mlkem_keygen_dk_avx2(uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32], const uint8_t z[32]) {
    x86_mlkem_keygen_calls++;
    mlkem_keygen_dk(dk, d, z);
}

int mlkem_encaps_derand_avx2(uint8_t widemul, uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                             const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]) {
    x86_mlkem_encaps_calls++;
    return mlkem_encaps_derand(widemul, ct, ss, ek, m);
}

void mlkem_decaps_avx2(uint8_t widemul, uint8_t ss[MLKEM_SS_LEN], const uint8_t ct[MLKEM_CT_LEN],
                       const uint8_t dk[MLKEM_DK_LEN]) {
    x86_mlkem_decaps_calls++;
    mlkem_decaps(widemul, ss, ct, dk);
}

// poly1305_vector_blocks_native takes any positive multiple of its group
// of four blocks, and a group of eight is two of them.
void poly1305_avx2_blocks_native(poly1305 *p, const uint8_t *m, size_t n) {
    x86_poly1305_avx2_calls++;
    poly1305_vector_blocks_native(p, m, n);
}

// A group of sixteen blocks is four of poly1305_vector_blocks_native's.
void poly1305_ifma_blocks_native(poly1305 *p, const uint8_t *m, size_t n) {
    x86_poly1305_ifma_calls++;
    poly1305_vector_blocks_native(p, m, n);
}

// sha512_compress_blocks is the binary's counted one
// (test/hash_runtime_compress_count.c), so its count holds every
// compression call, and this one the calls a session sent to the kernel.
void sha512_avx2_compress_blocks(uint64_t state[8], const uint8_t *p, size_t blocks) {
    x86_sha512_avx2_calls++;
    sha512_compress_blocks(state, p, blocks);
}

#endif // __x86_64__
