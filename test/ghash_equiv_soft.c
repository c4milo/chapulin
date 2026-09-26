// gcm.c with its portable GHASH, under second names, so one binary
// can hold the AEAD twice: once over the portable GHASH and once over
// ghash_hw.c's. test/ghash_equiv_test.c calls both.
//
// The line that builds bin/ghash_equiv_test defines CH_AES_HW for every
// file on it, because gcm.c and ghash_hw.c compiled there are
// the AES=hw build. This file undefines it before gcm.c is read, so
// the copy compiled here takes the #else arm: the 128-step multiply and
// the hash_data loop the proofs in proof/ cover. The AES block cipher is
// aes_hw.c for both copies, so GHASH is the only difference.
//
// The three #defines rewrite both the definitions in gcm.c and the
// declarations it reads from gcm.h, because they are in effect
// before that header is read. test/aes_equiv_soft.c renames the AES
// block cipher the same way.
#undef CH_AES_HW
#define gcm_seal gcm_seal_soft
#define gcm_open gcm_open_soft
#define gcm_ghash gcm_ghash_soft

#include "gcm.c"

// gcm.c keeps the two GHASH steps static, so they are reachable
// from the test main only through these.
void ghash_multiply_soft(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]);
void ghash_hash_data_soft(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *data, size_t n);

void ghash_multiply_soft(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]) {
    multiply_by_subkey(acc, subkey);
}

void ghash_hash_data_soft(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *data, size_t n) {
    hash_data(acc, subkey, data, n);
}
