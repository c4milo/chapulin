// gcm.c a second time, under second names, so the test can reach the
// portable GHASH's two static steps, and so one binary holds the AEAD
// twice. test/ghash_equiv_test.c calls both copies.
//
// The line that builds bin/ghash_equiv_test compiles every file on it as
// a QUIC host object (-DCH_CPU_RUNTIME), so gcm.c holds both GHASH bodies
// and runs the one a schedule names (aes_schedule.h): ghash_hw.c's for a
// schedule on the AES instructions, and the 128-step multiply and the
// hash_data loop the proofs in proof/ cover for a schedule on the table.
// The copy here compiles the same way. The test runs the AEAD through it
// under a schedule on the table, the one-block loop and the portable
// GHASH, and through the other copy under a schedule on the
// instructions; bin/aes_equiv_test holds the two block ciphers to each
// other.
//
// The three #defines rewrite both the definitions in gcm.c and the
// declarations it reads from gcm.h, because they are in effect
// before that header is read. test/aes_equiv_soft.c renames the AES
// block cipher the same way.
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
