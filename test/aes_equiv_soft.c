// The AES=soft implementation under a second name, so one binary can
// hold two implementations that define the same two entries.
//
// The #defines rewrite both the definitions in quic_aes_soft.c and the
// declarations it reads from quic_aes_block.h, because they are in
// effect before that header is read. test/aes_equiv_hw.c is the same
// file for AES=hw, and test/aes_equiv_test.c calls both.
//
// CH_AES_256_TEST turns on the AES-256 pair, which quic_aes_soft.c holds
// as the software reference for tests and proofs alone (quic_aes.h).
//
// CLAUDE.md lets a test binary compile two implementations that a
// library object may never hold at once, the way the test binaries
// compile both PIN algorithms so both stay tested.
#define CH_AES_256_TEST 1
#define aes_expand_round_keys aes_expand_round_keys_soft
#define aes_cipher_block aes_cipher_block_soft
#define aes_expand_round_keys_256 aes_expand_round_keys_256_soft
#define aes_cipher_block_256 aes_cipher_block_256_soft

#include "quic_aes_soft.c"
