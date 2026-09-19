// The AES=hw implementation under a second name. test/aes_equiv_soft.c
// states why the two renames are here and what they rewrite.
//
// CH_AES_HW is defined here rather than on the compile line because the
// same line compiles test/aes_equiv_soft.c, whose body is guarded off by
// that macro. Each wrapper turns on its own arm.
#define CH_AES_HW 1
#define aes_expand_round_keys aes_expand_round_keys_hw
#define aes_cipher_block aes_cipher_block_hw

#include "quic_aes_hw.c"
