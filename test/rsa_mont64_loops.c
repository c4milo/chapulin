// rsa_mont64.c with RSA_MONT64_BLOCKS at 0, under second names, so one
// binary can hold the loops beside the blocks (docs/decisions.md 118).
// bin/rsa_blocks_equiv_test compiles every unit with -DRSA_MONT64_BLOCKS=1,
// so rsa_mont64.c beside it runs rsa_mont64_blocks.c's blocks for a word
// count that is a multiple of 4. This unit sets the define back to 0 and
// compiles the loops, which the proofs, bin/rsa_equiv_test_compare and
// bin/rsa_equiv_test_sum hold.
//
// The #defines rewrite both the definitions in rsa_mont64.c and the
// declarations it reads from rsa_mont64.h, because they are in effect
// before that header is read. test/rsa_equiv_portable.c is the same
// construction for rsa_mont.c's 32-bit arm. A function rsa_mont64.c gains
// and this list lacks is defined twice, so the binary fails to link.
#undef RSA_MONT64_BLOCKS
#define RSA_MONT64_BLOCKS 0
#define rsa_mont64_from_bytes rsa_mont64_loops_from_bytes
#define rsa_mont64_to_bytes rsa_mont64_loops_to_bytes
#define rsa_mont64_modulus_init rsa_mont64_loops_modulus_init
#define rsa_mont64_modulus_load rsa_mont64_loops_modulus_load
#define rsa_mont64_mont_mul rsa_mont64_loops_mont_mul
#define rsa_mont64_mont_square rsa_mont64_loops_mont_square
#define rsa_mont64_add rsa_mont64_loops_add
#define rsa_mont64_sub rsa_mont64_loops_sub
#define rsa_mont64_reduce_once rsa_mont64_loops_reduce_once
#define rsa_mont64_reduce_once_with_top rsa_mont64_loops_reduce_once_with_top
#define rsa_mont64_mul_add rsa_mont64_loops_mul_add
#define rsa_mont64_public rsa_mont64_loops_public

#include "rsa_mont64.c"
