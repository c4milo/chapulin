// The rsa_mont_host proof with rsa_mont64.h's RSA_MONT64_BLOCKS set to 1, as a
// clang build for arm64 sets it: at the build's largest length, 48 words, the
// division that multiplies the base by R runs each step in blocks of four
// words, times_word_mod_blocks, over the words of R - m, and adds the
// modulus back with add_modulus_blocks (docs/decisions.md 208). The block
// itself, rsa_mont64_block_add, is a contract here, as
// rsa_mont_host_harness.c says. The cbmc of
// the prove job preprocesses as gcc does for x86-64, which leaves the
// blocks off, so this file names them. A proof name is one launch line, so
// the variant gets its own file, the rsa_mul_webpki precedent.
#define RSA_MONT64_BLOCKS 1
#include "rsa_mont_host_harness.c"
