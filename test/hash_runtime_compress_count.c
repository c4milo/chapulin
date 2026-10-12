// SHA-512's two compression functions for bin/hash_runtime_test, each a
// count and a call to sha512_compress_blocks.c's code
// (test/hash_runtime_count.h). The binary links this file in place of
// sha512_compress_blocks.c and of sha512_compress.c, so it reads which of
// the two a host object's sha512.c called (docs/decisions.md 127).
//
// sha512_compress_blocks.c compiles here under a second name for its
// function, so this file can define the library's name as the counted one.
// sha512_compress, the reference's name, takes one block, which is the
// other function's contract at a count of 1, so its count runs that code
// too and a caller gets the digest sha512_compress.c would give it.
#define sha512_compress_blocks sha512_compress_blocks_uncounted
#include "sha512_compress_blocks.c"
#undef sha512_compress_blocks

#include "hash_runtime_count.h"
#include "sha512_compress.h"

// sha512_compress_blocks.h's declaration of the call, which the rename
// above gave the second name.
void sha512_compress_blocks(uint64_t state[8], const uint8_t *p, size_t blocks);

unsigned long sha512_compress_blocks_calls;
unsigned long sha512_compress_calls;

void sha512_compress_blocks(uint64_t state[8], const uint8_t *p, size_t blocks) {
    sha512_compress_blocks_calls++;
    sha512_compress_blocks_uncounted(state, p, blocks);
}

void sha512_compress(uint64_t h[8], const uint8_t block[SHA512_BLOCK]) {
    sha512_compress_calls++;
    sha512_compress_blocks_uncounted(h, block, 1);
}
