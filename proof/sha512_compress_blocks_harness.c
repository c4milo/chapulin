// Proves: sha512_compress_blocks, the compression function a host object
// runs (sha512_compress_blocks.c under -DCH_CPU_RUNTIME), is memory-safe and
// UB-free over any eight-word state and any zero, one or two blocks: the
// claim sha512_compress_harness.c proves of sha512_compress over one block.
// Each count has a call of its own, on an array of exactly that many
// blocks, so a read past the count's last block is a read outside its
// array, which the bounds check fails. The call with no block takes a NULL
// pointer, because the contract says it reads nothing there. Two blocks
// take the path from the end of one block to the start of the next once.
//
// Wrapping uint64 arithmetic is the algorithm, not an accident, so only the
// UB classes are checked. The state is stored through its own type, as
// docs/proofs.md asks, never as a byte fill of a typed object, and it is
// havocked before each call. The file reads its ring and the state through
// volatile pointers, which CBMC reads as plain reads.
//
// What it does not prove: that the state it writes is sha512_compress's.
// sha512_compress_blocks_steps_harness.c and
// sha512_compress_blocks_advancing_harness.c prove each step of the file
// against FIPS 180-4's form, and bin/sha2_equiv_test and the published
// vectors hold the whole function (docs/verification.md).
#include "harness.h"

#include "sha512_compress_blocks.c"

uint64_t nondet_u64(void);

static void havoc_state(uint64_t state[8]) {
    for (size_t i = 0; i < 8; i++) {
        state[i] = nondet_u64();
    }
}

int main(void) {
    uint64_t state[8];
    havoc_state(state);
    sha512_compress_blocks(state, NULL, 0);

    uint8_t one_block[SHA512_BLOCK];
    fill_nondet(one_block, sizeof one_block);
    havoc_state(state);
    sha512_compress_blocks(state, one_block, 1);

    uint8_t two_blocks[2 * SHA512_BLOCK];
    fill_nondet(two_blocks, sizeof two_blocks);
    havoc_state(state);
    sha512_compress_blocks(state, two_blocks, 2);
    return 0;
}
