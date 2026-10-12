// Proves: the sha512 and sha384 framing as a host object compiles it
// (sha512.c's first arm, under -DCH_CPU_RUNTIME) is memory-safe and UB-free:
//
//   sha512_update from any context whose fill is below a block, the
//   invariant every call here keeps, over any input of up to
//   SHA512_HOST_INPUT_MAX bytes. That runs every copy into the pending
//   block, a chunk that fills it and then holds two whole blocks, and a
//   tail after them. The update leaves fill below a block, which is what
//   lets the next call start from any such context. An update of no bytes
//   takes a NULL pointer, as the contract allows.
//
//   sha512_final and sha384_final from any such context: the padding from
//   every fill, in one block or in two, the 128-bit length from any byte
//   count, and the digest's words.
//
//   sha512_of and sha384_of over any message of up to that many bytes,
//   with the wipe of the context they hash in.
//
// Each call that compresses is followed by the wipe of the stack below it,
// which runs here too. sha512_harness.c proves the second arm, a device
// object's, over a message in two chunks.
//
// An input is a heap object of exactly its length, so a read one byte past
// it fails the bounds check, which a longer array could not show, and its
// bytes are whatever malloc left there, which CBMC takes as any bytes
// (docs/proofs.md). The formula's size does not follow the input's bound:
// it measured the same at 127 bytes as at 320.
//
// sha512_compress_blocks is stubbed to its contract here: it reads
// blocks * SHA512_BLOCK bytes at p and writes the eight-word state,
// asserted, with the state havocked through its own type. Every call the
// framing makes at this bound passes one or two blocks, which the stub
// asserts, and sha512_compress_blocks_harness.c proves the function itself
// at those counts, so the stub is discharged. ct_wipe is
// proof/ct_wipe_stub.c's loop, whose stores are bounds-checked writes, so
// the two wipes write inside the array and the context they are handed.
// The call of wipe_frame goes through a pointer that sha512.c declares
// volatile, which CBMC reads as the function it was initialized with.
//
// What it does not prove: that the wipe covers the frame the compression
// function used, which is the compiler's layout. bin/sha2_equiv_test
// measures it and searches the stack each call leaves
// (docs/verification.md).
#include "harness.h"

#include <stdlib.h>

#include "sha512.c"

#define SHA512_HOST_INPUT_MAX 320

uint64_t nondet_u64(void);

void sha512_compress_blocks(uint64_t state[8], const uint8_t *p, size_t blocks) {
    __CPROVER_assert(blocks == 1 || blocks == 2,
                     "sha512_compress_blocks: a count its own harness runs");
    __CPROVER_assert(__CPROVER_w_ok(state, 8 * sizeof(uint64_t)),
                     "sha512_compress_blocks: state writable");
    __CPROVER_assert(__CPROVER_r_ok(p, blocks * SHA512_BLOCK),
                     "sha512_compress_blocks: blocks readable");
    for (size_t i = 0; i < 8; i++) {
        state[i] = nondet_u64();
    }
}

// Any context a call here can leave: each field stored through its own
// type, and fill below a block.
static void havoc_context(sha512 *s) {
    for (size_t i = 0; i < 8; i++) {
        s->h[i] = nondet_u64();
    }
    s->total_bytes = nondet_u64();
    fill_nondet(s->block, sizeof s->block);
    s->fill = nondet_size_t();
    __CPROVER_assume(s->fill < SHA512_BLOCK);
}

// Any input of *n bytes, *n at most SHA512_HOST_INPUT_MAX, as a heap object
// of that length.
static const uint8_t *any_input(size_t *n) {
    *n = nondet_size_t();
    __CPROVER_assume(*n <= SHA512_HOST_INPUT_MAX);
    uint8_t *input = malloc(*n);
    __CPROVER_assume(input != NULL);
    return input;
}

static void prove_update(void) {
    size_t n;
    const uint8_t *input = any_input(&n);
    sha512 s;
    havoc_context(&s);
    sha512_update(&s, input, n);
    __CPROVER_assert(s.fill < SHA512_BLOCK, "sha512_update leaves fill below a block");
    havoc_context(&s);
    sha512_update(&s, NULL, 0);
    __CPROVER_assert(s.fill < SHA512_BLOCK, "an update of no bytes leaves fill below a block");
}

static void prove_finals(void) {
    sha512 s;
    uint8_t out512[SHA512_LEN];
    havoc_context(&s);
    sha512_final(&s, out512);
    uint8_t out384[SHA384_LEN];
    havoc_context(&s);
    sha384_final(&s, out384);
}

static void prove_whole_messages(void) {
    size_t n;
    const uint8_t *input = any_input(&n);
    uint8_t out512[SHA512_LEN];
    sha512_of(input, n, out512);
    uint8_t out384[SHA384_LEN];
    sha384_of(input, n, out384);
}

int main(void) {
    prove_update();
    prove_finals();
    prove_whole_messages();
    return 0;
}
