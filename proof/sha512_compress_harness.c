// Proves: sha512_compress is memory-safe and UB-free over any eight-word
// state and any 128-byte block — the whole domain, so the stub in
// sha512_harness.c, which havocs the state after asserting the same
// reads and writes, is discharged. Wrapping uint64 arithmetic is the
// algorithm, not an accident, so only the UB classes are checked. The
// state is stored through its own type, as docs/proofs.md asks, never
// as a byte fill of a typed object.
#include "harness.h"

#include "sha512_compress.c"

uint64_t nondet_u64(void);

int main(void) {
    uint64_t h[8];
    for (size_t i = 0; i < 8; i++) {
        h[i] = nondet_u64();
    }
    uint8_t block[SHA512_BLOCK];
    fill_nondet(block, sizeof block);
    sha512_compress(h, block);
    return 0;
}
