// chacha20_vector.c compiled with one more entry, for bench/record.c's
// CHACHA=vector builds only. four_blocks, setup and store_16 are static in
// chacha20_vector.c, so this file includes the source. Those builds also
// link the library's own chacha20_vector.o, so this file first renames the
// external name chacha20_vector.c defines, and nothing calls the renamed
// function.
#define chacha20_vector_xor bench_chacha20_vector_copy_xor

#include "chacha20_vector.c"

#include "record_stages.h"

// chacha20_vector_xor over n bytes calls four_blocks once per 256 bytes
// and a last time for a shorter tail, and adds 4 to the block counter
// after each call. This makes the same calls in the same order and stores
// each group's keystream to out, so the time it takes is
// chacha20_vector_xor's less the loads, the exclusive-or and the stores of
// the data.
void bench_chacha20_vector_blocks(const uint8_t key[CHACHA20_KEY],
                                  const uint8_t nonce[CHACHA20_NONCE], uint32_t counter, size_t n,
                                  uint8_t out[4 * CHACHA20_BLOCK]) {
    uint32_t words[16];
    setup(words, key, nonce);
    lanes x[16];
    for (size_t off = 0; off < n; off += GROUP_BYTES) {
        four_blocks(words, counter, x);
        for (size_t b = 0; b < 4; b++) {
            for (size_t g = 0; g < 4; g++) {
                store_16(out + CHACHA20_BLOCK * b + 16 * g, x[4 * g + b]);
            }
        }
        counter += 4;
    }
}
