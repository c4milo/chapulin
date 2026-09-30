// chacha20_vector.c compiled with one more entry, for bench/record.c's
// CHACHA=vector builds only. group_input, double_round, group_keystream
// and store_16 are static in chacha20_vector.c, so this file includes the
// source. Those builds also link the library's own chacha20_vector.o, so
// this file first renames the external name chacha20_vector.c defines,
// and nothing calls the renamed function.
#define chacha20_vector_xor bench_chacha20_vector_copy_xor

#include "chacha20_vector.c"

#include "record_stages.h"

// chacha20_vector_xor over n bytes runs one pass per PASS_BYTES bytes and
// a last one for a shorter tail, and adds the pass's blocks to the block
// counter after each. This runs the same passes with the same counters
// and stores each pass's keystream to out, so the time it takes is
// chacha20_vector_xor's less the loads, the exclusive-or and the stores
// of the data.
void bench_chacha20_vector_blocks(const uint8_t key[CHACHA20_KEY],
                                  const uint8_t nonce[CHACHA20_NONCE], uint32_t counter, size_t n,
                                  uint8_t out[BENCH_CHACHA20_VECTOR_PASS_MAX]) {
    _Static_assert(PASS_BYTES <= BENCH_CHACHA20_VECTOR_PASS_MAX, "out holds one pass");
    uint32_t words[16];
    setup(words, key, nonce);
    for (size_t off = 0; off < n; off += PASS_BYTES) {
        lanes x[PASS_GROUPS][16];
#pragma GCC unroll 2
        for (size_t g = 0; g < PASS_GROUPS; g++) {
            group_input(x[g], words, counter + (uint32_t)(GROUP_BLOCKS * g));
        }
        for (int i = 0; i < 10; i++) {
#pragma GCC unroll 2
            for (size_t g = 0; g < PASS_GROUPS; g++) {
                double_round(x[g]);
            }
        }
#pragma GCC unroll 2
        for (size_t g = 0; g < PASS_GROUPS; g++) {
            group_keystream(x[g], words, counter + (uint32_t)(GROUP_BLOCKS * g));
#pragma GCC unroll 16
            for (size_t row = 0; row < 16; row++) {
                store_16(out + GROUP_BYTES * g + 16 * row, x[g][4 * (row % 4) + row / 4]);
            }
        }
        counter += PASS_GROUPS * GROUP_BLOCKS;
    }
}
