// The vector ChaCha20 source the bench's rows run under BENCH_CPU, compiled
// with one more entry, for bench/record.c: chacha20_avx2.c where the value
// names AVX2 on x86-64, and chacha20_vector.c under every other value
// (record_stages.h). The functions this entry runs are static in those
// files, so this file includes the source. The bench also links the
// library's own object of it, so this file first renames the external name
// the source defines, and nothing calls the renamed function.
#include "record_stages.h"

#ifdef BENCH_ON_AVX2
#define chacha20_avx2_xor bench_chacha20_avx2_copy_xor
#include "chacha20_avx2.c"
#else
#define chacha20_vector_xor bench_chacha20_vector_copy_xor
#include "chacha20_vector.c"
#endif

// The path's xor over n bytes runs one pass per PASS_BYTES bytes and a
// last one for a shorter tail, and adds the pass's blocks to the block
// counter after each. This runs the same passes with the same counters
// and stores each pass's keystream to out, so the time it takes is the
// xor's less the loads, the exclusive-or and the stores of the data. On the
// AVX2 kernel it takes the kernel's target attribute, because it holds the
// kernel's 256-bit values.
#ifdef BENCH_ON_AVX2
__attribute__((target("avx2"))) void
bench_chacha20_vector_blocks(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                             uint32_t counter, size_t n,
                             uint8_t out[BENCH_CHACHA20_VECTOR_PASS_MAX]) {
    _Static_assert(PASS_BYTES <= BENCH_CHACHA20_VECTOR_PASS_MAX, "out holds one pass");
    uint32_t words[16];
    setup(words, key, nonce);
    for (size_t off = 0; off < n; off += PASS_BYTES) {
        lanes x[16];
        pass_input(x, words, counter);
        for (int i = 0; i < 10; i++) {
            double_round(x);
        }
        pass_keystream(x, words, counter);
#pragma GCC unroll 16
        for (size_t row = 0; row < PASS_ROWS; row++) {
            store_32(out + ROW_BYTES * row, row_keystream(x, row));
        }
        counter += PASS_BLOCKS;
    }
}
#else
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
#endif
