// chacha20.c compiled with one more entry, for bench/record.c only. block
// and setup are static in chacha20.c, so this file includes the source.
// The bench also links the library's own chacha20.o, so this file first
// renames the two external names chacha20.c defines, and nothing calls the
// renamed functions.
#define chacha20_xor bench_chacha20_copy_xor
#define chacha20_block bench_chacha20_copy_block

#include "chacha20.c"

#include "record_stages.h"

// chacha20_xor over n bytes calls block once per 64 bytes and a last time
// for a shorter tail, and increments the block counter after each call.
// This makes the same calls in the same order and writes each block to
// out, so the time it takes is chacha20_xor's less the exclusive-or.
void bench_chacha20_blocks(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                           uint32_t counter, size_t n, uint8_t out[CHACHA20_BLOCK]) {
    uint32_t state[16];
    setup(state, key, nonce, counter);
    for (size_t off = 0; off < n; off += CHACHA20_BLOCK) {
        block(state, out);
        state[12]++;
    }
}
