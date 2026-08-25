// Proves: chacha20_xor and chacha20_block are memory-safe and UB-free for
// any input up to 160 bytes (three blocks: full, full, partial) at any
// initial counter, in-place or out-of-place. Wrapping uint32 adds are the
// cipher; only UB classes are checked.
#include "harness.h"

#include "chacha20.c"

int main(void) {
    uint8_t key[CHACHA20_KEY];
    uint8_t nonce[CHACHA20_NONCE];
    uint8_t buf[160];
    uint8_t keystream[CHACHA20_BLOCK];
    fill_nondet(key, sizeof key);
    fill_nondet(nonce, sizeof nonce);
    fill_nondet(buf, sizeof buf);

    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof buf);
    uint32_t counter = (uint32_t)nondet_size_t();

    chacha20_xor(key, nonce, counter, buf, buf, n);

    // Out-of-place, the shape the harness comment always claimed: a
    // fresh source and a distinct destination.
    uint8_t src[160];
    uint8_t dst[160];
    fill_nondet(src, sizeof src);
    n = nondet_size_t();
    __CPROVER_assume(n <= sizeof src);
    chacha20_xor(key, nonce, counter, src, dst, n);

    chacha20_block(key, nonce, counter, keystream);
    return 0;
}
