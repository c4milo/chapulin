// Proves: the reference generator is memory-safe and UB-free for any
// request up to 96 bytes (two rekey-block boundaries), seeded or across
// consecutive requests. ChaCha20 is a stub asserting its proven
// contract; what is under proof is the generator's own block walk and
// key handling. ct.c is real.
#include "harness.h"

#include "chacha20.h"

void chacha20_block(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    uint32_t counter, uint8_t out[CHACHA20_BLOCK]) {
    (void)counter;
    __CPROVER_assert(__CPROVER_r_ok(key, CHACHA20_KEY), "block: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, CHACHA20_NONCE), "block: nonce readable");
    __CPROVER_assert(__CPROVER_w_ok(out, CHACHA20_BLOCK), "block: out writable");
    fill_nondet(out, CHACHA20_BLOCK);
}

void chacha20_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                  uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
    (void)key;
    (void)nonce;
    (void)counter;
    (void)in;
    (void)out;
    (void)n;
    __CPROVER_assert(0, "chacha20_xor unreachable from the generator");
}

#include "drbg.c"

int main(void) {
    uint8_t seed[32];
    fill_nondet(seed, sizeof seed);
    ch_drbg_seed(seed);

    uint8_t out[96];
    size_t n1 = nondet_size_t();
    size_t n2 = nondet_size_t();
    __CPROVER_assume(n1 <= sizeof out);
    __CPROVER_assume(n2 <= sizeof out);
    ch_rand_bytes(out, n1);
    ch_rand_bytes(out, n2); // a second request crosses the rekeyed state
    return 0;
}
