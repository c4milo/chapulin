// Proves: the reference generator is memory-safe and UB-free for any
// seed of CH_DRBG_SEED_MIN to SEED_PROOF_MAX bytes and any request up to
// 96 bytes (two rekey-block boundaries), seeded or across consecutive
// requests. ChaCha20 and SHA-256 are stubs asserting their proven
// contracts; what is under proof is the seed's hand-off to SHA-256, the
// generator's own block walk and its key handling. ct.c is real.
#define CH_PROOF_STUB_SHA256
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

// Three 32-byte sources, the layered seed docs/entropy.md asks for. The
// SHA-256 stub reads the seed through one r_ok check whatever its
// length, so the bound sizes the buffer and not the formula.
#define SEED_PROOF_MAX 96

int main(void) {
    uint8_t seed[SEED_PROOF_MAX];
    fill_nondet(seed, sizeof seed);
    size_t seed_len = nondet_size_t();
    __CPROVER_assume(seed_len >= CH_DRBG_SEED_MIN && seed_len <= sizeof seed);
    ch_drbg_seed(seed, seed_len);

    uint8_t out[96];
    size_t n1 = nondet_size_t();
    size_t n2 = nondet_size_t();
    __CPROVER_assume(n1 <= sizeof out);
    __CPROVER_assume(n2 <= sizeof out);
    ch_rand_bytes(out, n1);
    ch_rand_bytes(out, n2); // a second request crosses the rekeyed state
    return 0;
}
