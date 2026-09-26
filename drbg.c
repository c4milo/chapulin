#include "drbg.h"

#include "ch_assert.h"
#include "chacha20.h"
#include "ct.h"
#include "rand.h"
#include "sha256.h"

_Static_assert(SHA256_LEN == CHACHA20_KEY, "the seed's SHA-256 is the whole generator key");
_Static_assert(CH_DRBG_SEED_MIN == CHACHA20_KEY, "the shortest seed is one key long");

static uint8_t g_key[CHACHA20_KEY];
static int g_seeded;

// The key is the SHA-256 of the whole seed, written straight into
// g_key, so no stack copy of the digest exists. The context holds seed
// bytes in its block buffer and chaining value, so it is wiped before
// return.
void ch_drbg_seed(const uint8_t *seed, size_t seed_len) {
    CH_ASSERT(seed_len >= CH_DRBG_SEED_MIN); // a short seed is a programmer error (drbg.h)
    sha256 s;
    sha256_init(&s);
    sha256_update(&s, seed, seed_len);
    sha256_final(&s, g_key);
    ct_wipe(&s, sizeof s);
    g_seeded = 1;
}

// Fast key erasure: one keystream per request, under the key as it was
// when the request began. The stream's first 32 bytes become the next
// key; output starts after them. The old key is gone before return, so
// no state that exists afterward can reproduce what was handed out.
void ch_rand_bytes(uint8_t *p, size_t n) {
    CH_ASSERT(g_seeded); // no entropy, no handshake (rand.h)
    static const uint8_t nonce[CHACHA20_NONCE] = {0};
    uint8_t block[CHACHA20_BLOCK];
    uint8_t next[CHACHA20_KEY];

    chacha20_block(g_key, nonce, 0, block);
    for (int i = 0; i < CHACHA20_KEY; i++) {
        next[i] = block[i];
    }
    size_t have = CHACHA20_BLOCK - CHACHA20_KEY; // output bytes in block
    size_t off = CHACHA20_KEY;
    uint32_t counter = 1;
    while (n > 0) {
        if (have == 0) {
            chacha20_block(g_key, nonce, counter, block);
            counter++;
            off = 0;
            have = CHACHA20_BLOCK;
        }
        size_t take = n < have ? n : have;
        for (size_t i = 0; i < take; i++) {
            p[i] = block[off + i];
        }
        p += take;
        off += take;
        have -= take;
        n -= take;
    }
    for (int i = 0; i < CHACHA20_KEY; i++) {
        g_key[i] = next[i];
    }
    ct_wipe(next, sizeof next);
    ct_wipe(block, sizeof block);
}
