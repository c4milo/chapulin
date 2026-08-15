// The reference generator: deterministic under a fixed seed, distinct
// across consecutive requests, key erased between them, and equal to the
// construction it claims to be (ChaCha20 keystream, first 32 bytes
// rekey, output after). Its own binary because drbg.c defines
// ch_rand_bytes, which the other test binaries define themselves.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "chacha20.h"
#include "diffdrv.h"
#include "drbg.h"
#include "rand.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

int main(void) {
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        seed[i] = (uint8_t)i;
    }

    // Deterministic: the same seed yields the same stream.
    uint8_t a[100];
    uint8_t b[100];
    ch_drbg_seed(seed);
    ch_rand_bytes(a, sizeof a);
    ch_drbg_seed(seed);
    ch_rand_bytes(b, sizeof b);
    CHECK(memcmp(a, b, sizeof a) == 0);

    // Consecutive requests differ: the key moved.
    ch_rand_bytes(b, sizeof b);
    CHECK(memcmp(a, b, sizeof b) != 0);

    // The construction is what the header claims: output bytes are the
    // ChaCha20 keystream under the seed key, zero nonce, skipping the
    // 32 bytes that became the next key.
    uint8_t stream[CHACHA20_BLOCK * 3] = {0};
    uint8_t nonce[CHACHA20_NONCE] = {0};
    chacha20_xor(seed, nonce, 0, stream, stream, sizeof stream);
    CHECK(memcmp(a, stream + 32, sizeof a) == 0);

    // And the second request came from the rekeyed state: key = first 32
    // stream bytes, output again offset by its own rekey block.
    uint8_t stream2[CHACHA20_BLOCK * 3] = {0};
    chacha20_xor(stream, nonce, 0, stream2, stream2, sizeof stream2);
    CHECK(memcmp(b, stream2 + 32, sizeof b) == 0);

    // Differential leg against the Lean spec, when its binary exists:
    // for random seeds and lengths, the C generator's output and the
    // spec's next() must agree, across two consecutive requests.
    if (access("spec/.lake/build/bin/diffspec", X_OK) == 0) {
        spawn_spec("spec/.lake/build/bin/diffspec");
        for (int i = 0; i < 50; i++) {
            uint8_t s0[32];
            rng_fill(s0, sizeof s0);
            size_t n = 1 + rng_below(96);
            char cmd[256];
            char reply[512];
            char shex[65];
            hex_enc(shex, s0, sizeof s0);
            (void)snprintf(cmd, sizeof cmd, "drbg %s %zu", shex, n);
            query(cmd, reply, sizeof reply);
            // reply: "<next-key-hex> <out-hex>"
            char *sp = strchr(reply, ' ');
            CHECK(sp != NULL);
            if (sp == NULL) {
                break;
            }
            *sp = 0;
            uint8_t want[96];
            CHECK(hex_dec(want, sp + 1, n) == 1);
            uint8_t got[96];
            ch_drbg_seed(s0);
            ch_rand_bytes(got, n);
            CHECK(memcmp(got, want, n) == 0);
            // Second request must match the spec continuing from its
            // next key — proving the C rekeyed exactly as specified.
            uint8_t k1[32];
            CHECK(hex_dec(k1, reply, 32) == 1);
            hex_enc(shex, k1, sizeof k1);
            (void)snprintf(cmd, sizeof cmd, "drbg %s %zu", shex, n);
            query(cmd, reply, sizeof reply);
            sp = strchr(reply, ' ');
            CHECK(sp != NULL);
            if (sp == NULL) {
                break;
            }
            CHECK(hex_dec(want, sp + 1, n) == 1);
            ch_rand_bytes(got, n);
            CHECK(memcmp(got, want, n) == 0);
            comparisons += 2;
        }
        (void)printf("drbg_test: %ld spec comparisons, C == spec\n", comparisons);
    } else {
        (void)printf("drbg_test: spec comparisons skipped (build spec/ first)\n");
    }

    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("drbg_test: all checks passed\n");
    return 0;
}
