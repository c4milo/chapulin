// Violation file for semgrep --test: each `ruleid:` line must be
// flagged by the named rule, each `ok:` line must not. This file
// never compiles and never should; it proves the tripwires trip.
#include <stdint.h>
#include <stddef.h>

// ruleid: inv-2-freestanding
#include <stdio.h>
// ruleid: inv-2-freestanding
#include <stdlib.h>
// ruleid: inv-2-freestanding
#include <time.h>

typedef struct {
    uint64_t seq;
} fake_dir;

// ok: inv-18-no-global-mutable-state
static const uint8_t table[4] = {1, 2, 3, 4};
// ruleid: inv-18-no-global-mutable-state
static int g_counter;
// ruleid: inv-18-no-global-mutable-state
static uint8_t g_key[32] = {0};

// ok: inv-18-no-global-mutable-state
static int helper(int x);

void ch_rand_bytes(uint8_t *p, size_t n);
void aead_seal(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_len,
               const uint8_t *pt, size_t n, uint8_t *out, uint8_t *tag);
int memcmp(const void *a, const void *b, size_t n);
int pkcs1_verify(const uint8_t *sig, size_t n);
void *malloc(size_t n);
void free(void *p);

static int helper(int x) {
    fake_dir d;
    // ruleid: inv-10-seq-reset-only-in-record
    d.seq = 0;
    fake_dir *pd = &d;
    // ruleid: inv-10-seq-reset-only-in-record
    pd->seq = 0;
    // ok: inv-10-seq-reset-only-in-record
    d.seq = 1;

    uint8_t buf[32];
    // ruleid: inv-4-randomness-sites
    ch_rand_bytes(buf, sizeof buf);

    // ruleid: inv-1-seal-only-in-record
    aead_seal(buf, buf, buf, 0, buf, 0, buf, buf);

    // ruleid: inv-16-no-variable-time-compare
    return memcmp(buf, buf, 32) == x;
}

int use_everything(void) {
    // ruleid: inv-2-no-allocator
    void *p = malloc(16);
    // ruleid: inv-2-no-allocator
    free(p);
    // ruleid: inv-5-no-certificate-parsing
    return pkcs1_verify(0, 0) + helper(1);
}
