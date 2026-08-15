// libFuzzer harness for rec_open, the record-layer entry that first meets
// attacker ciphertext. A fixed traffic secret seeds one long-lived rec_dir
// so the sequence-number nonce and in-place decrypt paths advance exactly
// as they do on a live connection; a rec_dir_update fires whenever a data
// byte selects it, exercising the KeyUpdate rekey between iterations.
#include <stdint.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "record.h"

noreturn void ms_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    abort();
}

static rec_dir g_dir;
static uint8_t g_secret[SHA256_LEN];
static int g_ready;

static void ensure_ready(void) {
    if (!g_ready) {
        memset(g_secret, 0x5a, sizeof g_secret);
        rec_dir_init(&g_dir, g_secret);
        g_ready = 1;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ensure_ready();
    // Cap covers the largest inner plaintext rec_open will accept (2^14+1).
    uint8_t pt[0x4001];
    size_t ptn = 0;
    uint8_t type = 0;
    (void)rec_open(&g_dir, data, size, pt, sizeof pt, &ptn, &type);
    // Rekey on ~1/32 of inputs, keyed off the first byte.
    if (size > 0 && (data[0] & 0x1f) == 0) {
        rec_dir_update(g_secret, &g_dir);
    }
    return 0;
}
