// The SHA-512 rows of the hash and key-derivation differential section:
// HMAC-SHA-512 and HKDF-SHA-512's extract and expand, which hash.h's calls
// take and no TLS 1.3 suite runs (docs/decisions.md 246). Every row runs
// the C module and spec/lean/Spec/Hkdf.lean on the same input, the spec
// with its sha512H hash. The Makefile builds bin/diff with -DCH_HASH, which
// is what turns SHA-512 on in hkdf.c. Included by test/diff_test.c after
// diff_hash384.h (single translation unit).
#ifndef CH_DIFF_HASH512_H
#define CH_DIFF_HASH512_H
#ifdef CH_HASH

#include "hkdf.h"
#include "sha512.h"

// Keys from empty to past SHA-512's 128-byte block, so the hash-the-key
// path of RFC 2104 runs on both sides of its edge.
static void diff_hmac512(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t key[300];
        size_t key_len = rng_below(301);
        rng_fill(key, key_len);
        uint8_t msg[200];
        size_t msg_len = rng_below(201);
        rng_fill(msg, msg_len);
        uint8_t mac[SHA512_LEN];
        hmac(SHA512_LEN, key, key_len, msg, msg_len, mac);
        char key_hex[601];
        (void)hex_encode(key_hex, key, key_len);
        char msg_hex[401];
        (void)hex_encode(msg_hex, msg, msg_len);
        char want[2 * SHA512_LEN + 1];
        (void)hex_encode(want, mac, SHA512_LEN);
        char cmd[1100];
        (void)snprintf(cmd, sizeof cmd, "hmac512 %s %s", key_hex, msg_hex);
        expect(cmd, want);
    }
}

// Extract under salts from empty to past the block, then Expand from the
// PRK with an info of up to 200 bytes and an output of up to three blocks.
static void diff_hkdf512(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t salt[160];
        size_t salt_len = rng_below(161);
        rng_fill(salt, salt_len);
        uint8_t ikm[96];
        size_t ikm_len = rng_below(97);
        rng_fill(ikm, ikm_len);
        uint8_t prk[SHA512_LEN];
        hkdf_extract(SHA512_LEN, salt, salt_len, ikm, ikm_len, prk);
        char salt_hex[321];
        (void)hex_encode(salt_hex, salt, salt_len);
        char ikm_hex[193];
        (void)hex_encode(ikm_hex, ikm, ikm_len);
        char want[2 * SHA512_LEN + 1];
        (void)hex_encode(want, prk, SHA512_LEN);
        char cmd[1100];
        (void)snprintf(cmd, sizeof cmd, "hkdf512_extract %s %s", salt_hex, ikm_hex);
        expect(cmd, want);

        uint8_t info[200];
        size_t info_len = rng_below(sizeof info + 1);
        rng_fill(info, info_len);
        size_t out_len = 1 + rng_below((size_t)3 * SHA512_LEN);
        uint8_t out[3 * SHA512_LEN];
        hkdf_expand(SHA512_LEN, prk, info, info_len, out, out_len);
        char prk_hex[2 * SHA512_LEN + 1];
        (void)hex_encode(prk_hex, prk, sizeof prk);
        char info_hex[2 * sizeof info + 1];
        (void)hex_encode(info_hex, info, info_len);
        char out_hex[2 * 3 * SHA512_LEN + 1];
        (void)hex_encode(out_hex, out, out_len);
        (void)snprintf(cmd, sizeof cmd, "hkdf512_expand %s %s %zu", prk_hex, info_hex, out_len);
        expect(cmd, out_hex);
    }
    // The boundary RFC 5869 section 2.3 sets at 255 * 64: the last length
    // the two take, and the first the spec refuses, which the C asserts.
    uint8_t prk[SHA512_LEN] = {9};
    static const uint8_t no_info[1] = {0};
    static uint8_t out[255 * SHA512_LEN];
    hkdf_expand(SHA512_LEN, prk, no_info, 0, out, sizeof out);
    char prk_hex[2 * SHA512_LEN + 1];
    (void)hex_encode(prk_hex, prk, sizeof prk);
    static char want[2 * 255 * SHA512_LEN + 1];
    (void)hex_encode(want, out, sizeof out);
    static char cmd[2 * 255 * SHA512_LEN + 200];
    (void)snprintf(cmd, sizeof cmd, "hkdf512_expand %s - %d", prk_hex, 255 * SHA512_LEN);
    expect(cmd, want);
    (void)snprintf(cmd, sizeof cmd, "hkdf512_expand %s - %d", prk_hex, 255 * SHA512_LEN + 1);
    expect(cmd, "ERR hkdf512_expand len over 255*HashLen");
}

#endif
#endif
