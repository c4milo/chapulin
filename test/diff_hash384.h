// The SHA-384 half of the hash and key-derivation differential section:
// HMAC-SHA-384, HKDF-SHA-384 extract and expand, expand_label at
// HashLen = 48, and the key schedule TLS_AES_256_GCM_SHA384 runs. Every row
// runs the C module and spec/lean/Spec/Hkdf.lean on the same input, the
// spec with its sha384H hash. The Makefile builds bin/diff with
// -DCH_HASH_SHA384, which is what turns SHA-384 on in hkdf.c.
// Included by test/diff_test.c after diff_hash.h (single translation unit).
#ifndef CH_DIFF_HASH384_H
#define CH_DIFF_HASH384_H
#ifdef CH_HASH_SHA384

#include "hkdf.h"
#include "keysched.h"
#include "sha512.h"

// Keys from empty to past SHA-384's 128-byte block, so the hash-the-key
// path of RFC 2104 runs on both sides of its edge.
static void diff_hmac384(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t key[300];
        size_t key_len = rng_below(301);
        rng_fill(key, key_len);
        uint8_t msg[200];
        size_t msg_len = rng_below(201);
        rng_fill(msg, msg_len);
        uint8_t mac[SHA384_LEN];
        hmac(SHA384_LEN, key, key_len, msg, msg_len, mac);
        char key_hex[601];
        (void)hex_encode(key_hex, key, key_len);
        char msg_hex[401];
        (void)hex_encode(msg_hex, msg, msg_len);
        char want[2 * SHA384_LEN + 1];
        (void)hex_encode(want, mac, SHA384_LEN);
        char cmd[1100];
        (void)snprintf(cmd, sizeof cmd, "hmac384 %s %s", key_hex, msg_hex);
        expect(cmd, want);
    }
}

static void diff_hkdf384(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t salt[96];
        size_t salt_len = rng_below(97);
        rng_fill(salt, salt_len);
        uint8_t ikm[96];
        size_t ikm_len = rng_below(97);
        rng_fill(ikm, ikm_len);
        uint8_t prk[SHA384_LEN];
        hkdf_extract(SHA384_LEN, salt, salt_len, ikm, ikm_len, prk);
        char salt_hex[193];
        (void)hex_encode(salt_hex, salt, salt_len);
        char ikm_hex[193];
        (void)hex_encode(ikm_hex, ikm, ikm_len);
        char want[2 * SHA384_LEN + 1];
        (void)hex_encode(want, prk, SHA384_LEN);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "hkdf384_extract %s %s", salt_hex, ikm_hex);
        expect(cmd, want);

        // HKDF-Expand over the whole asserted info domain and an output
        // of up to three blocks, from the PRK just extracted.
        uint8_t info[HKDF_INFO_MAX];
        size_t info_len = rng_below(HKDF_INFO_MAX + 1);
        rng_fill(info, info_len);
        size_t out_len = 1 + rng_below((size_t)3 * SHA384_LEN);
        uint8_t out[3 * SHA384_LEN];
        hkdf_expand(SHA384_LEN, prk, info, info_len, out, out_len);
        char prk_hex[2 * SHA384_LEN + 1];
        (void)hex_encode(prk_hex, prk, sizeof prk);
        char info_hex[2 * HKDF_INFO_MAX + 1];
        (void)hex_encode(info_hex, info, info_len);
        char out_hex[2 * 3 * SHA384_LEN + 1];
        (void)hex_encode(out_hex, out, out_len);
        (void)snprintf(cmd, sizeof cmd, "hkdf384_expand %s %s %zu", prk_hex, info_hex, out_len);
        expect(cmd, out_hex);
    }
}

// expand_label at HashLen = 48, with a context as long as a SHA-384
// transcript hash, and the boundary RFC 5869 §2.3 sets at 255 * 48.
static void diff_expand_label384(void) {
    static const char alnum[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < 200; i++) {
        uint8_t secret[SHA384_LEN];
        rng_fill(secret, sizeof secret);
        char label[HKDF_LABEL_MAX + 1];
        size_t label_len = 1 + rng_below(HKDF_LABEL_MAX);
        for (size_t j = 0; j < label_len; j++) {
            label[j] = alnum[rng_below(sizeof alnum - 1)];
        }
        label[label_len] = '\0';
        uint8_t ctx[SHA384_LEN];
        size_t ctx_len = rng_below(SHA384_LEN + 1);
        rng_fill(ctx, ctx_len);
        size_t out_len = 1 + rng_below((size_t)2 * SHA384_LEN);
        uint8_t out[2 * SHA384_LEN];
        hkdf_expand_label(SHA384_LEN, secret, label, ctx, ctx_len, out, out_len);
        char secret_hex[2 * SHA384_LEN + 1];
        (void)hex_encode(secret_hex, secret, sizeof secret);
        char label_hex[2 * HKDF_LABEL_MAX + 1];
        (void)hex_encode(label_hex, (const uint8_t *)label, label_len);
        char ctx_hex[2 * SHA384_LEN + 1];
        (void)hex_encode(ctx_hex, ctx, ctx_len);
        char want[2 * 2 * SHA384_LEN + 1];
        (void)hex_encode(want, out, out_len);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "expand_label384 %s %s %s %zu", secret_hex, label_hex,
                       ctx_hex, out_len);
        expect(cmd, want);
    }
    uint8_t secret[SHA384_LEN] = {7};
    static uint8_t out[255 * SHA384_LEN];
    hkdf_expand_label(SHA384_LEN, secret, "key", NULL, 0, out, sizeof out);
    char secret_hex[2 * SHA384_LEN + 1];
    (void)hex_encode(secret_hex, secret, sizeof secret);
    static char want[2 * 255 * SHA384_LEN + 1];
    (void)hex_encode(want, out, sizeof out);
    static char cmd[2 * 255 * SHA384_LEN + 160];
    (void)snprintf(cmd, sizeof cmd, "expand_label384 %s 6b6579 - %d", secret_hex, 255 * SHA384_LEN);
    expect(cmd, want);
    (void)snprintf(cmd, sizeof cmd, "expand_label384 %s 6b6579 - %d", secret_hex,
                   255 * SHA384_LEN + 1);
    expect(cmd, "ERR expand_label384 len over 255*HashLen");
}

// The spec's scheduleWith sha384H against the C composition, ks_early ->
// ks_handshake -> ks_master at SHA384_LEN, over both key-exchange IKM
// widths the handshake passes.
static void diff_schedule384(void) {
    for (int i = 0; i < 100; i++) {
        size_t ecdhe_len = (i % 2 == 0) ? 32 : 64;
        uint8_t psk[SHA384_LEN];
        rng_fill(psk, sizeof psk);
        uint8_t ecdhe[64];
        rng_fill(ecdhe, ecdhe_len);
        uint8_t hello[SHA384_LEN];
        rng_fill(hello, sizeof hello);
        uint8_t finished[SHA384_LEN];
        rng_fill(finished, sizeof finished);
        uint8_t early[SHA384_LEN];
        uint8_t binder[SHA384_LEN];
        ks_early(SHA384_LEN, psk, sizeof psk, 0, early, binder);
        uint8_t handshake_secret[SHA384_LEN];
        uint8_t secrets[4][SHA384_LEN];
        ks_handshake(SHA384_LEN, early, ecdhe, ecdhe_len, hello, handshake_secret, secrets[0],
                     secrets[1]);
        uint8_t master[SHA384_LEN];
        ks_master(SHA384_LEN, handshake_secret, finished, master, secrets[2], secrets[3]);
        char in_hex[3][2 * SHA384_LEN + 1];
        (void)hex_encode(in_hex[0], psk, sizeof psk);
        (void)hex_encode(in_hex[1], hello, sizeof hello);
        (void)hex_encode(in_hex[2], finished, sizeof finished);
        char ecdhe_hex[2 * sizeof ecdhe + 1];
        (void)hex_encode(ecdhe_hex, ecdhe, ecdhe_len);
        char out_hex[4][2 * SHA384_LEN + 1];
        for (size_t j = 0; j < 4; j++) {
            (void)hex_encode(out_hex[j], secrets[j], SHA384_LEN);
        }
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "schedule384 %s %s %s %s", in_hex[0], ecdhe_hex, in_hex[1],
                       in_hex[2]);
        char want[512];
        (void)snprintf(want, sizeof want, "%s %s %s %s", out_hex[0], out_hex[1], out_hex[2],
                       out_hex[3]);
        expect(cmd, want);
    }
}

#endif // CH_HASH_SHA384
#endif
