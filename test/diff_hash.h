// Hash and key-derivation differential section: SHA-256, HMAC-SHA-256,
// HKDF extract and expand, the TLS 1.3 expand_label encoding, and the
// key schedule the handshake composes from them. Every row runs the C
// module and the Lean spec on the same input and compares the bytes.
// Included by test/diff_test.c after diff_driver.h (single translation unit).
#ifndef CH_DIFFHASH_H
#define CH_DIFFHASH_H

#include "hkdf.h"
#include "keysched.h"
#include "sha256.h"

static void diff_sha256(void) {
    for (int i = 0; i < 300; i++) {
        uint8_t msg[200];
        size_t n = rng_below(201);
        rng_fill(msg, n);
        uint8_t d[SHA256_LEN];
        sha256_of(msg, n, d);
        char msg_hex[401];
        (void)hex_encode(msg_hex, msg, n);
        char want[65];
        (void)hex_encode(want, d, SHA256_LEN);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "sha256 %s", msg_hex);
        expect(cmd, want);
    }
}

static void diff_hmac(void) {
    for (int i = 0; i < 300; i++) {
        uint8_t key[200];
        size_t key_len = rng_below(201); // spans the B=64 hash-the-key edge
        rng_fill(key, key_len);
        uint8_t msg[200];
        size_t msg_len = rng_below(201);
        rng_fill(msg, msg_len);
        uint8_t mac[SHA256_LEN];
        hmac_sha256(key, key_len, msg, msg_len, mac);
        char key_hex[401];
        (void)hex_encode(key_hex, key, key_len);
        char msg_hex[401];
        (void)hex_encode(msg_hex, msg, msg_len);
        char want[65];
        (void)hex_encode(want, mac, SHA256_LEN);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "hmac %s %s", key_hex, msg_hex);
        expect(cmd, want);
    }
}

static void diff_hkdf_extract(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t salt[64];
        size_t salt_len = rng_below(65);
        rng_fill(salt, salt_len);
        uint8_t ikm[64];
        size_t ikm_len = rng_below(65);
        rng_fill(ikm, ikm_len);
        uint8_t prk[SHA256_LEN];
        hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
        char salt_hex[129];
        (void)hex_encode(salt_hex, salt, salt_len);
        char ikm_hex[129];
        (void)hex_encode(ikm_hex, ikm, ikm_len);
        char want[65];
        (void)hex_encode(want, prk, SHA256_LEN);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "hkdf_extract %s %s", salt_hex, ikm_hex);
        expect(cmd, want);
    }
}

static void diff_hkdf_expand(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t prk[SHA256_LEN];
        rng_fill(prk, sizeof prk);
        uint8_t info[64];
        size_t info_len = rng_below(65);
        rng_fill(info, info_len);
        size_t out_len = 1 + rng_below(64);
        uint8_t out[64];
        hkdf_expand(prk, info, info_len, out, out_len);
        char prk_hex[65];
        (void)hex_encode(prk_hex, prk, sizeof prk);
        char info_hex[129];
        (void)hex_encode(info_hex, info, info_len);
        char want[129];
        (void)hex_encode(want, out, out_len);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "hkdf_expand %s %s %zu", prk_hex, info_hex, out_len);
        expect(cmd, want);
    }
}

static void diff_expand_label(void) {
    static const char alnum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 200; i++) {
        uint8_t secret[SHA256_LEN];
        rng_fill(secret, sizeof secret);
        char label[HKDF_LABEL_MAX + 1];
        size_t label_len = 1 + rng_below(HKDF_LABEL_MAX);
        for (size_t j = 0; j < label_len; j++) {
            label[j] = alnum[rng_below(sizeof alnum - 1)];
        }
        label[label_len] = '\0';
        uint8_t ctx[32];
        size_t ctx_len = rng_below(33);
        rng_fill(ctx, ctx_len);
        size_t out_len = 1 + rng_below(64);
        uint8_t out[64];
        hkdf_expand_label(secret, label, ctx, ctx_len, out, out_len);
        char secret_hex[65];
        (void)hex_encode(secret_hex, secret, sizeof secret);
        char label_hex[2 * HKDF_LABEL_MAX + 1];
        (void)hex_encode(label_hex, (const uint8_t *)label, label_len);
        char ctx_hex[65];
        (void)hex_encode(ctx_hex, ctx, ctx_len);
        char want[129];
        (void)hex_encode(want, out, out_len);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "expand_label %s %s %s %zu", secret_hex, label_hex, ctx_hex,
                       out_len);
        expect(cmd, want);
    }

    // Boundary rows the random domain never reaches. The last valid
    // output length (255*HashLen, RFC 5869 §2.3) must agree byte for
    // byte; the first invalid length and unencodable label/context
    // fields (RFC 9846 §7.1 one-byte vectors) must be spec-side errors —
    // the C asserts on those inputs, so the spec is the comparable half.
    {
        uint8_t secret[SHA256_LEN] = {7};
        static uint8_t out[255 * SHA256_LEN];
        hkdf_expand_label(secret, "key", NULL, 0, out, sizeof out);
        char secret_hex[65];
        (void)hex_encode(secret_hex, secret, sizeof secret);
        static char want[2 * 255 * SHA256_LEN + 1];
        (void)hex_encode(want, out, sizeof out);
        static char cmd[2 * 255 * SHA256_LEN + 128];
        (void)snprintf(cmd, sizeof cmd, "expand_label %s 6b6579 - %d", secret_hex,
                       255 * SHA256_LEN);
        expect(cmd, want);
        (void)snprintf(cmd, sizeof cmd, "expand_label %s 6b6579 - %d", secret_hex,
                       255 * SHA256_LEN + 1);
        expect(cmd, "ERR expand_label len over 255*HashLen");
        char big[513];
        for (size_t i = 0; i < 250; i++) {
            big[2 * i] = '4';
            big[2 * i + 1] = '1';
        }
        big[500] = 0; // 250-byte label: "tls13 " prefix pushes it past 255
        (void)snprintf(cmd, sizeof cmd, "expand_label %s %s - 32", secret_hex, big);
        expect(cmd, "ERR expand_label label unencodable");
        for (size_t i = 0; i < 256; i++) {
            big[2 * i] = '0';
            big[2 * i + 1] = '0';
        }
        big[512] = 0; // 256-byte context: one over the one-byte vector
        (void)snprintf(cmd, sizeof cmd, "expand_label %s 6b6579 %s 32", secret_hex, big);
        expect(cmd, "ERR expand_label context unencodable");
    }
}

// The spec's schedule() must equal the C composition the handshake runs:
// ks_early -> ks_handshake (hello transcript) -> ks_master (finished
// transcript), per CONTRACT.md.
static void diff_schedule(void) {
    for (int i = 0; i < 100; i++) {
        uint8_t psk[32];
        rng_fill(psk, sizeof psk);
        uint8_t ecdhe[32];
        rng_fill(ecdhe, sizeof ecdhe);
        uint8_t hello[SHA256_LEN];
        rng_fill(hello, sizeof hello);
        uint8_t finished[SHA256_LEN];
        rng_fill(finished, sizeof finished);
        uint8_t early[SHA256_LEN];
        uint8_t binder[SHA256_LEN];
        ks_early(psk, sizeof psk, 0, early, binder);
        uint8_t handshake_secret[SHA256_LEN];
        uint8_t c_hs[SHA256_LEN];
        uint8_t s_hs[SHA256_LEN];
        ks_handshake(early, ecdhe, hello, handshake_secret, c_hs, s_hs);
        uint8_t master[SHA256_LEN];
        uint8_t c_ap[SHA256_LEN];
        uint8_t s_ap[SHA256_LEN];
        ks_master(handshake_secret, finished, master, c_ap, s_ap);
        char psk_hex[65];
        (void)hex_encode(psk_hex, psk, sizeof psk);
        char ecdhe_hex[65];
        (void)hex_encode(ecdhe_hex, ecdhe, sizeof ecdhe);
        char hello_hex[65];
        (void)hex_encode(hello_hex, hello, sizeof hello);
        char finished_hex[65];
        (void)hex_encode(finished_hex, finished, sizeof finished);
        char c_hs_hex[65];
        (void)hex_encode(c_hs_hex, c_hs, SHA256_LEN);
        char s_hs_hex[65];
        (void)hex_encode(s_hs_hex, s_hs, SHA256_LEN);
        char c_ap_hex[65];
        (void)hex_encode(c_ap_hex, c_ap, SHA256_LEN);
        char s_ap_hex[65];
        (void)hex_encode(s_ap_hex, s_ap, SHA256_LEN);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "schedule %s %s %s %s", psk_hex, ecdhe_hex, hello_hex,
                       finished_hex);
        char want[512];
        (void)snprintf(want, sizeof want, "%s %s %s %s", c_hs_hex, s_hs_hex, c_ap_hex, s_ap_hex);
        expect(cmd, want);
    }
}

#endif
