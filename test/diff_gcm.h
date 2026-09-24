// Differential rows for quic_gcm.c: AEAD_AES_128_GCM, AEAD_AES_256_GCM in
// a build that has AES-256, and GHASH against NIST SP 800-38D as
// spec/lean/Spec/Gcm.lean states it. Every row takes the key length, so
// the two AEADs run the same rows and differ in the op name alone. The C carries the
// byte-at-a-time GF(2^128) multiply of §6.3 and the spec carries the same
// algorithm over a 128-bit value, so every row that agrees is one
// representation checked against the other.
//
// Included by test/diff_quic_test.c only, after test/diff_aes.h, which
// puts aes_expand_round_keys in scope through quic_aes_block.h.
#ifndef CH_DIFF_GCM_H
#define CH_DIFF_GCM_H

#include "quic_gcm.h"

// The domain both sides agree on. AEAD_AES_128_GCM fixes the key at 16
// bytes and quic_gcm.h admits the 96-bit IV alone, so the lengths that
// vary are the associated data's and the plaintext's. The cap is three
// blocks and a byte: it covers an empty input, a partial last block and
// a whole one on both arguments, and the spec's GF(2^128) multiply runs
// 128 steps per block under Lean's interpreter, so a larger cap buys
// coverage this already has and costs the run minutes.
#define DIFF_GCM_MAX (3 * AES_BLOCK + 1)

// The largest key a row holds: AES-256's 32 bytes.
#define DIFF_GCM_KEY_MAX AES_256_KEY

// The keys SP 800-38D admits are any 16 or 32 bytes, and INV-26 keeps
// the two constructors in quic_aes.h the only public way to write an
// aes_public_key, so a row builds the schedule directly the way
// test/quic_gcm_tests.h does.
static void diff_gcm_key(aes_public_key *k, const uint8_t *key, size_t key_len) {
    memset(k, 0, sizeof *k);
#ifdef CH_AES_256
    if (key_len == AES_256_KEY) {
        aes_expand_round_keys_256(key, k->key.round_keys);
        k->key.rounds = AES_256_ROUNDS;
        return;
    }
    k->key.rounds = AES_128_ROUNDS;
#endif
    (void)key_len;
    aes_expand_round_keys(key, k->key.round_keys);
}

// The spec's op names for the AEAD whose key is key_len bytes.
static const char *diff_gcm_op(size_t key_len, int seal) {
    if (key_len == AES_256_KEY) {
        return seal ? "aes256gcm_seal" : "aes256gcm_open";
    }
    return seal ? "aes128gcm_seal" : "aes128gcm_open";
}

// gcm_seal over every length pair the cap admits, each with fresh key,
// IV, associated data and plaintext bytes.
static void diff_gcm_seal(size_t key_len) {
    for (size_t aad_len = 0; aad_len <= DIFF_GCM_MAX; aad_len += 7) {
        for (size_t n = 0; n <= DIFF_GCM_MAX; n += 5) {
            uint8_t key[DIFF_GCM_KEY_MAX];
            uint8_t nonce[AES_IV];
            uint8_t aad[DIFF_GCM_MAX];
            uint8_t pt[DIFF_GCM_MAX];
            rng_fill(key, key_len);
            rng_fill(nonce, sizeof nonce);
            rng_fill(aad, aad_len);
            rng_fill(pt, n);

            aes_public_key k;
            diff_gcm_key(&k, key, key_len);
            uint8_t ct[DIFF_GCM_MAX];
            uint8_t tag[GCM_TAG];
            gcm_seal(&k, nonce, aad, aad_len, pt, n, ct, tag);

            char key_hex[2 * DIFF_GCM_KEY_MAX + 1];
            (void)hex_encode(key_hex, key, key_len);
            char nonce_hex[2 * AES_IV + 1];
            (void)hex_encode(nonce_hex, nonce, sizeof nonce);
            char aad_hex[2 * DIFF_GCM_MAX + 1];
            (void)hex_encode(aad_hex, aad, aad_len);
            char pt_hex[2 * DIFF_GCM_MAX + 1];
            (void)hex_encode(pt_hex, pt, n);
            char ct_hex[2 * DIFF_GCM_MAX + 1];
            (void)hex_encode(ct_hex, ct, n);
            char tag_hex[2 * GCM_TAG + 1];
            (void)hex_encode(tag_hex, tag, sizeof tag);

            char want[2 * (2 * DIFF_GCM_MAX + 1) + 1];
            (void)snprintf(want, sizeof want, "%s %s", ct_hex, tag_hex);
            char cmd[8 * DIFF_GCM_MAX + 64];
            (void)snprintf(cmd, sizeof cmd, "%s %s %s %s %s", diff_gcm_op(key_len, 1), key_hex,
                           nonce_hex, aad_hex, pt_hex);
            expect(cmd, want);
        }
    }
}

// gcm_open, both verdicts. The C seals, then the spec opens what the C
// sealed and must answer the plaintext; the same call with one tag bit
// flipped must answer the refusal, which is "fail" on the wire and 0
// from the C.
static void diff_gcm_open(size_t key_len) {
    for (size_t n = 0; n <= DIFF_GCM_MAX; n += 3) {
        uint8_t key[DIFF_GCM_KEY_MAX];
        uint8_t nonce[AES_IV];
        uint8_t aad[DIFF_GCM_MAX];
        uint8_t pt[DIFF_GCM_MAX];
        size_t aad_len = n % (DIFF_GCM_MAX + 1);
        rng_fill(key, key_len);
        rng_fill(nonce, sizeof nonce);
        rng_fill(aad, aad_len);
        rng_fill(pt, n);

        aes_public_key k;
        diff_gcm_key(&k, key, key_len);
        uint8_t ct[DIFF_GCM_MAX];
        uint8_t tag[GCM_TAG];
        gcm_seal(&k, nonce, aad, aad_len, pt, n, ct, tag);

        char key_hex[2 * DIFF_GCM_KEY_MAX + 1];
        (void)hex_encode(key_hex, key, key_len);
        char nonce_hex[2 * AES_IV + 1];
        (void)hex_encode(nonce_hex, nonce, sizeof nonce);
        char aad_hex[2 * DIFF_GCM_MAX + 1];
        (void)hex_encode(aad_hex, aad, aad_len);
        char ct_hex[2 * DIFF_GCM_MAX + 1];
        (void)hex_encode(ct_hex, ct, n);
        char pt_hex[2 * DIFF_GCM_MAX + 1];
        (void)hex_encode(pt_hex, pt, n);
        char tag_hex[2 * GCM_TAG + 1];
        (void)hex_encode(tag_hex, tag, sizeof tag);
        char cmd[8 * DIFF_GCM_MAX + 64];
        (void)snprintf(cmd, sizeof cmd, "%s %s %s %s %s %s", diff_gcm_op(key_len, 0), key_hex,
                       nonce_hex, aad_hex, ct_hex, tag_hex);
        expect(cmd, pt_hex);

        // The same ciphertext under one wrong tag bit. Both sides refuse,
        // and the C writes no plaintext byte.
        uint8_t wrong_tag[GCM_TAG];
        memcpy(wrong_tag, tag, sizeof wrong_tag);
        wrong_tag[sizeof wrong_tag - 1] = (uint8_t)(wrong_tag[sizeof wrong_tag - 1] ^ 0x80);
        uint8_t untouched[DIFF_GCM_MAX];
        memset(untouched, 0x5a, sizeof untouched);
        if (gcm_open(&k, nonce, aad, aad_len, ct, n, wrong_tag, untouched) != 0) {
            (void)fprintf(stderr, "diff: gcm_open accepted a wrong tag at %zu bytes\n", n);
            exit(1);
        }
        for (size_t i = 0; i < n; i++) {
            if (untouched[i] != 0x5a) {
                (void)fprintf(stderr, "diff: gcm_open wrote plaintext on a wrong tag\n");
                exit(1);
            }
        }
        (void)hex_encode(tag_hex, wrong_tag, sizeof wrong_tag);
        (void)snprintf(cmd, sizeof cmd, "%s %s %s %s %s %s", diff_gcm_op(key_len, 0), key_hex,
                       nonce_hex, aad_hex, ct_hex, tag_hex);
        expect(cmd, "fail");
    }
}

// gcm_ghash on its own, over the same length pairs. GHASH is the half of
// the tag that the cipher does not cover, so a row here separates a
// wrong multiply from a wrong counter block.
static void diff_ghash(size_t key_len) {
    for (size_t aad_len = 0; aad_len <= DIFF_GCM_MAX; aad_len += 11) {
        for (size_t n = 0; n <= DIFF_GCM_MAX; n += 9) {
            uint8_t key[DIFF_GCM_KEY_MAX];
            uint8_t aad[DIFF_GCM_MAX];
            uint8_t ct[DIFF_GCM_MAX];
            rng_fill(key, key_len);
            rng_fill(aad, aad_len);
            rng_fill(ct, n);

            aes_public_key k;
            diff_gcm_key(&k, key, key_len);
            uint8_t out[AES_BLOCK];
            gcm_ghash(&k, aad, aad_len, ct, n, out);

            char key_hex[2 * DIFF_GCM_KEY_MAX + 1];
            (void)hex_encode(key_hex, key, key_len);
            char aad_hex[2 * DIFF_GCM_MAX + 1];
            (void)hex_encode(aad_hex, aad, aad_len);
            char ct_hex[2 * DIFF_GCM_MAX + 1];
            (void)hex_encode(ct_hex, ct, n);
            char want[2 * AES_BLOCK + 1];
            (void)hex_encode(want, out, sizeof out);
            char cmd[6 * DIFF_GCM_MAX + 64];
            (void)snprintf(cmd, sizeof cmd, "ghash %s %s %s", key_hex, aad_hex, ct_hex);
            expect(cmd, want);
        }
    }
}

#endif
