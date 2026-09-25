// The AES-GCM suites, AEAD_AES_128_GCM and AEAD_AES_256_GCM, in their own
// header for the reason test/wycheproof_p256.h is: test/wycheproof_test.c
// holds the helpers they read and every other suite, and it passed 500
// lines when the AES-256 suite joined. This file uses fail and COUNT from
// that file and is included after them.
#ifndef CH_WYCHEPROOF_AES_GCM_H
#define CH_WYCHEPROOF_AES_GCM_H

// The AES-GCM suite, for quic_gcm.c. Guarded because only a
// -DCH_TRANSPORT_QUIC_NONBLOCKING build compiles that file, and the generator emits
// the rows under the same guard, so the legs that build this file
// without the define read a header that declares nothing here.
//
// The key comes from the vector, so this builds an aes_public_key
// through the key schedule directly. INV-26 bounds which keys a library
// source may hand the AEAD and excludes `test` from the rule that holds
// it, for exactly this: a published suite fixes its own keys.
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// One case, laid out as the generator writes it: the key, the 12-byte IV,
// the 16-byte tag, the associated data, the message and the ciphertext.
// k already holds the expanded key; iv points just past the key bytes.
static void check_aes_gcm(const char *suite, uint32_t tc, const aes_public_key *k,
                          const uint8_t *iv, size_t aad_len, size_t n, uint8_t valid) {
    const uint8_t *tag = iv + 12;
    const uint8_t *aad = tag + 16;
    const uint8_t *msg = aad + aad_len;
    const uint8_t *ct = msg + n;
    // The generator skips anything longer, so this never trips; it is
    // a hard backstop because the vectors track upstream HEAD.
    if (n > 1024 || aad_len > 1024) {
        fail(suite, tc, "message exceeds the test buffer");
        return;
    }
    uint8_t got_ct[1024];
    uint8_t got_tag[16];
    uint8_t got_pt[1024];
    if (valid) {
        gcm_seal(k, iv, aad, aad_len, msg, n, got_ct, got_tag);
        if (memcmp(got_ct, ct, n) != 0 || memcmp(got_tag, tag, 16) != 0) {
            fail(suite, tc, "seal output differs from vector");
        }
        if (!gcm_open(k, iv, aad, aad_len, ct, n, tag, got_pt) || memcmp(got_pt, msg, n) != 0) {
            fail(suite, tc, "valid case failed to open");
        }
    } else if (gcm_open(k, iv, aad, aad_len, ct, n, tag, got_pt)) {
        fail(suite, tc, "invalid case accepted");
    }
}

static void run_aes_gcm(void) {
    for (size_t i = 0; i < COUNT(wp_aes_gcm); i++) {
        const uint8_t *key = wp_aes_gcm_data + wp_aes_gcm[i].off;
        aes_public_key k;
        memset(&k, 0, sizeof k);
        aes_expand_round_keys(key, k.key.round_keys);
#ifdef CH_AES_256
        k.key.rounds = AES_128_ROUNDS;
#endif
        check_aes_gcm("aes_gcm", wp_aes_gcm[i].tc, &k, key + AES_128_KEY, wp_aes_gcm[i].aad_len,
                      wp_aes_gcm[i].msg_len, wp_aes_gcm[i].valid);
    }
    printf("wycheproof aes-128-gcm: %zu cases, %d skipped (key/nonce/tag sizes the fixed"
           " API cannot express), %d skipped (over the 1 KB test buffer)\n",
           COUNT(wp_aes_gcm), WP_AES_GCM_SKIPPED, WP_AES_GCM_OVERSIZE);
}

#ifdef CH_AES_256
// AEAD_AES_256_GCM, TLS_AES_256_GCM_SHA384's AEAD. Every leg that builds
// this file passes -DCH_AES_256_TEST, so the AES=soft legs run the
// software reference and the AES=hw leg the instructions a suite build
// runs, and every leg answers the same suite.
static void run_aes256_gcm(void) {
    for (size_t i = 0; i < COUNT(wp_aes256_gcm); i++) {
        const uint8_t *key = wp_aes256_gcm_data + wp_aes256_gcm[i].off;
        aes_public_key k;
        memset(&k, 0, sizeof k);
        aes_expand_round_keys_256(key, k.key.round_keys);
        k.key.rounds = AES_256_ROUNDS;
        check_aes_gcm("aes256_gcm", wp_aes256_gcm[i].tc, &k, key + AES_256_KEY,
                      wp_aes256_gcm[i].aad_len, wp_aes256_gcm[i].msg_len, wp_aes256_gcm[i].valid);
    }
    printf("wycheproof aes-256-gcm: %zu cases, %d skipped (key/nonce/tag sizes the fixed"
           " API cannot express), %d skipped (over the 1 KB test buffer)\n",
           COUNT(wp_aes256_gcm), WP_AES256_GCM_SKIPPED, WP_AES256_GCM_OVERSIZE);
}
#endif // CH_AES_256
#endif // CH_TRANSPORT_QUIC_NONBLOCKING

#endif
