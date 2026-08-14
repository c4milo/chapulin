#include "aead.h"

#include "ct.h"

// MAC input per RFC 8439: aad, pad to 16, ct, pad to 16, le64(aadlen),
// le64(ctlen).
static void mac(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t n,
                uint8_t tag[AEAD_TAG]) {
    uint8_t otk[CHACHA20_BLOCK];
    chacha20_block(key, nonce, 0, otk);
    poly1305 p;
    poly1305_init(&p, otk);
    ct_wipe(otk, sizeof otk);

    static const uint8_t zeros[16] = {0};
    poly1305_update(&p, aad, aadlen);
    poly1305_update(&p, zeros, (16 - (aadlen % 16)) % 16);
    poly1305_update(&p, ct, n);
    poly1305_update(&p, zeros, (16 - (n % 16)) % 16);
    uint8_t len[16];
    for (int i = 0; i < 8; i++) {
        len[i] = (uint8_t)((uint64_t)aadlen >> (8 * i));
        len[8 + i] = (uint8_t)((uint64_t)n >> (8 * i));
    }
    poly1305_update(&p, len, 16);
    poly1305_final(&p, tag);
}

void aead_seal(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
               size_t aadlen, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]) {
    chacha20_xor(key, nonce, 1, pt, ct, n);
    mac(key, nonce, aad, aadlen, ct, n, tag);
}

int aead_open(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
              size_t aadlen, const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG],
              uint8_t *pt) {
    uint8_t want[AEAD_TAG];
    mac(key, nonce, aad, aadlen, ct, n, want);
    uint32_t ok = ct_memeq(want, tag, AEAD_TAG);
    ct_wipe(want, sizeof want);
    if (!ok) {
        return 0;
    }
    chacha20_xor(key, nonce, 1, ct, pt, n);
    return 1;
}
