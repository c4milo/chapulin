#include "aead.h"

#include "ct.h"
#include "widemul.h"

// MAC input per RFC 8439: aad, pad to 16, ct, pad to 16, le64(aad_len),
// le64(ctlen). widemul is the answer Poly1305's block loop runs under
// (widemul.h).
static void mac(uint8_t widemul, const uint8_t key[CHACHA20_KEY],
                const uint8_t nonce[CHACHA20_NONCE], const uint8_t *aad, size_t aad_len,
                const uint8_t *ct, size_t n, uint8_t tag[AEAD_TAG]) {
    uint8_t otk[CHACHA20_BLOCK];
    chacha20_block(key, nonce, 0, otk);
    poly1305 p;
    poly1305_init(&p, otk);
    ct_wipe(otk, sizeof otk);

    static const uint8_t zeros[16] = {0};
    widemul_poly1305_update(widemul, &p, aad, aad_len);
    widemul_poly1305_update(widemul, &p, zeros, (16 - (aad_len % 16)) % 16);
    widemul_poly1305_update(widemul, &p, ct, n);
    widemul_poly1305_update(widemul, &p, zeros, (16 - (n % 16)) % 16);
    uint8_t len[16];
    for (int i = 0; i < 8; i++) {
        len[i] = (uint8_t)((uint64_t)aad_len >> (8 * i));
        len[8 + i] = (uint8_t)((uint64_t)n >> (8 * i));
    }
    widemul_poly1305_update(widemul, &p, len, 16);
    widemul_poly1305_final(widemul, &p, tag);
}

void aead_seal(uint8_t widemul, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
               const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
               uint8_t tag[AEAD_TAG]) {
    chacha20_xor(key, nonce, 1, pt, ct, n);
    mac(widemul, key, nonce, aad, aad_len, ct, n, tag);
}

// Whether tag is the MAC of aad and the n bytes at ct under key and nonce:
// computed whole, compared in constant time, and wiped. Both opens call it
// before they release a byte of plaintext.
static int tag_matches(uint8_t widemul, const uint8_t key[AEAD_KEY],
                       const uint8_t nonce[AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG]) {
    uint8_t want[AEAD_TAG];
    mac(widemul, key, nonce, aad, aad_len, ct, n, want);
    uint32_t ok = ct_memeq(want, tag, AEAD_TAG);
    ct_wipe(want, sizeof want);
    return ok != 0;
}

int aead_open(uint8_t widemul, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
              const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
              const uint8_t tag[AEAD_TAG], uint8_t *pt) {
    if (!tag_matches(widemul, key, nonce, aad, aad_len, ct, n, tag)) {
        return 0;
    }
    chacha20_xor(key, nonce, 1, ct, pt, n);
    return 1;
}

#ifdef CH_CPU_RUNTIME
void aead_seal_cpu(uint32_t cpu, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
                   const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                   uint8_t tag[AEAD_TAG]) {
    chacha20_xor_cpu(cpu, key, nonce, 1, pt, ct, n);
    mac(widemul_of_cpu(cpu), key, nonce, aad, aad_len, ct, n, tag);
}

int aead_open_cpu(uint32_t cpu, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
                  const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                  const uint8_t tag[AEAD_TAG], uint8_t *pt) {
    if (!tag_matches(widemul_of_cpu(cpu), key, nonce, aad, aad_len, ct, n, tag)) {
        return 0;
    }
    chacha20_xor_cpu(cpu, key, nonce, 1, ct, pt, n);
    return 1;
}
#endif
