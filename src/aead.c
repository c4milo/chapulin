#include "aead.h"

#include "aead_avx2.h"
#include "ct.h"
#include "widemul.h"

// The padding Poly1305 absorbs after the aad and after the ciphertext.
static const uint8_t ZEROS[16] = {0};

// MAC input per RFC 8439: aad, pad to 16, ct, pad to 16, le64(aad_len),
// le64(ctlen). widemul is the answer Poly1305's block loop runs under
// (widemul.h). mac_start keys p and absorbs the aad and its padding, and
// mac_end absorbs the padding of n bytes of ciphertext and the lengths,
// and writes the tag.
static void mac_start(uint8_t widemul, poly1305 *p, const uint8_t key[CHACHA20_KEY],
                      const uint8_t nonce[CHACHA20_NONCE], const uint8_t *aad, size_t aad_len) {
    uint8_t otk[CHACHA20_BLOCK];
    chacha20_block(key, nonce, 0, otk);
    poly1305_init(p, otk);
    ct_wipe(otk, sizeof otk);
    widemul_poly1305_update(widemul, p, aad, aad_len);
    widemul_poly1305_update(widemul, p, ZEROS, (16 - (aad_len % 16)) % 16);
}

static void mac_end(uint8_t widemul, poly1305 *p, size_t aad_len, size_t n, uint8_t tag[AEAD_TAG]) {
    widemul_poly1305_update(widemul, p, ZEROS, (16 - (n % 16)) % 16);
    uint8_t len[16];
    for (int i = 0; i < 8; i++) {
        len[i] = (uint8_t)((uint64_t)aad_len >> (8 * i));
        len[8 + i] = (uint8_t)((uint64_t)n >> (8 * i));
    }
    widemul_poly1305_update(widemul, p, len, 16);
    widemul_poly1305_final(widemul, p, tag);
}

// The tag of aad and the n bytes at ct under key and nonce. cpu is the
// session's ch_cfg.cpu, from which the ciphertext's update picks its path
// (widemul_poly1305_update_cpu), and 0 from aead_seal and aead_open, which
// hold no description of the CPU.
static void mac(uint32_t cpu, uint8_t widemul, const uint8_t key[CHACHA20_KEY],
                const uint8_t nonce[CHACHA20_NONCE], const uint8_t *aad, size_t aad_len,
                const uint8_t *ct, size_t n, uint8_t tag[AEAD_TAG]) {
    poly1305 p;
    mac_start(widemul, &p, key, nonce, aad, aad_len);
    widemul_poly1305_update_cpu(cpu, widemul, &p, ct, n);
    mac_end(widemul, &p, aad_len, n, tag);
}

void aead_seal(uint8_t widemul, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
               const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
               uint8_t tag[AEAD_TAG]) {
    chacha20_xor(key, nonce, 1, pt, ct, n);
    mac(0, widemul, key, nonce, aad, aad_len, ct, n, tag);
}

// Whether tag is the MAC of aad and the n bytes at ct under key and nonce:
// computed whole, compared in constant time, and wiped. Both opens call it
// before they release a byte of plaintext.
static int tag_matches(uint32_t cpu, uint8_t widemul, const uint8_t key[AEAD_KEY],
                       const uint8_t nonce[AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG]) {
    uint8_t want[AEAD_TAG];
    mac(cpu, widemul, key, nonce, aad, aad_len, ct, n, want);
    uint32_t ok = ct_memeq_public(want, tag, AEAD_TAG);
    ct_wipe(want, sizeof want);
    return ok != 0;
}

int aead_open(uint8_t widemul, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
              const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
              const uint8_t tag[AEAD_TAG], uint8_t *pt) {
    if (!tag_matches(0, widemul, key, nonce, aad, aad_len, ct, n, tag)) {
        return 0;
    }
    chacha20_xor(key, nonce, 1, ct, pt, n);
    return 1;
}

#ifdef CH_AEAD_AVX2
// Whether a seal or an open of n bytes in a session whose ch_cfg.cpu is
// cpu runs aead_avx2.c's one pass: where the two-pass AEAD would run
// chacha20_avx2.c's keystream and poly1305_avx2.c's kernel, that is where
// cpu holds CH_CPU_AVX2 and CH_CPU_CONSTANT_TIME_MULTIPLY and not
// CH_CPU_AVX512_IFMA, and n is AEAD_AVX2_MIN or more (docs/decisions.md
// 199).
static int use_one_pass(uint32_t cpu, size_t n) {
    return widemul_poly1305_avx2(cpu, widemul_of_cpu(cpu)) &&
           !widemul_poly1305_ifma(cpu, widemul_of_cpu(cpu)) && n >= AEAD_AVX2_MIN;
}

// The one pass's seal and open stay out of line. Inlined, their poly1305
// and tag gave aead_seal_cpu and aead_open_cpu a frame of 136 bytes under
// gcc 13 and 168 under clang 23, where gcc gave them 32 and 64 before. Every
// session's two-pass AEAD then saved and restored that frame, and a short
// message paid for it (docs/decisions.md 207).
static __attribute__((noinline)) void
seal_one_pass(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
              size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]) {
    poly1305 p;
    mac_start(WIDEMUL_CONSTANT_TIME, &p, key, nonce, aad, aad_len);
    aead_avx2_seal(key, nonce, &p, pt, n, ct);
    mac_end(WIDEMUL_CONSTANT_TIME, &p, aad_len, n, tag);
}

// The open decrypts while it absorbs, and on a mismatch wipes the n bytes
// it wrote, as gcm.c's open does (docs/decisions.md 85).
static __attribute__((noinline)) int open_one_pass(const uint8_t key[AEAD_KEY],
                                                   const uint8_t nonce[AEAD_NONCE],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *ct, size_t n,
                                                   const uint8_t tag[AEAD_TAG], uint8_t *pt) {
    poly1305 p;
    uint8_t want[AEAD_TAG];
    mac_start(WIDEMUL_CONSTANT_TIME, &p, key, nonce, aad, aad_len);
    aead_avx2_open(key, nonce, &p, ct, n, pt);
    mac_end(WIDEMUL_CONSTANT_TIME, &p, aad_len, n, want);
    uint32_t ok = ct_memeq_public(want, tag, AEAD_TAG);
    ct_wipe(want, sizeof want);
    if (ok == 0) {
        ct_wipe(pt, n);
        return 0;
    }
    return 1;
}
#endif

#ifdef CH_CPU_RUNTIME
void aead_seal_cpu(uint32_t cpu, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
                   const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                   uint8_t tag[AEAD_TAG]) {
#ifdef CH_AEAD_AVX2
    if (use_one_pass(cpu, n)) {
        seal_one_pass(key, nonce, aad, aad_len, pt, n, ct, tag);
        return;
    }
#endif
    chacha20_xor_cpu(cpu, key, nonce, 1, pt, ct, n);
    mac(cpu, widemul_of_cpu(cpu), key, nonce, aad, aad_len, ct, n, tag);
}

int aead_open_cpu(uint32_t cpu, const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
                  const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                  const uint8_t tag[AEAD_TAG], uint8_t *pt) {
#ifdef CH_AEAD_AVX2
    if (use_one_pass(cpu, n)) {
        return open_one_pass(key, nonce, aad, aad_len, ct, n, tag, pt);
    }
#endif
    if (!tag_matches(cpu, widemul_of_cpu(cpu), key, nonce, aad, aad_len, ct, n, tag)) {
        return 0;
    }
    chacha20_xor_cpu(cpu, key, nonce, 1, ct, pt, n);
    return 1;
}
#endif
