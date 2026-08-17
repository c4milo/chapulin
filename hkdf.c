#include "hkdf.h"

#include <string.h>

#include "ch_assert.h"
#include "ct.h"

void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                 uint8_t out[SHA256_LEN]) {
    uint8_t k[SHA256_BLOCK] = {0};
    if (key_len > SHA256_BLOCK) {
        sha256_of(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }
    uint8_t pad[SHA256_BLOCK];
    sha256 s;
    for (int i = 0; i < SHA256_BLOCK; i++) {
        pad[i] = k[i] ^ 0x36;
    }
    sha256_init(&s);
    sha256_update(&s, pad, SHA256_BLOCK);
    sha256_update(&s, msg, msg_len);
    sha256_final(&s, out);
    for (int i = 0; i < SHA256_BLOCK; i++) {
        pad[i] = k[i] ^ 0x5c;
    }
    sha256_init(&s);
    sha256_update(&s, pad, SHA256_BLOCK);
    sha256_update(&s, out, SHA256_LEN);
    sha256_final(&s, out);
    ct_wipe(k, sizeof k);
    ct_wipe(pad, sizeof pad);
    ct_wipe(&s, sizeof s);
}

void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                  uint8_t prk[SHA256_LEN]) {
    static const uint8_t zeros[SHA256_LEN] = {0};
    if (salt == NULL) {
        salt = zeros;
        salt_len = SHA256_LEN;
    }
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

void hkdf_expand(const uint8_t prk[SHA256_LEN], const uint8_t *info, size_t info_len, uint8_t *out,
                 size_t out_len) {
    CH_ASSERT(out_len > 0 && out_len <= (size_t)255 * SHA256_LEN);
    CH_ASSERT(info_len <= 64);
    // T(n) = HMAC(prk, T(n-1) | info | n); msg buffer sized for the max.
    uint8_t msg[SHA256_LEN + 64 + 1];
    uint8_t t[SHA256_LEN] = {0}; // T(0) is empty; t_len 0 keeps it out of round 1
    size_t t_len = 0;
    uint8_t n = 0;
    size_t off = 0;
    while (off < out_len) {
        n++;
        memcpy(msg, t, t_len);
        memcpy(msg + t_len, info, info_len);
        msg[t_len + info_len] = n;
        hmac_sha256(prk, SHA256_LEN, msg, t_len + info_len + 1, t);
        t_len = SHA256_LEN;
        size_t take = out_len - off < SHA256_LEN ? out_len - off : SHA256_LEN;
        memcpy(out + off, t, take);
        off += take;
    }
    ct_wipe(t, sizeof t);
    ct_wipe(msg, sizeof msg);
}

void hkdf_expand_label(const uint8_t secret[SHA256_LEN], const char *label, const uint8_t *ctx,
                       size_t ctx_len, uint8_t *out, size_t out_len) {
    size_t label_len = strlen(label);
    CH_ASSERT(label_len > 0 && label_len <= HKDF_LABEL_MAX);
    CH_ASSERT(ctx_len <= SHA256_LEN);
    CH_ASSERT(out_len <= 0xffff);
    // struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
    uint8_t info[2 + 1 + 6 + HKDF_LABEL_MAX + 1 + SHA256_LEN];
    size_t p = 0;
    info[p++] = (uint8_t)(out_len >> 8);
    info[p++] = (uint8_t)out_len;
    info[p++] = (uint8_t)(6 + label_len);
    memcpy(info + p, "tls13 ", 6);
    p += 6;
    memcpy(info + p, label, label_len);
    p += label_len;
    info[p++] = (uint8_t)ctx_len;
    if (ctx_len > 0) {
        memcpy(info + p, ctx, ctx_len);
        p += ctx_len;
    }
    hkdf_expand(secret, info, p, out, out_len);
}

void hkdf_derive_secret(const uint8_t secret[SHA256_LEN], const char *label,
                        const uint8_t hash[SHA256_LEN], uint8_t out[SHA256_LEN]) {
    hkdf_expand_label(secret, label, hash, SHA256_LEN, out, SHA256_LEN);
}
