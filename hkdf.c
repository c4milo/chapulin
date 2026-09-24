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

#ifdef CH_HASH_SHA384
// hmac_sha256's body over SHA-384. Its own function rather than a hash
// argument inside one body: the one-function form measured cognitive
// complexity 24 against the tree's threshold of 15 (docs/server.md, "What
// it costs in this tree"), and two bodies behind the dispatcher below read
// as the RFC 2104 construction twice, with nothing to thread through.
void hmac_sha384(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                 uint8_t out[SHA384_LEN]) {
    uint8_t k[SHA512_BLOCK] = {0};
    if (key_len > SHA512_BLOCK) {
        sha384_of(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }
    uint8_t pad[SHA512_BLOCK];
    sha512 s;
    for (int i = 0; i < SHA512_BLOCK; i++) {
        pad[i] = k[i] ^ 0x36;
    }
    sha384_init(&s);
    sha512_update(&s, pad, SHA512_BLOCK);
    sha512_update(&s, msg, msg_len);
    sha384_final(&s, out);
    for (int i = 0; i < SHA512_BLOCK; i++) {
        pad[i] = k[i] ^ 0x5c;
    }
    sha384_init(&s);
    sha512_update(&s, pad, SHA512_BLOCK);
    sha512_update(&s, out, SHA384_LEN);
    sha384_final(&s, out);
    ct_wipe(k, sizeof k);
    ct_wipe(pad, sizeof pad);
    ct_wipe(&s, sizeof s);
}
#endif

void hmac(size_t hash_len, const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
          uint8_t *out) {
#ifdef CH_HASH_SHA384
    // hash_len is the suite's, which the ServerHello named in the clear, so
    // this branch reads a public value.
    if (hash_len == SHA384_LEN) {
        hmac_sha384(key, key_len, msg, msg_len, out);
        return;
    }
#endif
    CH_ASSERT(hash_len == SHA256_LEN);
    hmac_sha256(key, key_len, msg, msg_len, out);
}

void hkdf_extract(size_t hash_len, const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                  size_t ikm_len, uint8_t *prk) {
    static const uint8_t zeros[HKDF_HASH_MAX] = {0};
    if (salt == NULL) {
        salt = zeros;
        salt_len = hash_len;
    }
    hmac(hash_len, salt, salt_len, ikm, ikm_len, prk);
}

void hkdf_expand(size_t hash_len, const uint8_t *prk, const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len) {
    CH_ASSERT(hash_len <= HKDF_HASH_MAX);
    CH_ASSERT(out_len > 0 && out_len <= (size_t)255 * hash_len);
    CH_ASSERT(info_len <= HKDF_INFO_MAX);
    // T(n) = HMAC(prk, T(n-1) | info | n); msg buffer sized for the max.
    uint8_t msg[HKDF_HASH_MAX + HKDF_INFO_MAX + 1];
    uint8_t t[HKDF_HASH_MAX] = {0}; // T(0) is empty; t_len 0 keeps it out of round 1
    size_t t_len = 0;
    uint8_t n = 0;
    size_t off = 0;
    while (off < out_len) {
        n++;
        memcpy(msg, t, t_len);
        memcpy(msg + t_len, info, info_len);
        msg[t_len + info_len] = n;
        hmac(hash_len, prk, hash_len, msg, t_len + info_len + 1, t);
        t_len = hash_len;
        size_t take = out_len - off < hash_len ? out_len - off : hash_len;
        memcpy(out + off, t, take);
        off += take;
    }
    ct_wipe(t, sizeof t);
    ct_wipe(msg, sizeof msg);
}

void hkdf_expand_label(size_t hash_len, const uint8_t *secret, const char *label,
                       const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len) {
    size_t label_len = strlen(label);
    CH_ASSERT(label_len > 0 && label_len <= HKDF_LABEL_MAX);
    CH_ASSERT(ctx_len <= HKDF_HASH_MAX);
    CH_ASSERT(out_len <= 0xffff);
    // struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
    uint8_t info[HKDF_INFO_MAX];
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
    hkdf_expand(hash_len, secret, info, p, out, out_len);
}

void hkdf_derive_secret(size_t hash_len, const uint8_t *secret, const char *label,
                        const uint8_t *hash, uint8_t *out) {
    hkdf_expand_label(hash_len, secret, label, hash, hash_len, out, hash_len);
}
