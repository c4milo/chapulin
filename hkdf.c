#include "hkdf.h"

#include <string.h>

#include "ct.h"
#include "ms_assert.h"

void hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen,
                 uint8_t out[SHA256_LEN]) {
    uint8_t k[SHA256_BLOCK] = {0};
    if (keylen > SHA256_BLOCK) {
        sha256_of(key, keylen, k);
    } else {
        memcpy(k, key, keylen);
    }
    uint8_t pad[SHA256_BLOCK];
    sha256 s;
    for (int i = 0; i < SHA256_BLOCK; i++) {
        pad[i] = k[i] ^ 0x36;
    }
    sha256_init(&s);
    sha256_update(&s, pad, SHA256_BLOCK);
    sha256_update(&s, msg, msglen);
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

void hkdf_extract(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen,
                  uint8_t prk[SHA256_LEN]) {
    static const uint8_t zeros[SHA256_LEN] = {0};
    if (salt == NULL) {
        salt = zeros;
        saltlen = SHA256_LEN;
    }
    hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
}

void hkdf_expand(const uint8_t prk[SHA256_LEN], const uint8_t *info, size_t infolen, uint8_t *out,
                 size_t outlen) {
    MS_ASSERT(outlen > 0 && outlen <= (size_t)255 * SHA256_LEN);
    MS_ASSERT(infolen <= 64);
    // T(n) = HMAC(prk, T(n-1) | info | n); msg buffer sized for the max.
    uint8_t msg[SHA256_LEN + 64 + 1];
    uint8_t t[SHA256_LEN] = {0}; // T(0) is empty; tlen 0 keeps it out of round 1
    size_t tlen = 0;
    uint8_t n = 0;
    size_t off = 0;
    while (off < outlen) {
        n++;
        memcpy(msg, t, tlen);
        memcpy(msg + tlen, info, infolen);
        msg[tlen + infolen] = n;
        hmac_sha256(prk, SHA256_LEN, msg, tlen + infolen + 1, t);
        tlen = SHA256_LEN;
        size_t take = outlen - off < SHA256_LEN ? outlen - off : SHA256_LEN;
        memcpy(out + off, t, take);
        off += take;
    }
    ct_wipe(t, sizeof t);
    ct_wipe(msg, sizeof msg);
}

void hkdf_expand_label(const uint8_t secret[SHA256_LEN], const char *label, const uint8_t *ctx,
                       size_t ctxlen, uint8_t *out, size_t outlen) {
    size_t lab = strlen(label);
    MS_ASSERT(lab > 0 && lab <= HKDF_LABEL_MAX);
    MS_ASSERT(ctxlen <= SHA256_LEN);
    MS_ASSERT(outlen <= 0xffff);
    // struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
    uint8_t info[2 + 1 + 6 + HKDF_LABEL_MAX + 1 + SHA256_LEN];
    size_t p = 0;
    info[p++] = (uint8_t)(outlen >> 8);
    info[p++] = (uint8_t)outlen;
    info[p++] = (uint8_t)(6 + lab);
    memcpy(info + p, "tls13 ", 6);
    p += 6;
    memcpy(info + p, label, lab);
    p += lab;
    info[p++] = (uint8_t)ctxlen;
    memcpy(info + p, ctx, ctxlen);
    p += ctxlen;
    hkdf_expand(secret, info, p, out, outlen);
}

void hkdf_derive_secret(const uint8_t secret[SHA256_LEN], const char *label,
                        const uint8_t hash[SHA256_LEN], uint8_t out[SHA256_LEN]) {
    hkdf_expand_label(secret, label, hash, SHA256_LEN, out, SHA256_LEN);
}
