#include "record.h"

#include "ct.h"
#include "hkdf.h"

void rec_dir_init(rec_dir *d, const uint8_t secret[SHA256_LEN]) {
    hkdf_expand_label(secret, "key", NULL, 0, d->key, AEAD_KEY);
    hkdf_expand_label(secret, "iv", NULL, 0, d->iv, AEAD_NONCE);
    d->seq = 0;
}

void rec_dir_update(uint8_t secret[SHA256_LEN], rec_dir *d) {
    uint8_t next[SHA256_LEN];
    hkdf_expand_label(secret, "traffic upd", NULL, 0, next, SHA256_LEN);
    for (size_t i = 0; i < SHA256_LEN; i++) {
        secret[i] = next[i];
    }
    ct_wipe(next, sizeof next);
    rec_dir_init(d, secret);
}

// Per-record nonce: IV XOR the sequence number in the low 8 bytes.
static void nonce_of(const rec_dir *d, uint8_t nonce[AEAD_NONCE]) {
    for (size_t i = 0; i < AEAD_NONCE; i++) {
        nonce[i] = d->iv[i];
    }
    for (size_t i = 0; i < 8; i++) {
        nonce[AEAD_NONCE - 1 - i] ^= (uint8_t)(d->seq >> (8 * i));
    }
}

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *outn) {
    size_t body = n + 1 + AEAD_TAG; // inner type byte + tag
    if (body > 0x4000 + 256 || REC_HDR + body > cap) {
        return -1;
    }
    out[0] = REC_APPDATA; // outer type is always application_data
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (uint8_t)(body >> 8);
    out[4] = (uint8_t)body;

    // Build TLSInnerPlaintext in place: content || type, no padding.
    uint8_t *inner = out + REC_HDR;
    for (size_t i = 0; i < n; i++) {
        inner[i] = pt[i];
    }
    inner[n] = type;

    uint8_t nonce[AEAD_NONCE];
    nonce_of(d, nonce);
    aead_seal(d->key, nonce, out, REC_HDR, inner, n + 1, inner, inner + n + 1);
    d->seq++;
    *outn = REC_HDR + body;
    return 0;
}

int rec_open(rec_dir *d, const uint8_t *rec, size_t n, uint8_t *pt, size_t cap, size_t *ptn,
             uint8_t *type) {
    if (n < REC_HDR + 1 + AEAD_TAG) {
        return -1;
    }
    size_t body = ((size_t)rec[3] << 8) | rec[4];
    if (rec[0] != REC_APPDATA || body != n - REC_HDR || body > 0x4000 + 256) {
        return -1;
    }
    size_t innerlen = body - AEAD_TAG;
    if (innerlen > cap) {
        return -1;
    }
    uint8_t nonce[AEAD_NONCE];
    nonce_of(d, nonce);
    if (!aead_open(d->key, nonce, rec, REC_HDR, rec + REC_HDR, innerlen, rec + REC_HDR + innerlen,
                   pt)) {
        return -1;
    }
    d->seq++;
    // Strip zero padding to expose the inner content type; an all-zero
    // inner plaintext is malformed.
    while (innerlen > 0 && pt[innerlen - 1] == 0) {
        innerlen--;
    }
    if (innerlen == 0) {
        return -1;
    }
    *type = pt[innerlen - 1];
    *ptn = innerlen - 1;
    return 0;
}
