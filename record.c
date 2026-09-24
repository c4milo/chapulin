#include "record.h"

#include "ct.h"
#include "handshake_message.h"
#include "hkdf.h"
#ifdef CH_SUITE_AES_GCM
#include "aes_traffic_key.h"
#include "quic_gcm.h"

// The key each suite fixes. TLS_AES_128_GCM_SHA256 takes 16 and
// TLS_CHACHA20_POLY1305_SHA256 takes 32; both take the same 12-byte IV
// and write the same 16-byte tag, so only the key length varies.
static size_t suite_key_len(uint16_t suite) {
    return suite == SUITE_AES_128_GCM_SHA256 ? AES_128_KEY : AEAD_KEY;
}

// Whether d runs AES-GCM rather than ChaCha20-Poly1305. The suite is
// public: the ServerHello named it in the clear.
static int runs_aes_gcm(const rec_dir *d) {
    return d->suite == SUITE_AES_128_GCM_SHA256;
}

// Seals and opens one AES-GCM record body in place, the two AES arms of
// seal_body and open_body below. The round keys live on this frame and
// die with it: rec_dir keeps the key bytes and nothing expanded, so no
// schedule outlives the record it protected.
static void seal_aes_gcm(const rec_dir *d, const uint8_t nonce[AEAD_NONCE],
                         const uint8_t hdr[REC_HDR], uint8_t *body, size_t len) {
    aes_traffic_key k;
    aes_traffic_key_init(&k, d->key, suite_key_len(d->suite));
    gcm_traffic_seal(&k, nonce, hdr, REC_HDR, body, len, body, body + len);
    ct_wipe(&k, sizeof k);
}

static int open_aes_gcm(const rec_dir *d, const uint8_t nonce[AEAD_NONCE], const uint8_t *rec,
                        size_t len, uint8_t *pt) {
    aes_traffic_key k;
    aes_traffic_key_init(&k, d->key, suite_key_len(d->suite));
    int ok = gcm_traffic_open(&k, nonce, rec, REC_HDR, rec + REC_HDR, len, rec + REC_HDR + len, pt);
    ct_wipe(&k, sizeof k);
    return ok;
}
#endif

// The AEAD of one record: len bytes of TLSInnerPlaintext at body sealed
// in place with the tag after them, under whichever AEAD d runs, with
// the record header as the associated data (RFC 9846 §5.2).
static void seal_body(const rec_dir *d, const uint8_t nonce[AEAD_NONCE], const uint8_t hdr[REC_HDR],
                      uint8_t *body, size_t len) {
#ifdef CH_SUITE_AES_GCM
    if (runs_aes_gcm(d)) {
        seal_aes_gcm(d, nonce, hdr, body, len);
        return;
    }
#endif
    aead_seal(d->key, nonce, hdr, REC_HDR, body, len, body, body + len);
}

// The other direction: the record at rec holds a header, len bytes of
// ciphertext and the tag, and pt gets the plaintext. Returns 1 when the
// tag matched and 0, having written nothing, when it did not.
static int open_body(const rec_dir *d, const uint8_t nonce[AEAD_NONCE], const uint8_t *rec,
                     size_t len, uint8_t *pt) {
#ifdef CH_SUITE_AES_GCM
    if (runs_aes_gcm(d)) {
        return open_aes_gcm(d, nonce, rec, len, pt);
    }
#endif
    return aead_open(d->key, nonce, rec, REC_HDR, rec + REC_HDR, len, rec + REC_HDR + len, pt);
}

#ifdef CH_SUITE_AES_GCM

void rec_dir_init_suite(rec_dir *d, const uint8_t secret[SHA256_LEN], uint16_t suite) {
    // The whole array is written before the shorter derive, so an AES key
    // leaves no bytes of the previous key behind it.
    ct_wipe(d->key, sizeof d->key);
    d->suite = suite;
    hkdf_expand_label(secret, "key", NULL, 0, d->key, suite_key_len(suite));
    hkdf_expand_label(secret, "iv", NULL, 0, d->iv, AEAD_NONCE);
    d->seq = 0;
}
#endif

void rec_dir_init(rec_dir *d, const uint8_t secret[SHA256_LEN]) {
#ifdef CH_SUITE_AES_GCM
    rec_dir_init_suite(d, secret, SUITE_CHACHA20_POLY1305_SHA256);
#else
    hkdf_expand_label(secret, "key", NULL, 0, d->key, AEAD_KEY);
    hkdf_expand_label(secret, "iv", NULL, 0, d->iv, AEAD_NONCE);
    d->seq = 0;
#endif
}

void rec_dir_update(uint8_t secret[SHA256_LEN], rec_dir *d) {
    uint8_t next[SHA256_LEN];
    hkdf_expand_label(secret, "traffic upd", NULL, 0, next, SHA256_LEN);
    for (size_t i = 0; i < SHA256_LEN; i++) {
        secret[i] = next[i];
    }
    ct_wipe(next, sizeof next);
    // KeyUpdate changes the key and never the AEAD. rec_dir_init here
    // would move an AES-GCM direction to ChaCha20 at its first KeyUpdate.
    REC_DIR_INIT_SUITE(d, secret, d->suite);
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
             size_t *out_len) {
    if (d->seq == UINT64_MAX) {
        return -1; // RFC 9846 §5.3: stop before the next increment could wrap
    }
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
    seal_body(d, nonce, out, inner, n + 1);
    d->seq++;
    *out_len = REC_HDR + body;
    return 0;
}

int rec_open(rec_dir *d, const uint8_t *rec, size_t n, uint8_t *pt, size_t cap, size_t *pt_len,
             uint8_t *type) {
    if (d->seq == UINT64_MAX) {
        return -1; // RFC 9846 §5.3: stop before the next increment could wrap
    }
    if (n < REC_HDR + 1 + AEAD_TAG) {
        return -1;
    }
    size_t body = ((size_t)rec[3] << 8) | rec[4];
    if (rec[0] != REC_APPDATA || body != n - REC_HDR || body > 0x4000 + 256) {
        return -1;
    }
    size_t inner_len = body - AEAD_TAG;
    // RFC 9846 §5.4: TLSInnerPlaintext (content + type + padding) tops out
    // at 2^14 + 1 even when our buffer could hold more.
    if (inner_len > 0x4001 || inner_len > cap) {
        return -1;
    }
    uint8_t nonce[AEAD_NONCE];
    nonce_of(d, nonce);
    if (!open_body(d, nonce, rec, inner_len, pt)) {
        return -1;
    }
    d->seq++;
    // Strip zero padding to expose the inner content type; an all-zero
    // inner plaintext is malformed.
    while (inner_len > 0 && pt[inner_len - 1] == 0) {
        inner_len--;
    }
    if (inner_len == 0) {
        return -1;
    }
    *type = pt[inner_len - 1];
    *pt_len = inner_len - 1;
    return 0;
}
