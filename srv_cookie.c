// The HelloRetryRequest cookie: mint and open. srv_cookie.h states the format
// and what each term is there for. Reading goes through the rbuf reader and
// writing through the wbuf writer (buf.h), so no step here does raw buffer
// arithmetic and no multi-byte value assumes host endianness.
#include "srv_cookie.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake_message.h"
#include "hkdf.h"

// The cookie body's fixed head, in bytes: the version byte, the two suite
// bytes and the two group bytes. They are the first three terms of
// SRV_COOKIE_MAX (srv_cookie.h), and everything after them has a length the
// suite fixes.
#define SRV_COOKIE_HEAD 5

// The transcript hash length one cipher suite fixes (RFC 9846 §7.1 binds the
// hash to the suite), in bytes, or 0 for a suite this build does not hold.
//
// The suites that answer a length are the ones srv_select can choose:
// TLS_CHACHA20_POLY1305_SHA256 in every build, and TLS_AES_128_GCM_SHA256
// under -DCH_SUITE_AES_GCM. Both hash with SHA-256. Every other code point
// answers 0, and srv_cookie_open refuses the cookie that names it. A cookie
// must open under every suite srv_select can choose, because the server
// mints one for whichever suite it selected: a build that left AES-GCM out
// here refused its own cookie, and with it every retried ClientHello from a
// client that offers no ChaCha20.
static size_t suite_hash_len(uint16_t suite) {
#ifdef CH_SUITE_AES_GCM
    if (suite == SUITE_AES_128_GCM_SHA256) {
        return SHA256_LEN;
    }
#endif
    if (suite == SUITE_CHACHA20_POLY1305_SHA256) {
        return SHA256_LEN;
    }
    return 0;
}

size_t srv_cookie_mint(const uint8_t key[SRV_COOKIE_KEY_LEN], uint16_t suite, uint16_t group,
                       const uint8_t *ch1_hash, size_t hash_len, const uint8_t frozen[SHA256_LEN],
                       uint8_t *out, size_t cap) {
    if (hash_len < SHA256_LEN || hash_len > SRV_COOKIE_HASH_MAX) {
        return 0;
    }
    // The whole cookie's length, checked before the first byte is written,
    // because the contract refuses a short cap having written nothing and the
    // writer would leave a partial body behind.
    size_t total = SRV_COOKIE_HEAD + hash_len + SHA256_LEN + SHA256_LEN;
    if (cap < total) {
        return 0;
    }

    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, SRV_COOKIE_VERSION);
    wb_u16(&w, suite);
    wb_u16(&w, group);
    wb_bytes(&w, ch1_hash, hash_len);
    wb_bytes(&w, frozen, SHA256_LEN);

    // Everything written so far is the body, so the MAC covers the first
    // w.len bytes of out. The MAC goes out in the clear as the cookie's last
    // field, so nothing wipes it.
    const uint8_t *body = out;
    uint8_t mac[SHA256_LEN];
    hmac_sha256(key, SRV_COOKIE_KEY_LEN, body, w.len, mac);
    wb_bytes(&w, mac, sizeof mac);

    // The cap check above is what keeps the writer inside the caller's
    // buffer; this tail reports the writer's own verdict, as every builder in
    // this tree ends.
    return w.err ? 0 : w.len;
}

int srv_cookie_open(const uint8_t key[SRV_COOKIE_KEY_LEN], const uint8_t *cookie, size_t n,
                    uint16_t *suite, uint16_t *group, uint8_t *ch1_hash, size_t *hash_len,
                    uint8_t frozen[SHA256_LEN]) {
    rbuf r;
    rb_init(&r, cookie, n);
    uint8_t version = rb_u8(&r);
    uint16_t body_suite = rb_u16(&r);
    uint16_t body_group = rb_u16(&r);
    if (r.err || version != SRV_COOKIE_VERSION) {
        return CH_EPROTO;
    }

    // The suite fixes the length of the hash term, and that length fixes the
    // length of the whole cookie. A suite this build does not hold ends the
    // read here.
    size_t body_hash_len = suite_hash_len(body_suite);
    if (body_hash_len == 0) {
        return CH_EPROTO;
    }

    const uint8_t *body_hash = rb_bytes(&r, body_hash_len);
    const uint8_t *body_frozen = rb_bytes(&r, SHA256_LEN);
    const uint8_t *mac = rb_bytes(&r, SHA256_LEN);
    // INV-25's exact-fill check, and the length check the header promises
    // before the MAC runs: r.err refuses a cookie shorter than the suite
    // fixes, and a byte left over refuses one longer. The reader is bounded
    // by n, so neither answer came from a read past the end.
    if (r.err || rb_left(&r) != 0) {
        return CH_EPROTO;
    }

    // The MAC covers the body, which is every byte before the MAC itself.
    // ct_memeq compares all SHA256_LEN bytes, so a client cannot search for a
    // valid MAC one byte per round trip. want_mac is the correct MAC over a
    // body the client chose, so it is wiped rather than left on the stack.
    uint8_t want_mac[SHA256_LEN];
    hmac_sha256(key, SRV_COOKIE_KEY_LEN, cookie, n - SHA256_LEN, want_mac);
    uint32_t equal = ct_memeq(mac, want_mac, SHA256_LEN);
    ct_wipe(want_mac, sizeof want_mac);
    if (equal == 0) {
        return CH_EPROTO;
    }

    *suite = body_suite;
    *group = body_group;
    *hash_len = body_hash_len;
    memcpy(ch1_hash, body_hash, body_hash_len);
    memcpy(frozen, body_frozen, SHA256_LEN);
    return CH_OK;
}

#endif // CH_ROLE_SERVER
