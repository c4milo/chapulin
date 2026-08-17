// Proves: ch_handshake — the record pump, cross-record reassembly,
// ServerHello/EE parsing, HRR restart, and the run() state machine — is
// memory-safe and UB-free against ANY record stream a peer can send, at a
// 96-byte receive buffer (every reassembly and compaction state is
// reachable at that size; larger buffers only repeat the middle).
//
// Layered proof: io, record protection, the key schedule, hashing, and
// x25519 are stubs asserting their proven contracts and havocing results,
// so nothing here depends on crypto values — the object under proof is
// the driver's own arithmetic and state. buf.c, ct.c, and hsparse.c are
// real.
#include "harness.h"

#include <string.h>

#include "hsmsg.h"
#include "io.h"
#include "keysched.h"
#include "p256.h"
#include "rand.h"
#include "record.h"
#include "session.h"
#include "x25519.h"

void ch_rand_bytes(uint8_t *p, size_t n) {
    fill_nondet(p, n);
}

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    __CPROVER_assert(cfg != NULL, "send: cfg valid");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "send: bytes readable");
    return (nondet_u8() & 1) ? CH_OK : CH_EIO;
}

// The hostile input source: any outer type, any body bytes, any length
// the io contract admits (1..2^14+256 body, within cap), or any error.
int io_read_record(const ch_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer, size_t *reclen) {
    __CPROVER_assert(cfg != NULL, "read: cfg valid");
    uint8_t choice = nondet_u8();
    if (choice == 0) {
        return CH_EIO;
    }
    if (choice == 1) {
        return CH_EPROTO;
    }
    if (choice == 2 || cap < REC_HDR + 1) {
        return CH_ECAP;
    }
    size_t body = nondet_size_t();
    __CPROVER_assume(body >= 1 && body <= 0x4000 + 256 && REC_HDR + body <= cap);
    __CPROVER_assert(__CPROVER_w_ok(buf, REC_HDR + body), "read: buffer writable");
    fill_nondet(buf, REC_HDR + body);
    *outer = nondet_u8();
    *reclen = REC_HDR + body;
    return CH_OK;
}

void rec_dir_init(rec_dir *d, const uint8_t secret[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(secret, SHA256_LEN), "dir: secret readable");
    fill_nondet((uint8_t *)d, sizeof *d);
}

void rec_dir_update(uint8_t secret[SHA256_LEN], rec_dir *d) {
    __CPROVER_assert(__CPROVER_w_ok(secret, SHA256_LEN), "upd: secret writable");
    fill_nondet(secret, SHA256_LEN);
    fill_nondet((uint8_t *)d, sizeof *d);
}

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *outn) {
    (void)type;
    __CPROVER_assert(__CPROVER_w_ok(d, sizeof *d), "seal: dir writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "seal: pt readable");
    size_t total = REC_HDR + n + 1 + AEAD_TAG;
    if (n + 1 + AEAD_TAG > 0x4000 + 256 || total > cap) {
        return -1;
    }
    __CPROVER_assert(__CPROVER_w_ok(out, total), "seal: out writable");
    fill_nondet(out, total);
    *outn = total;
    return 0;
}

// All-or-nothing, like the proven aead contract: plaintext bytes appear
// only on success, and never more than the buffer or 2^14+1.
int rec_open(rec_dir *d, const uint8_t *rec, size_t n, uint8_t *pt, size_t cap, size_t *ptn,
             uint8_t *type) {
    __CPROVER_assert(__CPROVER_w_ok(d, sizeof *d), "open: dir writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(rec, n), "open: record readable");
    if (nondet_u8() & 1) {
        return -1;
    }
    size_t out = nondet_size_t();
    __CPROVER_assume(out <= cap && out <= 0x4001);
    __CPROVER_assert(out == 0 || __CPROVER_w_ok(pt, out), "open: pt writable");
    fill_nondet(pt, out);
    *ptn = out;
    *type = nondet_u8();
    return 0;
}

size_t hs_build_ch(uint8_t *out, size_t cap, const ch_cfg *cfg, const uint8_t pub[32],
                   const uint8_t random32[32], uint16_t rsl, const uint8_t *cookie,
                   size_t cookielen) {
    (void)rsl;
    __CPROVER_assert(__CPROVER_r_ok(cfg->psk_id, cfg->psk_id_len), "ch: identity readable");
    __CPROVER_assert(__CPROVER_r_ok(pub, 32), "ch: share readable");
    __CPROVER_assert(__CPROVER_r_ok(random32, 32), "ch: random readable");
    __CPROVER_assert(cookielen == 0 || __CPROVER_r_ok(cookie, cookielen), "ch: cookie readable");
    if (nondet_u8() & 1) {
        return 0; // does not fit
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= CH_BINDERS_TAIL + 4 && n <= cap);
    __CPROVER_assert(__CPROVER_w_ok(out, n), "ch: out writable");
    fill_nondet(out, n);
    return n;
}

void sha256_init(sha256 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha: ctx writable");
    fill_nondet((uint8_t *)s, sizeof *s);
}

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha: input readable");
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha: out writable");
    fill_nondet(out, SHA256_LEN);
}

void ks_early(const uint8_t *psk, size_t psklen, int resumption, uint8_t early[SHA256_LEN],
              uint8_t binder_key[SHA256_LEN]) {
    (void)resumption;
    __CPROVER_assert(psklen == 0 || __CPROVER_r_ok(psk, psklen), "ks: psk readable");
    fill_nondet(early, SHA256_LEN);
    fill_nondet(binder_key, SHA256_LEN);
}

void ks_verify_data(const uint8_t key[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
                    uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(key, SHA256_LEN), "ks: key readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "ks: transcript readable");
    fill_nondet(out, SHA256_LEN);
}

void ks_handshake(const uint8_t early[SHA256_LEN], const uint8_t ecdhe[32],
                  const uint8_t transcript[SHA256_LEN], uint8_t hs[SHA256_LEN],
                  uint8_t c_hs[SHA256_LEN], uint8_t s_hs[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(early, SHA256_LEN), "ks: early readable");
    __CPROVER_assert(__CPROVER_r_ok(ecdhe, 32), "ks: ecdhe readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "ks: transcript readable");
    fill_nondet(hs, SHA256_LEN);
    fill_nondet(c_hs, SHA256_LEN);
    fill_nondet(s_hs, SHA256_LEN);
}

void ks_master(const uint8_t hs[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
               uint8_t master[SHA256_LEN], uint8_t c_ap[SHA256_LEN], uint8_t s_ap[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(hs, SHA256_LEN), "ks: hs readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "ks: transcript readable");
    fill_nondet(master, SHA256_LEN);
    fill_nondet(c_ap, SHA256_LEN);
    fill_nondet(s_ap, SHA256_LEN);
}

void ks_res_master(const uint8_t master[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
                   uint8_t res_master[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(master, SHA256_LEN), "ks: master readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "ks: transcript readable");
    fill_nondet(res_master, SHA256_LEN);
}

int x25519(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
           const uint8_t point[X25519_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(scalar, X25519_LEN), "x: scalar readable");
    __CPROVER_assert(__CPROVER_r_ok(point, X25519_LEN), "x: point readable");
    fill_nondet(out, X25519_LEN);
    return nondet_u8() & 1;
}

void x25519_base(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(scalar, X25519_LEN), "x: scalar readable");
    fill_nondet(out, X25519_LEN);
}

int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(pub, 64), "p256: pub readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, 32), "p256: hash readable");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig_der, sig_len), "p256: sig readable");
    return nondet_u8() & 1;
}

// The default build's pinned verifier; the driver under proof only routes
// pointers into it, so the contract mirrors p256's. rsa_harness proves
// the real body against hostile signatures.
int rsa_pss_verify(const uint8_t *n, size_t nlen, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t siglen) {
    __CPROVER_assert(nlen == 0 || __CPROVER_r_ok(n, nlen), "rsa: modulus readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, 32), "rsa: hash readable");
    __CPROVER_assert(siglen == 0 || __CPROVER_r_ok(sig, siglen), "rsa: sig readable");
    return nondet_u8() & 1;
}

void tlsi_fail(ch_tls *t, uint8_t desc) {
    (void)desc;
    __CPROVER_assert(__CPROVER_w_ok(t, sizeof *t), "fail: session writable");
    t->state = CH_ST_FAILED;
}

int tlsi_send_alert(ch_tls *t, uint8_t level, uint8_t desc) {
    (void)level;
    (void)desc;
    __CPROVER_assert(__CPROVER_w_ok(t, sizeof *t), "alert: session writable");
    return CH_OK;
}

#include "handshake.c"

int main(void) {
    static ch_tls t;
    memset(&t, 0, sizeof t);
    uint8_t buf[96];
    uint8_t psk[32];
    uint8_t id[8];
    // Sized for the largest pin either build accepts (an RSA-3072
    // modulus); the ECDSA build reads only its first 64 bytes.
    uint8_t pin[384];
    fill_nondet(psk, sizeof psk);
    fill_nondet(id, sizeof id);
    fill_nondet(pin, sizeof pin);
    t.cfg.buf = buf;
    t.cfg.buf_len = sizeof buf;
    if (nondet_u8() & 1) {
        t.cfg.psk = psk;
        t.cfg.psk_id = id;
        size_t psklen = nondet_size_t();
        size_t idlen = nondet_size_t();
        __CPROVER_assume(psklen >= 1 && psklen <= sizeof psk);
        __CPROVER_assume(idlen >= 1 && idlen <= sizeof id);
        t.cfg.psk_len = psklen;
        t.cfg.psk_id_len = idlen;
        t.cfg.resumption = nondet_u8() & 1;
    } else {
        // Pinned-key mode: server_auth path. The length domain is what
        // ch_connect admits before ch_handshake ever runs.
        t.cfg.server_pubkey = pin;
        size_t pinlen = nondet_size_t();
#ifdef CH_PIN_ECDSA
        __CPROVER_assume(pinlen == 64);
#else
        __CPROVER_assume(pinlen >= 256 && pinlen <= sizeof pin && pinlen % 8 == 0);
        // ch_connect rejects an even pin before the handshake ever runs.
        __CPROVER_assume((pin[pinlen - 1] & 1) == 1);
#endif
        t.cfg.server_pubkey_len = pinlen;
    }

    (void)ch_handshake(&t);
    return 0;
}
