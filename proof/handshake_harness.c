// Proves: ch_handshake — the record pump, cross-record reassembly,
// HRR restart, and the run() state machine — is
// memory-safe and UB-free against ANY record stream a peer can send, at a
// 96-byte receive buffer (every reassembly and compaction state is
// reachable at that size; larger buffers only repeat the middle).
//
// Layered proof: io, record protection, the key schedule, hashing,
// x25519, and the two message parsers are stubs asserting their proven
// contracts and havocing results — the parsers are proven concrete in
// hsparse_harness and eeparse_harness, so dragging their real bodies
// into this formula only grows it (measured: past CI's whole budget).
// The object under proof is the driver's own arithmetic and state.
// buf.c and ct.c are real.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "hsmsg.h"
#include "hsparse.h"
#include "io.h"
#include "keysched.h"
#include "p256.h"
#include "rand.h"
#include "record.h"
#include "session.h"
#include "x25519.h"

void ch_rand_bytes(uint8_t *p, size_t n) {
    fill_nondet(p, n);
    // rand.h requires strong random bytes and forbids failure, and the
    // driver now asserts the buffer is not left as it found it. State
    // that contract here rather than proving over a hook that returns
    // without writing, which rand.h already rules out.
    uint32_t any = 0;
    for (size_t i = 0; i < n; i++) {
        any |= p[i];
    }
    __CPROVER_assume(any != 0);
}

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    __CPROVER_assert(cfg != NULL, "send: cfg valid");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "send: bytes readable");
    return (nondet_u8() & 1) ? CH_OK : CH_EIO;
}

// The hostile input source: any outer type, any body bytes, any length
// the io contract admits (1..2^14+256 body, within cap), or any error.
int io_read_record(const ch_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer,
                   size_t *record_len) {
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
    *record_len = REC_HDR + body;
    return CH_OK;
}

uint64_t nondet_u64(void);
int nondet_int(void);

// Typed stores: a byte-pointer fill through a member pointer makes
// every store a whole-object update of the enclosing struct in the
// SSA (docs/proofs.md).
static void fill_rec_dir_nondet(rec_dir *d) {
    fill_nondet(d->key, sizeof d->key);
    fill_nondet(d->iv, sizeof d->iv);
    d->seq = nondet_u64();
}

void rec_dir_init(rec_dir *d, const uint8_t secret[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(secret, SHA256_LEN), "dir: secret readable");
    fill_rec_dir_nondet(d);
}

void rec_dir_update(uint8_t secret[SHA256_LEN], rec_dir *d) {
    __CPROVER_assert(__CPROVER_w_ok(secret, SHA256_LEN), "upd: secret writable");
    fill_nondet(secret, SHA256_LEN);
    fill_rec_dir_nondet(d);
}

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    (void)type;
    __CPROVER_assert(__CPROVER_w_ok(d, sizeof *d), "seal: dir writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "seal: pt readable");
    size_t total = REC_HDR + n + 1 + AEAD_TAG;
    if (n + 1 + AEAD_TAG > 0x4000 + 256 || total > cap) {
        return -1;
    }
    if (nondet_u8() & 1) {
        return -1; // the real function also refuses at seq == UINT64_MAX,
                   // which this stub does not track: any call may fail
    }
    __CPROVER_assert(__CPROVER_w_ok(out, total), "seal: out writable");
    fill_nondet(out, total);
    *out_len = total;
    return 0;
}

// All-or-nothing, like the proven aead contract: plaintext bytes appear
// only on success, and never more than the buffer or 2^14+1.
int rec_open(rec_dir *d, const uint8_t *rec, size_t n, uint8_t *pt, size_t cap, size_t *pt_len,
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
    *pt_len = out;
    *type = nondet_u8();
    return 0;
}

size_t hs_build_client_hello(uint8_t *out, size_t cap, const ch_cfg *cfg, const uint8_t pub[32],
                             const uint8_t random32[32], uint16_t record_size_limit,
                             const uint8_t *cookie, size_t cookie_len) {
    (void)record_size_limit;
    __CPROVER_assert(cfg->psk_id_len == 0 || __CPROVER_r_ok(cfg->psk_id, cfg->psk_id_len),
                     "ch: identity readable");
    __CPROVER_assert(__CPROVER_r_ok(pub, 32), "ch: share readable");
    __CPROVER_assert(__CPROVER_r_ok(random32, 32), "ch: random readable");
    __CPROVER_assert(cookie_len == 0 || __CPROVER_r_ok(cookie, cookie_len), "ch: cookie readable");
    if (nondet_u8() & 1) {
        return 0; // does not fit
    }
    size_t n = nondet_size_t();
    // ASSUMED, not proven: a successful build returns at least the
    // binders tail plus the handshake header. hsmsg.c has no harness
    // (the README names it), so this contract rests on the unit tests
    // until one exists; the binder patching below is what leans on it.
    __CPROVER_assume(n >= CH_BINDERS_TAIL + 4 && n <= cap);
    __CPROVER_assert(__CPROVER_w_ok(out, n), "ch: out writable");
    fill_nondet(out, n);
    return n;
}

void ks_early(const uint8_t *psk, size_t psk_len, int resumption, uint8_t early[SHA256_LEN],
              uint8_t binder_key[SHA256_LEN]) {
    (void)resumption;
    __CPROVER_assert(psk_len == 0 || __CPROVER_r_ok(psk, psk_len), "ks: psk readable");
    fill_nondet(early, SHA256_LEN);
    fill_nondet(binder_key, SHA256_LEN);
}

void ks_verify_data(const uint8_t key[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
                    uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(key, SHA256_LEN), "ks: key readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "ks: transcript readable");
    fill_nondet(out, SHA256_LEN);
}

void ks_handshake(const uint8_t early[SHA256_LEN], const uint8_t *ecdhe, size_t ecdhe_len,
                  const uint8_t transcript[SHA256_LEN], uint8_t handshake_secret[SHA256_LEN],
                  uint8_t c_hs[SHA256_LEN], uint8_t s_hs[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(early, SHA256_LEN), "ks: early readable");
    __CPROVER_assert(ecdhe_len == 0 || __CPROVER_r_ok(ecdhe, ecdhe_len), "ks: ecdhe readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "ks: transcript readable");
    fill_nondet(handshake_secret, SHA256_LEN);
    fill_nondet(c_hs, SHA256_LEN);
    fill_nondet(s_hs, SHA256_LEN);
}

void ks_master(const uint8_t handshake_secret[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
               uint8_t master[SHA256_LEN], uint8_t c_ap[SHA256_LEN], uint8_t s_ap[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(handshake_secret, SHA256_LEN), "ks: handshake secret readable");
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
int rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t sig_len) {
    __CPROVER_assert(n_len == 0 || __CPROVER_r_ok(n, n_len), "rsa: modulus readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, 32), "rsa: hash readable");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig, sig_len), "rsa: sig readable");
    return nondet_u8() & 1;
}

// Parser contracts (proven in their own harnesses): on success the
// cookie is NULL or points into the caller's message with a bounded
// length — the guarantee read_server_hello's copy relies on. Everything
// else havocs.
int hsp_parse_server_hello(const uint8_t *body, size_t n, server_hello_info *info, int psk_mode) {
    (void)psk_mode;
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(body, n), "sh: body readable");
    __CPROVER_assert(__CPROVER_w_ok(info, sizeof *info), "sh: info writable");
    info->hrr = nondet_int();
    info->version_ok = nondet_int();
    info->have_share = nondet_int();
    info->psk_ok = nondet_int();
    info->seen = nondet_u8();
    fill_nondet(info->server_pub, sizeof info->server_pub);
    if (nondet_u8() & 1) {
        info->cookie = NULL;
        info->cookie_len = 0;
    } else {
        size_t off = nondet_size_t();
        size_t cookie_len = nondet_size_t();
        __CPROVER_assume(off <= n && cookie_len <= n - off && cookie_len <= HSP_COOKIE_MAX);
        info->cookie = body + off;
        info->cookie_len = cookie_len;
    }
    return (nondet_u8() & 1) ? CH_OK : CH_EPROTO;
}

int hsp_parse_encrypted_exts(const uint8_t *body, size_t n, uint16_t *peer_limit, uint8_t *alert) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(body, n), "ee: body readable");
    __CPROVER_assert(__CPROVER_w_ok(peer_limit, sizeof *peer_limit), "ee: limit writable");
    __CPROVER_assert(__CPROVER_w_ok(alert, sizeof *alert), "ee: alert writable");
    *peer_limit = (uint16_t)nondet_size_t();
    fill_nondet(alert, sizeof *alert);
    return (nondet_u8() & 1) ? CH_OK : CH_EPROTO;
}

// On success the list points into the caller's message with a length
// that fits it — the pointer contract the transcript update and the
// coming CA build rest on. certparse_harness.c proves the real parser
// keeps it, on hostile bytes.
int hsp_parse_certificate(const uint8_t *body, size_t n, const uint8_t **list, size_t *list_len,
                          uint8_t *alert) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(body, n), "cert: body readable");
    __CPROVER_assert(__CPROVER_w_ok(list, sizeof *list), "cert: list out writable");
    __CPROVER_assert(__CPROVER_w_ok(list_len, sizeof *list_len), "cert: len out writable");
    __CPROVER_assert(__CPROVER_w_ok(alert, sizeof *alert), "cert: alert writable");
    fill_nondet(alert, sizeof *alert);
    if (nondet_u8() & 1) {
        return CH_EPROTO;
    }
    size_t off = nondet_size_t();
    size_t len = nondet_size_t();
    __CPROVER_assume(off <= n && len <= n - off);
    *list = body + off;
    *list_len = len;
    return CH_OK;
}

// On success the signature points into the caller's message with a
// length that fits it — what check_certificate_verify hands the
// verifier. certparse_harness.c proves the real parser keeps it, on
// hostile bytes.
int hsp_parse_certificate_verify(const uint8_t *body, size_t n, const uint8_t **sig,
                                 size_t *sig_len, uint8_t *alert) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(body, n), "cv: body readable");
    __CPROVER_assert(__CPROVER_w_ok(sig, sizeof *sig), "cv: sig out writable");
    __CPROVER_assert(__CPROVER_w_ok(sig_len, sizeof *sig_len), "cv: len out writable");
    __CPROVER_assert(__CPROVER_w_ok(alert, sizeof *alert), "cv: alert writable");
    fill_nondet(alert, sizeof *alert);
    if (nondet_u8() & 1) {
        return (nondet_u8() & 1) ? CH_EPROTO : CH_EAUTH;
    }
    size_t off = nondet_size_t();
    size_t len = nondet_size_t();
    __CPROVER_assume(off <= n && len <= n - off);
    *sig = body + off;
    *sig_len = len;
    return CH_OK;
}

void tlsi_fail(ch_tls *t, uint8_t description) {
    (void)description;
    __CPROVER_assert(__CPROVER_w_ok(t, sizeof *t), "fail: session writable");
    t->state = CH_ST_FAILED;
}

int tlsi_send_alert(ch_tls *t, uint8_t level, uint8_t description) {
    (void)level;
    (void)description;
    __CPROVER_assert(__CPROVER_w_ok(t, sizeof *t), "alert: session writable");
    return CH_OK;
}

#include "handshake.c"

// One auth mode per formula. Driving both under a nondet branch put the
// two flights in one formula and CBMC ran out of memory on it after
// 399 s. The modes share no state — the config picks one before
// ch_handshake runs — so proving them apart proves the same disjunction
// in two pieces. handshake_psk and handshake_pin define the selector and
// include this file; it has no launch line of its own.
#if !defined(CH_PROOF_PSK) && !defined(CH_PROOF_PIN)
#error "define CH_PROOF_PSK or CH_PROOF_PIN"
#endif

int main(void) {
    static ch_tls t;
    memset(&t, 0, sizeof t);
    uint8_t buf[96];
    uint8_t psk[32];
    uint8_t id[8];
    // Sized for the largest pin either build accepts (an RSA-3072
    // modulus); the ECDSA build reads only its first 64 bytes.
    uint8_t pin[384];
    uint8_t pin2[384];
    fill_nondet(psk, sizeof psk);
    fill_nondet(id, sizeof id);
    fill_nondet(pin, sizeof pin);
    fill_nondet(pin2, sizeof pin2);
    t.cfg.buf = buf;
    t.cfg.buf_len = sizeof buf;
#ifdef CH_PROOF_PSK
    {
        t.cfg.psk = psk;
        t.cfg.psk_id = id;
        size_t psk_len = nondet_size_t();
        size_t idlen = nondet_size_t();
        __CPROVER_assume(psk_len >= 1 && psk_len <= sizeof psk);
        __CPROVER_assume(idlen >= 1 && idlen <= sizeof id);
        t.cfg.psk_len = psk_len;
        t.cfg.psk_id_len = idlen;
        t.cfg.resumption = nondet_u8() & 1;
    }
#else
    {
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
        // Optional slot B (key rotation), in the same validated domain.
        if (nondet_u8() & 1) {
            t.cfg.server_pubkey2 = pin2;
            size_t pin2len = nondet_size_t();
#ifdef CH_PIN_ECDSA
            __CPROVER_assume(pin2len == 64);
#else
            __CPROVER_assume(pin2len >= 256 && pin2len <= sizeof pin2 && pin2len % 8 == 0);
            __CPROVER_assume((pin2[pin2len - 1] & 1) == 1);
#endif
            t.cfg.server_pubkey2_len = pin2len;
        }
    }
#endif

    (void)ch_handshake(&t);
    return 0;
}
