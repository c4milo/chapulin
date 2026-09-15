// Proves: webpki_read_sigalg and webpki_verify are memory-safe and
// UB-free over any input, and webpki_verify's dispatch does what
// webpki.h states.
//
// webpki_read_sigalg runs CONCRETE (real x509_der.c, buf.c and ct.c)
// over any bytes up to CH_WEBPKI_CERT_MAX, the certificate its caller
// hands it with the field anywhere inside. On success err stays clear,
// the value is one of the four WEBPKI_SIG_* values, and the reader
// consumed exactly that algorithm's encoding: 15 bytes for an RSA
// identifier, 12 for an ECDSA one.
//
// webpki_verify runs over any certificate and any signer: any sigalg
// byte, any key algorithm byte, and tbs, sig and key pointing anywhere
// inside readable objects at any lengths. The key points either into a
// separate anchor buffer or into the certificate buffer itself, the two
// shapes the walk passes (an anchor's SPKI, or an issuer's certificate
// read from the same Certificate message). x509_emit_header and the
// wbuf writer are real. Every callee below the dispatch is a stub that
// asserts its header's contract and havocs its output, because each
// has its own proof: SHA-256 (sha256), SHA-384 (sha512),
// rsa_pkcs1_verify (rsa_pkcs1, rsa_pkcs1_webpki), p256_ecdsa_verify
// (p256) and p384_ecdsa_verify (p384). The hash stubs are this file's
// own rather than proof/harness.h's shared SHA-256 stub, because they
// record the digest they wrote.
//
// The stubs also record what they were called with, and the harness
// asserts the dispatch rules over those records:
//
//   - a tbs over CH_WEBPKI_CERT_MAX, an unknown sigalg, or a key of the
//     other family reaches no hash and no verifier, and returns 0
//   - the hash is the one sigalg names, over two updates: first the
//     minimal DER SEQUENCE header for cert->tbs_len, which the harness
//     writes itself rather than with x509_emit_header, then exactly
//     cert->tbs for cert->tbs_len
//   - the verifier is the one signer->alg names, and it gets
//     signer->key for signer->key_len and cert->sig for cert->sig_len:
//     rsa_pkcs1_verify gets the digest length the hash wrote;
//     p256_ecdsa_verify gets a 64-byte key and, as msg_hash, the first
//     32 bytes the hash wrote (the FIPS 186-4 §6.4 cut for SHA-384);
//     p384_ecdsa_verify gets a 96-byte key and 48 bytes that are the
//     SHA-384 digest, or 16 zero bytes then the SHA-256 digest (the pad)
//   - the return value is the verifier's
//
// Built with -DCH_TRUST_WEBPKI. The certificate and anchor objects are
// static and their bytes are never read by the dispatch, only by the
// stubs' readability asserts, so their contents need no havoc; every
// pointer and length into them is havocked per call.
#include "harness.h"

#include <string.h>

#include "buf.h"
#include "p256.h"
#include "p384.h"
#include "rsa_pkcs1.h"
#include "sha256.h"
#include "sha512.h"
#include "webpki.h"

#include "webpki_sigalg.c"

uint32_t nondet_u32(void);
int nondet_int(void);

// What the stubs saw. digest_written holds the bytes the hash final
// wrote, and first_update the bytes of the first update, copied because
// they live on webpki_verify's stack. verifier_alg is the WEBPKI_KEY_*
// value of the verifier called.
static int hash_updates;
static int hash_is_sha384;
static int hash_finals;
static uint8_t digest_written[SHA384_LEN];
static uint8_t first_update[4];
static size_t first_update_len;
static const uint8_t *second_update_in;
static size_t second_update_len;
static int verifier_calls;
static int verifier_result;
static uint8_t verifier_alg;
static const uint8_t *verifier_key;
static size_t verifier_key_len;
static const uint8_t *verifier_sig;
static size_t verifier_sig_len;

// The bookkeeping both update stubs share: the first update is the
// 2..4-byte header, copied out, and the second is recorded by pointer.
static void record_update(const uint8_t *in, size_t n) {
    hash_updates++;
    if (hash_updates == 1) {
        __CPROVER_assert(n >= 2 && n <= sizeof first_update,
                         "the first update is the 2..4-byte header");
        if (n <= sizeof first_update) {
            memcpy(first_update, in, n);
        }
        first_update_len = n;
    } else if (hash_updates == 2) {
        second_update_in = in;
        second_update_len = n;
    }
}

// What a verifier stub was called with.
static void record_verifier(uint8_t alg, const uint8_t *key, size_t key_len, const uint8_t *sig,
                            size_t sig_len) {
    verifier_calls++;
    verifier_alg = alg;
    verifier_key = key;
    verifier_key_len = key_len;
    verifier_sig = sig;
    verifier_sig_len = sig_len;
    verifier_result = nondet_int() ? 1 : 0;
}

// The DER SEQUENCE header for a content of len bytes, its length in the
// fewest octets (X.690 §10.1), len at most 0xffff. Returns its length.
static size_t sequence_header(size_t len, uint8_t out[4]) {
    out[0] = 0x30;
    if (len < 0x80) {
        out[1] = (uint8_t)len;
        return 2;
    }
    if (len < 0x100) {
        out[1] = 0x81;
        out[2] = (uint8_t)len;
        return 3;
    }
    out[1] = 0x82;
    out[2] = (uint8_t)(len >> 8);
    out[3] = (uint8_t)len;
    return 4;
}

// sha512.h's streaming contract, stubbed: the context is writable, the
// input readable, the output writable; the digest is havocked.
void sha384_init(sha512 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha384_init: ctx writable");
    hash_is_sha384 = 1;
}

void sha512_update(sha512 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha512_update: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha512_update: input readable");
    record_update(in, n);
}

void sha384_final(sha512 *s, uint8_t out[SHA384_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha384_final: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA384_LEN), "sha384_final: output writable");
    fill_nondet(out, SHA384_LEN);
    memcpy(digest_written, out, SHA384_LEN);
    hash_finals++;
}

// sha256.h's streaming contract, stubbed the same way.
void sha256_init(sha256 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_init: ctx writable");
    hash_is_sha384 = 0;
}

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_update: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha256_update: input readable");
    record_update(in, n);
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_final: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha256_final: output writable");
    fill_nondet(out, SHA256_LEN);
    memset(digest_written, 0, sizeof digest_written);
    memcpy(digest_written, out, SHA256_LEN);
    hash_finals++;
}

int rsa_pkcs1_verify(const uint8_t *n, size_t n_len, const uint8_t *digest, size_t digest_len,
                     const uint8_t *sig, size_t sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(n, n_len), "rsa_pkcs1_verify: modulus readable");
    __CPROVER_assert(__CPROVER_r_ok(sig, sig_len), "rsa_pkcs1_verify: signature readable");
    __CPROVER_assert(digest_len == (hash_is_sha384 ? SHA384_LEN : SHA256_LEN),
                     "rsa_pkcs1_verify: the digest length the hash wrote");
    __CPROVER_assert(__CPROVER_r_ok(digest, digest_len), "rsa_pkcs1_verify: digest readable");
    __CPROVER_assert(memcmp(digest, digest_written, digest_len) == 0,
                     "rsa_pkcs1_verify: the digest the hash wrote");
    record_verifier(WEBPKI_KEY_RSA, n, n_len, sig, sig_len);
    return verifier_result;
}

int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(pub, 64), "p256_ecdsa_verify: point readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, 32), "p256_ecdsa_verify: hash readable");
    __CPROVER_assert(__CPROVER_r_ok(sig_der, sig_len), "p256_ecdsa_verify: signature readable");
    __CPROVER_assert(memcmp(msg_hash, digest_written, 32) == 0,
                     "p256_ecdsa_verify: the leftmost 32 bytes of the digest");
    record_verifier(WEBPKI_KEY_P256, pub, 64, sig_der, sig_len);
    return verifier_result;
}

int p384_ecdsa_verify(const uint8_t pub[P384_PUB_LEN], const uint8_t msg_hash[P384_LEN],
                      const uint8_t *sig_der, size_t sig_len) {
    static const uint8_t zeros[P384_PAD_LEN] = {0};
    __CPROVER_assert(__CPROVER_r_ok(pub, P384_PUB_LEN), "p384_ecdsa_verify: point readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, P384_LEN), "p384_ecdsa_verify: hash readable");
    __CPROVER_assert(__CPROVER_r_ok(sig_der, sig_len), "p384_ecdsa_verify: signature readable");
    if (hash_is_sha384) {
        __CPROVER_assert(memcmp(msg_hash, digest_written, P384_LEN) == 0,
                         "p384_ecdsa_verify: the whole SHA-384 digest");
    } else {
        __CPROVER_assert(memcmp(msg_hash, zeros, P384_PAD_LEN) == 0 &&
                             memcmp(msg_hash + P384_PAD_LEN, digest_written, SHA256_LEN) == 0,
                         "p384_ecdsa_verify: 16 zero bytes, then the SHA-256 digest");
    }
    record_verifier(WEBPKI_KEY_P384, pub, P384_PUB_LEN, sig_der, sig_len);
    return verifier_result;
}

// A pointer into buf at a nondet offset with a nondet length that fits.
static const uint8_t *slice_nondet(const uint8_t *buf, size_t cap, size_t *len) {
    size_t off = nondet_size_t();
    size_t n = nondet_size_t();
    __CPROVER_assume(off <= cap && n <= cap - off);
    *len = n;
    return buf + off;
}

// A tbs length that may run past the cap, to prove the cap check; the
// bytes behind it are only ever hashed by a stub, so the object stays
// readable at the cap plus one.
#define TBS_OBJECT (CH_WEBPKI_CERT_MAX + 1)

static void verify_any(const uint8_t *cert_buf, const uint8_t *anchor_buf, size_t anchor_cap) {
    webpki_cert cert;
    cert.tbs = slice_nondet(cert_buf, TBS_OBJECT, &cert.tbs_len);
    cert.sig = slice_nondet(cert_buf, TBS_OBJECT, &cert.sig_len);
    cert.sigalg = nondet_u8();

    webpki_spki signer;
    signer.alg = nondet_u8();
    if (nondet_int()) {
        signer.key = slice_nondet(anchor_buf, anchor_cap, &signer.key_len);
    } else {
        signer.key = slice_nondet(cert_buf, TBS_OBJECT, &signer.key_len);
    }

    hash_updates = 0;
    first_update_len = 0;
    hash_finals = 0;
    verifier_calls = 0;
    verifier_result = 0;
    verifier_alg = 0;
    int rc = webpki_verify(&cert, &signer);

    int rsa_sigalg = cert.sigalg == WEBPKI_SIG_RSA_SHA256 || cert.sigalg == WEBPKI_SIG_RSA_SHA384;
    int ecdsa_sigalg =
        cert.sigalg == WEBPKI_SIG_ECDSA_SHA256 || cert.sigalg == WEBPKI_SIG_ECDSA_SHA384;
    int key_fits = (rsa_sigalg && signer.alg == WEBPKI_KEY_RSA) ||
                   (ecdsa_sigalg && signer.alg == WEBPKI_KEY_P256 && signer.key_len == 64) ||
                   (ecdsa_sigalg && signer.alg == WEBPKI_KEY_P384 && signer.key_len == 96);
    if (!key_fits || cert.tbs_len > CH_WEBPKI_CERT_MAX) {
        __CPROVER_assert(rc == 0 && hash_finals == 0 && verifier_calls == 0,
                         "a cap, sigalg or family refusal reaches no hash and no verifier");
        return;
    }
    __CPROVER_assert(hash_updates == 2 && hash_finals == 1 && verifier_calls == 1,
                     "one hash of two updates, then one verifier");
    __CPROVER_assert(hash_is_sha384 == (cert.sigalg == WEBPKI_SIG_RSA_SHA384 ||
                                        cert.sigalg == WEBPKI_SIG_ECDSA_SHA384),
                     "the hash is the one sigalg names");
    uint8_t header[4];
    size_t header_len = sequence_header(cert.tbs_len, header);
    __CPROVER_assert(first_update_len == header_len &&
                         memcmp(first_update, header, header_len) == 0,
                     "the first update is the DER SEQUENCE header for cert->tbs_len");
    __CPROVER_assert(second_update_in == cert.tbs && second_update_len == cert.tbs_len,
                     "the second update is exactly cert->tbs");
    __CPROVER_assert(verifier_alg == signer.alg, "the verifier is the one signer->alg names");
    __CPROVER_assert(verifier_key == signer.key && verifier_key_len == signer.key_len,
                     "the verifier gets signer->key for signer->key_len");
    __CPROVER_assert(verifier_sig == cert.sig && verifier_sig_len == cert.sig_len,
                     "the verifier gets cert->sig for cert->sig_len");
    __CPROVER_assert(rc == verifier_result, "verify returns the verifier's verdict");
}

int main(void) {
    // webpki_read_sigalg over any bytes at the certificate bound.
    {
        uint8_t input[CH_WEBPKI_CERT_MAX];
        fill_nondet(input, sizeof input);
        size_t n = nondet_size_t();
        __CPROVER_assume(n <= sizeof input);
        rbuf r;
        rb_init(&r, input, n);
        uint8_t sigalg = nondet_u8();
        if (webpki_read_sigalg(&r, &sigalg)) {
            __CPROVER_assert(!r.err, "sigalg success leaves err clear");
            __CPROVER_assert(sigalg >= WEBPKI_SIG_RSA_SHA256 && sigalg <= WEBPKI_SIG_ECDSA_SHA384,
                             "sigalg is one of the four");
            size_t consumed = n - rb_left(&r);
            __CPROVER_assert(consumed == (sigalg <= WEBPKI_SIG_RSA_SHA384 ? 15U : 12U),
                             "the reader consumed exactly the algorithm's encoding");
        }
    }

    // webpki_verify: each operand fresh, both key shapes.
    static uint8_t cert_buf[TBS_OBJECT];
    static uint8_t anchor_buf[CH_WEBPKI_CERT_MAX];
    verify_any(cert_buf, anchor_buf, sizeof anchor_buf);
    verify_any(cert_buf, anchor_buf, sizeof anchor_buf);
    return 0;
}
