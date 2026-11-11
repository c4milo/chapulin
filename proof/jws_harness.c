// Proves: ch_jws_verify (jws.c) is memory safe and free of UB over any
// algorithm byte, any key, signing input and signature of up to the
// harness's bounds. And that it keeps what jws.h states:
// - it answers CH_OK, CH_EAUTH or CH_EINVAL, and CH_OK only for
//   CH_JWS_RS256, CH_JWS_ES256 and CH_JWS_EDDSA, and only when the one
//   verifier it called answered 1;
// - it calls one verifier at most, and the algorithm's own;
// - it reads RFC 3110 section 2's key form for RS256: the exponent it
//   hands the RSA check is the big-endian value of the bytes the length
//   names, in the one-byte and the three-byte length forms, and the
//   modulus is the rest of the key;
// - it hands the RSA check only an exponent that is odd and at least 3,
//   a modulus that is odd, begins with a nonzero byte, and has from
//   CH_JWS_RSA_MODULUS_LEN_MIN to CH_JWS_RSA_MODULUS_LEN_MAX bytes, and a
//   32-byte digest;
// - ES256 reaches the P-256 check only with a 64-byte key and a 64-byte
//   signature, and EdDSA the Ed25519 check only with a 32-byte key and a
//   64-byte signature;
// - a key of the wrong length for ES256 or EdDSA gives CH_EINVAL, and
//   with a key of the right length a signature of the wrong length gives
//   CH_EAUTH.
//
// rsa_pkcs1_verify_exponent, p256_ecdsa_verify_raw and
// ed25519_verify_hram are contract stubs that record their arguments and
// answer either verdict; rsa_pkcs1_exponent and the p256 and
// x25519_wide_ed25519 harnesses prove the verifiers, and bin/jws_test
// runs them against OpenSSL's tokens. SHA-256 and SHA-512 are harness.h's
// contract stubs, which hold each call to a readable input and answer any
// digest. buf.c is real.
//
// Bounds. KEY_MAX is 267 bytes: the shortest modulus the RSA check takes,
// 256 bytes, behind a length form of up to 3 bytes and an exponent of up
// to 8. A longer modulus takes the same path: the reader's one loop is
// over the exponent. SIG_MAX is 66, two bytes past an ES256 signature,
// and INPUT_MAX is 8.
#define CH_PROOF_STUB_SHA256
#define CH_PROOF_STUB_SHA384
#include "harness.h"

#include "jws.h"
#include "rsa.h"

#define KEY_MAX 267
#define INPUT_MAX 8
#define SIG_MAX 66

// harness.h's SHA-384 stub holds sha512_update. These two complete
// SHA-512 under the same contract.
void sha512_init(sha512 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha512_init: ctx writable");
    fill_nondet((uint8_t *)s, sizeof *s);
}

void sha512_final(sha512 *s, uint8_t out[SHA512_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha512_final: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA512_LEN), "sha512_final: output writable");
    fill_nondet(out, SHA512_LEN);
}

static const uint8_t *rsa_n;
static size_t rsa_n_len;
static uint64_t rsa_e;
static int rsa_calls;
static int p256_calls;
static int ed25519_calls;
static int verdict;

int rsa_pkcs1_verify_exponent(const uint8_t *n, size_t n_len, uint64_t e, const uint8_t *digest,
                              size_t digest_len, const uint8_t *sig, size_t sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(n, n_len), "rsa: modulus readable");
    __CPROVER_assert(digest_len == 32 && __CPROVER_r_ok(digest, digest_len),
                     "rsa: a readable SHA-256 digest");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig, sig_len), "rsa: signature readable");
    __CPROVER_assert(n_len >= CH_JWS_RSA_MODULUS_LEN_MIN && n_len <= CH_JWS_RSA_MODULUS_LEN_MAX &&
                         n[0] != 0 && (n[n_len - 1] & 1) == 1,
                     "rsa: a modulus jws.h takes");
    __CPROVER_assert(e >= 3 && (e & 1) == 1, "rsa: an odd exponent of at least 3");
    rsa_n = n;
    rsa_n_len = n_len;
    rsa_e = e;
    rsa_calls++;
    verdict = nondet_u8() & 1;
    return verdict;
}

int p256_ecdsa_verify_raw(const uint8_t pub[64], const uint8_t msg_hash[32],
                          const uint8_t sig[64]) {
    __CPROVER_assert(__CPROVER_r_ok(pub, 64) && __CPROVER_r_ok(msg_hash, 32) &&
                         __CPROVER_r_ok(sig, 64),
                     "p256: key, digest and signature readable");
    p256_calls++;
    verdict = nondet_u8() & 1;
    return verdict;
}

int ed25519_verify_hram(const uint8_t key[32], const uint8_t hram[64], const uint8_t sig[64]) {
    __CPROVER_assert(__CPROVER_r_ok(key, 32) && __CPROVER_r_ok(hram, 64) && __CPROVER_r_ok(sig, 64),
                     "ed25519: key, hash and signature readable");
    ed25519_calls++;
    verdict = nondet_u8() & 1;
    return verdict;
}

int main(void) {
    uint8_t key[KEY_MAX];
    uint8_t input[INPUT_MAX];
    uint8_t sig[SIG_MAX];
    fill_nondet(key, sizeof key);
    fill_nondet(input, sizeof input);
    fill_nondet(sig, sizeof sig);
    size_t key_len = nondet_size_t();
    size_t input_len = nondet_size_t();
    size_t sig_len = nondet_size_t();
    __CPROVER_assume(key_len <= KEY_MAX && input_len <= INPUT_MAX && sig_len <= SIG_MAX);
    uint8_t algorithm = nondet_u8();

    int rc = ch_jws_verify(algorithm, key, key_len, input, input_len, sig, sig_len);

    int calls = rsa_calls + p256_calls + ed25519_calls;
    __CPROVER_assert(rc == CH_OK || rc == CH_EAUTH || rc == CH_EINVAL, "one of its three codes");
    __CPROVER_assert(calls <= 1, "one verifier at most");
    if (rc == CH_OK) {
        __CPROVER_assert(algorithm == CH_JWS_RS256 || algorithm == CH_JWS_ES256 ||
                             algorithm == CH_JWS_EDDSA,
                         "CH_OK only for an algorithm jws.h names");
        __CPROVER_assert(calls == 1 && verdict == 1, "CH_OK only when a verifier accepted");
    }
    if (calls == 1) {
        __CPROVER_assert(rc == (verdict ? CH_OK : CH_EAUTH),
                         "the verifier's verdict is the answer");
    }
    if (rc == CH_EINVAL) {
        __CPROVER_assert(calls == 0, "a refused call runs no verifier");
    }
    if (algorithm == CH_JWS_ES256) {
        __CPROVER_assert(rsa_calls == 0 && ed25519_calls == 0, "ES256 runs the P-256 check alone");
        if (key_len != 64) {
            __CPROVER_assert(rc == CH_EINVAL, "ES256: a key that is not 64 bytes is refused");
        } else if (sig_len != 64) {
            __CPROVER_assert(rc == CH_EAUTH && calls == 0,
                             "ES256: a signature that is not 64 bytes fails");
        } else {
            __CPROVER_assert(p256_calls == 1, "ES256: a 64-byte key and signature are checked");
        }
    }
    if (algorithm == CH_JWS_EDDSA) {
        __CPROVER_assert(rsa_calls == 0 && p256_calls == 0, "EdDSA runs the Ed25519 check alone");
        if (key_len != 32) {
            __CPROVER_assert(rc == CH_EINVAL, "EdDSA: a key that is not 32 bytes is refused");
        } else if (sig_len != 64) {
            __CPROVER_assert(rc == CH_EAUTH && calls == 0,
                             "EdDSA: a signature that is not 64 bytes fails");
        } else {
            __CPROVER_assert(ed25519_calls == 1,
                             "EdDSA: a 32-byte key and a 64-byte signature are checked");
        }
    }
    if (algorithm == CH_JWS_RS256) {
        __CPROVER_assert(p256_calls == 0 && ed25519_calls == 0, "RS256 runs the RSA check alone");
    }
    if (rsa_calls != 0) {
        // RFC 3110 section 2, decoded here apart from rsa_key_field.h's
        // reader.
        size_t start = key[0] != 0 ? 1 : 3;
        size_t e_len = key[0] != 0 ? key[0] : ((size_t)key[1] << 8 | key[2]);
        uint64_t e = 0;
        for (size_t i = 0; i < e_len; i++) {
            e = (e << 8) | key[start + i];
        }
        __CPROVER_assert(algorithm == CH_JWS_RS256, "the RSA check runs for RS256 alone");
        __CPROVER_assert(e_len <= CH_JWS_RSA_EXPONENT_LEN_MAX && rsa_e == e,
                         "the exponent is the bytes the length names");
        __CPROVER_assert(rsa_n == key + start + e_len && rsa_n + rsa_n_len == key + key_len,
                         "the modulus is the rest of the key");
    }
    return 0;
}
