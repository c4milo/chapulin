// Proves: dnssec_verify (dnssec.c) is memory safe and free of UB over any
// algorithm byte, any key field, digest and signature of up to the
// harness's bounds. And that it keeps what dnssec.h states:
// - it answers CH_OK, CH_EAUTH or CH_EINVAL, and CH_OK only for
//   algorithms 8, 10 and 13 with a digest of their hash's length;
// - it reads RFC 3110 section 2's key field: the exponent it hands the
//   RSA check is the big-endian value of the bytes the length names, in
//   the one-byte and the three-byte length forms, and the modulus is the
//   rest of the field;
// - it hands the RSA check only an exponent that is odd and at least 3,
//   and a modulus that is odd, begins with a nonzero byte, and has from
//   DNSSEC_RSA_MODULUS_MIN to CH_RSA_MODULUS_MAX bytes;
// - algorithm 13 reaches the P-256 check only with a 64-byte key and a
//   64-byte signature.
//
// rsa_pkcs1_verify_exponent and p256_ecdsa_verify_raw are contract stubs
// that record their arguments and answer either verdict; rsa_pkcs1 and
// the p256 harnesses prove the verifiers, and bin/dnssec_test runs them
// against OpenSSL's signatures. buf.c is real.
//
// Bounds. KEY_MAX is 80 bytes: the shortest modulus the RSA check takes
// is 64 bytes, behind a length form of up to 3 bytes and an exponent of
// up to 8.
#include "harness.h"

#include "dnssec.h"
#include "rsa.h"
#include "tls.h"

#define KEY_MAX 80
#define DIGEST_MAX 64
#define SIG_MAX 80

static const uint8_t *rsa_n;
static size_t rsa_n_len;
static uint64_t rsa_e;
static int rsa_calls;
static int p256_calls;

int rsa_pkcs1_verify_exponent(const uint8_t *n, size_t n_len, uint64_t e, const uint8_t *digest,
                              size_t digest_len, const uint8_t *sig, size_t sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(n, n_len), "rsa: modulus readable");
    __CPROVER_assert(__CPROVER_r_ok(digest, digest_len), "rsa: digest readable");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig, sig_len), "rsa: signature readable");
    __CPROVER_assert(n_len >= DNSSEC_RSA_MODULUS_MIN && n_len <= CH_RSA_MODULUS_MAX && n[0] != 0 &&
                         (n[n_len - 1] & 1) == 1,
                     "rsa: a modulus the check takes");
    __CPROVER_assert(e >= 3 && (e & 1) == 1, "rsa: an odd exponent of at least 3");
    rsa_n = n;
    rsa_n_len = n_len;
    rsa_e = e;
    rsa_calls++;
    return nondet_u8() & 1;
}

int p256_ecdsa_verify_raw(const uint8_t pub[64], const uint8_t msg_hash[32],
                          const uint8_t sig[64]) {
    __CPROVER_assert(__CPROVER_r_ok(pub, 64) && __CPROVER_r_ok(msg_hash, 32) &&
                         __CPROVER_r_ok(sig, 64),
                     "p256: key, digest and signature readable");
    p256_calls++;
    return nondet_u8() & 1;
}

int main(void) {
    uint8_t key[KEY_MAX];
    uint8_t digest[DIGEST_MAX];
    uint8_t sig[SIG_MAX];
    fill_nondet(key, sizeof key);
    fill_nondet(digest, sizeof digest);
    fill_nondet(sig, sizeof sig);
    size_t key_len = nondet_size_t();
    size_t digest_len = nondet_size_t();
    size_t sig_len = nondet_size_t();
    __CPROVER_assume(key_len <= KEY_MAX && digest_len <= DIGEST_MAX && sig_len <= SIG_MAX);
    uint8_t algorithm = nondet_u8();

    int rc = dnssec_verify(algorithm, key, key_len, digest, digest_len, sig, sig_len);

    __CPROVER_assert(rc == CH_OK || rc == CH_EAUTH || rc == CH_EINVAL, "one of its three codes");
    if (rc == CH_OK) {
        __CPROVER_assert((algorithm == DNSSEC_ALG_RSASHA256 && digest_len == 32) ||
                             (algorithm == DNSSEC_ALG_RSASHA512 && digest_len == 64) ||
                             (algorithm == DNSSEC_ALG_ECDSAP256SHA256 && digest_len == 32),
                         "CH_OK only for a checked algorithm and its digest length");
    }
    if (p256_calls != 0) {
        __CPROVER_assert(algorithm == DNSSEC_ALG_ECDSAP256SHA256 && key_len == 64 && sig_len == 64,
                         "the P-256 check sees a 64-byte key and signature");
    }
    if (rsa_calls != 0) {
        // RFC 3110 section 2, decoded here apart from dnssec.c's reader.
        size_t start = key[0] != 0 ? 1 : 3;
        size_t e_len = key[0] != 0 ? key[0] : ((size_t)key[1] << 8 | key[2]);
        uint64_t e = 0;
        for (size_t i = 0; i < e_len; i++) {
            e = (e << 8) | key[start + i];
        }
        __CPROVER_assert(e_len <= DNSSEC_RSA_EXPONENT_MAX && rsa_e == e,
                         "the exponent is the bytes the length names");
        __CPROVER_assert(rsa_n == key + start + e_len && rsa_n + rsa_n_len == key + key_len,
                         "the modulus is the rest of the field");
    }
    return 0;
}
