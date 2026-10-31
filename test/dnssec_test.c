// dnssec_verify (https://github.com/c4milo/chapulin/issues/189) against
// keys and signatures OpenSSL wrote (test/gen_dnssec_vectors.py), and at
// each edge dnssec.h states: every refusal of a key, a digest of the wrong
// length, an algorithm the file does not check, and a changed signature or
// digest. The binary builds as a host object with CH_DNSSEC at the
// 512-byte bound.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "dnssec.h"
#include "dnssec_vectors.h"
#include "tls.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures;

static void expect(int got, int want, const char *what) {
    if (got != want) {
        printf("FAIL dnssec: %s: got %d, want %d\n", what, got, want);
        failures++;
    }
}

static int verify(const dnssec_vector *v) {
    return dnssec_verify(v->algorithm, v->key, v->key_len, v->digest, v->digest_len, v->sig,
                         v->sig_len);
}

// Each vector verifies, and a one-bit change to its signature or its
// digest does not.
static void published(void) {
    for (size_t i = 0; i < sizeof dnssec_vectors / sizeof dnssec_vectors[0]; i++) {
        const dnssec_vector *v = &dnssec_vectors[i];
        expect(verify(v), CH_OK, "a vector verifies");
        uint8_t sig[512];
        uint8_t digest[64];
        memcpy(sig, v->sig, v->sig_len);
        memcpy(digest, v->digest, v->digest_len);
        sig[v->sig_len - 1] ^= 1;
        expect(dnssec_verify(v->algorithm, v->key, v->key_len, v->digest, v->digest_len, sig,
                             v->sig_len),
               CH_EAUTH, "a changed signature fails");
        digest[0] ^= 0x80;
        expect(dnssec_verify(v->algorithm, v->key, v->key_len, digest, v->digest_len, v->sig,
                             v->sig_len),
               CH_EAUTH, "a changed digest fails");
    }
}

// A key field built from the 512-bit key of vector 0, with the exponent
// bytes given and its modulus.
static size_t rsa_field(uint8_t *out, const uint8_t *e, size_t e_len) {
    const dnssec_vector *v = &dnssec_vectors[0];
    size_t old_e_len = v->key[0];
    size_t n_len = v->key_len - 1 - old_e_len;
    out[0] = (uint8_t)e_len;
    memcpy(out + 1, e, e_len);
    memcpy(out + 1 + e_len, v->key + 1 + old_e_len, n_len);
    return 1 + e_len + n_len;
}

static void refused_keys(void) {
    const dnssec_vector *v = &dnssec_vectors[0];
    uint8_t key[600];
    static const uint8_t even[] = {0x02};
    static const uint8_t one[] = {0x01};
    static const uint8_t leading_zero[] = {0x00, 0x03};
    static const uint8_t nine[] = {1, 0, 0, 0, 0, 0, 0, 0, 1};
    size_t n = rsa_field(key, even, sizeof even);
    expect(dnssec_verify(8, key, n, v->digest, v->digest_len, v->sig, v->sig_len), CH_EINVAL,
           "an even exponent is refused");
    n = rsa_field(key, one, sizeof one);
    expect(dnssec_verify(8, key, n, v->digest, v->digest_len, v->sig, v->sig_len), CH_EINVAL,
           "an exponent below 3 is refused");
    n = rsa_field(key, leading_zero, sizeof leading_zero);
    expect(dnssec_verify(8, key, n, v->digest, v->digest_len, v->sig, v->sig_len), CH_EINVAL,
           "an exponent with a leading zero byte is refused");
    n = rsa_field(key, nine, sizeof nine);
    expect(dnssec_verify(8, key, n, v->digest, v->digest_len, v->sig, v->sig_len), CH_EINVAL,
           "an exponent of 9 bytes is refused");

    // The 3-byte length form of RFC 3110: a zero byte, then two bytes.
    uint8_t wide[600];
    wide[0] = 0;
    wide[1] = 0;
    wide[2] = (uint8_t)v->key[0];
    memcpy(wide + 3, v->key + 1, v->key_len - 1);
    expect(dnssec_verify(8, wide, v->key_len + 2, v->digest, v->digest_len, v->sig, v->sig_len),
           CH_OK, "the long length form reads the same key");

    // The modulus: 63 bytes is one under the floor, and a leading zero
    // byte or an even last byte names no key this file takes.
    memcpy(key, v->key, v->key_len);
    expect(dnssec_verify(8, key, v->key_len - 1, v->digest, v->digest_len, v->sig, v->sig_len - 1),
           CH_EINVAL, "a 63-byte modulus is refused");
    key[v->key_len - 1] ^= 1;
    expect(dnssec_verify(8, key, v->key_len, v->digest, v->digest_len, v->sig, v->sig_len),
           CH_EINVAL, "an even modulus is refused");
    key[v->key_len - 1] ^= 1;
    key[1 + v->key[0]] = 0;
    expect(dnssec_verify(8, key, v->key_len, v->digest, v->digest_len, v->sig, v->sig_len),
           CH_EINVAL, "a modulus with a leading zero byte is refused");
    expect(dnssec_verify(8, v->key, 1, v->digest, v->digest_len, v->sig, v->sig_len), CH_EINVAL,
           "a field that ends inside the exponent is refused");
}

static void refused_shapes(void) {
    const dnssec_vector *rsa = &dnssec_vectors[0];
    const dnssec_vector *ec = &dnssec_vectors[5];
    expect(dnssec_verify(8, rsa->key, rsa->key_len, rsa->digest, 64, rsa->sig, rsa->sig_len),
           CH_EINVAL, "algorithm 8 takes a 32-byte digest alone");
    expect(dnssec_verify(10, rsa->key, rsa->key_len, rsa->digest, 32, rsa->sig, rsa->sig_len),
           CH_EINVAL, "algorithm 10 takes a 64-byte digest alone");
    uint8_t digest64[64] = {0};
    expect(dnssec_verify(10, rsa->key, rsa->key_len, digest64, 64, rsa->sig, rsa->sig_len),
           CH_EAUTH, "a 64-byte modulus cannot hold a SHA-512 encoding");
    expect(dnssec_verify(5, rsa->key, rsa->key_len, rsa->digest, 32, rsa->sig, rsa->sig_len),
           CH_EINVAL, "algorithm 5 is not checked here");
    expect(dnssec_verify(13, ec->key, 63, ec->digest, 32, ec->sig, 64), CH_EINVAL,
           "algorithm 13 takes a 64-byte key alone");
    expect(dnssec_verify(13, ec->key, 64, ec->digest, 32, ec->sig, 63), CH_EAUTH,
           "a 63-byte signature fails");
    expect(dnssec_verify(13, ec->key, 64, ec->digest, 48, ec->sig, 64), CH_EINVAL,
           "algorithm 13 takes a 32-byte digest alone");
}

int main(void) {
    published();
    refused_keys();
    refused_shapes();
    if (failures != 0) {
        return 1;
    }
    printf("dnssec: %zu vectors and every refusal dnssec.h states\n",
           sizeof dnssec_vectors / sizeof dnssec_vectors[0]);
    return 0;
}
