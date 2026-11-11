// Proves: ch_tls_server_end_point (x509_end_point.c) is memory safe and
// free of UB over any bytes of up to CERT_MAX, and that it keeps what
// scram.h states:
// - it answers CH_OK or CH_EINVAL;
// - a refusal runs no hash and writes nothing: the output room and
//   *out_len are as they were;
// - an acceptance runs one hash, over the whole of cert and no other
//   bytes, and *out_len is that hash's digest length, 32, 48 or 64;
// - it accepts only bytes that begin with a SEQUENCE whose length fills
//   them, which hold a second SEQUENCE and end with a BIT STRING.
//
// x509_der.c, buf.c and ct.c are real. The three hashes are contract
// stubs that record their input and answer any digest; the sha256 and
// sha512 harnesses prove them, and bin/scram_test holds the value to
// hashlib's over 15 certificates OpenSSL minted.
//
// Bounds. CERT_MAX is 56 bytes. The least bytes the call reads as a
// certificate are 9 and the algorithm's content: an empty TBSCertificate
// and an empty signature. The longest content it accepts here is
// RSASSA-PSS with its four fields, which those 56 bytes hold with a
// hash field, a salt length and a trailer field. A real certificate is
// longer in its TBSCertificate and its signature alone, which the call
// skips by their lengths.
#include "harness.h"

#include "scram.h"
#include "sha256.h"
#include "sha512.h"

#define CERT_MAX 56

static const uint8_t *hashed;
static size_t hashed_len;
static size_t digest_len;
static int hash_calls;

static void hash_stub(const uint8_t *in, size_t n, uint8_t *out, size_t len) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "hash: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, len), "hash: output writable");
    hashed = in;
    hashed_len = n;
    digest_len = len;
    hash_calls++;
    fill_nondet(out, len);
}

void sha256_of(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]) {
    hash_stub(in, n, out, SHA256_LEN);
}

void sha384_of(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]) {
    hash_stub(in, n, out, SHA384_LEN);
}

void sha512_of(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]) {
    hash_stub(in, n, out, SHA512_LEN);
}

int main(void) {
    uint8_t cert[CERT_MAX];
    uint8_t out[CH_TLS_SERVER_END_POINT_LEN_MAX];
    uint8_t before[CH_TLS_SERVER_END_POINT_LEN_MAX];
    fill_nondet(cert, sizeof cert);
    fill_nondet(out, sizeof out);
    for (size_t i = 0; i < sizeof out; i++) {
        before[i] = out[i];
    }
    size_t cert_len = nondet_size_t();
    __CPROVER_assume(cert_len <= CERT_MAX);
    size_t out_len = nondet_size_t();
    size_t unset = out_len;

    int rc = ch_tls_server_end_point(cert, cert_len, out, &out_len);

    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "one of its two codes");
    if (rc == CH_EINVAL) {
        __CPROVER_assert(hash_calls == 0 && out_len == unset, "a refusal runs no hash");
        for (size_t i = 0; i < sizeof out; i++) {
            __CPROVER_assert(out[i] == before[i], "a refusal writes nothing");
        }
        return 0;
    }
    __CPROVER_assert(hash_calls == 1 && hashed == cert && hashed_len == cert_len,
                     "one hash, over the whole certificate");
    __CPROVER_assert(out_len == digest_len && (out_len == 32 || out_len == 48 || out_len == 64),
                     "the length is the digest length of the hash that ran");
    // The outer shape, read here apart from x509_der.c: a short-form
    // length is the only one that 56 bytes hold.
    __CPROVER_assert(cert_len >= 9 && cert[0] == 0x30 && cert[1] == cert_len - 2,
                     "a SEQUENCE whose length fills the bytes");
    __CPROVER_assert(cert[2] == 0x30, "a TBSCertificate SEQUENCE comes first");
    return 0;
}
