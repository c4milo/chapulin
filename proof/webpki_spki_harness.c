// Proves: webpki_read_spki is memory-safe and UB-free over any bytes,
// CONCRETE (real x509_der.c primitives, real rbuf via buf.c, real
// ct_memeq via ct.c), and honours what webpki.h states and the chain
// walk rests on. On success:
//
//   - r's err stays clear, and the reader consumed exactly the length of
//     the canonical encoding of the key it returned:
//     RSA_SPKI_OVERHEAD + key_len bytes for an RSA key, P256_SPKI_LEN or
//     P384_SPKI_LEN for a point. Every part of the encoding has a
//     minimum size, so the equality leaves no container room for a byte
//     after its last field and no header room for a longer length form
//   - so the reader consumed at most SPKI_MAX bytes, the largest
//     SubjectPublicKeyInfo the modulus size check admits: a SEQUENCE header,
//     rsaEncryption's 15-byte AlgorithmIdentifier, a BIT STRING header
//     and its unused-bits octet, the RSAPublicKey and INTEGER headers,
//     the pad octet, CH_RSA_MODULUS_MAX value bytes and the 5-byte
//     exponent: 4 + 15 + 4 + 1 + 4 + 4 + 1 + 512 + 5 = 550
//   - the key lies inside the bytes it consumed
//   - alg is one of the three WEBPKI_KEY_* values, and the key has that
//     algorithm's shape: an RSA modulus of 256 to CH_RSA_MODULUS_MAX
//     bytes in steps of 8 with its top bit set and its low bit set, a
//     64-byte P-256 point or a 96-byte P-384 point
//
// Bound: the input is up to CH_WEBPKI_CERT_MAX bytes, the largest
// certificate the walk reads, whose TBS holds the SPKI the walk hands
// this reader with the rest of the certificate after it. That is above
// SPKI_MAX, so the consumption assertion is tested against inputs that
// could exceed it. An anchor's SPKI buffer is the same shape at a
// shorter length. Built with -DCH_TRUST_WEBPKI, so CH_RSA_MODULUS_MAX
// is 512 as it is in the webpki object.
//
// x509_der.c and its static helpers come in as their own translation
// unit on the launch line: webpki_spki.c has a static of the same
// name, so the two cannot share this one.
#include "harness.h"

#include "buf.h"
#include "rsa.h"
#include "webpki.h"

#include "webpki_spki.c"

// An RSA SPKI's bytes other than the modulus value. Every content here
// is 256 bytes or longer, so each of the four headers takes the 4-byte
// form: the SEQUENCE header, the AlgorithmIdentifier, the BIT STRING
// header and its unused-bits octet, the RSAPublicKey and INTEGER
// headers, the pad octet and the exponent.
#define RSA_SPKI_OVERHEAD (4 + sizeof algid_rsa + 4 + 1 + 4 + 4 + 1 + sizeof rsa_exponent)
#define SPKI_MAX (RSA_SPKI_OVERHEAD + CH_RSA_MODULUS_MAX)
// An EC SPKI: both contents are under 128 bytes, so the SEQUENCE and
// BIT STRING headers take the 2-byte form, around the AlgorithmIdentifier,
// the unused-bits octet, the 0x04 marker and the two coordinates.
#define P256_SPKI_LEN (2 + sizeof algid_p256 + 2 + 1 + 1 + 2 * P256_COORDINATE_LEN)
#define P384_SPKI_LEN (2 + sizeof algid_p384 + 2 + 1 + 1 + 2 * P384_COORDINATE_LEN)

int main(void) {
    uint8_t input[CH_WEBPKI_CERT_MAX];
    fill_nondet(input, sizeof input);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof input);
    rbuf r;
    rb_init(&r, input, n);

    // alg and key_len start nondet and key starts NULL, so the
    // assertions below prove that success writes all three.
    webpki_spki out;
    out.alg = nondet_u8();
    out.key = NULL;
    out.key_len = nondet_size_t();

    if (!webpki_read_spki(&r, &out)) {
        return 0;
    }
    __CPROVER_assert(!r.err, "spki success leaves err clear");
    size_t consumed = n - rb_left(&r);
    __CPROVER_assert(consumed <= SPKI_MAX, "an accepted spki is at most SPKI_MAX bytes");
    __CPROVER_assert(out.key != NULL && out.key >= input && out.key_len <= consumed &&
                         out.key - input <= (ptrdiff_t)(consumed - out.key_len),
                     "the key lies inside the consumed bytes");
    if (out.alg == WEBPKI_KEY_RSA) {
        __CPROVER_assert(out.key_len >= 256 && out.key_len <= CH_RSA_MODULUS_MAX &&
                             (out.key_len & 7U) == 0,
                         "an rsa key is 256 to CH_RSA_MODULUS_MAX bytes in steps of 8");
        __CPROVER_assert((out.key[0] & 0x80) != 0, "an rsa modulus has its top bit set");
        __CPROVER_assert((out.key[out.key_len - 1] & 1U) != 0, "an rsa modulus is odd");
        __CPROVER_assert(consumed == RSA_SPKI_OVERHEAD + out.key_len,
                         "an rsa spki is its canonical encoding's length");
    } else if (out.alg == WEBPKI_KEY_P256) {
        __CPROVER_assert(out.key_len == 64, "a p256 key is X||Y, 64 bytes");
        __CPROVER_assert(consumed == P256_SPKI_LEN,
                         "a p256 spki is its canonical encoding's length");
    } else {
        __CPROVER_assert(out.alg == WEBPKI_KEY_P384, "alg is one of the three key algorithms");
        __CPROVER_assert(out.key_len == 96, "a p384 key is X||Y, 96 bytes");
        __CPROVER_assert(consumed == P384_SPKI_LEN,
                         "a p384 spki is its canonical encoding's length");
    }
    return 0;
}
