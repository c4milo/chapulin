// subjectPublicKeyInfo for the TRUST=webpki chain verifier: the three
// public-key algorithms a public chain carries, each AlgorithmIdentifier
// byte-compared against its one canonical encoding. x509_der.c reads
// the build's one pinned algorithm for the device modes; this file
// carries its own three tables because a public chain mixes them.
// Contract in webpki.h; the algorithm list in docs/webpki.md.
#include "webpki.h"

#include "buf.h"
#include "rsa.h"
#include "x509_der.h"

// DER tags this file reads.
#define TAG_SEQUENCE 0x30
#define TAG_INTEGER 0x02

// rsaEncryption with its mandatory NULL parameters (RFC 3279 §2.3.1).
static const uint8_t algid_rsa[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
// id-ecPublicKey with namedCurve prime256v1 (RFC 5480 §2.1.1).
static const uint8_t algid_p256[] = {0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                                     0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                                     0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
// id-ecPublicKey with namedCurve secp384r1, OID 1.3.132.0.34 (RFC 5480
// §2.1.1).
static const uint8_t algid_p384[] = {0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
                                     0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
// publicExponent: 65537 and nothing else.
static const uint8_t rsa_exponent[] = {0x02, 0x03, 0x01, 0x00, 0x01};

// One admitted AlgorithmIdentifier and the WEBPKI_KEY_* value it names.
typedef struct {
    uint8_t alg;
    const uint8_t *der;
    size_t der_len;
} key_algorithm;

static const key_algorithm key_algorithms[] = {
    {WEBPKI_KEY_RSA,  algid_rsa,  sizeof algid_rsa },
    {WEBPKI_KEY_P256, algid_p256, sizeof algid_p256},
    {WEBPKI_KEY_P384, algid_p384, sizeof algid_p384},
};
#define KEY_ALGORITHM_COUNT (sizeof key_algorithms / sizeof key_algorithms[0])

// The modulus size check rsa_pkcs1_verify applies: RSA-2048 up to
// CH_RSA_MODULUS_MAX (rsa.h) in 8-byte steps.
#define MODULUS_MIN 256
#define MODULUS_STEP_MASK 7U // a length is a whole step when these bits are zero

// The uncompressed-point marker (SEC 1 v2 §2.3.3) and the coordinate
// lengths of the two curves.
#define POINT_UNCOMPRESSED 0x04
#define P256_COORDINATE_LEN 32
#define P384_COORDINATE_LEN 48

// Reads the AlgorithmIdentifier at fields against each admitted
// encoding. Each comparison starts from a copy of fields, so a failed
// comparison leaves fields where the AlgorithmIdentifier starts. Returns
// the WEBPKI_KEY_* value and advances fields past it, or returns 0.
static uint8_t read_key_algorithm(rbuf *fields) {
    for (size_t i = 0; i < KEY_ALGORITHM_COUNT; i++) {
        rbuf attempt = *fields;
        if (x509_read_exact(&attempt, key_algorithms[i].der, key_algorithms[i].der_len)) {
            *fields = attempt;
            return key_algorithms[i].alg;
        }
    }
    return 0;
}

// The modulus INTEGER. A real modulus has its top bit set, so canonical
// DER demands exactly one 0x00 pad octet: a missing pad reads as a
// negative number, and an unneeded pad is not minimal. Yields the value
// bytes rsa_pkcs1_verify consumes.
static int read_rsa_modulus(rbuf *rsa_key, const uint8_t **value, size_t *value_len) {
    size_t content_len = 0;
    if (!x509_read_header(rsa_key, TAG_INTEGER, &content_len) || content_len < 2) {
        return 0;
    }
    if (rb_u8(rsa_key) != 0x00 || rsa_key->err) {
        return 0; // the pad octet
    }
    size_t modulus_len = content_len - 1;
    const uint8_t *modulus = rb_bytes(rsa_key, modulus_len);
    if (modulus == NULL) {
        return 0;
    }
    if (!(modulus[0] & 0x80)) {
        return 0; // a pad the value did not need
    }
    if (modulus_len < MODULUS_MIN || modulus_len > CH_RSA_MODULUS_MAX ||
        (modulus_len & MODULUS_STEP_MASK) != 0) {
        return 0; // the verifier's own admitted range (rsa.h)
    }
    if ((modulus[modulus_len - 1] & 1U) == 0) {
        return 0; // rsa_mont's Montgomery arithmetic needs an odd modulus
    }
    *value = modulus;
    *value_len = modulus_len;
    return 1;
}

// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
// (RFC 3279 §2.3.1), filling the BIT STRING's bytes exactly.
static int read_rsa_key(const uint8_t *bits, size_t bits_len, webpki_spki *out) {
    rbuf rsa_key;
    rb_init(&rsa_key, bits, bits_len);
    size_t seq_len = 0;
    if (!x509_read_header(&rsa_key, TAG_SEQUENCE, &seq_len) || seq_len != rb_left(&rsa_key)) {
        return 0;
    }
    const uint8_t *modulus = NULL;
    size_t modulus_len = 0;
    if (!read_rsa_modulus(&rsa_key, &modulus, &modulus_len)) {
        return 0;
    }
    if (!x509_read_exact(&rsa_key, rsa_exponent, sizeof rsa_exponent) || rsa_key.err ||
        rb_left(&rsa_key) != 0) {
        return 0; // an exponent other than 65537, or a byte after it
    }
    out->alg = WEBPKI_KEY_RSA;
    out->key = modulus;
    out->key_len = modulus_len;
    return 1;
}

// ECPoint in the uncompressed form, 0x04 || X || Y, filling the BIT
// STRING's bytes exactly (RFC 5480 §2.2). The compressed forms are
// refused. Whether the point lies on the curve is not checked here:
// p256_ecdsa_verify and p384_ecdsa_verify check both coordinates below
// the field prime and the curve equation before any arithmetic.
static int read_ec_point(const uint8_t *bits, size_t bits_len, uint8_t alg, size_t coordinate_len,
                         webpki_spki *out) {
    rbuf ec_point;
    rb_init(&ec_point, bits, bits_len);
    if (rb_u8(&ec_point) != POINT_UNCOMPRESSED || ec_point.err) {
        return 0;
    }
    const uint8_t *point = rb_bytes(&ec_point, 2 * coordinate_len);
    if (point == NULL || rb_left(&ec_point) != 0) {
        return 0;
    }
    out->alg = alg;
    out->key = point;
    out->key_len = 2 * coordinate_len;
    return 1;
}

int webpki_read_spki(rbuf *r, webpki_spki *out) {
    size_t len = 0;
    if (!x509_read_header(r, TAG_SEQUENCE, &len)) {
        return 0;
    }
    const uint8_t *body = rb_bytes(r, len);
    if (body == NULL) {
        return 0;
    }
    rbuf fields;
    rb_init(&fields, body, len);
    uint8_t alg = read_key_algorithm(&fields);
    const uint8_t *bits = NULL;
    size_t bits_len = 0;
    if (alg == 0 || !x509_read_bitstring(&fields, &bits, &bits_len) || fields.err ||
        rb_left(&fields) != 0) {
        return 0; // an unknown algorithm, a malformed BIT STRING, or a byte after it
    }
    if (alg == WEBPKI_KEY_RSA) {
        return read_rsa_key(bits, bits_len, out);
    }
    if (alg == WEBPKI_KEY_P256) {
        return read_ec_point(bits, bits_len, WEBPKI_KEY_P256, P256_COORDINATE_LEN, out);
    }
    return read_ec_point(bits, bits_len, WEBPKI_KEY_P384, P384_COORDINATE_LEN, out);
}
