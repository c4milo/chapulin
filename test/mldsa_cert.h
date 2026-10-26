// X.509 v3 certificates of docs/ca.md's profile for ML-DSA-87 keys, signed
// by the test-only signer (test/mldsa_sign.h): a leaf with keyUsage
// digitalSignature, extendedKeyUsage serverAuth and basicConstraints
// CA:FALSE, or an intermediate with basicConstraints CA:TRUE, pathlen 0
// and keyUsage keyCertSign and cRLSign, the extensions OpenSSL 3.5 writes
// for docs/ca.md's recipe. The ML-DSA-87 tests build their chains here at
// run time, so a mutant of a field is signed again and a field the
// grammar admits reaches the signature check. Include it after
// mldsa_sign.h. Not a standalone translation unit.
#ifndef CH_TEST_MLDSA_CERT_H
#define CH_TEST_MLDSA_CERT_H

#include <string.h>

#include "mldsa_sign.h"

// id-ml-dsa-87, parameters absent (RFC 9881 section 2).
static const uint8_t mldsa_cert_algid[] = {0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
                                           0x01, 0x65, 0x03, 0x04, 0x03, 0x13};

// What a certificate departs from the profile in, for the strict tests.
// A zeroed shape is a certificate of the profile.
typedef struct {
    int is_ca;               // the intermediate's extensions in place of the leaf's
    const uint8_t *sigalg;   // the AlgorithmIdentifier in both places, NULL for id-ml-dsa-87
    size_t sigalg_len;       //
    const uint8_t *spki_alg; // the SPKI's AlgorithmIdentifier, NULL for id-ml-dsa-87
    size_t spki_alg_len;     //
    int key_delta;           // bytes added to, or less than 0 taken from, the 2592-byte key
    size_t name_pad;         // bytes the subject name adds, to reach an exact size
    int sig_delta;           // bytes added to, or taken from, the 4627-byte signature
} mldsa_cert_shape;

// Writes the tag and the DER length of len to out. Returns the header's length.
static size_t mldsa_der_header(uint8_t *out, uint8_t tag, size_t len) {
    out[0] = tag;
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

// Writes a TLV of the n bytes at content to out. content may be out + 4 or
// any buffer that does not overlap out. Returns the TLV's length.
static size_t mldsa_der_tlv(uint8_t *out, uint8_t tag, const uint8_t *content, size_t n) {
    uint8_t header[4];
    size_t h = mldsa_der_header(header, tag, n);
    memmove(out + h, content, n);
    memcpy(out, header, h);
    return h + n;
}

// A Name of one commonName of n bytes of name, then pad bytes of 'x'.
static size_t mldsa_cert_name(uint8_t *out, const char *name, size_t pad) {
    static uint8_t cn[512];
    static const uint8_t oid_cn[] = {0x06, 0x03, 0x55, 0x04, 0x03};
    size_t n = strlen(name);
    memcpy(cn, name, n);
    memset(cn + n, 'x', pad);
    uint8_t atv[600];
    memcpy(atv, oid_cn, sizeof oid_cn);
    size_t atv_len = sizeof oid_cn + mldsa_der_tlv(atv + sizeof oid_cn, 0x0c, cn, n + pad);
    uint8_t set[600];
    size_t set_len = mldsa_der_tlv(set, 0x30, atv, atv_len);
    uint8_t rdn[600];
    size_t rdn_len = mldsa_der_tlv(rdn, 0x31, set, set_len);
    return mldsa_der_tlv(out, 0x30, rdn, rdn_len);
}

// The extensions [3] wrapper for a leaf or an intermediate.
static size_t mldsa_cert_extensions(uint8_t *out, int is_ca) {
    static const uint8_t leaf[] = {// keyUsage, critical, digitalSignature
                                   0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
                                   0x04, 0x03, 0x02, 0x07, 0x80,
                                   // extendedKeyUsage serverAuth
                                   0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a,
                                   0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
                                   // basicConstraints CA:FALSE
                                   0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30,
                                   0x00};
    static const uint8_t ca[] = {// basicConstraints, critical, CA:TRUE, pathlen 0
                                 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
                                 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00,
                                 // keyUsage, critical, keyCertSign and cRLSign
                                 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
                                 0x04, 0x03, 0x02, 0x01, 0x06};
    uint8_t ext_list[64];
    size_t ext_list_len = is_ca ? mldsa_der_tlv(ext_list, 0x30, ca, sizeof ca)
                                : mldsa_der_tlv(ext_list, 0x30, leaf, sizeof leaf);
    return mldsa_der_tlv(out, 0xa3, ext_list, ext_list_len);
}

// The SubjectPublicKeyInfo of pk, under the shape's algorithm and length.
static size_t mldsa_cert_spki(uint8_t *out, const uint8_t pk[MLDSA87_PK_LEN],
                              const mldsa_cert_shape *shape) {
    static uint8_t bits[MLDSA87_PK_LEN + 2];
    long key_long = (long)MLDSA87_PK_LEN + shape->key_delta;
    size_t key_len = (size_t)key_long;
    bits[0] = 0; // no unused bits
    memset(bits + 1, 0x5a, key_len);
    memcpy(bits + 1, pk, key_len < MLDSA87_PK_LEN ? key_len : MLDSA87_PK_LEN);
    static uint8_t body[MLDSA87_PK_LEN + 64];
    const uint8_t *alg = shape->spki_alg != NULL ? shape->spki_alg : mldsa_cert_algid;
    size_t alg_len = shape->spki_alg != NULL ? shape->spki_alg_len : sizeof mldsa_cert_algid;
    memcpy(body, alg, alg_len);
    size_t n = alg_len + mldsa_der_tlv(body + alg_len, 0x03, bits, key_len + 1);
    return mldsa_der_tlv(out, 0x30, body, n);
}

// Writes the certificate of subject_pk, named subject and issued by
// issuer under issuer_name, into out, which holds at least 8192 bytes.
// Returns its length, or 0 when the signer fails.
static size_t mldsa_cert_build(uint8_t *out, const uint8_t subject_pk[MLDSA87_PK_LEN],
                               const char *subject, const mldsa_test_key *issuer,
                               const char *issuer_name, const mldsa_cert_shape *shape) {
    static const uint8_t head[] = {0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01};
    static const uint8_t validity[] = {0x30, 0x1e, 0x17, 0x0d, '2', '6', '0',  '1',  '0', '1', '0',
                                       '0',  '0',  '0',  '0',  '0', 'Z', 0x17, 0x0d, '3', '6', '0',
                                       '1',  '0',  '1',  '0',  '0', '0', '0',  '0',  '0', 'Z'};
    const uint8_t *alg = shape->sigalg != NULL ? shape->sigalg : mldsa_cert_algid;
    size_t alg_len = shape->sigalg != NULL ? shape->sigalg_len : sizeof mldsa_cert_algid;
    static uint8_t tbs[8192];
    size_t n = 0;
    memcpy(tbs, head, sizeof head);
    n += sizeof head;
    memcpy(tbs + n, alg, alg_len);
    n += alg_len;
    n += mldsa_cert_name(tbs + n, issuer_name, 0);
    memcpy(tbs + n, validity, sizeof validity);
    n += sizeof validity;
    n += mldsa_cert_name(tbs + n, subject, shape->name_pad);
    n += mldsa_cert_spki(tbs + n, subject_pk, shape);
    n += mldsa_cert_extensions(tbs + n, shape->is_ca);
    static uint8_t body[8192];
    size_t body_len = mldsa_der_tlv(body, 0x30, tbs, n);
    static uint8_t sig[MLDSA87_SIG_LEN + 16];
    static const uint8_t no_rnd[32];
    sig[0] = 0; // no unused bits
    if (!mldsa_test_sign(issuer, body, body_len, NULL, 0, no_rnd, sig + 1)) {
        return 0;
    }
    long sig_long = (long)MLDSA87_SIG_LEN + shape->sig_delta;
    size_t sig_len = (size_t)sig_long;
    memcpy(body + body_len, alg, alg_len);
    body_len += alg_len;
    body_len += mldsa_der_tlv(body + body_len, 0x03, sig, sig_len + 1);
    return mldsa_der_tlv(out, 0x30, body, body_len);
}

#endif
