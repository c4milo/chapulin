// The DER inside the PEM files that an operator provisions
// (pem_files.h). It reads these things:
//  - a certificate, as far as its subject Name and its
//    subjectPublicKeyInfo;
//  - a P-256 private key in PKCS #8 or SEC 1 form;
//  - an RSA private key in PKCS #8 form, in a server role;
//  - an ML-DSA-87 private key in PKCS #8 form, in an object that signs
//    ML-DSA-87;
//  - the EC PARAMETERS that a SEC 1 key file may hold above its key.
//
// These are certificate files under INV-5, beside x509_ca.c. They read
// DER through x509_der.c's canonical readers, and they return no verdict
// on a certificate. No path that peer input takes calls them. pem_files.c
// is their one caller, and no library source calls pem_files.c's calls
// (.semgrep/invariants.yml).
//
// A block that decodes is not authenticated (pem.h).
#ifndef CH_X509_PEM_H
#define CH_X509_PEM_H

#include <stddef.h>
#include <stdint.h>

// Reads cert, one certificate's DER, as far as its subjectPublicKeyInfo,
// and judges nothing: no signature, date, name, extension or key
// algorithm. It reads the outer fields alone, each length in canonical
// DER (x509_der.h):
//  - a Certificate SEQUENCE that fills cert. It holds a TBSCertificate
//    SEQUENCE, a signatureAlgorithm SEQUENCE and a signature BIT STRING,
//    and nothing after them;
//  - in the TBSCertificate, an optional version [0], then serialNumber
//    INTEGER, signature SEQUENCE, issuer SEQUENCE, validity SEQUENCE,
//    subject SEQUENCE and subjectPublicKeyInfo SEQUENCE.
// The fields after the key go unread, so a version 1 certificate, which
// has none, reads too.
//
// Returns 1, and then *name and *spki point into cert at the whole TLVs
// of the subject and the subjectPublicKeyInfo, header included. Those
// are the bytes a ch_trust_anchor holds (webpki_cfg.h), and their
// lengths are set. Returns 0 otherwise, and then the four outputs hold
// nothing the caller may read.
int x509_pem_read_subject_key(const uint8_t *cert, size_t cert_len, const uint8_t **name,
                              size_t *name_len, const uint8_t **spki, size_t *spki_len);

// Whether spki, a whole SubjectPublicKeyInfo TLV, is the P-256 key
// point, byte for byte. Such a key is id-ecPublicKey with the namedCurve
// prime256v1 (RFC 5480 section 2.1.1) and the uncompressed point
// 0x04||X||Y. point is X||Y, 64 bytes, as p256.h takes a point. Returns
// 1 or 0.
int x509_pem_spki_is_p256(const uint8_t *spki, size_t spki_len, const uint8_t point[64]);

// Reads der as a PKCS #8 PrivateKeyInfo (RFC 5958 section 2) that holds
// a P-256 key. Its fields are these:
//  - version 0;
//  - the AlgorithmIdentifier id-ecPublicKey with namedCurve prime256v1,
//    byte for byte (RFC 5480 section 2.1.1);
//  - a privateKey OCTET STRING that holds an ECPrivateKey and fills the
//    rest, so no attributes and no publicKey field.
// The ECPrivateKey reads as x509_pem_read_sec1 reads it, but its curve
// field may be absent, because the AlgorithmIdentifier names the curve
// (RFC 5915 section 3).
//
// Returns 1, and copies the scalar, 32 big-endian bytes, to scalar. Then
// *point points into der at the ECPrivateKey's X||Y, 64 bytes, when the
// ECPrivateKey carries a publicKey, and is NULL when it does not. Returns
// 0 otherwise, and then it has written nothing to scalar. The scalar is a
// secret, and so is der: the caller wipes both.
int x509_pem_read_pkcs8(const uint8_t *der, size_t der_len, uint8_t scalar[32],
                        const uint8_t **point);

// Reads der as a SEC 1 ECPrivateKey (RFC 5915 section 3) on P-256. Its
// fields are these, and nothing after them:
//  - version 1;
//  - a privateKey OCTET STRING of exactly 32 bytes;
//  - the parameters [0] field, which names prime256v1 byte for byte. RFC
//    5915 requires it outside PKCS #8;
//  - an optional publicKey [1] BIT STRING, which holds the uncompressed
//    point.
// Outputs and wipes as x509_pem_read_pkcs8.
int x509_pem_read_sec1(const uint8_t *der, size_t der_len, uint8_t scalar[32],
                       const uint8_t **point);

// Whether der, an EC PARAMETERS block's DER, is ECParameters' namedCurve
// prime256v1, the OBJECT IDENTIFIER alone and byte for byte (RFC 5480
// section 2.1.1). `openssl ecparam -genkey` writes this block above an EC
// PRIVATE KEY block. Any other curve, an explicit curve and any byte
// after the OBJECT IDENTIFIER answer 0. Returns 1 or 0.
int x509_pem_parameters_are_p256(const uint8_t *der, size_t der_len);

#if defined(CH_ROLE_SERVER) && !defined(CH_PROFILE_CNSA2)
// One INTEGER's content octets in der: where they start and how many
// there are. The count is the DER's length field, which the reader
// branches on. The octets themselves may be secret, and the reader reads
// none of them.
typedef struct {
    const uint8_t *bytes;
    size_t len;
} x509_pem_integer;

// The integers of an RSAPrivateKey (RFC 8017 appendix A.1.2) after its
// version, under RFC 8017's names, with the public exponent left out:
// x509_pem_read_rsa_pkcs8 requires it to be 65537.
typedef struct {
    x509_pem_integer n;
    x509_pem_integer d;
    x509_pem_integer p;
    x509_pem_integer q;
    x509_pem_integer dp;
    x509_pem_integer dq;
    x509_pem_integer qinv;
} x509_pem_rsa_key;

// Whether spki, a whole SubjectPublicKeyInfo TLV, is the RSA key with the
// modulus n, n_len bytes, and the public exponent 65537, byte for byte.
// Such a key is rsaEncryption with NULL parameters and a BIT STRING that
// holds an RSAPublicKey (RFC 8017 appendix A.1.1). n must have its top
// bit set, so its INTEGER is a zero octet and then n. Returns 1 or 0.
int x509_pem_spki_is_rsa(const uint8_t *spki, size_t spki_len, const uint8_t *n, size_t n_len);

// Reads der as a PKCS #8 PrivateKeyInfo (RFC 5958 section 2) that holds
// an RSA key. Its fields are these:
//  - version 0;
//  - the AlgorithmIdentifier rsaEncryption with NULL parameters, byte
//    for byte (RFC 8017 appendix A.1);
//  - a privateKey OCTET STRING that fills the rest, so no attributes and
//    no publicKey field. It holds an RSAPrivateKey: version two-prime
//    (0), so no otherPrimeInfos, then modulus, publicExponent,
//    privateExponent, prime1, prime2, exponent1, exponent2 and
//    coefficient, and nothing after them. The publicExponent must be
//    65537, its INTEGER byte for byte.
// The reader checks each INTEGER's tag and length, and reads no content
// octet of any INTEGER but the exponent. x509_pem_integer_to_bytes reads
// and checks them.
//
// Returns 1, and points each field of key at its INTEGER's content
// octets in der. Returns 0 otherwise, and then key holds nothing the
// caller may read. der is a secret: the caller wipes it.
int x509_pem_read_rsa_pkcs8(const uint8_t *der, size_t der_len, x509_pem_rsa_key *key);

// Copies the value of v, an INTEGER's content octets, to out, out_len
// bytes, big-endian and padded on the left with zero bytes. Returns 1
// when v is a non-negative INTEGER in canonical DER whose value fits
// out_len bytes:
//  - the first octet does not have its top bit set, since that makes the
//    value negative;
//  - a first octet of zero comes before an octet with its top bit set,
//    or is the only octet (X.690 section 8.3.2);
//  - the octets after a leading zero octet are at most out_len.
// Returns 0 otherwise, and then out holds unspecified bytes.
//
// v.len and out_len are public, and the call branches on them alone. It
// reads the octets with no branch and no memory index that their values
// decide, and it computes the answer from them with masks. The answer
// leaves as the result, which is public.
int x509_pem_integer_to_bytes(x509_pem_integer v, uint8_t *out, size_t out_len);
#endif

#ifdef CH_SIGN_MLDSA
// Whether spki, a whole SubjectPublicKeyInfo TLV, is the ML-DSA-87 key
// key, byte for byte: id-ml-dsa-87 with no parameters, and a BIT STRING
// that holds the 2,592-byte key (draft-ietf-lamps-dilithium-certificates).
// Returns 1 or 0.
int x509_pem_spki_is_mldsa87(const uint8_t *spki, size_t spki_len, const uint8_t key[2592]);

// Reads der as a PKCS #8 OneAsymmetricKey (RFC 5958 section 2) that holds
// an ML-DSA-87 key (draft-ietf-lamps-dilithium-certificates). Its fields
// are these:
//  - version 0;
//  - the AlgorithmIdentifier id-ml-dsa-87 with no parameters, byte for
//    byte;
//  - a privateKey OCTET STRING that fills the rest, so no attributes and
//    no publicKey field. It holds an ML-DSA-87-PrivateKey in one of two
//    forms: the seed, a [0] IMPLICIT OCTET STRING of 32 bytes, or both, a
//    SEQUENCE of the seed's OCTET STRING and the expanded key's OCTET
//    STRING of 4,896 bytes. OpenSSL 3.5 writes the both form by default.
// The expandedKey form, the expanded key alone, holds no seed, and the
// call refuses it (docs/decisions.md 159).
//
// Returns 1, and copies the seed to seed. Then *expanded points into der
// at the expanded key in the both form, and is NULL in the seed form. The
// caller expands the seed and compares the result with *expanded. Returns
// 0 otherwise, and then it has written nothing to seed. The seed is a
// secret, and so is der: the caller wipes both.
int x509_pem_read_mldsa87_pkcs8(const uint8_t *der, size_t der_len, uint8_t seed[32],
                                const uint8_t **expanded);
#endif

#endif
