// The DER inside the PEM files that an operator provisions
// (pem_files.h). It reads three things:
//  - a certificate, as far as its subject Name and its
//    subjectPublicKeyInfo;
//  - a P-256 private key in PKCS #8 or SEC 1 form;
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
