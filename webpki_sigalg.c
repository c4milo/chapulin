// Certificate signature algorithms for the TRUST=webpki chain verifier:
// the four AlgorithmIdentifiers a public CA writes, each byte-compared
// against its one canonical encoding, and the verify that hashes a
// certificate's signed bytes and hands them to the verifier the
// signer's key names. Contract in webpki.h; the algorithm list and the
// digest-length rule in docs/webpki.md.
//
// Every input is public: a certificate the peer sent, and a key from
// the same flight or from the caller's anchors. The code is straight
// line and variable time.
#include "webpki.h"

#include "buf.h"
#include "p256.h"
#include "p384.h"
#include "rsa_pkcs1.h"
#include "sha256.h"
#include "sha512.h"
#include "x509_der.h"

// sha256WithRSAEncryption, NULL parameters (RFC 4055 §5).
static const uint8_t sigalg_rsa_sha256[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                            0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00};
// sha384WithRSAEncryption, NULL parameters (RFC 4055 §5).
static const uint8_t sigalg_rsa_sha384[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                            0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00};
// ecdsa-with-SHA256, parameters absent (RFC 5758 §3.2).
static const uint8_t sigalg_ecdsa_sha256[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                              0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
// ecdsa-with-SHA384, parameters absent (RFC 5758 §3.2).
static const uint8_t sigalg_ecdsa_sha384[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                              0x48, 0xce, 0x3d, 0x04, 0x03, 0x03};

// One admitted AlgorithmIdentifier and the WEBPKI_SIG_* value it names.
typedef struct {
    uint8_t sigalg;
    const uint8_t *der;
    size_t der_len;
} signature_algorithm;

static const signature_algorithm signature_algorithms[] = {
    {WEBPKI_SIG_RSA_SHA256,   sigalg_rsa_sha256,   sizeof sigalg_rsa_sha256  },
    {WEBPKI_SIG_RSA_SHA384,   sigalg_rsa_sha384,   sizeof sigalg_rsa_sha384  },
    {WEBPKI_SIG_ECDSA_SHA256, sigalg_ecdsa_sha256, sizeof sigalg_ecdsa_sha256},
    {WEBPKI_SIG_ECDSA_SHA384, sigalg_ecdsa_sha384, sizeof sigalg_ecdsa_sha384},
};
#define SIGNATURE_ALGORITHM_COUNT (sizeof signature_algorithms / sizeof signature_algorithms[0])

// The tag of the TBSCertificate header x509_emit_header re-emits.
#define TAG_SEQUENCE 0x30
// The raw P-256 point p256_ecdsa_verify takes, X||Y.
#define P256_PUB_LEN 64
// The zero bytes a SHA-256 digest takes on its left to fill P384_LEN.
#define P384_PAD_LEN (P384_LEN - SHA256_LEN)

int webpki_read_sigalg(rbuf *r, uint8_t *sigalg) {
    for (size_t i = 0; i < SIGNATURE_ALGORITHM_COUNT; i++) {
        // Each comparison starts from a copy of r, so a failed one
        // leaves r where the field starts.
        rbuf attempt = *r;
        if (x509_read_exact(&attempt, signature_algorithms[i].der,
                            signature_algorithms[i].der_len)) {
            *r = attempt;
            *sigalg = signature_algorithms[i].sigalg;
            return 1;
        }
    }
    return 0;
}

static int sigalg_is_rsa(uint8_t sigalg) {
    return sigalg == WEBPKI_SIG_RSA_SHA256 || sigalg == WEBPKI_SIG_RSA_SHA384;
}

static int sigalg_is_ecdsa(uint8_t sigalg) {
    return sigalg == WEBPKI_SIG_ECDSA_SHA256 || sigalg == WEBPKI_SIG_ECDSA_SHA384;
}

// 1 when signer's key belongs to the family cert's signature algorithm
// names, with the length that family's verifier reads. An RSA modulus's
// length is rsa_pkcs1_verify's own check.
static int signer_matches_sigalg(uint8_t sigalg, const webpki_spki *signer) {
    if (sigalg_is_rsa(sigalg)) {
        return signer->alg == WEBPKI_KEY_RSA;
    }
    if (sigalg_is_ecdsa(sigalg)) {
        return (signer->alg == WEBPKI_KEY_P256 && signer->key_len == P256_PUB_LEN) ||
               (signer->alg == WEBPKI_KEY_P384 && signer->key_len == (size_t)P384_PUB_LEN);
    }
    return 0;
}

// Hashes the signed bytes, the re-emitted TBSCertificate header then
// cert->tbs, with the hash cert->sigalg names. Returns the digest
// length, SHA256_LEN or SHA384_LEN. The caller has checked sigalg.
static size_t hash_signed_bytes(const webpki_cert *cert, uint8_t digest[SHA384_LEN]) {
    uint8_t header[4];
    size_t header_len = x509_emit_header(TAG_SEQUENCE, cert->tbs_len, header);
    if (cert->sigalg == WEBPKI_SIG_RSA_SHA256 || cert->sigalg == WEBPKI_SIG_ECDSA_SHA256) {
        sha256 hash;
        sha256_init(&hash);
        sha256_update(&hash, header, header_len);
        sha256_update(&hash, cert->tbs, cert->tbs_len);
        sha256_final(&hash, digest);
        return SHA256_LEN;
    }
    sha512 hash;
    sha384_init(&hash);
    sha512_update(&hash, header, header_len);
    sha512_update(&hash, cert->tbs, cert->tbs_len);
    sha384_final(&hash, digest);
    return SHA384_LEN;
}

// FIPS 186-4 §6.4 for P-384: the message hash is the leftmost 384 bits
// of the digest. A SHA-384 digest is all of them. A SHA-256 digest has
// only 256, so it takes P384_PAD_LEN zero bytes on its left, which
// leaves its integer value unchanged.
static void p384_message_hash(const uint8_t *digest, size_t digest_len,
                              uint8_t msg_hash[P384_LEN]) {
    static const uint8_t zeros[P384_PAD_LEN] = {0};
    wbuf writer;
    wb_init(&writer, msg_hash, P384_LEN);
    wb_bytes(&writer, zeros, P384_LEN - digest_len);
    wb_bytes(&writer, digest, digest_len);
}

int webpki_verify(const webpki_cert *cert, const webpki_spki *signer) {
    // x509_emit_header writes at most two length octets, and no parsed
    // certificate's TBS exceeds the certificate cap.
    if (!signer_matches_sigalg(cert->sigalg, signer) || cert->tbs_len > CH_WEBPKI_CERT_MAX) {
        return 0;
    }
    uint8_t digest[SHA384_LEN] = {0};
    size_t digest_len = hash_signed_bytes(cert, digest);
    if (signer->alg == WEBPKI_KEY_RSA) {
        // rsa_pkcs1_verify refuses a signature whose length is not the
        // modulus length, and a modulus outside its size range.
        return rsa_pkcs1_verify(signer->key, signer->key_len, digest, digest_len, cert->sig,
                                cert->sig_len);
    }
    if (signer->alg == WEBPKI_KEY_P256) {
        // FIPS 186-4 §6.4 for P-256: the leftmost 256 bits, which are the
        // first 32 bytes of either digest. p256_ecdsa_verify reads exactly
        // those, so a SHA-384 digest is cut by passing it whole.
        return p256_ecdsa_verify(signer->key, digest, cert->sig, cert->sig_len);
    }
    uint8_t msg_hash[P384_LEN];
    p384_message_hash(digest, digest_len, msg_hash);
    return p384_ecdsa_verify(signer->key, msg_hash, cert->sig, cert->sig_len);
}
