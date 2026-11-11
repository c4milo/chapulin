// RSASSA-PKCS1-v1_5 verification (RFC 8017 §8.2.2): recover the encoded
// message with RSAVP1, build the expected encoded message from the
// digest, and compare the two whole. Encode-and-compare, not
// decode-and-judge: the verifier never parses the recovered bytes, so
// the padding-parser mistakes that let a forged signature pass (a short
// PS, a trailing garbage run after the digest) have nothing to act on.
// Every input is public, so the code is straight-line and variable time
// (see rsa_pkcs1.h).
#include "rsa_pkcs1.h"

#include <string.h>

#include "ct.h"
#include "dnssec.h"
#include "rsa.h"
#include "rsa_mont64.h"
#include "sha256.h"
#include "sha512.h"

// The modulus size check, byte for byte the one rsa_pss_verify applies:
// RSA-2048 up to CH_RSA_MODULUS_MAX (rsa_key.h) in 8-byte steps. The bound
// is rsa.h's, so the two verifiers and rsa_mont.c's word arrays move
// together.
#define MODULUS_MIN 256
#define MODULUS_STEP 8

// EM = 0x00 || 0x01 || PS || 0x00 || T (RFC 8017 §9.2), with PS a run of
// 0xff bytes at least PS_MIN long and T = DigestInfo || digest.
#define EM_LEADING_BYTE 0x00
#define EM_BLOCK_TYPE 0x01
#define PS_BYTE 0xff
#define PS_MIN 8
#define EM_SEPARATOR 0x00 // the byte between PS and T
#define EM_OVERHEAD 3     // the leading byte, the block type, and the separator

// DigestInfo for SHA-256 and SHA-384 (RFC 8017 §9.2 note 1): the DER of
// SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING header }, 19 bytes
// each; the digest follows as the OCTET STRING's content.
// test/gen_rsa_pkcs1_vectors.py recovers every vector's encoded message
// with openssl and checks these bytes against it.
#define DIGEST_INFO_LEN 19
static const uint8_t digest_info_sha256[DIGEST_INFO_LEN] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
static const uint8_t digest_info_sha384[DIGEST_INFO_LEN] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};

// The smallest modulus still leaves PS at least PS_MIN bytes under the
// longest T, so the encoder below never computes a negative PS length.
_Static_assert(MODULUS_MIN >= EM_OVERHEAD + PS_MIN + DIGEST_INFO_LEN + SHA384_LEN,
               "the modulus size check must leave room for the minimum PS");

// The DigestInfo for a digest of digest_len bytes, or NULL when no
// supported hash produces that length.
static const uint8_t *digest_info_for(size_t digest_len) {
    if (digest_len == SHA256_LEN) {
        return digest_info_sha256;
    }
    if (digest_len == SHA384_LEN) {
        return digest_info_sha384;
    }
    return NULL;
}

// 1 if the len-byte big-endian a >= b. Both operands are public. The
// same predicate rsa.c keeps private for rsa_pss_verify's range check.
static int greater_or_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return a[i] > b[i];
        }
    }
    return 1; // equal
}

// EMSA-PKCS1-v1_5-ENCODE (RFC 8017 §9.2) into em[0..em_len): the two
// fixed bytes, PS sized to fill, the separator, DigestInfo, and the
// digest. em_len is at least MODULUS_MIN, so PS is at least PS_MIN bytes
// by the static assertion above. em is a local block of this module,
// never a wire buffer, so it is filled directly, the way rsa.c fills its
// own DB; the wbuf writer is for bytes that leave the library.
static void emsa_pkcs1_v1_5_encode(uint8_t *em, size_t em_len, const uint8_t *digest_info,
                                   const uint8_t *digest, size_t digest_len) {
    size_t t_len = DIGEST_INFO_LEN + digest_len;
    size_t ps_len = em_len - EM_OVERHEAD - t_len;
    em[0] = EM_LEADING_BYTE;
    em[1] = EM_BLOCK_TYPE;
    memset(em + 2, PS_BYTE, ps_len);
    em[2 + ps_len] = EM_SEPARATOR;
    memcpy(em + EM_OVERHEAD + ps_len, digest_info, DIGEST_INFO_LEN);
    memcpy(em + EM_OVERHEAD + ps_len + DIGEST_INFO_LEN, digest, digest_len);
}

// 1 when rsa_pkcs1_verify takes the lengths, the modulus and the signature
// to RSAVP1: the modulus size check, an odd modulus, a digest length a
// supported hash produces, and a signature below the modulus.
static int inputs_admitted(const uint8_t *n, size_t n_len, size_t digest_len, const uint8_t *sig,
                           size_t sig_len) {
    if (n_len < MODULUS_MIN || n_len > CH_RSA_MODULUS_MAX || n_len % MODULUS_STEP != 0 ||
        sig_len != n_len) {
        return 0;
    }
    // An even modulus is not an RSA modulus, and rsa_vp1's Montgomery
    // inverse of the low word exists only for an odd one.
    if ((n[n_len - 1] & 1) == 0) {
        return 0;
    }
    if (digest_info_for(digest_len) == NULL) {
        return 0;
    }
    // Reject a signature numerically >= the modulus (RSAVP1 step 1), the
    // range rsa_vp1's contract leaves to its caller.
    return !greater_or_equal(sig, n, n_len);
}

// 1 when em, the n_len bytes RSAVP1 recovered (I2OSP with k = n_len, RFC
// 8017 §8.2.2 step 2), is the expected encoding of digest at the same
// length. inputs_admitted has checked digest_len.
static int encoded_message_matches(size_t n_len, const uint8_t *digest, size_t digest_len,
                                   const uint8_t *em) {
    uint8_t expected[CH_RSA_MODULUS_MAX];
    emsa_pkcs1_v1_5_encode(expected, n_len, digest_info_for(digest_len), digest, digest_len);

    // Both operands are public, so a plain byte compare would be sound;
    // ct_memeq is the tree's one byte-equality function and costs nothing
    // here, so this follows rsa.c's final compare rather than adding a
    // second idiom.
    return (int)ct_memeq(em, expected, n_len);
}

// rsa_pkcs1_verify and rsa_pkcs1_verify_cpu share every check and differ
// in the one call that computes RSAVP1, em = sig^65537 mod n as n_len
// bytes.
int rsa_pkcs1_verify(const uint8_t *n, size_t n_len, const uint8_t *digest, size_t digest_len,
                     const uint8_t *sig, size_t sig_len) {
    if (!inputs_admitted(n, n_len, digest_len, sig, sig_len)) {
        return 0;
    }
    uint8_t em[CH_RSA_MODULUS_MAX];
    rsa_vp1(n, n_len, sig, em);
    return encoded_message_matches(n_len, digest, digest_len, em);
}

#ifdef CH_CPU_RUNTIME
int rsa_pkcs1_verify_cpu(uint32_t cpu, const uint8_t *n, size_t n_len, const uint8_t *digest,
                         size_t digest_len, const uint8_t *sig, size_t sig_len) {
    if (!inputs_admitted(n, n_len, digest_len, sig, sig_len)) {
        return 0;
    }
    uint8_t em[CH_RSA_MODULUS_MAX];
    rsa_vp1_cpu(cpu, n, n_len, sig, em);
    return encoded_message_matches(n_len, digest, digest_len, em);
}
#endif

#if (defined(CH_DNSSEC) || defined(CH_JWS)) && defined(CH_CPU_RUNTIME)
// DigestInfo for SHA-512 (RFC 8017 section 9.2 note 1), which algorithm
// 10 signs with (RFC 5702 section 3); only a DNSSEC check reads it, so no
// TLS path admits a 64-byte digest, and jws.c passes a 32-byte one alone.
static const uint8_t digest_info_sha512[DIGEST_INFO_LEN] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

// The bit length of the n_len-byte n, whose first byte is not zero.
static size_t bit_length_of(const uint8_t *n, size_t n_len) {
    size_t bits = 8 * n_len;
    for (uint8_t top = n[0]; (top & 0x80) == 0; top = (uint8_t)(top << 1)) {
        bits--;
    }
    return bits;
}

int rsa_pkcs1_verify_exponent(const uint8_t *n, size_t n_len, uint64_t e, const uint8_t *digest,
                              size_t digest_len, const uint8_t *sig, size_t sig_len) {
    const uint8_t *digest_info = digest_len == SHA256_LEN   ? digest_info_sha256
                                 : digest_len == SHA512_LEN ? digest_info_sha512
                                                            : NULL;
    if (digest_info == NULL || n_len < CH_DNSSEC_RSA_MODULUS_MIN ||
        n_len < EM_OVERHEAD + PS_MIN + DIGEST_INFO_LEN + digest_len || n_len > CH_RSA_MODULUS_MAX ||
        sig_len != n_len || n[0] == 0 || (n[n_len - 1] & 1) == 0 || e < 3 || (e & 1) == 0 ||
        greater_or_equal(sig, n, n_len)) {
        return 0;
    }
    rsa_mont64_modulus mod;
    rsa_mont64_modulus_init(&mod, n, n_len, bit_length_of(n, n_len));
    uint8_t em[CH_RSA_MODULUS_MAX];
    rsa_mont64_public_exp(em, sig, n_len, &mod, e);
    uint8_t expected[CH_RSA_MODULUS_MAX];
    emsa_pkcs1_v1_5_encode(expected, n_len, digest_info, digest, digest_len);
    return (int)ct_memeq(em, expected, n_len);
}
#endif

#if defined(CH_JWS) && defined(CH_CPU_RUNTIME) && defined(CH_ROLE_SERVER)
#include "widemul.h"

int rsa_pkcs1_sign(uint32_t cpu, const ch_rsa_priv *k, const uint8_t digest[32],
                   const uint8_t blind[RSA_BLIND_LEN], uint8_t *sig) {
    uint8_t widemul = widemul_of_cpu(cpu);
    // The key's lengths are public, and the 64-bit signer's test of the
    // primes computes in constant time and publishes its verdict alone.
    // The verdict on the key is the one a server's configuration check
    // reports, so it is public, as rsa_sign.c marks it.
    int key_ok = widemul_rsa_pss_sign_key_ok(widemul, k);
    CT_DECLASSIFY(&key_ok, sizeof key_ok);
    if (!key_ok) {
        return 0;
    }
    size_t n_len = k->n_len;
    // The encoded message begins with a zero byte, so it is below n, whose
    // top bit the key test requires.
    uint8_t em[CH_RSA_MODULUS_MAX];
    emsa_pkcs1_v1_5_encode(em, n_len, digest_info_sha256, digest, SHA256_LEN);
    int written = widemul_rsa_sp1_cpu(cpu, widemul, k, em, blind, sig);
    // The ladder has no check of its own, and the 64-bit signer's check
    // reads its own arithmetic. This one runs the verifier a peer runs,
    // whose arithmetic is variable time, so the signature is marked public
    // first: the call publishes it when no fault changed it. The 64-bit
    // signer has already checked it in constant time. A ladder signature
    // that a fault changed is never written, and it is no CRT signature,
    // so it does not give a prime away (docs/decisions.md 223).
    CT_DECLASSIFY(&written, sizeof written);
    CT_DECLASSIFY(sig, n_len);
    if (!written || !rsa_pkcs1_verify_cpu(cpu, k->n, n_len, digest, SHA256_LEN, sig, n_len)) {
        ct_wipe(sig, n_len);
        return 0;
    }
    return 1;
}
#endif
