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
#include "rsa.h"
#include "sha256.h"
#include "sha512.h"

// The modulus size gate, byte for byte the one rsa_pss_verify applies:
// RSA-2048 to RSA-3072 in 8-byte steps. rsa.c keeps its limit private, so
// the value is repeated here; the two must move together, and
// rsa_mont.c's LIMBS_MAX (96 limbs = 384 bytes) bounds both.
#define MODULUS_MIN 256
#define MODULUS_MAX 384
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
               "the modulus gate must leave room for the minimum PS");

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

int rsa_pkcs1_verify(const uint8_t *n, size_t n_len, const uint8_t *digest, size_t digest_len,
                     const uint8_t *sig, size_t sig_len) {
    if (n_len < MODULUS_MIN || n_len > MODULUS_MAX || n_len % MODULUS_STEP != 0 ||
        sig_len != n_len) {
        return 0;
    }
    // An even modulus is not an RSA modulus, and rsa_vp1's Montgomery
    // inverse of the low limb exists only for an odd one.
    if ((n[n_len - 1] & 1) == 0) {
        return 0;
    }
    const uint8_t *digest_info = digest_info_for(digest_len);
    if (digest_info == NULL) {
        return 0;
    }
    // Reject a signature numerically >= the modulus (RSAVP1 step 1), the
    // range rsa_vp1's contract leaves to its caller.
    if (greater_or_equal(sig, n, n_len)) {
        return 0;
    }

    // em = sig^65537 mod n as n_len bytes (I2OSP with k = n_len, RFC
    // 8017 §8.2.2 step 2), then the expected encoding at the same length.
    uint8_t em[MODULUS_MAX];
    rsa_vp1(n, n_len, sig, em);
    uint8_t expected[MODULUS_MAX];
    emsa_pkcs1_v1_5_encode(expected, n_len, digest_info, digest, digest_len);

    // Both operands are public, so a plain byte compare would be sound;
    // ct_memeq is the tree's one byte-equality function and costs nothing
    // here, so this follows rsa.c's final compare rather than adding a
    // second idiom.
    return (int)ct_memeq(em, expected, n_len);
}
