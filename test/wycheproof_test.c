// Drives the real chapulin APIs over the Wycheproof (C2SP) vectors in
// bin/wycheproof_vectors.h: attack-derived inputs — small-order and
// twist points, signature malleability, tag truncation — that broke
// mature libraries, and for ML-KEM-768 the encapsulation keys with a
// coefficient at or above q that the FIPS 203 section 7.2 modulus
// check must refuse. Valid cases must pass, invalid ones must be
// rejected, and "acceptable" (Wycheproof: the implementation's choice)
// is recorded either way, except zero-shared-secret x25519 cases, which
// TLS 1.3 requires the client to reject, and the signature suites, where
// an acceptable case is a lax encoding the one-encoding verifiers must
// refuse. Skips are reported, never silent: AEAD nonce sizes the fixed
// nonce[12] API cannot express, HKDF cases outside the library's
// CH_ASSERT domain, and RSA PKCS#1 v1.5 groups with a public exponent
// other than the fixed 65537.
//
// The ECDSA arms cover the two digest-length mismatches FIPS 186-4
// section 6.4 defines, because a public chain can sign a P-384 key with
// SHA-256 or a P-256 key with SHA-512: the digest is an integer, so a
// digest shorter than the order is used whole and a longer one keeps
// its leftmost order-length bits. The RSA suites run up to RSA-4096:
// this binary builds with -DCH_RSA_MODULUS_MAX=512, the value rsa.h
// gives CH_RSA_MODULUS_MAX in the webpki build that
// verifies a public chain; the device builds stop at RSA-3072.
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"

// The AES-GCM arm only. A published suite fixes its own key, and INV-26
// keeps the two constructors in quic_aes.h the only public way to write
// an aes_public_key, so the suite reaches the cipher through
// quic_aes_block.h's two entries, which take plain bytes.
// quic_aes_key.h gives the type a body here, which INV-26 admits in a
// test. quic_aes.c, quic_gcm.c and the AES implementation the build
// picked are all linked.
#ifdef CH_TRANSPORT_QUIC
#include "quic_aes_block.h"
#include "quic_aes_key.h"
#include "quic_gcm.h"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    fprintf(stderr, "CH_ASSERT(%s) failed at %s:%d\n", cond, file, line);
    abort();
}

#include "aead.h"
#include "hkdf.h"
#include "mlkem.h"
#include "p256.h"
#include "p256_ecdh.h"
#include "p256_sign.h"
#include "p384.h"
#include "rsa.h"
#include "rsa_pkcs1.h"
#include "rsa_sign.h"
#include "sha256.h"
#include "sha512.h"
#include "x25519.h"

// rsa_sign.c reads the entropy hook for its salt. This binary never
// calls the encoder -- run_rsa_sign drives the exponentiation alone --
// but the object carries the reference, so the host hook comes in here
// as it does in every other test main.
#include "test_random.h"

#include "wycheproof_vectors.h"

// The RSA-4096 suites need the webpki bound; a narrower build would
// refuse every one of their cases at the size check and fail here.
_Static_assert(CH_RSA_MODULUS_MAX >= 512, "wycheproof_test builds with -DCH_RSA_MODULUS_MAX=512");

static int failures;

static void fail(const char *suite, uint32_t tc, const char *what) {
    printf("FAIL %s tc%" PRIu32 ": %s\n", suite, tc, what);
    failures++;
}

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static void run_x25519(void) {
    size_t rejected_zero = 0;
    size_t accepted_ok = 0;
    for (size_t i = 0; i < COUNT(wp_x25519); i++) {
        const uint8_t *p = wp_x25519_data + wp_x25519[i].off;
        const uint8_t *priv = p;
        const uint8_t *pub = p + 32;
        const uint8_t *shared = p + 64;
        uint8_t out[32];
        int ok = x25519(out, priv, pub);
        switch (wp_x25519[i].kind) {
        case 0: // valid: must accept and match
            if (!ok || memcmp(out, shared, 32) != 0) {
                fail("x25519", wp_x25519[i].tc, "valid case rejected or mismatched");
            }
            break;
        case 1: // zero shared secret: must reject
            if (ok) {
                fail("x25519", wp_x25519[i].tc, "zero shared secret accepted");
            } else {
                rejected_zero++;
            }
            break;
        default: // acceptable: either verdict, but a match if accepted
            if (ok) {
                if (memcmp(out, shared, 32) != 0) {
                    fail("x25519", wp_x25519[i].tc, "accepted with wrong shared secret");
                } else {
                    accepted_ok++;
                }
            }
            break;
        }
    }
    printf("wycheproof x25519: %zu cases, %zu zero-secret rejected, %zu acceptable matched\n",
           COUNT(wp_x25519), rejected_zero, accepted_ok);
}

static void run_aead(void) {
    for (size_t i = 0; i < COUNT(wp_aead); i++) {
        const uint8_t *p = wp_aead_data + wp_aead[i].off;
        const uint8_t *key = p;
        const uint8_t *iv = p + 32;
        const uint8_t *tag = p + 44;
        const uint8_t *aad = p + 60;
        const uint8_t *msg = aad + wp_aead[i].aad_len;
        const uint8_t *ct = msg + wp_aead[i].msg_len;
        size_t n = wp_aead[i].msg_len;
        // The generator skips anything longer, so this never trips; it is
        // a hard backstop because the vectors track upstream HEAD.
        if (n > 1024 || wp_aead[i].aad_len > 1024) {
            fail("aead", wp_aead[i].tc, "message exceeds the test buffer");
            continue;
        }
        uint8_t got_ct[1024];
        uint8_t got_tag[16];
        uint8_t got_pt[1024];
        if (wp_aead[i].valid) {
            aead_seal(key, iv, aad, wp_aead[i].aad_len, msg, n, got_ct, got_tag);
            if (memcmp(got_ct, ct, n) != 0 || memcmp(got_tag, tag, 16) != 0) {
                fail("aead", wp_aead[i].tc, "seal output differs from vector");
            }
            if (!aead_open(key, iv, aad, wp_aead[i].aad_len, ct, n, tag, got_pt) ||
                memcmp(got_pt, msg, n) != 0) {
                fail("aead", wp_aead[i].tc, "valid case failed to open");
            }
        } else {
            if (aead_open(key, iv, aad, wp_aead[i].aad_len, ct, n, tag, got_pt)) {
                fail("aead", wp_aead[i].tc, "invalid case accepted");
            }
        }
    }
    printf("wycheproof chacha20-poly1305: %zu cases, %d skipped (key/nonce/tag sizes the fixed"
           " API cannot express), %d skipped (over the 1 KB test buffer)\n",
           COUNT(wp_aead), WP_AEAD_SKIPPED, WP_AEAD_OVERSIZE);
}

// The AES-GCM suite, for quic_gcm.c. Guarded because only a
// -DCH_TRANSPORT_QUIC build compiles that file, and the generator emits
// the rows under the same guard, so the legs that build this file
// without the define read a header that declares nothing here.
//
// The key comes from the vector, so this builds an aes_public_key
// through the key schedule directly. INV-26 bounds which keys a library
// source may hand the AEAD and excludes `test` from the rule that holds
// it, for exactly this: a published suite fixes its own keys.
#ifdef CH_TRANSPORT_QUIC
static void run_aes_gcm(void) {
    for (size_t i = 0; i < COUNT(wp_aes_gcm); i++) {
        const uint8_t *p = wp_aes_gcm_data + wp_aes_gcm[i].off;
        const uint8_t *key = p;
        const uint8_t *iv = p + 16;
        const uint8_t *tag = p + 28;
        const uint8_t *aad = p + 44;
        const uint8_t *msg = aad + wp_aes_gcm[i].aad_len;
        const uint8_t *ct = msg + wp_aes_gcm[i].msg_len;
        size_t n = wp_aes_gcm[i].msg_len;
        // The generator skips anything longer, so this never trips; it is
        // a hard backstop because the vectors track upstream HEAD.
        if (n > 1024 || wp_aes_gcm[i].aad_len > 1024) {
            fail("aes_gcm", wp_aes_gcm[i].tc, "message exceeds the test buffer");
            continue;
        }
        aes_public_key k;
        memset(&k, 0, sizeof k);
        aes_expand_round_keys(key, k.key.round_keys);
        uint8_t got_ct[1024];
        uint8_t got_tag[16];
        uint8_t got_pt[1024];
        if (wp_aes_gcm[i].valid) {
            gcm_seal(&k, iv, aad, wp_aes_gcm[i].aad_len, msg, n, got_ct, got_tag);
            if (memcmp(got_ct, ct, n) != 0 || memcmp(got_tag, tag, 16) != 0) {
                fail("aes_gcm", wp_aes_gcm[i].tc, "seal output differs from vector");
            }
            if (!gcm_open(&k, iv, aad, wp_aes_gcm[i].aad_len, ct, n, tag, got_pt) ||
                memcmp(got_pt, msg, n) != 0) {
                fail("aes_gcm", wp_aes_gcm[i].tc, "valid case failed to open");
            }
        } else {
            if (gcm_open(&k, iv, aad, wp_aes_gcm[i].aad_len, ct, n, tag, got_pt)) {
                fail("aes_gcm", wp_aes_gcm[i].tc, "invalid case accepted");
            }
        }
    }
    printf("wycheproof aes-128-gcm: %zu cases, %d skipped (key/nonce/tag sizes the fixed"
           " API cannot express), %d skipped (over the 1 KB test buffer)\n",
           COUNT(wp_aes_gcm), WP_AES_GCM_SKIPPED, WP_AES_GCM_OVERSIZE);
}
#endif // CH_TRANSPORT_QUIC

static void run_hkdf(void) {
    for (size_t i = 0; i < COUNT(wp_hkdf); i++) {
        const uint8_t *p = wp_hkdf_data + wp_hkdf[i].off;
        const uint8_t *ikm = p;
        const uint8_t *salt = ikm + wp_hkdf[i].ikm_len;
        const uint8_t *info = salt + wp_hkdf[i].salt_len;
        const uint8_t *okm = info + wp_hkdf[i].info_len;
        uint8_t prk[SHA256_LEN];
        uint8_t out[8160];
        hkdf_extract(salt, wp_hkdf[i].salt_len, ikm, wp_hkdf[i].ikm_len, prk);
        hkdf_expand(prk, info, wp_hkdf[i].info_len, out, wp_hkdf[i].size);
        int match = wp_hkdf[i].okm_len == wp_hkdf[i].size && memcmp(out, okm, wp_hkdf[i].size) == 0;
        if (wp_hkdf[i].valid && !match) {
            fail("hkdf", wp_hkdf[i].tc, "valid case mismatched");
        }
        if (!wp_hkdf[i].valid && match) {
            fail("hkdf", wp_hkdf[i].tc, "invalid case matched");
        }
    }
    printf("wycheproof hkdf-sha256: %zu cases, %d skipped (outside the asserted domain;"
           " CH_ASSERT faults there instead of proceeding)\n",
           COUNT(wp_hkdf), WP_HKDF_SKIPPED);
}

// One signature verdict against the vector's, for every signature arm.
static void check_verdict(const char *suite, uint32_t tc, int ok, int valid) {
    if (ok != valid) {
        fail(suite, tc, ok ? "invalid signature accepted" : "valid rejected");
    }
}

#include "wycheproof_p256.h"

static void run_ecdsa_p384_sha384(void) {
    for (size_t i = 0; i < COUNT(wp_ecdsa_p384_sha384); i++) {
        const uint8_t *pub = wp_ecdsa_p384_sha384_data + wp_ecdsa_p384_sha384[i].pub_off;
        const uint8_t *p = wp_ecdsa_p384_sha384_data + wp_ecdsa_p384_sha384[i].off;
        uint8_t hash[SHA384_LEN];
        sha384_of(p, wp_ecdsa_p384_sha384[i].msg_len, hash);
        int ok = p384_ecdsa_verify(pub, hash, p + wp_ecdsa_p384_sha384[i].msg_len,
                                   wp_ecdsa_p384_sha384[i].sig_len);
        check_verdict("ecdsa-p384-sha384", wp_ecdsa_p384_sha384[i].tc, ok,
                      wp_ecdsa_p384_sha384[i].valid);
    }
    printf("wycheproof ecdsa-p384-sha384: %zu cases\n", COUNT(wp_ecdsa_p384_sha384));
}

// A 32-byte digest under a P-384 key. FIPS 186-4 section 6.4 reads the
// digest as an integer and uses it whole when it is shorter than the
// order, so the same integer written as 48 big-endian bytes is the
// SHA-256 output behind 16 zero bytes.
static void run_ecdsa_p384_sha256(void) {
    for (size_t i = 0; i < COUNT(wp_ecdsa_p384_sha256); i++) {
        const uint8_t *pub = wp_ecdsa_p384_sha256_data + wp_ecdsa_p384_sha256[i].pub_off;
        const uint8_t *p = wp_ecdsa_p384_sha256_data + wp_ecdsa_p384_sha256[i].off;
        uint8_t hash[SHA384_LEN] = {0};
        sha256_of(p, wp_ecdsa_p384_sha256[i].msg_len, hash + (SHA384_LEN - SHA256_LEN));
        int ok = p384_ecdsa_verify(pub, hash, p + wp_ecdsa_p384_sha256[i].msg_len,
                                   wp_ecdsa_p384_sha256[i].sig_len);
        check_verdict("ecdsa-p384-sha256", wp_ecdsa_p384_sha256[i].tc, ok,
                      wp_ecdsa_p384_sha256[i].valid);
    }
    printf("wycheproof ecdsa-p384-sha256: %zu cases\n", COUNT(wp_ecdsa_p384_sha256));
}

static void run_rsa(void) {
    for (size_t i = 0; i < COUNT(wp_rsa); i++) {
        const uint8_t *n = wp_rsa_data + wp_rsa[i].n_off;
        const uint8_t *p = wp_rsa_data + wp_rsa[i].off;
        uint8_t hash[SHA256_LEN];
        sha256_of(p, wp_rsa[i].msg_len, hash);
        int ok = rsa_pss_verify(n, wp_rsa[i].n_len, hash, p + wp_rsa[i].msg_len, wp_rsa[i].sig_len);
        check_verdict("rsa-pss", wp_rsa[i].tc, ok, wp_rsa[i].valid);
    }
    printf("wycheproof rsa-pss: %zu cases\n", COUNT(wp_rsa));
}

// The v1.5 suites for SHA-256 and SHA-384 in one arm; digest_len picks
// the hash, and with it the DigestInfo prefix rsa_pkcs1_verify expects.
static void run_rsa_pkcs1(void) {
    for (size_t i = 0; i < COUNT(wp_rsa_pkcs1); i++) {
        const uint8_t *n = wp_rsa_pkcs1_data + wp_rsa_pkcs1[i].n_off;
        const uint8_t *p = wp_rsa_pkcs1_data + wp_rsa_pkcs1[i].off;
        size_t digest_len = wp_rsa_pkcs1[i].digest_len;
        uint8_t digest[SHA384_LEN];
        if (digest_len == SHA256_LEN) {
            sha256_of(p, wp_rsa_pkcs1[i].msg_len, digest);
        } else if (digest_len == SHA384_LEN) {
            sha384_of(p, wp_rsa_pkcs1[i].msg_len, digest);
        } else {
            // The generator refuses any other hash, so this never trips;
            // it is a hard backstop because the vectors track upstream.
            fail("rsa-pkcs1", wp_rsa_pkcs1[i].tc, "digest length without a hash");
            continue;
        }
        int ok = rsa_pkcs1_verify(n, wp_rsa_pkcs1[i].n_len, digest, digest_len,
                                  p + wp_rsa_pkcs1[i].msg_len, wp_rsa_pkcs1[i].sig_len);
        check_verdict("rsa-pkcs1", wp_rsa_pkcs1[i].tc, ok, wp_rsa_pkcs1[i].valid);
    }
    printf("wycheproof rsa-pkcs1: %zu cases, %d skipped (a public exponent other than 65537)\n",
           COUNT(wp_rsa_pkcs1), WP_RSA_PKCS1_SKIPPED);
}

// The private exponentiation, the one arm here that signs rather than
// verifies. Wycheproof publishes no RSA-PSS generation vectors -- a PSS
// signature depends on a fresh salt, so there is no known answer -- so
// the generator reads the RSASSA-PKCS1-v1_5 generation suites, recovers
// each encoded message with the public exponent, and hands this loop the
// pair. RSASP1 is the same primitive under either padding: rsa_sp1 must
// turn that encoded message back into that signature, byte for byte.
//
// The key and the output are static: ch_rsa_priv is a kilobyte at this
// build's modulus bound, and the Cortex-M3 lane runs this binary.
static void run_rsa_sign(void) {
    static ch_rsa_priv key;
    static uint8_t sig[CH_RSA_MODULUS_MAX];
    for (size_t i = 0; i < COUNT(wp_rsa_sign); i++) {
        const uint8_t *p = wp_rsa_sign_data + wp_rsa_sign[i].off;
        size_t n_len = wp_rsa_sign[i].n_len;
        memcpy(key.n, p, n_len);
        memcpy(key.d, p + n_len, n_len);
        key.n_len = n_len;
        rsa_sp1(&key, p + 2 * n_len, sig);
        if (memcmp(sig, p + 3 * n_len, n_len) != 0) {
            fail("rsa-sign", wp_rsa_sign[i].tc, "signature differs from the vector");
        }
    }
    printf("wycheproof rsa-sign: %zu cases, %d skipped (past the per-size cap, or a key"
           " rsa_sign.c refuses)\n",
           COUNT(wp_rsa_sign), WP_RSA_SIGN_SKIPPED);
}

static void run_mlkem_keygen(void) {
    for (size_t i = 0; i < COUNT(wp_mlkem_keygen); i++) {
        const uint8_t *p = wp_mlkem_keygen_data + wp_mlkem_keygen[i].off;
        const uint8_t *d = p; // seed is d then z (FIPS 203 Algorithm 19)
        const uint8_t *z = p + 32;
        const uint8_t *want_ek = p + 64;
        const uint8_t *want_dk = p + 64 + MLKEM_EK_LEN;
        static uint8_t ek[MLKEM_EK_LEN], dk[MLKEM_DK_LEN];
        mlkem_keygen_derand(ek, dk, d, z);
        if (memcmp(ek, want_ek, MLKEM_EK_LEN) != 0) {
            fail("mlkem-keygen", wp_mlkem_keygen[i].tc, "ek mismatch");
        }
        if (memcmp(dk, want_dk, MLKEM_DK_LEN) != 0) {
            fail("mlkem-keygen", wp_mlkem_keygen[i].tc, "dk mismatch");
        }
    }
    printf("wycheproof mlkem-768 keygen: %zu cases\n", COUNT(wp_mlkem_keygen));
}

static void run_mlkem_encaps(void) {
    size_t rejected = 0;
    for (size_t i = 0; i < COUNT(wp_mlkem_encaps); i++) {
        const uint8_t *p = wp_mlkem_encaps_data + wp_mlkem_encaps[i].off;
        const uint8_t *m = p;
        const uint8_t *ek = p + 32;
        const uint8_t *want_ct = p + 32 + MLKEM_EK_LEN;
        const uint8_t *want_k = p + 32 + MLKEM_EK_LEN + MLKEM_CT_LEN;
        static uint8_t ct[MLKEM_CT_LEN], ss[MLKEM_SS_LEN];
        int rc = mlkem_encaps_derand(ct, ss, ek, m);
        if (wp_mlkem_encaps[i].valid) {
            if (rc != 0) {
                fail("mlkem-encaps", wp_mlkem_encaps[i].tc, "valid ek rejected");
            } else if (memcmp(ct, want_ct, MLKEM_CT_LEN) != 0 ||
                       memcmp(ss, want_k, MLKEM_SS_LEN) != 0) {
                fail("mlkem-encaps", wp_mlkem_encaps[i].tc, "ct or K mismatch");
            }
        } else if (rc == 0) {
            // A correct-length ek with a coefficient at or above q: the
            // FIPS 203 section 7.2 modulus check must refuse it.
            fail("mlkem-encaps", wp_mlkem_encaps[i].tc, "out-of-range ek accepted");
        } else {
            rejected++;
        }
    }
    printf("wycheproof mlkem-768 encaps: %zu cases, %zu out-of-range ek rejected,"
           " %d skipped (ek lengths the fixed API cannot express)\n",
           COUNT(wp_mlkem_encaps), rejected, WP_MLKEM_ENCAPS_SKIPPED);
}

static void run_mlkem_full(void) {
    for (size_t i = 0; i < COUNT(wp_mlkem); i++) {
        const uint8_t *p = wp_mlkem_data + wp_mlkem[i].off;
        const uint8_t *d = p;
        const uint8_t *z = p + 32;
        const uint8_t *want_ek = p + 64;
        const uint8_t *c = p + 64 + MLKEM_EK_LEN;
        const uint8_t *want_k = p + 64 + MLKEM_EK_LEN + MLKEM_CT_LEN;
        static uint8_t ek[MLKEM_EK_LEN], dk[MLKEM_DK_LEN];
        static uint8_t ss[MLKEM_SS_LEN];
        mlkem_keygen_derand(ek, dk, d, z);
        if (memcmp(ek, want_ek, MLKEM_EK_LEN) != 0) {
            fail("mlkem", wp_mlkem[i].tc, "ek mismatch");
            continue;
        }
        // K is the expected output either way: the real secret for an
        // honest ciphertext, the implicit-rejection secret for a
        // tampered one — decapsulation must not reveal which.
        mlkem_decaps(ss, c, dk);
        if (memcmp(ss, want_k, MLKEM_SS_LEN) != 0) {
            fail("mlkem", wp_mlkem[i].tc, "K mismatch");
        }
    }
    printf("wycheproof mlkem-768 full: %zu cases, %d skipped"
           " (input lengths the fixed API cannot express)\n",
           COUNT(wp_mlkem), WP_MLKEM_SKIPPED);
}

int main(void) {
    printf("wycheproof vectors at commit %s\n", WYCHEPROOF_COMMIT);
    run_x25519();
    run_ecdh_p256();
    run_aead();
#ifdef CH_TRANSPORT_QUIC
    run_aes_gcm();
#endif
    run_hkdf();
    run_ecdsa_p256_sha256();
    run_ecdsa_p256_sign();
    run_ecdsa_p384_sha384();
    run_ecdsa_p384_sha256();
    run_ecdsa_p256_sha512();
    run_rsa();
    run_rsa_pkcs1();
    run_rsa_sign();
    run_mlkem_keygen();
    run_mlkem_encaps();
    run_mlkem_full();
    if (failures) {
        printf("wycheproof: %d FAILURES\n", failures);
        return 1;
    }
    printf("wycheproof: all suites passed\n");
    return 0;
}
