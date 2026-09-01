// Drives the real chapulin APIs over the Wycheproof (C2SP) vectors in
// bin/wycheproof_vectors.h: attack-derived inputs — small-order and
// twist points, signature malleability, tag truncation — that broke
// mature libraries. Valid cases must pass, invalid ones must be
// rejected, and "acceptable" (Wycheproof: the implementation's choice)
// is recorded either way, except zero-shared-secret x25519 cases, which
// TLS 1.3 requires the client to reject. Skips are reported, never
// silent: AEAD nonce sizes the fixed nonce[12] API cannot express, and
// HKDF cases outside the library's CH_ASSERT domain.
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    fprintf(stderr, "CH_ASSERT(%s) failed at %s:%d\n", cond, file, line);
    abort();
}

#include "aead.h"
#include "hkdf.h"
#include "p256.h"
#include "rsa.h"
#include "sha256.h"
#include "x25519.h"

#include "wycheproof_vectors.h"

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
        int match = wp_hkdf[i].okm_len == wp_hkdf[i].size &&
                    memcmp(out, okm, wp_hkdf[i].size) == 0;
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

static void run_ecdsa(void) {
    for (size_t i = 0; i < COUNT(wp_ecdsa); i++) {
        const uint8_t *pub = wp_ecdsa_data + wp_ecdsa[i].pub_off;
        const uint8_t *p = wp_ecdsa_data + wp_ecdsa[i].off;
        uint8_t hash[SHA256_LEN];
        sha256 s;
        sha256_init(&s);
        sha256_update(&s, p, wp_ecdsa[i].msg_len);
        sha256_final(&s, hash);
        int ok = p256_ecdsa_verify(pub, hash, p + wp_ecdsa[i].msg_len, wp_ecdsa[i].sig_len);
        if (ok != wp_ecdsa[i].valid) {
            fail("ecdsa", wp_ecdsa[i].tc, ok ? "invalid signature accepted" : "valid rejected");
        }
    }
    printf("wycheproof ecdsa-p256: %zu cases\n", COUNT(wp_ecdsa));
}

static void run_rsa(void) {
    for (size_t i = 0; i < COUNT(wp_rsa); i++) {
        const uint8_t *n = wp_rsa_data + wp_rsa[i].n_off;
        const uint8_t *p = wp_rsa_data + wp_rsa[i].off;
        uint8_t hash[SHA256_LEN];
        sha256 s;
        sha256_init(&s);
        sha256_update(&s, p, wp_rsa[i].msg_len);
        sha256_final(&s, hash);
        int ok = rsa_pss_verify(n, wp_rsa[i].n_len, hash, p + wp_rsa[i].msg_len,
                                wp_rsa[i].sig_len);
        if (ok != wp_rsa[i].valid) {
            fail("rsa-pss", wp_rsa[i].tc, ok ? "invalid signature accepted" : "valid rejected");
        }
    }
    printf("wycheproof rsa-pss: %zu cases\n", COUNT(wp_rsa));
}

int main(void) {
    printf("wycheproof vectors at commit %s\n", WYCHEPROOF_COMMIT);
    run_x25519();
    run_aead();
    run_hkdf();
    run_ecdsa();
    run_rsa();
    if (failures) {
        printf("wycheproof: %d FAILURES\n", failures);
        return 1;
    }
    printf("wycheproof: all suites passed\n");
    return 0;
}
