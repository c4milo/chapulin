// Holds the library's ML-DSA-87 signer, mldsa_signer.c, to every case of
// Wycheproof's two signing suites (docs/decisions.md 159). It reads
// bin/wycheproof_mldsa_sign_vectors.h, which test/gen_wycheproof.py writes.
//
// The seeded suite's cases expand the seed with mldsa87_keygen, and the
// public key must be the suite's. The unseeded suite's cases take the
// suite's expanded key. Each case then signs, and each valid case's
// signature must be the suite's byte for byte. Each invalid case must
// return 0 with sig zeroed: a context over 255 bytes, a key of the wrong
// length and a key whose s1 or s2 is out of range. A seed of the wrong
// length goes to x509_pem_read_mldsa87_pkcs8 inside a PKCS #8 seed form,
// the one path a seed takes in the library, which must refuse it.
//
// A hedged case signs through mldsa87_sign, the library's entry. A
// deterministic case, rnd of 32 zero bytes, signs through the test entry
// mldsa87_sign_any_rnd, because mldsa87_sign refuses zero rnd. A case that
// gives mu alone signs through mldsa87_sign_mu. CH_MLDSA_SIGN_TEST
// declares both test entries, and no library object is built with it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"

#include "mldsa.h"
#include "mldsa_signer.h"
#include "wycheproof_mldsa_sign_vectors.h"
#include "x509_pem.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int all_zero(const uint8_t *p, size_t n) {
    uint8_t any = 0;
    for (size_t i = 0; i < n; i++) {
        any |= p[i];
    }
    return any == 0;
}

// A PKCS #8 OneAsymmetricKey in the seed form (draft-ietf-lamps-dilithium-
// certificates): version 0, id-ml-dsa-87, and an OCTET STRING that holds
// the [0] seed. Every length here is under 128, so each header is 2 bytes.
static size_t seed_pkcs8(uint8_t out[64], const uint8_t *seed, size_t seed_len) {
    static const uint8_t head[] = {0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60,
                                   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};
    size_t body = sizeof head + 4 + seed_len;
    out[0] = 0x30;
    out[1] = (uint8_t)body;
    memcpy(out + 2, head, sizeof head);
    size_t at = 2 + sizeof head;
    out[at++] = 0x04;
    out[at++] = (uint8_t)(seed_len + 2);
    out[at++] = 0x80;
    out[at++] = (uint8_t)seed_len;
    memcpy(out + at, seed, seed_len);
    return at + seed_len;
}

// The key a case signs under: the seed's expansion or the suite's key.
// Returns 1 and points *sk at it, or 0 when the case's key must be refused
// before it signs, which is then the verdict the case requires.
static int case_key(size_t i, const uint8_t *key, const uint8_t *pk, uint8_t room[MLDSA87_SK_LEN],
                    uint8_t pk_room[MLDSA87_PK_LEN], const uint8_t **sk, size_t *sk_len) {
    if (wp_mldsa_library[i].suite == 1) {
        *sk = key;
        *sk_len = wp_mldsa_library[i].key_len;
        return 1;
    }
    if (wp_mldsa_library[i].key_len != MLDSA87_SEED_LEN) {
        uint8_t der[64];
        uint8_t seed[MLDSA87_SEED_LEN];
        const uint8_t *expanded = NULL;
        size_t der_len = seed_pkcs8(der, key, wp_mldsa_library[i].key_len);
        return x509_pem_read_mldsa87_pkcs8(der, der_len, seed, &expanded) == 1;
    }
    if (!mldsa87_keygen(room, pk_room, key)) {
        return 0;
    }
    *sk = room;
    *sk_len = MLDSA87_SK_LEN;
    return wp_mldsa_library[i].pk_len != MLDSA87_PK_LEN || memcmp(pk_room, pk, MLDSA87_PK_LEN) == 0;
}

static int sign_case(size_t i, uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len,
                     const uint8_t *pk, const uint8_t *rnd, const uint8_t *msg,
                     const uint8_t *ctx) {
    size_t pk_len = wp_mldsa_library[i].pk_len;
    size_t msg_len = wp_mldsa_library[i].msg_len;
    size_t ctx_len = wp_mldsa_library[i].ctx_len;
    if (wp_mldsa_library[i].by_mu) {
        return sk_len == MLDSA87_SK_LEN && pk_len == MLDSA87_PK_LEN &&
               mldsa87_sign_mu(sig, sk, pk, msg, rnd) != 0;
    }
    if (all_zero(rnd, MLDSA87_RND_LEN)) {
        return mldsa87_sign_any_rnd(sig, sk, sk_len, pk, pk_len, msg, msg_len, ctx, ctx_len, rnd);
    }
    return mldsa87_sign(sig, sk, sk_len, pk, pk_len, msg, msg_len, ctx, ctx_len, rnd);
}

int main(void) {
    static uint8_t room[MLDSA87_SK_LEN];
    static uint8_t pk_room[MLDSA87_PK_LEN];
    int failures = 0;
    size_t refused = 0;
    for (size_t i = 0; i < COUNT(wp_mldsa_library); i++) {
        const uint8_t *key = wp_mldsa_library_data + wp_mldsa_library[i].off;
        const uint8_t *pk = key + wp_mldsa_library[i].key_len;
        const uint8_t *rnd = pk + wp_mldsa_library[i].pk_len;
        const uint8_t *msg = rnd + MLDSA87_RND_LEN;
        const uint8_t *ctx = msg + wp_mldsa_library[i].msg_len;
        const uint8_t *want = ctx + wp_mldsa_library[i].ctx_len;
        const uint8_t *sk = NULL;
        size_t sk_len = 0;
        uint8_t sig[MLDSA87_SIG_LEN];
        memset(sig, 0xa5, sizeof sig);
        int ok;
        if (!case_key(i, key, pk, room, pk_room, &sk, &sk_len)) {
            ok = !wp_mldsa_library[i].valid;
        } else {
            int signed_ok = sign_case(i, sig, sk, sk_len, pk, rnd, msg, ctx);
            ok = wp_mldsa_library[i].valid
                     ? signed_ok == 1 && memcmp(sig, want, MLDSA87_SIG_LEN) == 0
                     : signed_ok == 0 && all_zero(sig, sizeof sig);
        }
        refused += !wp_mldsa_library[i].valid;
        if (!ok) {
            (void)fprintf(stderr, "FAIL mldsa-87 library signer %s tc%u\n",
                          wp_mldsa_library[i].suite ? "noseed" : "seed",
                          (unsigned)wp_mldsa_library[i].tc);
            failures++;
        }
    }
    if (failures > 0 || COUNT(wp_mldsa_library) != WP_MLDSA_LIBRARY_CASES) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("wycheproof mldsa-87 library signer: %zu cases, %zu refused as the suites "
                 "require, every signature matches (commit %.12s)\n",
                 COUNT(wp_mldsa_library), refused, WYCHEPROOF_COMMIT);
    return 0;
}
