// ch_mldsa_key_from_pem (pem_files.h) against files that OpenSSL 3.5
// wrote, and the library signer over the key it expands
// (docs/decisions.md 159). The files are test/gen_pem_fixtures.py's:
//  - one key in the three forms that `openssl pkey` writes: both, the
//    default; seed-only; and priv-only, the expandedKey form;
//  - a certificate of that key, and a certificate of another key.
// The both form carries OpenSSL's expanded key, so the call reads it only
// when mldsa87_keygen writes the same 4,896 bytes from the seed. The seed
// form must give the same sk and pk. The expandedKey form, a file whose
// expanded key differs from its seed's by one byte, a leaf of another
// key, a P-256 key file, a cpu value the object refuses and a file one
// byte over the text cap are each refused with sk and pk zeroed. The text
// cap has its exact pair. A signature under the expanded key verifies
// under the leaf's key. Then the stack below each call holds no 8 bytes of
// the seed or of K, and no two coefficients of NTT(s1[0]), which key
// generation holds, or of NTT(t0[7]), which a round of signing holds
// last.
//
// The Makefile builds it as a ROLE=server device object with
// -DCH_SIGN_MLDSA, the define that commit 2 of stage 4 gives the
// PROFILE=cnsa2 server (bin/pem_files_mldsa_test).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "ct.h"
#include "mldsa.h"
#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"
#include "mldsa_signer.h"
#include "pem.h"
#include "pem_files.h"
#include "pem_fixtures.h"
#include "pem_fixtures_mldsa.h"
#include "x509_pem.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

static uint8_t sk[MLDSA87_SK_LEN];
static uint8_t pk[MLDSA87_PK_LEN];
static uint8_t first_sk[MLDSA87_SK_LEN];
static uint8_t first_pk[MLDSA87_PK_LEN];
static uint8_t file[CH_PEM_MLDSA_KEY_TEXT_MAX + 1];

static int key_zeroed(void) {
    uint8_t any = 0;
    for (size_t i = 0; i < sizeof sk; i++) {
        any |= sk[i];
    }
    for (size_t i = 0; i < sizeof pk; i++) {
        any |= pk[i];
    }
    return any == 0;
}

static __attribute__((noinline)) int key_of(uint32_t cpu, const uint8_t *pem, size_t pem_len,
                                            const uint8_t *leaf, size_t leaf_len) {
    memset(sk, 0xa5, sizeof sk);
    memset(pk, 0xa5, sizeof pk);
    return ch_mldsa_key_from_pem(cpu, pem, pem_len, leaf, leaf_len, sk, pk);
}

// The seed of the fixture key, read from the seed form's DER.
static void fixture_seed(uint8_t seed[32]) {
    static uint8_t der[CH_PEM_MLDSA_KEY_DER_MAX];
    wbuf w;
    wb_init(&w, der, sizeof der);
    const uint8_t *expanded = NULL;
    CHECK(pem_decode_one(pem_fixture_mldsa_seed, sizeof pem_fixture_mldsa_seed,
                         PEM_LABEL_PRIVATE_KEY, &w) == 1);
    CHECK(x509_pem_read_mldsa87_pkcs8(der, w.len, seed, &expanded) == 1 && expanded == NULL);
}

static void test_forms(void) {
    const uint8_t *leaf = pem_fixture_mldsa_leaf;
    size_t leaf_len = sizeof pem_fixture_mldsa_leaf;
    CHECK(key_of(0, pem_fixture_mldsa_both, sizeof pem_fixture_mldsa_both, leaf, leaf_len) ==
          CH_OK);
    memcpy(first_sk, sk, sizeof sk);
    memcpy(first_pk, pk, sizeof pk);
    CHECK(key_of(0, pem_fixture_mldsa_seed, sizeof pem_fixture_mldsa_seed, leaf, leaf_len) ==
          CH_OK);
    CHECK(memcmp(sk, first_sk, sizeof sk) == 0 && memcmp(pk, first_pk, sizeof pk) == 0);
    CHECK(key_of(0, pem_fixture_mldsa_expanded, sizeof pem_fixture_mldsa_expanded, leaf,
                 leaf_len) == CH_EINVAL &&
          key_zeroed());
    CHECK(key_of(0, pem_fixture_mldsa_both, sizeof pem_fixture_mldsa_both,
                 pem_fixture_mldsa_other_leaf, sizeof pem_fixture_mldsa_other_leaf) == CH_EINVAL &&
          key_zeroed());
    CHECK(key_of(0, pem_fixture_key_pkcs8, sizeof pem_fixture_key_pkcs8, leaf, leaf_len) ==
              CH_EINVAL &&
          key_zeroed());
    CHECK(key_of(1, pem_fixture_mldsa_both, sizeof pem_fixture_mldsa_both, leaf, leaf_len) ==
              CH_EINVAL &&
          key_zeroed());
    // A base64 character 3,000 bytes into the both form's text lies in the
    // expanded key, which starts 62 bytes into the DER. Another letter
    // there changes one of its bytes, and the call refuses the file.
    memcpy(file, pem_fixture_mldsa_both, sizeof pem_fixture_mldsa_both);
    file[3000] = file[3000] == 'A' ? 'B' : 'A';
    CHECK(key_of(0, file, sizeof pem_fixture_mldsa_both, leaf, leaf_len) == CH_EINVAL &&
          key_zeroed());
}

// CH_PEM_MLDSA_KEY_TEXT_MAX bytes read, and one more is refused.
static void test_text_cap(void) {
    CHECK(CH_PEM_MLDSA_KEY_TEXT_MAX == 9988);
    memcpy(file, pem_fixture_mldsa_both, sizeof pem_fixture_mldsa_both);
    memset(file + sizeof pem_fixture_mldsa_both, '\n', sizeof file - sizeof pem_fixture_mldsa_both);
    CHECK(key_of(0, file, CH_PEM_MLDSA_KEY_TEXT_MAX, pem_fixture_mldsa_leaf,
                 sizeof pem_fixture_mldsa_leaf) == CH_OK);
    CHECK(key_of(0, file, CH_PEM_MLDSA_KEY_TEXT_MAX + 1, pem_fixture_mldsa_leaf,
                 sizeof pem_fixture_mldsa_leaf) == CH_EINVAL &&
          key_zeroed());
}

static void test_signs(void) {
    static uint8_t sig[MLDSA87_SIG_LEN];
    const uint8_t rnd[MLDSA87_RND_LEN] = {1, 2, 3};
    const uint8_t msg[] = "the content CertificateVerify signs";
    CHECK(key_of(0, pem_fixture_mldsa_both, sizeof pem_fixture_mldsa_both, pem_fixture_mldsa_leaf,
                 sizeof pem_fixture_mldsa_leaf) == CH_OK);
    CHECK(mldsa87_sign(sig, sk, sizeof sk, pk, sizeof pk, msg, sizeof msg, NULL, 0, rnd) == 1);
    CHECK(mldsa87_verify(pk, sizeof pk, msg, sizeof msg, NULL, 0, sig, sizeof sig) == 1);
}

// The bytes the search reads below the caller: the call's frames, the key
// expansion's 10 kB among them, and the signer's 18 kB.
#define RESIDUE_BYTES 32768
static uint8_t residue[RESIDUE_BYTES];

static __attribute__((noinline)) void snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue);
}

static int residue_holds(const uint8_t *secret, size_t n) {
    for (size_t s = 0; s + 8 <= n; s += 4) {
        for (size_t i = 0; i + 8 <= RESIDUE_BYTES; i++) {
            if (memcmp(residue + i, secret + s, 8) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

// Whether the copy holds 8 bytes of p's coefficients at any 4-byte step:
// two coefficients of a polynomial the call held in the NTT domain.
static int residue_holds_poly(const mld_poly *p) {
    return residue_holds((const uint8_t *)p->coeffs, sizeof p->coeffs);
}

// NTT of the polynomial of sk at part, as the signer computes it.
static void transformed(mld_poly *p, const uint8_t *part, unsigned bits, int32_t offset) {
    mlds_unpack(p, part, bits, offset);
    mlds_poly_ntt(p);
}

static __attribute__((noinline)) int sign_call(uint8_t *sig) {
    const uint8_t rnd[MLDSA87_RND_LEN] = {9};
    return mldsa87_sign(sig, first_sk, sizeof first_sk, first_pk, sizeof first_pk, NULL, 0, NULL, 0,
                        rnd);
}

static void test_wipes(void) {
    const char *reason = stack_residue_unsearched();
    if (reason != NULL) {
        (void)printf("pem_files_mldsa_test: the stack is not searched: %s\n", reason);
        return;
    }
    static uint8_t seed[32];
    static uint8_t key[32];
    static mld_poly s1_hat;
    static mld_poly t0_hat;
    fixture_seed(seed);
    memcpy(key, first_sk + 32, sizeof key);
    // NTT(s1[0]), which key generation holds first, and NTT(t0[7]), which
    // a round of signing holds last.
    transformed(&s1_hat, first_sk + 128, 3, 2);
    transformed(&t0_hat, first_sk + 128 + 15 * 96 + 7 * 416, 13, 1 << 12);
    CHECK(key_of(0, pem_fixture_mldsa_both, sizeof pem_fixture_mldsa_both, pem_fixture_mldsa_leaf,
                 sizeof pem_fixture_mldsa_leaf) == CH_OK);
    snapshot();
    CHECK(!residue_holds(seed, sizeof seed) && !residue_holds(key, sizeof key));
    CHECK(!residue_holds_poly(&s1_hat));
    CHECK(key_of(0, pem_fixture_mldsa_both, sizeof pem_fixture_mldsa_both,
                 pem_fixture_mldsa_other_leaf, sizeof pem_fixture_mldsa_other_leaf) == CH_EINVAL);
    snapshot();
    CHECK(!residue_holds(seed, sizeof seed) && !residue_holds(key, sizeof key));
    CHECK(!residue_holds_poly(&s1_hat));
    static uint8_t sig[MLDSA87_SIG_LEN];
    CHECK(sign_call(sig) == 1);
    snapshot();
    CHECK(!residue_holds(key, sizeof key) && !residue_holds_poly(&t0_hat));
    ct_wipe(seed, sizeof seed);
    ct_wipe(&s1_hat, sizeof s1_hat);
    ct_wipe(&t0_hat, sizeof t0_hat);
}

int main(void) {
    test_forms();
    test_text_cap();
    test_signs();
    test_wipes();
    if (failures != 0) {
        (void)fprintf(stderr, "pem_files_mldsa_test: %d failure(s)\n", failures);
        return 1;
    }
    (void)printf("pem_files_mldsa_test: OpenSSL's both and seed forms expand to one key, every "
                 "refusal zeroes the rooms, the stack holds no seed: ok\n");
    return 0;
}
