// ML-KEM-768 against known-answer vectors: keygen and encaps reproduce
// the reference bytes exactly, decaps round-trips, the ciphertext input
// check rejects a malformed key, and the implicit-reject path returns
// the reference shared secret on a tampered ciphertext. Its own binary,
// like drbg_test and sha3_test: the module stays testable without the
// rest of the stack, and only the KEX=pq build packages mlkem.c into
// the library object.
#include <stdio.h>
#include <string.h>

#include "mlkem.h"
#include "mlkem_vectors.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// Every seed KAT: keygen produces the reference ek and dk, encaps
// produces the reference ct and shared secret, and decaps recovers it.
static void test_kats(void) {
    for (int i = 0; i < MLKEM_KAT_COUNT; i++) {
        uint8_t ek[MLKEM_EK_LEN];
        uint8_t dk[MLKEM_DK_LEN];
        mlkem_keygen_derand(ek, dk, mlk_kat_d[i], mlk_kat_z[i]);
        CHECK(memcmp(ek, mlk_kat_ek[i], MLKEM_EK_LEN) == 0);
        CHECK(memcmp(dk, mlk_kat_dk[i], MLKEM_DK_LEN) == 0);

        uint8_t ct[MLKEM_CT_LEN];
        uint8_t ss[MLKEM_SS_LEN];
        CHECK(mlkem_encaps_derand(ct, ss, ek, mlk_kat_m[i]) == 0);
        CHECK(memcmp(ct, mlk_kat_ct[i], MLKEM_CT_LEN) == 0);
        CHECK(memcmp(ss, mlk_kat_K[i], MLKEM_SS_LEN) == 0);

        uint8_t ss2[MLKEM_SS_LEN];
        mlkem_decaps(ss2, ct, dk);
        CHECK(memcmp(ss2, mlk_kat_K[i], MLKEM_SS_LEN) == 0);
    }
}

// mlkem_keygen_dk writes the same dk as mlkem_keygen_derand, with the
// ek readable at the dk + 1152 slice (FIPS 203's own dk layout).
static void test_keygen_dk_matches(void) {
    for (int i = 0; i < MLKEM_KAT_COUNT; i++) {
        uint8_t dk2[MLKEM_DK_LEN];
        mlkem_keygen_dk(dk2, mlk_kat_d[i], mlk_kat_z[i]);
        CHECK(memcmp(dk2, mlk_kat_dk[i], MLKEM_DK_LEN) == 0);
        CHECK(memcmp(dk2 + 1152, mlk_kat_ek[i], MLKEM_EK_LEN) == 0);
    }
}

// The C2SP/CCTV authoritative decaps vector: decaps of a reference
// (dk, ct) yields the reference shared secret. Anchors the FO transform
// against the pq-crystals reference, not only kyber-py.
static void test_cctv_decaps(void) {
    uint8_t ss[MLKEM_SS_LEN];
    mlkem_decaps(ss, mlk_decaps_ct, mlk_decaps_dk);
    CHECK(memcmp(ss, mlk_decaps_ss, MLKEM_SS_LEN) == 0);
}

// CCTV's strcmp vector exercises the implicit-reject comparison with an
// embedded byte that a strcmp would stop at; a constant-time equality
// reads the whole ciphertext and returns the derived reject secret.
static void test_cctv_strcmp(void) {
    uint8_t ss[MLKEM_SS_LEN];
    mlkem_decaps(ss, mlk_strcmp_ct, mlk_strcmp_dk);
    CHECK(memcmp(ss, mlk_strcmp_ss, MLKEM_SS_LEN) == 0);
}

// A tampered ciphertext must not recover the shared secret, and decaps
// must still return a defined 32-byte value (implicit reject), never
// fault or leak which check failed.
static void test_implicit_reject(void) {
    uint8_t ct[MLKEM_CT_LEN];
    memcpy(ct, mlk_kat_ct[0], MLKEM_CT_LEN);
    ct[5] ^= 1;
    uint8_t ss[MLKEM_SS_LEN];
    mlkem_decaps(ss, ct, mlk_kat_dk[0]);
    CHECK(memcmp(ss, mlk_kat_K[0], MLKEM_SS_LEN) != 0);
    // The same tampered input is deterministic: two decaps agree.
    uint8_t ss2[MLKEM_SS_LEN];
    mlkem_decaps(ss2, ct, mlk_kat_dk[0]);
    CHECK(memcmp(ss, ss2, MLKEM_SS_LEN) == 0);
}

// CCTV's unluckysample vectors: the ek's embedded rho forces SampleNTT
// past 575 XOF bytes (the read cap sits at 1536). Encaps from the ek
// and decaps from the dk both re-run that sampling; the keygen
// direction is unusable because the file derives rho without the
// FIPS 203 final domain byte, which the vectors header states.
static void test_cctv_unlucky(void) {
    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ss[MLKEM_SS_LEN];
    CHECK(mlkem_encaps_derand(ct, ss, mlk_unlucky_ek, mlk_unlucky_m) == 0);
    CHECK(memcmp(ct, mlk_unlucky_c, MLKEM_CT_LEN) == 0);
    CHECK(memcmp(ss, mlk_unlucky_K, MLKEM_SS_LEN) == 0);
    uint8_t ss2[MLKEM_SS_LEN];
    mlkem_decaps(ss2, mlk_unlucky_c, mlk_unlucky_dk);
    CHECK(memcmp(ss2, mlk_unlucky_K, MLKEM_SS_LEN) == 0);
}

// The encaps modulus check (FIPS 203 Section 7.2): an encapsulation key
// whose coefficients do not survive a ByteDecode/ByteEncode round trip
// is rejected. Setting the top coefficient bytes to 0xff overflows q.
static void test_encaps_rejects_bad_key(void) {
    uint8_t ek[MLKEM_EK_LEN];
    memcpy(ek, mlk_kat_ek[0], MLKEM_EK_LEN);
    ek[0] = 0xff;
    ek[1] = 0xff;
    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ss[MLKEM_SS_LEN];
    CHECK(mlkem_encaps_derand(ct, ss, ek, mlk_kat_m[0]) != 0);
}

int main(void) {
    test_kats();
    test_keygen_dk_matches();
    test_cctv_decaps();
    test_cctv_strcmp();
    test_cctv_unlucky();
    test_implicit_reject();
    test_encaps_rejects_bad_key();
    if (failures == 0) {
        (void)printf("mlkem: all tests passed\n");
    }
    return failures != 0;
}
