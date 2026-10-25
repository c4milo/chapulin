// ML-KEM-768 against known-answer vectors: keygen and encaps reproduce
// the reference bytes exactly, decaps round-trips, the ciphertext input
// check rejects a malformed key, and the implicit-reject path returns
// the reference shared secret on a tampered ciphertext. Its own binary,
// like drbg_test and sha3_test: the module stays testable without the
// rest of the stack, and only the KEX=pq build packages mlkem.c into
// the library object.
//
// Under -DCH_MLKEM_1024 it tests ML-KEM-1024 with no vector of its own:
// the three calls agree on fixed seeds, both keygen calls write one dk,
// a tampered ciphertext gives SHAKE256(z || c), and the modulus check
// refuses a bad ek. bin/wycheproof_mlkem1024_test holds the known
// answers, from the Wycheproof pin (docs/decisions.md 150).
#include <stdio.h>
#include <string.h>

#include "mlkem.h"
#include "test_widemul.h"
#ifndef CH_MLKEM_1024
#include "mlkem_vectors.h"
#endif

// Where FIPS 203's dk holds the ek and z.
#define TEST_DK_EK_AT ((size_t)MLKEM_K * 384)
#define TEST_DK_Z_AT (MLKEM_DK_LEN - 32)

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

#ifndef CH_MLKEM_1024
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
        CHECK(mlkem_encaps_derand(TEST_WIDEMUL, ct, ss, ek, mlk_kat_m[i]) == 0);
        CHECK(memcmp(ct, mlk_kat_ct[i], MLKEM_CT_LEN) == 0);
        CHECK(memcmp(ss, mlk_kat_K[i], MLKEM_SS_LEN) == 0);

        uint8_t ss2[MLKEM_SS_LEN];
        mlkem_decaps(TEST_WIDEMUL, ss2, ct, dk);
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
        CHECK(memcmp(dk2 + TEST_DK_EK_AT, mlk_kat_ek[i], MLKEM_EK_LEN) == 0);
    }
}

// The C2SP/CCTV authoritative decaps vector: decaps of a reference
// (dk, ct) yields the reference shared secret. Anchors the FO transform
// against the pq-crystals reference, not only kyber-py.
static void test_cctv_decaps(void) {
    uint8_t ss[MLKEM_SS_LEN];
    mlkem_decaps(TEST_WIDEMUL, ss, mlk_decaps_ct, mlk_decaps_dk);
    CHECK(memcmp(ss, mlk_decaps_ss, MLKEM_SS_LEN) == 0);
}

// CCTV's strcmp vector exercises the implicit-reject comparison with an
// embedded byte that a strcmp would stop at; a constant-time equality
// reads the whole ciphertext and returns the derived reject secret.
static void test_cctv_strcmp(void) {
    uint8_t ss[MLKEM_SS_LEN];
    mlkem_decaps(TEST_WIDEMUL, ss, mlk_strcmp_ct, mlk_strcmp_dk);
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
    mlkem_decaps(TEST_WIDEMUL, ss, ct, mlk_kat_dk[0]);
    CHECK(memcmp(ss, mlk_kat_K[0], MLKEM_SS_LEN) != 0);
    // The same tampered input is deterministic: two decaps agree.
    uint8_t ss2[MLKEM_SS_LEN];
    mlkem_decaps(TEST_WIDEMUL, ss2, ct, mlk_kat_dk[0]);
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
    CHECK(mlkem_encaps_derand(TEST_WIDEMUL, ct, ss, mlk_unlucky_ek, mlk_unlucky_m) == 0);
    CHECK(memcmp(ct, mlk_unlucky_c, MLKEM_CT_LEN) == 0);
    CHECK(memcmp(ss, mlk_unlucky_K, MLKEM_SS_LEN) == 0);
    uint8_t ss2[MLKEM_SS_LEN];
    mlkem_decaps(TEST_WIDEMUL, ss2, mlk_unlucky_c, mlk_unlucky_dk);
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
    CHECK(mlkem_encaps_derand(TEST_WIDEMUL, ct, ss, ek, mlk_kat_m[0]) != 0);
}

#else
// Each seed's bytes: byte j of seed s is s * 31 + j + tag.
static void fill_seed(uint8_t out[32], int s, uint8_t tag) {
    for (int j = 0; j < 32; j++) {
        out[j] = (uint8_t)(s * 31 + j + tag);
    }
}

// Under eight seeds the three calls agree: decaps recovers the secret
// encaps chose, and mlkem_keygen_dk writes mlkem_keygen_derand's dk with
// the ek at FIPS 203's dk + 1536 slice.
static void test_round_trips(void) {
    for (int s = 0; s < 8; s++) {
        uint8_t d[32];
        uint8_t z[32];
        uint8_t m[32];
        fill_seed(d, s, 0x10);
        fill_seed(z, s, 0x20);
        fill_seed(m, s, 0x30);
        static uint8_t ek[MLKEM_EK_LEN];
        static uint8_t dk[MLKEM_DK_LEN];
        static uint8_t dk2[MLKEM_DK_LEN];
        mlkem_keygen_derand(ek, dk, d, z);
        mlkem_keygen_dk(dk2, d, z);
        CHECK(memcmp(dk, dk2, MLKEM_DK_LEN) == 0);
        CHECK(memcmp(dk + TEST_DK_EK_AT, ek, MLKEM_EK_LEN) == 0);
        CHECK(memcmp(dk + TEST_DK_Z_AT, z, 32) == 0);
        uint8_t ct[MLKEM_CT_LEN];
        uint8_t ss[MLKEM_SS_LEN];
        uint8_t ss2[MLKEM_SS_LEN];
        CHECK(mlkem_encaps_derand(TEST_WIDEMUL, ct, ss, ek, m) == 0);
        mlkem_decaps(TEST_WIDEMUL, ss2, ct, dk);
        CHECK(memcmp(ss, ss2, MLKEM_SS_LEN) == 0);
    }
}

// A tampered ciphertext gives the implicit-reject secret, K_bar =
// SHAKE256(z || c, 32) (FIPS 203 Algorithm 18), computed here from z and
// the tampered c, and never the secret of the honest ciphertext.
static void test_implicit_reject(void) {
    uint8_t d[32];
    uint8_t z[32];
    uint8_t m[32];
    fill_seed(d, 9, 0x10);
    fill_seed(z, 9, 0x20);
    fill_seed(m, 9, 0x30);
    static uint8_t ek[MLKEM_EK_LEN];
    static uint8_t dk[MLKEM_DK_LEN];
    mlkem_keygen_derand(ek, dk, d, z);
    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ss[MLKEM_SS_LEN];
    CHECK(mlkem_encaps_derand(TEST_WIDEMUL, ct, ss, ek, m) == 0);
    // One byte of u and the last byte of v.
    const size_t at[2] = {5, MLKEM_CT_LEN - 1};
    for (size_t k = 0; k < 2; k++) {
        ct[at[k]] ^= 1;
        uint8_t got[MLKEM_SS_LEN];
        mlkem_decaps(TEST_WIDEMUL, got, ct, dk);
        uint8_t want[32];
        shake x;
        shake256_init(&x);
        shake_absorb(&x, z, 32);
        shake_absorb(&x, ct, MLKEM_CT_LEN);
        shake_squeeze(&x, want, 32);
        CHECK(memcmp(got, want, 32) == 0);
        CHECK(memcmp(got, ss, MLKEM_SS_LEN) != 0);
        ct[at[k]] ^= 1;
    }
}

// The encaps modulus check (FIPS 203 Section 7.2): a coefficient at or
// above q in the first and in the last poly of t-hat is refused. The last
// coefficient of the fourth poly sits in bytes 1534 and 1535.
static void test_encaps_rejects_bad_key(void) {
    uint8_t d[32];
    uint8_t z[32];
    uint8_t m[32];
    fill_seed(d, 3, 0x10);
    fill_seed(z, 3, 0x20);
    fill_seed(m, 3, 0x30);
    static uint8_t ek[MLKEM_EK_LEN];
    static uint8_t dk[MLKEM_DK_LEN];
    mlkem_keygen_derand(ek, dk, d, z);
    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ss[MLKEM_SS_LEN];
    CHECK(mlkem_encaps_derand(TEST_WIDEMUL, ct, ss, ek, m) == 0);
    const uint8_t first[2] = {ek[0], ek[1]};
    ek[0] = 0xff;
    ek[1] = 0xff;
    CHECK(mlkem_encaps_derand(TEST_WIDEMUL, ct, ss, ek, m) != 0);
    ek[0] = first[0];
    ek[1] = first[1];
    ek[TEST_DK_EK_AT - 2] = 0xff;
    ek[TEST_DK_EK_AT - 1] = 0xff;
    CHECK(mlkem_encaps_derand(TEST_WIDEMUL, ct, ss, ek, m) != 0);
}
#endif

// A host binary takes the ch_cfg.cpu value it runs under as its one
// argument (test/test_cpu.h); every other binary takes none.
int main(int argc, char **argv) {
    test_take_cpu(argc, argv);
#ifdef CH_MLKEM_1024
    test_round_trips();
    test_implicit_reject();
    test_encaps_rejects_bad_key();
#else
    test_kats();
    test_keygen_dk_matches();
    test_cctv_decaps();
    test_cctv_strcmp();
    test_cctv_unlucky();
    test_implicit_reject();
    test_encaps_rejects_bad_key();
#endif
    if (failures == 0) {
#ifdef CH_MLKEM_1024
        (void)printf("mlkem-1024: all tests passed\n");
#else
        (void)printf("mlkem: all tests passed\n");
#endif
    }
    return failures != 0;
}
