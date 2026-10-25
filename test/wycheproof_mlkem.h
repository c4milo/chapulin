// The three Wycheproof ML-KEM suites: keygen from a seed, encaps against
// a peer ek, and keygen then decaps of a ciphertext that may be tampered.
// wycheproof_test.c runs them at ML-KEM-768 and wycheproof_mlkem1024_test.c
// at ML-KEM-1024, each over the header test/gen_wycheproof.py writes for
// its parameter set. The includer defines fail(), COUNT and TEST_WIDEMUL,
// and includes mlkem.h and its vectors header first.
#ifndef CH_TEST_WYCHEPROOF_MLKEM_H
#define CH_TEST_WYCHEPROOF_MLKEM_H

#ifdef CH_MLKEM_1024
#define WP_MLKEM_SET "mlkem-1024"
#else
#define WP_MLKEM_SET "mlkem-768"
#endif

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
    printf("wycheproof %s keygen: %zu cases\n", WP_MLKEM_SET, COUNT(wp_mlkem_keygen));
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
        int rc = mlkem_encaps_derand(TEST_WIDEMUL, ct, ss, ek, m);
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
    printf("wycheproof %s encaps: %zu cases, %zu out-of-range ek rejected,"
           " %d skipped (ek lengths the fixed API cannot express)\n",
           WP_MLKEM_SET, COUNT(wp_mlkem_encaps), rejected, WP_MLKEM_ENCAPS_SKIPPED);
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
        mlkem_decaps(TEST_WIDEMUL, ss, c, dk);
        if (memcmp(ss, want_k, MLKEM_SS_LEN) != 0) {
            fail("mlkem", wp_mlkem[i].tc, "K mismatch");
        }
    }
    printf("wycheproof %s full: %zu cases, %d skipped"
           " (input lengths the fixed API cannot express)\n",
           WP_MLKEM_SET, COUNT(wp_mlkem), WP_MLKEM_SKIPPED);
}

#endif
