// ML-KEM-768 differential section: keygen, encaps, and decaps against
// the Lean spec on random seeds, plus the two disagreement-prone
// paths — a tampered ciphertext (both sides must derive the same
// implicit-reject secret) and an encapsulation key that fails the
// FIPS 203 modulus check (both sides must refuse).
// Included by test/diff_test.c after diff_driver.h (single translation unit).
#ifndef CH_DIFFMLKEM_H
#define CH_DIFFMLKEM_H

#include "mlkem.h"

static void diff_mlkem_keygen(void) {
    for (int i = 0; i < 12; i++) {
        uint8_t d[32];
        uint8_t z[32];
        rng_fill(d, sizeof d);
        rng_fill(z, sizeof z);
        uint8_t ek[MLKEM_EK_LEN];
        uint8_t dk[MLKEM_DK_LEN];
        mlkem_keygen_derand(ek, dk, d, z);
        char d_hex[65];
        (void)hex_encode(d_hex, d, sizeof d);
        char z_hex[65];
        (void)hex_encode(z_hex, z, sizeof z);
        static char want[2 * MLKEM_EK_LEN + 2 * MLKEM_DK_LEN + 2];
        size_t at = hex_encode(want, ek, sizeof ek);
        want[at] = ' ';
        (void)hex_encode(want + at + 1, dk, sizeof dk);
        char cmd[192];
        (void)snprintf(cmd, sizeof cmd, "mlkem_keygen %s %s", d_hex, z_hex);
        expect(cmd, want);
    }
}

static void diff_mlkem_encaps(void) {
    for (int i = 0; i < 12; i++) {
        uint8_t d[32];
        uint8_t z[32];
        uint8_t m[32];
        rng_fill(d, sizeof d);
        rng_fill(z, sizeof z);
        rng_fill(m, sizeof m);
        uint8_t ek[MLKEM_EK_LEN];
        uint8_t dk[MLKEM_DK_LEN];
        mlkem_keygen_derand(ek, dk, d, z);
        uint8_t ct[MLKEM_CT_LEN];
        uint8_t ss[MLKEM_SS_LEN];
        if (mlkem_encaps_derand(ct, ss, ek, m) != 0) {
            die("mlkem_encaps refused a key its own keygen produced");
        }
        static char ek_hex[2 * MLKEM_EK_LEN + 1];
        (void)hex_encode(ek_hex, ek, sizeof ek);
        char m_hex[65];
        (void)hex_encode(m_hex, m, sizeof m);
        static char want[2 * MLKEM_CT_LEN + 2 * MLKEM_SS_LEN + 2];
        size_t at = hex_encode(want, ct, sizeof ct);
        want[at] = ' ';
        (void)hex_encode(want + at + 1, ss, sizeof ss);
        static char cmd[2 * MLKEM_EK_LEN + 128];
        (void)snprintf(cmd, sizeof cmd, "mlkem_encaps %s %s", ek_hex, m_hex);
        expect(cmd, want);
    }
    // The modulus check: a coefficient encoding past q must be refused
    // by both sides. 0xffff in the first coefficient bytes overflows q.
    {
        uint8_t d[32] = {1};
        uint8_t z[32] = {2};
        uint8_t m[32] = {3};
        uint8_t ek[MLKEM_EK_LEN];
        uint8_t dk[MLKEM_DK_LEN];
        mlkem_keygen_derand(ek, dk, d, z);
        ek[0] = 0xff;
        ek[1] = 0xff;
        uint8_t ct[MLKEM_CT_LEN];
        uint8_t ss[MLKEM_SS_LEN];
        if (mlkem_encaps_derand(ct, ss, ek, m) == 0) {
            die("mlkem_encaps accepted an off-modulus key");
        }
        static char ek_hex[2 * MLKEM_EK_LEN + 1];
        (void)hex_encode(ek_hex, ek, sizeof ek);
        char m_hex[65];
        (void)hex_encode(m_hex, m, sizeof m);
        static char cmd[2 * MLKEM_EK_LEN + 128];
        (void)snprintf(cmd, sizeof cmd, "mlkem_encaps %s %s", ek_hex, m_hex);
        expect(cmd, "FAIL");
    }
}

static void diff_mlkem_decaps(void) {
    for (int i = 0; i < 12; i++) {
        uint8_t d[32];
        uint8_t z[32];
        uint8_t m[32];
        rng_fill(d, sizeof d);
        rng_fill(z, sizeof z);
        rng_fill(m, sizeof m);
        uint8_t ek[MLKEM_EK_LEN];
        uint8_t dk[MLKEM_DK_LEN];
        mlkem_keygen_derand(ek, dk, d, z);
        uint8_t ct[MLKEM_CT_LEN];
        uint8_t ss[MLKEM_SS_LEN];
        if (mlkem_encaps_derand(ct, ss, ek, m) != 0) {
            die("mlkem_encaps refused a key its own keygen produced");
        }
        // Odd rows tamper the ciphertext, so the row compares the
        // implicit-reject secret instead of the round-trip secret.
        if ((i & 1) != 0) {
            ct[i] ^= 1;
        }
        uint8_t out[MLKEM_SS_LEN];
        mlkem_decaps(out, ct, dk);
        static char dk_hex[2 * MLKEM_DK_LEN + 1];
        (void)hex_encode(dk_hex, dk, sizeof dk);
        static char ct_hex[2 * MLKEM_CT_LEN + 1];
        (void)hex_encode(ct_hex, ct, sizeof ct);
        char want[2 * MLKEM_SS_LEN + 1];
        (void)hex_encode(want, out, sizeof out);
        static char cmd[2 * MLKEM_DK_LEN + 2 * MLKEM_CT_LEN + 128];
        (void)snprintf(cmd, sizeof cmd, "mlkem_decaps %s %s", dk_hex, ct_hex);
        expect(cmd, want);
    }
}

#endif
