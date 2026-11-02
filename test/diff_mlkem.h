// ML-KEM differential section: keygen, encaps, and decaps against
// the Lean spec on random seeds, plus the two disagreement-prone
// paths — a tampered ciphertext (both sides must derive the same
// implicit-reject secret) and an encapsulation key that fails the
// FIPS 203 modulus check (both sides must refuse).
// Included by test/diff_test.c after diff_driver.h (single translation unit).
#ifndef CH_DIFFMLKEM_H
#define CH_DIFFMLKEM_H

#include "mlkem.h"
#include "test_widemul.h"

// Each row runs at the rank its caller names, through the _rank calls:
// bin/diff at ML-KEM-768, bin/diff_mlkem1024 (-DCH_MLKEM_1024) at
// ML-KEM-1024 (docs/decisions.md 150), and bin/diff_mlkem_two_ranks
// (-DCH_MLKEM_TWO_RANKS) at both (docs/decisions.md 177). The oracle's
// commands for each rank.
static const char *diff_mlkem_command(unsigned rank) {
    return rank == MLKEM_RANK_1024 ? "mlkem1024" : "mlkem";
}

static void diff_mlkem_keygen(unsigned rank) {
    for (int i = 0; i < 12; i++) {
        uint8_t d[32];
        uint8_t z[32];
        rng_fill(d, sizeof d);
        rng_fill(z, sizeof z);
        uint8_t ek[MLKEM_EK_LEN_MAX];
        uint8_t dk[MLKEM_DK_LEN_MAX];
        mlkem_keygen_derand_rank(rank, ek, dk, d, z);
        char d_hex[65];
        (void)hex_encode(d_hex, d, sizeof d);
        char z_hex[65];
        (void)hex_encode(z_hex, z, sizeof z);
        static char want[2 * MLKEM_EK_LEN_MAX + 2 * MLKEM_DK_LEN_MAX + 2];
        size_t at = hex_encode(want, ek, mlkem_ek_len(rank));
        want[at] = ' ';
        (void)hex_encode(want + at + 1, dk, mlkem_dk_len(rank));
        char cmd[192];
        (void)snprintf(cmd, sizeof cmd, "%s_keygen %s %s", diff_mlkem_command(rank), d_hex, z_hex);
        expect(cmd, want);
    }
}

static void diff_mlkem_encaps(unsigned rank) {
    for (int i = 0; i < 12; i++) {
        uint8_t d[32];
        uint8_t z[32];
        uint8_t m[32];
        rng_fill(d, sizeof d);
        rng_fill(z, sizeof z);
        rng_fill(m, sizeof m);
        uint8_t ek[MLKEM_EK_LEN_MAX];
        uint8_t dk[MLKEM_DK_LEN_MAX];
        mlkem_keygen_derand_rank(rank, ek, dk, d, z);
        uint8_t ct[MLKEM_CT_LEN_MAX];
        uint8_t ss[MLKEM_SS_LEN];
        if (mlkem_encaps_derand_rank(TEST_WIDEMUL, rank, ct, ss, ek, m) != 0) {
            die("mlkem_encaps refused a key its own keygen produced");
        }
        static char ek_hex[2 * MLKEM_EK_LEN_MAX + 1];
        (void)hex_encode(ek_hex, ek, mlkem_ek_len(rank));
        char m_hex[65];
        (void)hex_encode(m_hex, m, sizeof m);
        static char want[2 * MLKEM_CT_LEN_MAX + 2 * MLKEM_SS_LEN + 2];
        size_t at = hex_encode(want, ct, mlkem_ct_len(rank));
        want[at] = ' ';
        (void)hex_encode(want + at + 1, ss, sizeof ss);
        static char cmd[2 * MLKEM_EK_LEN_MAX + 128];
        (void)snprintf(cmd, sizeof cmd, "%s_encaps %s %s", diff_mlkem_command(rank), ek_hex, m_hex);
        expect(cmd, want);
    }
    // The modulus check: a coefficient encoding past q must be refused
    // by both sides. 0xffff in the first coefficient bytes overflows q.
    {
        uint8_t d[32] = {1};
        uint8_t z[32] = {2};
        uint8_t m[32] = {3};
        uint8_t ek[MLKEM_EK_LEN_MAX];
        uint8_t dk[MLKEM_DK_LEN_MAX];
        mlkem_keygen_derand_rank(rank, ek, dk, d, z);
        ek[0] = 0xff;
        ek[1] = 0xff;
        uint8_t ct[MLKEM_CT_LEN_MAX];
        uint8_t ss[MLKEM_SS_LEN];
        if (mlkem_encaps_derand_rank(TEST_WIDEMUL, rank, ct, ss, ek, m) == 0) {
            die("mlkem_encaps accepted an off-modulus key");
        }
        static char ek_hex[2 * MLKEM_EK_LEN_MAX + 1];
        (void)hex_encode(ek_hex, ek, mlkem_ek_len(rank));
        char m_hex[65];
        (void)hex_encode(m_hex, m, sizeof m);
        static char cmd[2 * MLKEM_EK_LEN_MAX + 128];
        (void)snprintf(cmd, sizeof cmd, "%s_encaps %s %s", diff_mlkem_command(rank), ek_hex, m_hex);
        expect(cmd, "FAIL");
    }
}

static void diff_mlkem_decaps(unsigned rank) {
    for (int i = 0; i < 12; i++) {
        uint8_t d[32];
        uint8_t z[32];
        uint8_t m[32];
        rng_fill(d, sizeof d);
        rng_fill(z, sizeof z);
        rng_fill(m, sizeof m);
        uint8_t ek[MLKEM_EK_LEN_MAX];
        uint8_t dk[MLKEM_DK_LEN_MAX];
        mlkem_keygen_derand_rank(rank, ek, dk, d, z);
        uint8_t ct[MLKEM_CT_LEN_MAX];
        uint8_t ss[MLKEM_SS_LEN];
        if (mlkem_encaps_derand_rank(TEST_WIDEMUL, rank, ct, ss, ek, m) != 0) {
            die("mlkem_encaps refused a key its own keygen produced");
        }
        // Odd rows tamper the ciphertext, so the row compares the
        // implicit-reject secret instead of the round-trip secret.
        if ((i & 1) != 0) {
            ct[i] ^= 1;
        }
        uint8_t out[MLKEM_SS_LEN];
        mlkem_decaps_rank(TEST_WIDEMUL, rank, out, ct, dk);
        static char dk_hex[2 * MLKEM_DK_LEN_MAX + 1];
        (void)hex_encode(dk_hex, dk, mlkem_dk_len(rank));
        static char ct_hex[2 * MLKEM_CT_LEN_MAX + 1];
        (void)hex_encode(ct_hex, ct, mlkem_ct_len(rank));
        char want[2 * MLKEM_SS_LEN + 1];
        (void)hex_encode(want, out, sizeof out);
        static char cmd[2 * MLKEM_DK_LEN_MAX + 2 * MLKEM_CT_LEN_MAX + 128];
        (void)snprintf(cmd, sizeof cmd, "%s_decaps %s %s", diff_mlkem_command(rank), dk_hex,
                       ct_hex);
        expect(cmd, want);
    }
}

#endif
