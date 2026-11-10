// The long division of rsa_mont.c's host arm, rsa_mont_division.h, in the
// differential oracle: times_word_mod, times_word_mod_blocks and rsa_vp1 against
// spec/lean/Spec/RsaDivision.lean in the same Lean spec process
// test/diff_test.c drives. That module models a step of the division from
// the C and proves that it writes rem * 2^64 mod m, that the step in
// blocks writes the same value, and that the public operation, which
// computes no R^2, writes sig^65537 mod m. These rows make those proofs
// about the C: each compares the words the C writes with the model's
// value, so an error in the transcription on either side fails a row
// (docs/decisions.md 208).
//
// Its own main, for bin/diff_rsa_mont64_square's reason: it compiles
// rsa_mont.c with -DRSA_MONT64_BLOCKS=1 on every host, so every machine
// runs the step in blocks, and no row of bin/diff reads it. This unit
// includes rsa_mont.c, so it calls the static functions that file compiles.
//
// The step runs at 2 to 64 words, and in blocks at each multiple of 4,
// under random odd moduli with the top bit set, the modulus of all ones,
// one whose top word is 2^63 with ones below it, and one whose top word
// is 2^63 with zeros between it and a low word of 1. Under each, the
// remainders are 0, 1, m - 1, m's top word with zeros below it, m's top
// word less one with ones below it, and random values below m. The
// public operation runs under the same moduli with the bases 0, 1,
// m - 1, m, all ones and random values.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"

// rsa_mont.c's host arm, whose static functions the rows below call.
#include "rsa_mont.c"

#include "diff_driver.h"

#if !RSA_MONT64_BLOCKS
#error "compile with -DRSA_MONT64_BLOCKS=1"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// The n words of a value, top word first, as 8 * n big-endian bytes in hex.
static void words_hex(char *hex, const uint64_t *w, size_t n) {
    uint8_t bytes[CH_RSA_MODULUS_MAX];
    rsa_mont64_to_bytes(bytes, 8 * n, w);
    (void)hex_encode(hex, bytes, 8 * n);
}

// Modulus of shape s over k words: random odd with the top bit set, all
// ones, a top word of 2^63 with ones below it, and a top word of 2^63 with
// zeros between it and a low word of 1.
static void make_modulus(uint64_t *m, size_t k, unsigned s) {
    for (size_t i = 0; i < k; i++) {
        m[i] = s == 3 ? 0 : (s == 0 ? rng_next() : UINT64_MAX);
    }
    m[0] |= 1;
    m[k - 1] |= (uint64_t)1 << 63;
    if (s >= 2) {
        m[k - 1] = (uint64_t)1 << 63;
    }
}

// Remainder of shape s below m: 0, 1, m - 1, m's top word with zeros below
// it, m's top word less one with ones below it, then random values below
// m. The fourth takes the estimate 2^64 - 1.
static void make_remainder(uint64_t *rem, const uint64_t *m, size_t k, unsigned s) {
    memset(rem, 0, k * sizeof(uint64_t));
    if (s == 1) {
        rem[0] = 1;
    } else if (s == 2) {
        memcpy(rem, m, k * sizeof(uint64_t));
        rem[0] -= 1; // m is odd
    } else if (s == 3) {
        rem[k - 1] = m[k - 1];
    } else if (s == 4) {
        memset(rem, 0xff, k * sizeof(uint64_t));
        rem[k - 1] = m[k - 1] - 1;
    } else if (s >= 5) {
        for (size_t i = 0; i < k; i++) {
            rem[i] = rng_next();
        }
        rem[k - 1] %= m[k - 1]; // a top word below m's, so below m
    }
}

static void diff_step(const uint64_t *m, const char *m_hex, const uint64_t *rem, size_t k) {
    static char rem_hex[2 * CH_RSA_MODULUS_MAX + 1];
    static char want[2 * CH_RSA_MODULUS_MAX + 1];
    static char cmd[8 * CH_RSA_MODULUS_MAX];
    uint64_t out[RSA_MONT64_WORDS_MAX];
    words_hex(rem_hex, rem, k);
    memcpy(out, rem, k * sizeof(uint64_t));
    times_word_mod(out, m, k);
    words_hex(want, out, k);
    (void)snprintf(cmd, sizeof cmd, "rsa_division_step %zu %s %s", k, m_hex, rem_hex);
    expect(cmd, want);
    if (k % 4 != 0) {
        return;
    }
    uint64_t negated[RSA_MONT64_WORDS_MAX];
    uint64_t carry = 1;
    for (size_t j = 0; j < k; j++) {
        ct_u128 sum = (ct_u128)~m[j] + carry;
        negated[j] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    memcpy(out, rem, k * sizeof(uint64_t));
    times_word_mod_blocks(out, m, negated, k);
    words_hex(want, out, k);
    (void)snprintf(cmd, sizeof cmd, "rsa_division_step_blocks %zu %s %s", k, m_hex, rem_hex);
    expect(cmd, want);
}

// rsa_vp1 under the k-word modulus m and the base of shape s: 0, 1, m - 1,
// m, all ones, then random values of k words. The fourth and the fifth
// are at or above m, so the first subtraction runs.
static void diff_public(const uint64_t *m, const char *m_hex, size_t k, unsigned s) {
    static char sig_hex[2 * CH_RSA_MODULUS_MAX + 1];
    static char want[2 * CH_RSA_MODULUS_MAX + 1];
    static char cmd[8 * CH_RSA_MODULUS_MAX];
    uint8_t n[CH_RSA_MODULUS_MAX];
    uint8_t sig[CH_RSA_MODULUS_MAX];
    uint8_t em[CH_RSA_MODULUS_MAX];
    uint64_t base[RSA_MONT64_WORDS_MAX];
    make_remainder(base, m, k, s <= 2 ? s : 5);
    if (s == 3) {
        memcpy(base, m, k * sizeof(uint64_t));
    } else if (s == 4) {
        memset(base, 0xff, k * sizeof(uint64_t));
    } else if (s >= 5) {
        base[k - 1] = rng_next();
    }
    rsa_mont64_to_bytes(n, 8 * k, m);
    rsa_mont64_to_bytes(sig, 8 * k, base);
    rsa_mont64_modulus mod;
    rsa_mont64_modulus_load(&mod, n, 8 * k);
    rsa_vp1(n, 8 * k, sig, em);
    (void)hex_encode(sig_hex, sig, 8 * k);
    (void)hex_encode(want, em, 8 * k);
    (void)snprintf(cmd, sizeof cmd, "rsa_division_public %zu %llu %s %s", k,
                   (unsigned long long)mod.m0inv, m_hex, sig_hex);
    expect(cmd, want);
}

static void diff_modulus(size_t k, unsigned shape) {
    static char m_hex[2 * CH_RSA_MODULUS_MAX + 1];
    uint64_t m[RSA_MONT64_WORDS_MAX];
    uint64_t rem[RSA_MONT64_WORDS_MAX];
    make_modulus(m, k, shape);
    words_hex(m_hex, m, k);
    for (unsigned s = 0; s < 12; s++) {
        make_remainder(rem, m, k, s);
        diff_step(m, m_hex, rem, k);
    }
    for (unsigned s = 0; s < 8; s++) {
        diff_public(m, m_hex, k, s);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff rsa division: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    static const size_t WORDS[] = {2, 3, 4, 5, 8, 12, 16, 24, 31, 32, 33, 48, 64};
    for (size_t i = 0; i < sizeof WORDS / sizeof WORDS[0]; i++) {
        for (int c = 0; c < 3; c++) {
            diff_modulus(WORDS[i], 0);
        }
        for (unsigned shape = 1; shape < 4; shape++) {
            diff_modulus(WORDS[i], shape);
        }
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff rsa division: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
