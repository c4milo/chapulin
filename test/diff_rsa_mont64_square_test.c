// The blocks' square in the differential oracle: rsa_mont64_blocks.c's
// rsa_mont64_blocks_square against spec/lean/Spec/RsaMont64Square.lean in
// the same Lean spec process test/diff_test.c drives. That module models the
// words the C keeps for each row, 2a with a_i and a_{i+1} moved up one bit
// written over two of them, and the rows with the multiples of m between
// them, and proves that they give (a a + U m) / R, the value
// rsa_mont64_blocks_mul(o, a, a, mod) writes. These rows make those proofs
// about the C: each compares the words and the word above them that the C
// returns with the model's value, so an error in the transcription on either
// side fails a row (docs/decisions.md 192).
//
// Its own main, for bin/diff_rsa_mont64_adx's reason: it compiles the blocks
// with -DRSA_MONT64_BLOCKS=1 on every host, as bin/rsa_blocks_equiv_test
// does, and no row of bin/diff reads them.
//
// Each multiple of 4 from 4 to 64 words runs 10 random odd moduli with the
// top bit set and the modulus of all ones, and under each the operands 0, 1,
// m - 1, all ones under a top word one below m's, and random values below m.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rsa_mont64.h"
#include "rsa_mont64_blocks.h"

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
    uint8_t bytes[CH_RSA_MODULUS_MAX + 8];
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < 8; j++) {
            bytes[8 * (n - 1 - i) + (7 - j)] = (uint8_t)(w[i] >> (8 * j));
        }
    }
    (void)hex_encode(hex, bytes, 8 * n);
}

// Operand x of shape s below mod: 0, 1, m - 1, all ones under a top word one
// below m's, then random values below m.
static void make_operand(uint64_t *x, const rsa_mont64_modulus *mod, unsigned s) {
    size_t k = mod->words;
    memset(x, 0, k * sizeof(uint64_t));
    if (s == 1) {
        x[0] = 1;
    } else if (s == 2) {
        memcpy(x, mod->m, k * sizeof(uint64_t));
        x[0] -= 1;
    } else if (s == 3) {
        memset(x, 0xff, k * sizeof(uint64_t));
        x[k - 1] = mod->m[k - 1] - 1;
    } else if (s >= 4) {
        for (size_t i = 0; i < k; i++) {
            x[i] = rng_next();
        }
        x[k - 1] &= mod->m[k - 1] >> 1; // below m, whose top bit is set
    }
}

static void diff_square(const rsa_mont64_modulus *mod, const char *m_hex, const uint64_t *x) {
    size_t k = mod->words;
    static char x_hex[2 * CH_RSA_MODULUS_MAX + 1];
    static char want[2 * CH_RSA_MODULUS_MAX + 17];
    static char cmd[8 * CH_RSA_MODULUS_MAX];
    uint64_t o[RSA_MONT64_WORDS_MAX + 1];
    words_hex(x_hex, x, k);
    o[k] = rsa_mont64_blocks_square(o, x, mod);
    words_hex(want, o, k + 1);
    (void)snprintf(cmd, sizeof cmd, "rsa_blocks_square %zu %llu %s %s", k,
                   (unsigned long long)mod->m0inv, m_hex, x_hex);
    expect(cmd, want);
}

static void diff_modulus(const uint8_t *m, size_t k) {
    static rsa_mont64_modulus mod;
    static char m_hex[2 * CH_RSA_MODULUS_MAX + 1];
    uint64_t x[RSA_MONT64_WORDS_MAX];
    rsa_mont64_modulus_init(&mod, m, 8 * k, 64 * k);
    words_hex(m_hex, mod.m, k);
    for (unsigned s = 0; s < 8; s++) {
        make_operand(x, &mod, s);
        diff_square(&mod, m_hex, x);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff rsa_mont64 square: seed 0x%016llx\n",
                 (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    uint8_t m[CH_RSA_MODULUS_MAX];
    for (size_t k = 4; k <= RSA_MONT64_WORDS_MAX; k += 4) {
        for (int c = 0; c < 10; c++) {
            rng_fill(m, 8 * k);
            m[0] |= 0x80;
            m[8 * k - 1] |= 1;
            diff_modulus(m, k);
        }
        memset(m, 0xff, 8 * k);
        diff_modulus(m, k);
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff rsa_mont64 square: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
