// The x86-64 RSA signer's arm of the differential oracle: rsa_mont64_adx.c
// compiled over test/rsa_mont64_adx_model.h, as bin/rsa_mont64_adx_test
// compiles it, against spec/lean/Spec/RsaMont64Adx.lean in the same Lean spec
// process test/diff_test.c drives. That module models the rows, the square's
// doubling, the reduction and the final subtraction from the C on a Nat, and
// proves that the result is below m and is a b R^-1 mod m. These rows are what
// make those proofs about the C: each compares the words the C writes with the
// model's value, so an error in the transcription on either side fails a row
// (docs/decisions.md 183).
//
// Its own main, for bin/diff_x25519_adx's reason: only a unit that defines
// CH_RSA_MONT64_ADX_MODEL compiles the file on every host, and no row of
// bin/diff reads it. bin/rsa_mont64_adx_test holds the assembly to the model
// on a CPU with BMI2 and ADX.
//
// Each word count from 2 to 64 runs 10 random odd moduli with the top bit
// set, and under each the operands 0, 1, m - 1 and random values below m,
// through the multiplication and the square.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rsa_mont64.h"

#include "diff_driver.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// test/rsa_mont64_adx_model.c's names for rsa_mont64_adx.c's entries.
void rsa_mont64_adx_model_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                              const rsa_mont64_modulus *mod);
void rsa_mont64_adx_model_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod);

// The words of a value, top word first, as 8 * k big-endian bytes in hex.
static void words_hex(char *hex, const uint64_t *w, size_t k) {
    uint8_t bytes[CH_RSA_MODULUS_MAX];
    for (size_t i = 0; i < k; i++) {
        for (size_t j = 0; j < 8; j++) {
            bytes[8 * (k - 1 - i) + (7 - j)] = (uint8_t)(w[i] >> (8 * j));
        }
    }
    (void)hex_encode(hex, bytes, 8 * k);
}

// Operand x of shape s below mod: 0, 1, m - 1, then random values below m.
static void make_operand(uint64_t *x, const rsa_mont64_modulus *mod, unsigned s) {
    size_t k = mod->words;
    memset(x, 0, k * sizeof(uint64_t));
    if (s == 1) {
        x[0] = 1;
    } else if (s == 2) {
        memcpy(x, mod->m, k * sizeof(uint64_t));
        x[0] -= 1;
    } else if (s >= 3) {
        for (size_t i = 0; i < k; i++) {
            x[i] = rng_next();
        }
        x[k - 1] &= mod->m[k - 1] >> 1; // below m, whose top bit is set
    }
}

static void diff_pair(const rsa_mont64_modulus *mod, const char *m_hex, const uint64_t *x,
                      const uint64_t *y) {
    size_t k = mod->words;
    static char x_hex[2 * CH_RSA_MODULUS_MAX + 1];
    static char y_hex[2 * CH_RSA_MODULUS_MAX + 1];
    static char want[2 * CH_RSA_MODULUS_MAX + 1];
    static char cmd[8 * CH_RSA_MODULUS_MAX];
    uint64_t o[RSA_MONT64_WORDS_MAX];
    words_hex(x_hex, x, k);
    words_hex(y_hex, y, k);
    rsa_mont64_adx_model_mul(o, x, y, mod);
    words_hex(want, o, k);
    (void)snprintf(cmd, sizeof cmd, "rsa_adx_mul %zu %llu %s %s %s", k,
                   (unsigned long long)mod->m0inv, m_hex, x_hex, y_hex);
    expect(cmd, want);
    rsa_mont64_adx_model_square(o, x, mod);
    words_hex(want, o, k);
    (void)snprintf(cmd, sizeof cmd, "rsa_adx_square %zu %llu %s %s", k,
                   (unsigned long long)mod->m0inv, m_hex, x_hex);
    expect(cmd, want);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff rsa_mont64 adx: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    static rsa_mont64_modulus mod;
    static char m_hex[2 * CH_RSA_MODULUS_MAX + 1];
    uint8_t m[CH_RSA_MODULUS_MAX];
    uint64_t x[RSA_MONT64_WORDS_MAX];
    uint64_t y[RSA_MONT64_WORDS_MAX];
    for (size_t k = 2; k <= RSA_MONT64_WORDS_MAX; k++) {
        for (int c = 0; c < 10; c++) {
            rng_fill(m, 8 * k);
            m[0] |= 0x80;
            m[8 * k - 1] |= 1;
            rsa_mont64_modulus_init(&mod, m, 8 * k, 64 * k);
            words_hex(m_hex, mod.m, k);
            for (unsigned xs = 0; xs < 5; xs++) {
                for (unsigned ys = 0; ys < 5; ys++) {
                    make_operand(x, &mod, xs);
                    make_operand(y, &mod, ys);
                    diff_pair(&mod, m_hex, x, y);
                }
            }
        }
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff rsa_mont64 adx: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
