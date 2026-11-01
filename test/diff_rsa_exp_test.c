// The DNSSEC exponent's arm of the differential oracle:
// rsa_mont64_public_exp, the public operation with a DNSKEY's own
// exponent, against the same Lean spec process test/diff_test.c drives.
// spec/lean/Spec/RsaExp.lean models the C's schedule over ZMod m, with the
// Montgomery product as a * b / R, and proves that it computes x^e for
// every odd e of at least 3. These rows are what make that proof about the
// C: an error in the transcription on either side fails a row.
//
// Its own main, as test/diff_rsa_avx2_test.c is: the call compiles only in
// a host object built with -DCH_DNSSEC, and no file bin/diff compiles
// defines it.
//
// At each modulus length in LENGTHS, which holds every length of one and
// two words and the lengths around the DNSSEC floor and the 512-byte
// bound, under four kinds of modulus, the bases 0, 1, m - 1 and a random
// one below m, each raised to the exponents in EXPONENTS and to random odd
// ones of a random bit length.
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

_Static_assert(CH_RSA_MODULUS_MAX == 512, "bin/diff_rsa_exp builds at the 512-byte bound");

#define LEN_MAX CH_RSA_MODULUS_MAX
#define HEX_LEN(n) (2 * (n) + 1)
#define COMMAND_SIZE (64 + 2 * HEX_LEN(LEN_MAX))

static const size_t LENGTHS[] = {1,  2,  3,  4,  5,  6,   7,   8,   9,   10,  11,  12,  13,
                                 14, 15, 16, 63, 64, 65,  128, 129, 256, 384, 511, 512};

static const uint64_t EXPONENTS[] = {
    3, 5, 7, 17, 65537, UINT64_C(0x100000001), UINT64_C(0x8000000000000001), UINT64_MAX,
};

// The random odd exponents each base takes beside EXPONENTS.
#define RANDOM_EXPONENTS 4

// The kinds of modulus: random bytes with the low bit set and a top byte
// that is not zero, all ones, 2^(8 len - 1) + 1, and a top byte of 1, the
// shortest bit length the length holds. A modulus of one byte stays above
// 1, which publicExp_eq's guard asks for.
enum { MODULUS_KINDS = 4 };
static void modulus_of_kind(uint8_t *m, size_t len, int kind) {
    memset(m, 0, len);
    switch (kind) {
    case 0:
        rng_fill(m, len);
        m[0] |= (uint8_t)(1 + rng_below(255));
        break;
    case 1:
        memset(m, 0xff, len);
        break;
    case 2:
        m[0] = 0x80;
        break;
    default:
        m[0] = 1;
        break;
    }
    m[len - 1] |= 1;
    if (len == 1 && m[0] == 1) {
        m[0] = 3;
    }
}

// The bit length of a modulus whose top byte is not zero.
static size_t bit_length(const uint8_t *m, size_t len) {
    size_t bits = 8 * len;
    for (uint8_t top = m[0]; (top & 0x80) == 0; top = (uint8_t)(top << 1)) {
        bits--;
    }
    return bits;
}

// A random odd exponent of 2 to 64 bits.
static uint64_t random_exponent(void) {
    unsigned bits = 2 + (unsigned)rng_below(63);
    uint64_t e = rng_next();
    if (bits < 64) {
        e &= (UINT64_C(1) << bits) - 1;
    }
    return e | (UINT64_C(1) << (bits - 1)) | 1;
}

static void diff_one(const uint8_t *m, size_t len, const rsa_mont64_modulus *mod,
                     const uint8_t *base, uint64_t e) {
    static char cmd[COMMAND_SIZE];
    static char want[HEX_LEN(LEN_MAX)];
    uint8_t out[LEN_MAX];
    rsa_mont64_public_exp(out, base, len, mod, e);
    size_t at = (size_t)snprintf(cmd, sizeof cmd, "rsa_exp ");
    at += hex_encode(cmd + at, m, len);
    cmd[at++] = ' ';
    at += hex_encode(cmd + at, base, len);
    (void)snprintf(cmd + at, sizeof cmd - at, " %llu", (unsigned long long)e);
    (void)hex_encode(want, out, len);
    expect(cmd, want);
}

static void diff_modulus(const uint8_t *m, size_t len) {
    rsa_mont64_modulus mod;
    rsa_mont64_modulus_init(&mod, m, len, bit_length(m, len));
    uint8_t bases[4][LEN_MAX] = {{0}};
    bases[1][len - 1] = 1;
    memcpy(bases[2], m, len);
    bases[2][len - 1] ^= 1;
    rng_fill(bases[3], len);
    // A top byte below m's keeps the base below m.
    bases[3][0] = (uint8_t)rng_below(m[0]);
    for (size_t b = 0; b < 4; b++) {
        for (size_t i = 0; i < sizeof EXPONENTS / sizeof EXPONENTS[0]; i++) {
            diff_one(m, len, &mod, bases[b], EXPONENTS[i]);
        }
        for (int i = 0; i < RANDOM_EXPONENTS; i++) {
            diff_one(m, len, &mod, bases[b], random_exponent());
        }
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff rsa exp: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    for (size_t i = 0; i < sizeof LENGTHS / sizeof LENGTHS[0]; i++) {
        for (int kind = 0; kind < MODULUS_KINDS; kind++) {
            uint8_t m[LEN_MAX];
            modulus_of_kind(m, LENGTHS[i], kind);
            diff_modulus(m, LENGTHS[i]);
        }
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff rsa exp: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
