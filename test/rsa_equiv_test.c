// A host object's RSA arithmetic against the portable code, which stays
// the reference (docs/decisions.md 95): the same inputs into both, the
// same bytes out.
//
// The public operation, rsa_vp1. A host object computes it on
// rsa_mont64.c's 64-bit limbs and a device object on rsa_mont.c's 32-bit
// limbs. This binary holds both: rsa_vp1 is the host arm, and
// rsa_vp1_portable is the device arm, which test/rsa_equiv_portable.c
// compiles under that name. The 32-bit arm carries the CBMC lemma, the
// Lean differential and the openssl vectors of bin/rsa_test; this binary
// is what carries the 64-bit arm to the same answers on every input it
// tries:
//
//   - random odd moduli with the top bit set at every length rsa.h
//     admits, 256 bytes to CH_RSA_MODULUS_MAX in steps of 8, each with
//     random signatures below it;
//   - moduli a limb scheme is most likely to get wrong: all ones, the top
//     and bottom bits alone, a low limb of 1 and a low limb of all ones,
//     which are the two ends of the inverse rsa_mont64.c computes from
//     that limb, a top limb of 2^63 with zeros under it, and a modulus
//     whose division of R^2 in rsa_mont.c meets the remainder n - 1;
//   - moduli of every bit length around a limb boundary and down to two
//     bits, in the same number of bytes, which the verifier admits
//     because a peer's key comes from elsewhere. Those start
//     rsa_mont64_modulus_init at another power of two and run it through
//     more doublings;
//   - under each of those, the signatures 0, 1, 2, n - 2 and n - 1, a
//     single bit and random values.
//
// rsa_mont64.c's square is held to its multiplication of a number by
// itself, at every limb count from 1 to the bound, which the signer's
// primes need: 0, 1, n - 1, the top bit alone and random values below n.
//
// Three answers are known without either arm: 0 and 1 are their own
// 65537th powers, and n - 1 is its own, because 65537 is odd. Each is
// checked against both arms, so neither is held only to the other.
//
// An even modulus is no RSA modulus, and the two arms write different
// bytes for one: neither has an inverse of its low limb to compute. So
// no case here is even, and rsa.h says so of rsa_vp1.
//
// The random values come from the seeded generator below, so an ordinary
// run replays exactly and the nightly can vary CH_RSA_EQUIV_SEED.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "rsa.h"
#include "rsa_mont64.h"

// The device arm of rsa_mont.c (test/rsa_equiv_portable.c).
void rsa_vp1_portable(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em);

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// xorshift64, as test/x25519_equiv_test.c writes it and for its reasons:
// a fixed default seed, so a mismatch reproduces bit for bit, and an
// environment variable the nightly sets to vary it. Never time().
#define RSA_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = RSA_EQUIV_DEFAULT_SEED;

// Reads CH_RSA_EQUIV_SEED, if set, as the seed, and returns the seed in
// use. A value that is not a number, or zero, keeps the default:
// xorshift64 is all zeroes forever from zero.
static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_RSA_EQUIV_SEED");
    if (text != NULL) {
        char *end = NULL;
        unsigned long long value = strtoull(text, &end, 0);
        if (end != text && *end == 0 && value != 0) {
            rng_state = (uint64_t)value;
        }
    }
    return rng_state;
}

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static void rng_fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(rng_next() >> 56);
    }
}

static int failures = 0;
static unsigned long compared = 0;
static unsigned long squared = 0;

static void print_hex(const char *name, const uint8_t *p, size_t n) {
    (void)fprintf(stderr, "  %s ", name);
    for (size_t i = 0; i < n; i++) {
        (void)fprintf(stderr, "%02x", p[i]);
    }
    (void)fprintf(stderr, "\n");
}

// One modulus and one signature into both arms. The outputs start from
// different bytes, so an arm that wrote nothing cannot agree with the
// other by chance. out takes the host arm's answer.
static void compare(const char *case_name, const uint8_t *n, size_t n_len, const uint8_t *sig,
                    uint8_t *out) {
    uint8_t portable_out[CH_RSA_MODULUS_MAX];
    memset(portable_out, 0x55, sizeof portable_out);
    memset(out, 0xaa, n_len);
    rsa_vp1_portable(n, n_len, sig, portable_out);
    rsa_vp1(n, n_len, sig, out);
    if (memcmp(portable_out, out, n_len) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: the two limb widths differ at %zu bytes\n", case_name,
                      n_len);
        print_hex("n       ", n, n_len);
        print_hex("sig     ", sig, n_len);
        print_hex("portable", portable_out, n_len);
        print_hex("64-bit  ", out, n_len);
        return;
    }
    compared++;
}

// compare, and the answer both arms must give.
static void compare_known(const char *case_name, const uint8_t *n, size_t n_len, const uint8_t *sig,
                          const uint8_t *want) {
    uint8_t out[CH_RSA_MODULUS_MAX];
    compare(case_name, n, n_len, sig, out);
    if (memcmp(out, want, n_len) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: both arms agree on a value that is not the power\n",
                      case_name);
        print_hex("n   ", n, n_len);
        print_hex("got ", out, n_len);
        print_hex("want", want, n_len);
    }
}

// a -= small, over len big-endian bytes, for a at or above small.
static void subtract_small(uint8_t *a, size_t len, unsigned small) {
    unsigned borrow = small;
    for (size_t i = len; i-- > 0 && borrow != 0;) {
        unsigned byte = a[i];
        a[i] = (uint8_t)(byte - borrow);
        borrow = byte < borrow ? 1 : 0;
    }
}

// The index of the top set bit of the len-byte n, counted from bit 0 at
// the end, for n not zero.
static size_t top_bit(const uint8_t *n, size_t len) {
    size_t i = 0;
    while (n[i] == 0) {
        i++;
    }
    size_t bit = 8 * (len - i) - 1;
    for (uint8_t mask = 0x80; (n[i] & mask) == 0; mask >>= 1) {
        bit--;
    }
    return bit;
}

// A random value below the len-byte n, for n above 1: random bits under
// n's top bit.
static void random_below(uint8_t *out, const uint8_t *n, size_t len) {
    rng_fill(out, len);
    size_t top = top_bit(n, len);
    for (size_t bit = top; bit < 8 * len; bit++) {
        out[len - 1 - bit / 8] &= (uint8_t)~(1U << (bit % 8));
    }
}

// Every signature this test tries under one modulus above 3: the three
// whose powers are known, their neighbours, a single bit, and random
// values.
static void run_modulus(const char *case_name, const uint8_t *n, size_t n_len, int random_count) {
    uint8_t sig[CH_RSA_MODULUS_MAX];
    uint8_t out[CH_RSA_MODULUS_MAX];

    memset(sig, 0, n_len);
    compare_known(case_name, n, n_len, sig, sig);
    sig[n_len - 1] = 1;
    compare_known(case_name, n, n_len, sig, sig);
    sig[n_len - 1] = 2;
    compare(case_name, n, n_len, sig, out);

    memcpy(sig, n, n_len);
    subtract_small(sig, n_len, 1);
    compare_known(case_name, n, n_len, sig, sig);
    subtract_small(sig, n_len, 1);
    compare(case_name, n, n_len, sig, out);

    // The top bit of n alone is below n, because n is odd and above 1.
    size_t top = top_bit(n, n_len);
    memset(sig, 0, n_len);
    sig[n_len - 1 - top / 8] = (uint8_t)(1U << (top % 8));
    compare(case_name, n, n_len, sig, out);

    for (int i = 0; i < random_count; i++) {
        random_below(sig, n, n_len);
        compare(case_name, n, n_len, sig, out);
    }
}

// Random odd moduli with the top bit set, the shape every key generator
// produces, at every length rsa.h admits.
static void run_random(void) {
    for (size_t n_len = 256; n_len <= CH_RSA_MODULUS_MAX; n_len += 8) {
        for (int i = 0; i < 4; i++) {
            uint8_t n[CH_RSA_MODULUS_MAX];
            rng_fill(n, n_len);
            n[0] |= 0x80;
            n[n_len - 1] |= 1;
            run_modulus("random modulus", n, n_len, 4);
        }
    }
}

// The moduli whose limbs sit at an edge, at the smallest length, the
// largest, and one between that is 8 bytes past a multiple of 16.
static void run_edge_moduli(size_t n_len) {
    uint8_t n[CH_RSA_MODULUS_MAX];

    memset(n, 0xff, n_len);
    run_modulus("all ones", n, n_len, 2);

    memset(n, 0, n_len);
    n[0] = 0x80;
    n[n_len - 1] = 1;
    run_modulus("top and bottom bits", n, n_len, 2);

    // A low 64-bit limb of 1, and of all ones, under random limbs.
    rng_fill(n, n_len);
    n[0] |= 0x80;
    memset(n + n_len - 8, 0, 8);
    n[n_len - 1] = 1;
    run_modulus("low limb 1", n, n_len, 2);
    memset(n + n_len - 8, 0xff, 8);
    run_modulus("low limb all ones", n, n_len, 2);

    // Zero limbs between a random top limb and a random low limb.
    memset(n, 0, n_len);
    rng_fill(n, 8);
    n[0] |= 0x80;
    rng_fill(n + n_len - 8, 8);
    n[n_len - 1] |= 1;
    run_modulus("zero middle limbs", n, n_len, 2);

    // (B^(k + 1) + 1) / (B + 1), for B = 2^64 and an even limb count k:
    // limb 0 is 1, every odd limb is all ones and every other limb is
    // zero. B^(k + 1) is -1 modulo it, so the division by which
    // rsa_mont.c computes R^2 meets the remainder n - 1, whose top limb is
    // n's, and its next step takes the largest estimate, 2^64 - 1, where
    // the division of the top limbs would pass 2^64. No random modulus
    // meets that step: a remainder's top limb equals the modulus's about
    // once in 2^64 steps.
    if ((n_len / 8) % 2 == 0) {
        memset(n, 0, n_len);
        for (size_t limb = 1; limb < n_len / 8; limb += 2) {
            memset(n + n_len - 8 * (limb + 1), 0xff, 8);
        }
        n[n_len - 1] = 1;
        run_modulus("alternating limbs", n, n_len, 2);
    }
}

// A random odd modulus of exactly bits bits in n_len bytes.
static void run_bit_length(size_t n_len, size_t bits) {
    uint8_t n[CH_RSA_MODULUS_MAX];
    rng_fill(n, n_len);
    for (size_t bit = bits; bit < 8 * n_len; bit++) {
        n[n_len - 1 - bit / 8] &= (uint8_t)~(1U << (bit % 8));
    }
    n[n_len - 1 - (bits - 1) / 8] |= (uint8_t)(1U << ((bits - 1) % 8));
    n[n_len - 1] |= 1;
    run_modulus("short modulus", n, n_len, 2);
}

// Bit lengths below the top bit: each side of every limb boundary of both
// limb widths near the top and near the bottom, and the smallest moduli.
// 3 is the smallest odd modulus above 1, and 5 the smallest with a
// signature of 2 below n - 2.
static void run_short_moduli(size_t n_len) {
    static const size_t from_top[] = {1, 7, 8, 9, 31, 32, 33, 63, 64, 65, 127, 128, 129};
    for (size_t i = 0; i < sizeof from_top / sizeof from_top[0]; i++) {
        run_bit_length(n_len, 8 * n_len - from_top[i]);
    }
    static const size_t from_bottom[] = {3, 8, 31, 32, 33, 63, 64, 65, 66, 128, 129};
    for (size_t i = 0; i < sizeof from_bottom / sizeof from_bottom[0]; i++) {
        run_bit_length(n_len, from_bottom[i]);
    }

    // n = 3: the signatures 0, 1 and 2, which is n - 1.
    uint8_t n[CH_RSA_MODULUS_MAX] = {0};
    uint8_t sig[CH_RSA_MODULUS_MAX] = {0};
    n[n_len - 1] = 3;
    for (uint8_t s = 0; s < 3; s++) {
        sig[n_len - 1] = s;
        compare_known("n = 3", n, n_len, sig, sig);
    }
    // n = 1 has one value below it, and its power is itself.
    n[n_len - 1] = 1;
    sig[n_len - 1] = 0;
    compare_known("n = 1", n, n_len, sig, sig);
}

// One square against the product of the same number with itself, which
// the rows above hold to the 32-bit arm through the public operation:
// apart from its operand and on it, as the signer and the public
// operation call it.
static void compare_square(const char *case_name, const uint64_t *a,
                           const rsa_mont64_modulus *mod) {
    uint64_t product[RSA_MONT64_LIMBS_MAX];
    uint64_t square[RSA_MONT64_LIMBS_MAX];
    uint64_t in_place[RSA_MONT64_LIMBS_MAX];
    size_t k = mod->limbs;
    rsa_mont64_mont_mul(product, a, a, mod);
    rsa_mont64_mont_square(square, a, mod);
    memcpy(in_place, a, k * sizeof(uint64_t));
    rsa_mont64_mont_square(in_place, in_place, mod);
    if (memcmp(product, square, k * sizeof(uint64_t)) != 0 ||
        memcmp(product, in_place, k * sizeof(uint64_t)) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: the square differs from the product at %zu limbs\n",
                      case_name, k);
        return;
    }
    squared++;
}

// The square of rsa_mont64.c, at every limb count from 1 to the bound: a
// prime of the signer has half a modulus's limbs, so the counts below the
// rows above matter too. Under each modulus it squares 0, 1, n - 1, the
// top bit alone and random values below n, and each modulus has its top
// bit set, so n - 1 and the top bit alone make the top limb's top bit,
// which the square adds under a mask, 1.
static void run_squares(void) {
    for (size_t k = 1; k <= RSA_MONT64_LIMBS_MAX; k++) {
        for (int i = 0; i < 2; i++) {
            uint8_t n[CH_RSA_MODULUS_MAX];
            uint8_t value[CH_RSA_MODULUS_MAX];
            size_t len = 8 * k;
            rng_fill(n, len);
            n[0] |= 0x80;
            n[len - 1] |= 1;
            rsa_mont64_modulus mod;
            rsa_mont64_modulus_init(&mod, n, len, 8 * len);
            uint64_t a[RSA_MONT64_LIMBS_MAX] = {0};
            compare_square("square of 0", a, &mod);
            a[0] = 1;
            compare_square("square of 1", a, &mod);
            memcpy(a, mod.m, k * sizeof(uint64_t));
            a[0] -= 1;
            compare_square("square of n - 1", a, &mod);
            memset(a, 0, sizeof a);
            a[k - 1] = UINT64_C(1) << 63;
            compare_square("square of the top bit", a, &mod);
            for (int j = 0; j < 4; j++) {
                random_below(value, n, len);
                rsa_mont64_from_bytes(a, k, value, len);
                compare_square("square of a random value", a, &mod);
            }
        }
    }
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    run_random();
    run_squares();
    static const size_t edge_lengths[] = {256, 264, CH_RSA_MODULUS_MAX};
    for (size_t i = 0; i < sizeof edge_lengths / sizeof edge_lengths[0]; i++) {
        run_edge_moduli(edge_lengths[i]);
        run_short_moduli(edge_lengths[i]);
    }
    if (failures != 0) {
        (void)fprintf(stderr, "rsa_equiv_test: %d failure(s), seed 0x%llx\n", failures,
                      (unsigned long long)seed);
        return 1;
    }
    (void)printf("rsa_equiv_test: %lu comparisons of rsa_vp1 and %lu of a square, seed 0x%llx, all "
                 "equal\n",
                 compared, squared, (unsigned long long)seed);
    return 0;
}
