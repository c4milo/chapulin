// X25519=wide against X25519=portable: the same scalar and u-coordinate
// into both fields, the same 32 bytes and the same return value out. The
// 16-limb field carries ten CBMC harnesses, the Lean differential and a
// prior Coq proof of its limb scheme; this binary is what carries the
// radix-2^51 field to the same answers on every input it tries.
//
// Both fields also answer the published values directly, so neither is
// checked only through the other: RFC 7748 section 5.2's two vectors and
// its iterated vector after 1 and 1,000 rounds, and section 6.1's key
// exchange. Then come the inputs a limb scheme is most likely to get
// wrong, and then random pairs:
//
//   - the u-coordinates of order 1, 2, 4 and 8, which must give an all-zero
//     result and a return value of 0 whatever the scalar;
//   - every u in [p, 2^255), which each field must reduce to u - p;
//   - each of those again with bit 255 set, which RFC 7748 masks off;
//   - 10,000 random scalars and u-coordinates, half of them with bit 255
//     set, and 1,000 random scalars times the base point.
//
// The random pairs come from the seeded generator below, so an ordinary
// run replays exactly and the nightly can vary CH_X25519_EQUIV_SEED.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x25519.h"

// The two fields, each compiled under its own name by
// test/x25519_equiv_portable.c and test/x25519_equiv_wide.c. Declared here
// rather than in a header because the renaming is this binary's alone.
int x25519_portable(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                    const uint8_t point[X25519_LEN]);
void x25519_base_portable(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]);
int x25519_wide(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                const uint8_t point[X25519_LEN]);
void x25519_base_wide(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]);

// xorshift64, as test/aes_equiv_test.c writes it and for its reasons: a
// fixed default seed, so a mismatch reproduces bit for bit, and an
// environment variable the nightly sets to vary it. Never time().
#define X25519_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = X25519_EQUIV_DEFAULT_SEED;

// Reads CH_X25519_EQUIV_SEED, if set, as the seed, and returns the seed in
// use. A value that is not a number, or zero, keeps the default: xorshift64
// is all zeroes forever from zero.
static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_X25519_EQUIV_SEED");
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

static void print_hex(const char *name, const uint8_t *p, size_t n) {
    (void)fprintf(stderr, "  %s ", name);
    for (size_t i = 0; i < n; i++) {
        (void)fprintf(stderr, "%02x", p[i]);
    }
    (void)fprintf(stderr, "\n");
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    return c - 'a' + 10;
}

static void unhex(const char *hex, uint8_t out[X25519_LEN]) {
    for (size_t i = 0; i < X25519_LEN; i++) {
        out[i] = (uint8_t)((hex_value(hex[2 * i]) << 4) | hex_value(hex[2 * i + 1]));
    }
}

// One input to both fields. Returns the wide field's verdict, after
// checking that the two outputs and the two verdicts agree; the case name
// says which input produced a mismatch.
static int compare(const char *case_name, const uint8_t scalar[X25519_LEN],
                   const uint8_t point[X25519_LEN], uint8_t out[X25519_LEN]) {
    uint8_t portable_out[X25519_LEN];
    int portable_ok = x25519_portable(portable_out, scalar, point);
    int wide_ok = x25519_wide(out, scalar, point);
    if (portable_ok != wide_ok || memcmp(portable_out, out, X25519_LEN) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: the fields differ (portable %d, wide %d)\n", case_name,
                      portable_ok, wide_ok);
        print_hex("scalar  ", scalar, X25519_LEN);
        print_hex("u       ", point, X25519_LEN);
        print_hex("portable", portable_out, X25519_LEN);
        print_hex("wide    ", out, X25519_LEN);
        return wide_ok;
    }
    compared++;
    return wide_ok;
}

static void compare_base(const char *case_name, const uint8_t scalar[X25519_LEN],
                         uint8_t out[X25519_LEN]) {
    uint8_t portable_out[X25519_LEN];
    x25519_base_portable(portable_out, scalar);
    x25519_base_wide(out, scalar);
    if (memcmp(portable_out, out, X25519_LEN) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: the fields differ on the base point\n", case_name);
        print_hex("scalar  ", scalar, X25519_LEN);
        print_hex("portable", portable_out, X25519_LEN);
        print_hex("wide    ", out, X25519_LEN);
        return;
    }
    compared++;
}

static void expect_hex(const char *case_name, const uint8_t got[X25519_LEN], const char *hex) {
    uint8_t want[X25519_LEN];
    unhex(hex, want);
    if (memcmp(got, want, X25519_LEN) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: both fields agree on a value RFC 7748 does not print\n",
                      case_name);
        print_hex("got ", got, X25519_LEN);
        print_hex("want", want, X25519_LEN);
    }
}

// RFC 7748 section 5.2's two vectors and section 6.1's exchange.
static void run_rfc_vectors(void) {
    uint8_t k[X25519_LEN];
    uint8_t u[X25519_LEN];
    uint8_t out[X25519_LEN];
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
    (void)compare("rfc7748 5.2 first", k, u, out);
    expect_hex("rfc7748 5.2 first", out,
               "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", k);
    unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u);
    (void)compare("rfc7748 5.2 second", k, u, out);
    expect_hex("rfc7748 5.2 second", out,
               "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

    uint8_t alice[X25519_LEN];
    uint8_t bob[X25519_LEN];
    uint8_t alice_public[X25519_LEN];
    uint8_t bob_public[X25519_LEN];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alice);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bob);
    compare_base("rfc7748 6.1 alice public", alice, alice_public);
    expect_hex("rfc7748 6.1 alice public", alice_public,
               "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    compare_base("rfc7748 6.1 bob public", bob, bob_public);
    expect_hex("rfc7748 6.1 bob public", bob_public,
               "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    (void)compare("rfc7748 6.1 alice shared", alice, bob_public, out);
    expect_hex("rfc7748 6.1 alice shared", out,
               "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    (void)compare("rfc7748 6.1 bob shared", bob, alice_public, out);
    expect_hex("rfc7748 6.1 bob shared", out,
               "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
}

// RFC 7748 section 5.2's iterated vector: k and u start at 9, and each
// round sets k to x25519(k, u) and u to the old k. Every round of both
// fields is compared, and the values after 1 and 1,000 rounds against the
// RFC. The 1,000,000-round value is left out: it takes minutes on the
// 16-limb field.
static void run_iterated(void) {
    uint8_t k[X25519_LEN] = {9};
    uint8_t u[X25519_LEN] = {9};
    for (int i = 1; i <= 1000; i++) {
        uint8_t next[X25519_LEN];
        (void)compare("rfc7748 5.2 iterated", k, u, next);
        memcpy(u, k, X25519_LEN);
        memcpy(k, next, X25519_LEN);
        if (i == 1) {
            expect_hex("rfc7748 5.2 after 1 round", k,
                       "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        }
    }
    expect_hex("rfc7748 5.2 after 1,000 rounds", k,
               "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
}

// The u-coordinates of small order, little-endian: 0 and 1, the two points
// of order 8, p - 1 (order 2), and p and p + 1, which reduce to 0 and 1.
// A clamped scalar is a multiple of 8, so each gives the all-zero result.
static const char *const LOW_ORDER[] = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
};

static void run_low_order(void) {
    for (size_t i = 0; i < sizeof LOW_ORDER / sizeof LOW_ORDER[0]; i++) {
        uint8_t u[X25519_LEN];
        unhex(LOW_ORDER[i], u);
        for (int top = 0; top < 2; top++) {
            u[31] = (uint8_t)((u[31] & 0x7f) | (top << 7));
            for (int j = 0; j < 8; j++) {
                uint8_t k[X25519_LEN];
                uint8_t out[X25519_LEN];
                rng_fill(k, sizeof k);
                if (compare("low order", k, u, out) != 0) {
                    failures++;
                    (void)fprintf(stderr, "FAIL low order: u #%zu (bit 255 %d) returned 1\n", i,
                                  top);
                }
            }
        }
    }
}

// u = p + j for j in 0..18, every value in [p, 2^255), with bit 255 clear
// and set. Each must give what u = j gives.
static void run_non_canonical(void) {
    for (uint8_t j = 0; j < 19; j++) {
        uint8_t k[X25519_LEN];
        rng_fill(k, sizeof k);
        uint8_t canonical[X25519_LEN] = {0};
        canonical[0] = j;
        uint8_t want[X25519_LEN];
        (void)compare("u = j", k, canonical, want);
        uint8_t u[X25519_LEN];
        memset(u, 0xff, sizeof u);
        u[0] = (uint8_t)(0xed + j);
        for (int top = 0; top < 2; top++) {
            u[31] = (uint8_t)(0x7f | (top << 7));
            uint8_t out[X25519_LEN];
            (void)compare("u = p + j", k, u, out);
            if (memcmp(out, want, X25519_LEN) != 0) {
                failures++;
                (void)fprintf(stderr, "FAIL u = p + %u (bit 255 %d): not reduced to u = %u\n", j,
                              top, j);
            }
        }
    }
}

static void run_random(void) {
    for (int i = 0; i < 10000; i++) {
        uint8_t k[X25519_LEN];
        uint8_t u[X25519_LEN];
        uint8_t out[X25519_LEN];
        rng_fill(k, sizeof k);
        rng_fill(u, sizeof u);
        u[31] = (uint8_t)((u[31] & 0x7f) | ((i & 1) << 7));
        (void)compare("random", k, u, out);
    }
    for (int i = 0; i < 1000; i++) {
        uint8_t k[X25519_LEN];
        uint8_t out[X25519_LEN];
        rng_fill(k, sizeof k);
        compare_base("random base", k, out);
    }
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    run_rfc_vectors();
    run_iterated();
    run_low_order();
    run_non_canonical();
    run_random();
    if (failures != 0) {
        (void)printf("x25519_equiv: %d failures (seed 0x%016llx)\n", failures,
                     (unsigned long long)seed);
        return 1;
    }
    (void)printf("x25519_equiv: %lu inputs, X25519=wide == X25519=portable (seed 0x%016llx)\n",
                 compared, (unsigned long long)seed);
    return 0;
}
