// The wide P-256 files against the files under their own names, as a host
// object holds them (docs/decisions.md 89 and 94): the same inputs into
// both, the same words, bytes and verdicts out. p256_field.c,
// p256_scalar.c and p256_point.c carry the CBMC harnesses, Python's
// vectors, RFC 6979's and the Wycheproof suites; this binary is what
// carries the four words of 64 bits to the same answers on every input it
// tries.
//
// test/p256_equiv_field.h holds the field and the scalar arithmetic,
// routine by routine. This file holds the points and the entries
// widemul.h dispatches:
//
//   - the complete addition on coordinates that are on no curve, where
//     both files must still compute the same words, and on the cases the
//     formula claims: a point with itself, with its negative, and with the
//     point at infinity on either side;
//   - the point decode on a point, on each way a point is refused, and the
//     affine conversion on a finite point and on the point at infinity;
//   - both scalar multiplications on scalars at the edges, 0, 1, n - 1, n,
//     n + 1 and 2^256 - 1 among them, and on random ones, half of them
//     even;
//   - a signature, a key pair and a shared secret under both answers.
//
// test/p256_equiv_table.h recomputes the table of multiples of G that the
// base multiplication reads, and holds the mixed addition to the complete
// one. test/p256_equiv_residue.h then looks at what the wide calls leave
// on the stack.
//
// The Makefile builds this file three times. bin/p256_equiv_test runs the
// form of p256_wide_word.h's two carry steps that its compiler picks.
// bin/p256_equiv_test_sum names the 128-bit sums, which gcc picks outside
// x86-64 and no machine that runs check does. bin/p256_equiv_test_builtin
// names the overflow builtins, which clang picks and CI's gcc does not.
//
// The random inputs come from the seeded generator below, so an ordinary
// run replays exactly and the nightly can vary CH_P256_EQUIV_SEED.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "p256.h"
#include "p256_ecdh.h"
#include "p256_field.h"
#include "p256_field_vectors.h"
#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_sign.h"
#include "p256_wide_field.h"
#include "p256_wide_mul.h"
#include "p256_wide_point.h"
#include "p256_wide_scalar.h"
#include "widemul.h"

// p256.c's 32-bit arm, a device object's (test/p256_verify_portable.c).
// The wide files compute none of it, so it reads each signature
// independently of them; a host object's own verifier runs on them
// (p256_wide_verify.c).
int p256_ecdsa_verify_portable(const uint8_t pub[64], const uint8_t msg_hash[32],
                               const uint8_t *sig_der, size_t sig_len);

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// xorshift64, as test/x25519_equiv_test.c writes it and for its reasons: a
// fixed default seed, so a mismatch reproduces bit for bit, and an
// environment variable the nightly sets to vary it. Never time().
#define P256_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = P256_EQUIV_DEFAULT_SEED;

static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_P256_EQUIV_SEED");
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

// Counts one comparison, and prints the first few that failed.
static void report(const char *group, const char *what, int ok) {
    if (ok) {
        compared++;
        return;
    }
    failures++;
    if (failures <= 20) {
        (void)fprintf(stderr, "FAIL %s: %s\n", group, what);
    }
}

#include "p256_equiv_field.h"

// Three coordinates of random elements: a point on no curve, which the
// addition formula still takes to the same words in both files.
static void random_coordinates(p256_point *o) {
    random_fe(&o->x);
    random_fe(&o->y);
    random_fe(&o->z);
}

static int same_point(const p256_wide_point *wide, const p256_point *portable) {
    p256_point back;
    p256_wide_point_to_portable(&back, wide);
    return memcmp(&back, portable, sizeof back) == 0;
}

// a + b in both files, in each aliasing shape a caller uses.
static void add_case(const char *name, const p256_point *a, const p256_point *b) {
    p256_point want;
    p256_wide_point wa;
    p256_wide_point wb;
    p256_wide_point got;
    int ok = 1;
    p256_wide_point_from_portable(&wa, a);
    p256_wide_point_from_portable(&wb, b);
    p256_point_add(&want, a, b);
    p256_wide_point_add(&got, &wa, &wb);
    ok &= same_point(&got, &want);
    got = wa;
    p256_wide_point_add(&got, &got, &wb);
    ok &= same_point(&got, &want);
    got = wb;
    p256_wide_point_add(&got, &wa, &got);
    ok &= same_point(&got, &want);
    p256_point_add(&want, a, a);
    got = wa;
    p256_wide_point_add(&got, &got, &got);
    ok &= same_point(&got, &want);
    report("point add", name, ok);
}

// A scalar's words: random, with one byte in four all ones and one in four
// zero, so a window of the scalar holds every digit, and the low bit as
// low_bit says.
static void random_wide_scalar(p256_scalar *k, uint32_t low_bit) {
    random_words(k->word);
    k->word[0] = (k->word[0] & ~UINT32_C(1)) | low_bit;
}

// The scalars a multiplication is most likely to get wrong, as 32
// big-endian bytes: 0, 1, 2, 15, 16, 17, n - 1, n, n + 1, 2^256 - 1, 2^255,
// a scalar of one digit per window, and one with every window at its top
// digit, for the four-bit windows of p256_wide_mul; then for the six-bit
// windows of p256_wide_base_mul, one bit at the bottom of every window, which
// makes every digit 1, one at the top of every window, which makes every
// digit but the top one negative, and that scalar's complement, which makes
// every digit positive.
static const char *const SCALAR_EDGE_HEX[] = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "000000000000000000000000000000000000000000000000000000000000000f",
    "0000000000000000000000000000000000000000000000000000000000000010",
    "0000000000000000000000000000000000000000000000000000000000000011",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "8000000000000000000000000000000000000000000000000000000000000000",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "8888888888888888888888888888888888888888888888888888888888888888",
    "7777777777777777777777777777777777777777777777777777777777777777",
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    "0000000000000000000000000000000100000000000000000000000000000000",
    "1041041041041041041041041041041041041041041041041041041041041041",
    "0820820820820820820820820820820820820820820820820820820820820820",
    "f7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df",
};

static uint8_t nibble(char c) {
    return (uint8_t)(c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10);
}

static void edge_scalar(p256_scalar *k, size_t i) {
    uint8_t bytes[P256_SCALAR_LEN];
    for (size_t j = 0; j < sizeof bytes; j++) {
        bytes[j] = (uint8_t)((nibble(SCALAR_EDGE_HEX[i][2 * j]) << 4) |
                             nibble(SCALAR_EDGE_HEX[i][2 * j + 1]));
    }
    p256_scalar_from_bytes(k, bytes);
}

// Whether two points are the same point: both infinite, or both finite
// with the same affine bytes. p256_point_affine reads both.
static int same_affine(const p256_point *a, const p256_point *b) {
    uint8_t ax[P256_FE_LEN];
    uint8_t ay[P256_FE_LEN];
    uint8_t bx[P256_FE_LEN];
    uint8_t by[P256_FE_LEN];
    uint32_t a_finite = p256_point_affine(ax, ay, a);
    uint32_t b_finite = p256_point_affine(bx, by, b);
    if (a_finite != b_finite) {
        return 0;
    }
    return a_finite == 0 || (memcmp(ax, bx, sizeof ax) == 0 && memcmp(ay, by, sizeof ay) == 0);
}

// k * p and k * G in both files, and the affine conversion of the result
// in both.
static void mul_case(const char *name, const p256_scalar *k, const p256_point *p) {
    p256_point want;
    p256_point got;
    uint8_t want_x[P256_FE_LEN];
    uint8_t want_y[P256_FE_LEN];
    uint8_t got_x[P256_FE_LEN];
    uint8_t got_y[P256_FE_LEN];
    int ok = 1;
    p256_point_mul(&want, k, p);
    p256_wide_mul(&got, k, p);
    ok &= same_affine(&got, &want);
    uint32_t want_finite = p256_point_affine(want_x, want_y, &want);
    uint32_t got_finite = p256_wide_point_affine(got_x, got_y, &got);
    ok &= want_finite == got_finite;
    ok &= want_finite == 0 ||
          (memcmp(want_x, got_x, sizeof got_x) == 0 && memcmp(want_y, got_y, sizeof got_y) == 0);
    // X alone, the form a signature and a shared secret read.
    memset(got_x, 0, sizeof got_x);
    ok &= p256_wide_point_affine(got_x, NULL, &got) == want_finite;
    ok &= want_finite == 0 || memcmp(want_x, got_x, sizeof got_x) == 0;
    report("point mul", name, ok);
}

static void base_mul_case(const char *name, const p256_scalar *k) {
    p256_point want;
    p256_point got;
    p256_point_base_mul(&want, k);
    p256_wide_base_mul(&got, k);
    report("base mul", name, same_affine(&got, &want));
}

static void run_points(void) {
    p256_point a;
    p256_point b;
    p256_point negated;
    p256_scalar k;
    for (int i = 0; i < 3000; i++) {
        random_coordinates(&a);
        random_coordinates(&b);
        add_case("random coordinates", &a, &b);
    }
    // Points on the curve: multiples of G with a Z that is not 1.
    random_wide_scalar(&k, 1);
    p256_wide_base_mul(&a, &k);
    random_wide_scalar(&k, 0);
    p256_wide_base_mul(&b, &k);
    negated = a;
    p256_fe_neg(&negated.y, &negated.y);
    add_case("two points", &a, &b);
    add_case("a point and itself", &a, &a);
    add_case("a point and its negative", &a, &negated);
    add_case("a point and infinity", &a, &p256_point_infinity);
    add_case("infinity and a point", &p256_point_infinity, &b);
    add_case("infinity and infinity", &p256_point_infinity, &p256_point_infinity);
    add_case("the generator and itself", &p256_point_generator, &p256_point_generator);

    for (size_t i = 0; i < COUNT(SCALAR_EDGE_HEX); i++) {
        edge_scalar(&k, i);
        base_mul_case("edge scalar", &k);
        mul_case("edge scalar", &k, &a);
    }
    mul_case("the point at infinity", &k, &p256_point_infinity);
    for (uint32_t i = 0; i < 40; i++) {
        random_wide_scalar(&k, i & 1U);
        base_mul_case("random scalar", &k);
        mul_case("random scalar", &k, i < 20 ? &a : &b);
    }
}

// The point decode on one encoding in both files.
static void decode_case(const char *name, const uint8_t in[P256_POINT_LEN]) {
    p256_point want;
    p256_point got;
    memset(&want, 0, sizeof want);
    memset(&got, 0, sizeof got);
    uint32_t want_ok = p256_point_from_bytes(&want, in);
    uint32_t got_ok = p256_wide_point_from_bytes(&got, in);
    int ok = want_ok == got_ok;
    ok &= want_ok == 0 || memcmp(&want, &got, sizeof got) == 0;
    report("point decode", name, ok);
}

static void run_decode(void) {
    uint8_t draw[P256_SCALAR_LEN];
    uint8_t priv[P256_SCALAR_LEN];
    uint8_t point[P256_POINT_LEN];
    uint8_t bad[P256_POINT_LEN];
    for (int i = 0; i < 20; i++) {
        do {
            rng_fill(draw, sizeof draw);
        } while (!p256_ecdh_keygen(WIDEMUL_CONSTANT_TIME, draw, priv, point));
        decode_case("a point on the curve", point);
        memcpy(bad, point, sizeof bad);
        bad[0] = (uint8_t)(i & 1 ? 0x02 : 0x00);
        decode_case("another leading byte", bad);
        memcpy(bad, point, sizeof bad);
        bad[1 + (rng_next() & 63)] ^= (uint8_t)(1U << (rng_next() & 7));
        decode_case("one bit flipped", bad);
        memcpy(bad, point, sizeof bad);
        memset(bad + 1 + (i & 1 ? P256_FE_LEN : 0), 0xff, P256_FE_LEN);
        decode_case("a coordinate at or above p", bad);
    }
    memset(bad, 0, sizeof bad);
    bad[0] = 0x04;
    decode_case("x and y both zero", bad);
}

// The two answers every entry runs under: the files under their own names,
// then the wide files.
static const uint8_t ANSWERS[2] = {WIDEMUL_NOT_STATED, WIDEMUL_CONSTANT_TIME};

// A key pair from one draw under both answers. Returns whether both made
// one, and leaves it in priv and pub.
static int keypair_case(const uint8_t draw[P256_SCALAR_LEN], uint8_t priv[P256_SCALAR_LEN],
                        uint8_t pub[P256_POINT_LEN]) {
    uint8_t other_priv[P256_SCALAR_LEN];
    uint8_t other_pub[P256_POINT_LEN];
    int made = p256_ecdh_keygen(ANSWERS[0], draw, priv, pub);
    int other_made = p256_ecdh_keygen(ANSWERS[1], draw, other_priv, other_pub);
    int ok = made == other_made;
    ok &= memcmp(priv, other_priv, sizeof other_priv) == 0;
    ok &= memcmp(pub, other_pub, sizeof other_pub) == 0;
    report("entries", "a key pair under both answers", ok);
    return made;
}

// A signature under both answers, which the independent verifier reads.
static void signature_case(const uint8_t priv[P256_SCALAR_LEN], const uint8_t pub[P256_POINT_LEN],
                           const uint8_t hash[32]) {
    uint8_t sig[2][P256_SIG_MAX];
    size_t sig_len[2] = {0, 0};
    int ok = 1;
    for (size_t j = 0; j < 2; j++) {
        ok &= p256_sign(ANSWERS[j], priv, hash, sig[j], sizeof sig[j], &sig_len[j]) == 1;
    }
    ok &= sig_len[0] == sig_len[1];
    ok &= memcmp(sig[0], sig[1], sig_len[0]) == 0;
    ok &= p256_ecdsa_verify_portable(pub + 1, hash, sig[1], sig_len[1]) == 1;
    report("entries", "a signature under both answers", ok);
}

// A shared secret with one peer under both answers.
static void secret_case(const uint8_t priv[P256_SCALAR_LEN], const uint8_t peer[P256_POINT_LEN]) {
    uint8_t shared[2][P256_SECRET_LEN];
    int ok = 1;
    for (size_t j = 0; j < 2; j++) {
        ok &= p256_ecdh(ANSWERS[j], priv, peer, shared[j]) == 1;
    }
    ok &= memcmp(shared[0], shared[1], sizeof shared[0]) == 0;
    ok &= p256_ecdh_point_valid(ANSWERS[0], peer) == p256_ecdh_point_valid(ANSWERS[1], peer);
    report("entries", "a shared secret under both answers", ok);
}

// A key pair, a signature and a shared secret under both answers.
static void run_entries(void) {
    for (int i = 0; i < 30; i++) {
        uint8_t draw[P256_SCALAR_LEN];
        uint8_t priv[P256_SCALAR_LEN];
        uint8_t pub[P256_POINT_LEN];
        uint8_t peer_priv[P256_SCALAR_LEN];
        uint8_t peer[P256_POINT_LEN];
        uint8_t hash[32];
        rng_fill(draw, sizeof draw);
        if (i == 0) {
            memset(draw, 0xff, sizeof draw); // above n: both refuse it
        }
        rng_fill(hash, sizeof hash);
        if (!keypair_case(draw, priv, pub)) {
            continue;
        }
        do {
            rng_fill(draw, sizeof draw);
        } while (!p256_ecdh_keygen(WIDEMUL_CONSTANT_TIME, draw, peer_priv, peer));
        signature_case(priv, pub, hash);
        secret_case(priv, peer);
    }
}

#include "p256_equiv_residue.h"
#include "p256_equiv_table.h"

int main(void) {
    uint64_t seed = rng_seed_from_env();
    run_field();
    run_field_vectors();
    run_scalar();
    run_points();
    run_table();
    run_formulas();
    run_decode();
    run_entries();
    run_stack();
    if (failures != 0) {
        (void)printf("p256_equiv: %d failures (seed 0x%016llx)\n", failures,
                     (unsigned long long)seed);
        return 1;
    }
    (void)printf("p256_equiv: %lu comparisons, the wide files == the files under their own names "
                 "(seed 0x%016llx)\n",
                 compared, (unsigned long long)seed);
    return 0;
}
