// The constant-time P-256 arm of the differential oracle: a key
// generation, a signature and a key exchange through p256_ecdh.h's and
// p256_sign.h's entries, against the same Lean spec process
// test/diff_test.c drives. The Makefile builds it as a host object's
// sources, with -DCH_CPU_RUNTIME, and every row runs under both answers:
// WIDEMUL_CONSTANT_TIME, which runs the wide files, four words of 64 bits
// (docs/decisions.md 94), and WIDEMUL_NOT_STATED, which runs p256_field.c,
// p256_scalar.c and p256_point.c on the decomposition.
//
// Its own main, as test/diff_x25519_test.c is: test/diff_test.c diffs the
// verifier in p256.c, which shares no arithmetic with these files, and no
// other row it runs reads them. spec/lean/Spec/P256.lean computes over Nat
// modulo p and n, so it states no word representation and serves both
// copies unchanged.
//
// Five rows, each on fresh random inputs. The first three run under both answers:
//
//   key generation: the point p256_ecdh_keygen writes for a scalar d is the
//   spec's p256_pub of d;
//
//   signature: the spec's p256_verify accepts what p256_sign writes for the
//   key and a hash, under the spec's own public key, and refuses it for a
//   hash with one byte changed. The C side picks the nonce (RFC 6979), so
//   the spec cannot predict r and s, and its verifier is what judges them;
//
//   key exchange: the X coordinate p256_ecdh writes for a scalar a and the
//   spec's point b G is the X coordinate of the spec's (a b mod n) G. The
//   spec has no entry that multiplies a point other than G, so the row
//   reduces the exchange to one. The product a b mod n comes from
//   p256_scalar_mul, which test/p256_sign_test.c holds to Python's
//   integers;
//
//   doubling: the three coordinates p256_wide_point_double writes are the
//   spec's p256_double of the same three, coordinate for coordinate.
//   spec/lean/Spec/P256WidePoint.lean holds that function and proves that it
//   doubles every point of the curve, so this row is what makes the proof
//   about the C. The row reads the wide file alone, so it runs once;
//
//   incomplete addition: the three coordinates
//   p256_wide_point_add_affine_incomplete writes for a projective point and
//   an affine one are the spec's p256_add_affine_incomplete of the same five,
//   coordinate for coordinate. The same module proves that function adds two
//   points whose x differ, and this row, like the doubling's, runs once.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "test_random.h"

#include "diff_driver.h"

// A build without the define holds no wide file, so it could only diff
// the 32-bit files twice and report success for the wrong ones.
#ifndef CH_CPU_RUNTIME
#error "test/diff_p256_wide_test.c diffs the wide P-256 files: build it with -DCH_CPU_RUNTIME"
#endif

#include "p256_ecdh.h"
#include "p256_scalar.h"
#include "p256_sign.h"
#include "p256_wide_point.h"
#include "widemul.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define HEX_LEN(n) (2 * (n) + 1)
// The spec's public key, X then Y, in bytes and in the hex digits of a reply.
enum { PUB_LEN = 2 * P256_FE_LEN, PUB_HEX_LEN = 2 * PUB_LEN };

// A scalar both sides take: the top bit clear keeps it below 2^255, which
// is below n, and the low bit set keeps it from zero.
static void draw_scalar(uint8_t d[P256_SCALAR_LEN]) {
    rng_fill(d, P256_SCALAR_LEN);
    d[0] &= 0x7f;
    d[P256_SCALAR_LEN - 1] |= 1;
}

// The spec's public key for d, X then Y, 64 bytes.
static void spec_pub(uint8_t pub[PUB_LEN], const uint8_t d[P256_SCALAR_LEN]) {
    char d_hex[HEX_LEN(P256_SCALAR_LEN)];
    char cmd[128];
    char reply[256];
    (void)hex_encode(d_hex, d, P256_SCALAR_LEN);
    (void)snprintf(cmd, sizeof cmd, "p256_pub %s", d_hex);
    query(cmd, reply, sizeof reply);
    if (strlen(reply) != PUB_HEX_LEN || !hex_decode(pub, reply, PUB_LEN)) {
        die("p256_pub: malformed spec response");
    }
}

static void diff_keygen(uint8_t widemul) {
    uint8_t d[P256_SCALAR_LEN];
    uint8_t priv[P256_SCALAR_LEN];
    uint8_t point[P256_POINT_LEN];
    draw_scalar(d);
    if (p256_ecdh_keygen(widemul, d, priv, point) != 1) {
        die("p256_ecdh_keygen refused a scalar below 2^255");
    }
    char d_hex[HEX_LEN(P256_SCALAR_LEN)];
    char want[HEX_LEN(PUB_LEN)];
    char cmd[128];
    (void)hex_encode(d_hex, d, sizeof d);
    (void)hex_encode(want, point + 1, PUB_LEN);
    (void)snprintf(cmd, sizeof cmd, "p256_pub %s", d_hex);
    expect(cmd, want);
}

// The two INTEGERs of the ECDSA-Sig-Value p256_sign wrote, each as 32
// big-endian bytes. p256_sign_harness.c proves the writer's layout: two
// short-form lengths and at most one leading zero byte on each value.
static void read_signature(uint8_t r[P256_SCALAR_LEN], uint8_t s[P256_SCALAR_LEN],
                           const uint8_t *sig) {
    uint8_t *value[2] = {r, s};
    const uint8_t *at = sig + 2;
    for (size_t i = 0; i < 2; i++) {
        size_t len = at[1];
        const uint8_t *content = at + 2;
        size_t skip = len > P256_SCALAR_LEN ? len - P256_SCALAR_LEN : 0;
        memset(value[i], 0, P256_SCALAR_LEN);
        memcpy(value[i] + P256_SCALAR_LEN - (len - skip), content + skip, len - skip);
        at = content + len;
    }
}

static void diff_sign(uint8_t widemul) {
    uint8_t d[P256_SCALAR_LEN];
    uint8_t hash[32];
    uint8_t bad[32];
    uint8_t pub[PUB_LEN];
    uint8_t sig[P256_SIG_MAX];
    uint8_t r[P256_SCALAR_LEN];
    uint8_t s[P256_SCALAR_LEN];
    size_t sig_len = 0;
    draw_scalar(d);
    rng_fill(hash, sizeof hash);
    memcpy(bad, hash, sizeof bad);
    bad[rng_below(sizeof bad)] ^= (uint8_t)(1 + rng_below(255));
    spec_pub(pub, d);
    if (p256_sign(widemul, d, hash, sig, sizeof sig, &sig_len) != 1) {
        die("p256_sign refused a scalar below 2^255");
    }
    read_signature(r, s, sig);

    char pub_hex[HEX_LEN(PUB_LEN)];
    char hash_hex[HEX_LEN(32)];
    char bad_hex[HEX_LEN(32)];
    char r_hex[HEX_LEN(P256_SCALAR_LEN)];
    char s_hex[HEX_LEN(P256_SCALAR_LEN)];
    char cmd[512];
    (void)hex_encode(pub_hex, pub, sizeof pub);
    (void)hex_encode(hash_hex, hash, sizeof hash);
    (void)hex_encode(bad_hex, bad, sizeof bad);
    (void)hex_encode(r_hex, r, sizeof r);
    (void)hex_encode(s_hex, s, sizeof s);
    (void)snprintf(cmd, sizeof cmd, "p256_verify %s %s %s %s", pub_hex, hash_hex, r_hex, s_hex);
    expect(cmd, "1");
    (void)snprintf(cmd, sizeof cmd, "p256_verify %s %s %s %s", pub_hex, bad_hex, r_hex, s_hex);
    expect(cmd, "0");
}

static void diff_ecdh(uint8_t widemul) {
    uint8_t a[P256_SCALAR_LEN];
    uint8_t b[P256_SCALAR_LEN];
    uint8_t product[P256_SCALAR_LEN];
    uint8_t peer[P256_POINT_LEN];
    uint8_t shared[P256_SECRET_LEN];
    draw_scalar(a);
    draw_scalar(b);
    peer[0] = 0x04;
    spec_pub(peer + 1, b);
    if (p256_ecdh(widemul, a, peer, shared) != 1) {
        die("p256_ecdh refused the spec's point");
    }
    // a b mod n, on the 32-bit scalar under its own name.
    p256_scalar scalar_a;
    p256_scalar scalar_b;
    p256_scalar_from_bytes(&scalar_a, a);
    p256_scalar_from_bytes(&scalar_b, b);
    p256_scalar_mul(&scalar_a, &scalar_a, &scalar_b);
    p256_scalar_to_bytes(product, &scalar_a);

    // The spec's (a b) G, X then Y: the row compares its X.
    uint8_t point[PUB_LEN];
    spec_pub(point, product);
    comparisons++;
    if (memcmp(point, shared, P256_SECRET_LEN) != 0) {
        char a_hex[HEX_LEN(P256_SCALAR_LEN)];
        char b_hex[HEX_LEN(P256_SCALAR_LEN)];
        (void)hex_encode(a_hex, a, sizeof a);
        (void)hex_encode(b_hex, b, sizeof b);
        (void)fprintf(stderr, "diff mismatch: p256_ecdh under answer %u\n  a: %s\n  b: %s\n",
                      (unsigned)widemul, a_hex, b_hex);
        exit(1);
    }
}

// A row's coordinates are plain field elements below p, each 32 big-endian bytes: X, Y and Z of
// each point it reads, and then x and y for an affine one. A point routine writes three.
#define COORDINATES 3
#define MOST_COORDINATES 6

// One element below p: the top bit clear keeps it below 2^255, which is below p.
static void draw_element(uint8_t element[P256_FE_LEN]) {
    rng_fill(element, P256_FE_LEN);
    element[0] &= 0x7f;
}

// A plain element below p, as 32 big-endian bytes, moved into the Montgomery domain.
static void element_to_mont(p256_wide_fe *o, const uint8_t element[P256_FE_LEN]) {
    p256_wide_fe plain;
    p256_wide_fe_from_bytes(&plain, element);
    p256_wide_fe_to_mont(o, &plain);
}

// The spec's command for op on count plain elements: op, then each element in hex.
static void element_command(char *cmd, size_t cmd_size, const char *op,
                            uint8_t element[][P256_FE_LEN], size_t count) {
    size_t cmd_len = (size_t)snprintf(cmd, cmd_size, "%s", op);
    for (size_t i = 0; i < count; i++) {
        cmd[cmd_len++] = ' ';
        cmd_len += hex_encode(cmd + cmd_len, element[i], P256_FE_LEN);
    }
}

// One point routine of p256_wide_point.h, on the row's coordinates in the Montgomery domain: it
// writes the three coordinates of its answer.
typedef void (*point_routine)(p256_wide_fe out[COORDINATES], const p256_wide_fe in[]);

// The routine on count coordinates against the spec's op on the same ones, coordinate for
// coordinate. Both sides take plain elements: this side moves each into the Montgomery domain,
// runs the routine and moves each coordinate of its answer back out.
static void diff_point_row(const char *op, uint8_t coordinate[][P256_FE_LEN], size_t count,
                           point_routine routine) {
    p256_wide_fe in[MOST_COORDINATES];
    p256_wide_fe out[COORDINATES];
    char cmd[32 + MOST_COORDINATES * HEX_LEN(P256_FE_LEN)];
    char want[COORDINATES * HEX_LEN(P256_FE_LEN)];
    element_command(cmd, sizeof cmd, op, coordinate, count);
    for (size_t i = 0; i < count; i++) {
        element_to_mont(&in[i], coordinate[i]);
    }
    routine(out, in);
    size_t want_len = 0;
    for (size_t i = 0; i < COORDINATES; i++) {
        p256_wide_fe plain;
        uint8_t bytes[P256_FE_LEN];
        p256_wide_fe_from_mont(&plain, &out[i]);
        p256_wide_fe_to_bytes(bytes, &plain);
        if (i > 0) {
            want[want_len++] = ' ';
        }
        want_len += hex_encode(want + want_len, bytes, sizeof bytes);
    }
    expect(cmd, want);
}

// The routines, each in the shape p256_wide_mul.c or p256_wide_base_mul calls it in: the two
// additions and the doubling write over their first point.
static void run_add_affine_incomplete(p256_wide_fe out[COORDINATES], const p256_wide_fe in[]) {
    p256_wide_point a = {in[0], in[1], in[2]};
    p256_wide_affine b = {in[3], in[4]};
    p256_wide_point_add_affine_incomplete(&a, &a, &b);
    out[0] = a.x;
    out[1] = a.y;
    out[2] = a.z;
}

static void run_to_jacobian(p256_wide_fe out[COORDINATES], const p256_wide_fe in[]) {
    p256_wide_point a = {in[0], in[1], in[2]};
    p256_wide_jacobian o;
    p256_wide_point_to_jacobian(&o, &a);
    out[0] = o.x;
    out[1] = o.y;
    out[2] = o.z;
}

static void run_from_jacobian(p256_wide_fe out[COORDINATES], const p256_wide_fe in[]) {
    p256_wide_jacobian a = {in[0], in[1], in[2]};
    p256_wide_point o;
    p256_wide_point_from_jacobian(&o, &a);
    out[0] = o.x;
    out[1] = o.y;
    out[2] = o.z;
}

static void run_double_jacobian(p256_wide_fe out[COORDINATES], const p256_wide_fe in[]) {
    p256_wide_jacobian a = {in[0], in[1], in[2]};
    p256_wide_point_double_jacobian(&a, &a);
    out[0] = a.x;
    out[1] = a.y;
    out[2] = a.z;
}

static void run_add_jacobian_incomplete(p256_wide_fe out[COORDINATES], const p256_wide_fe in[]) {
    p256_wide_jacobian a = {in[0], in[1], in[2]};
    p256_wide_jacobian b = {in[3], in[4], in[5]};
    p256_wide_point_add_jacobian_incomplete(&a, &a, &b);
    out[0] = a.x;
    out[1] = a.y;
    out[2] = a.z;
}

// Z^2 for the plain element Z: through the Montgomery domain, where the square is.
static void plain_square(uint8_t out[P256_FE_LEN], const uint8_t element[P256_FE_LEN]) {
    p256_wide_fe value;
    element_to_mont(&value, element);
    p256_wide_fe_sqr(&value, &value);
    p256_wide_fe_from_mont(&value, &value);
    p256_wide_fe_to_bytes(out, &value);
}

// The incomplete mixed addition on random coordinates, on the curve or not, and then on two
// inputs outside its condition: Z = 0, and Z = 1 with x = X, two points with the same x. On
// both the result's Z is zero, and the two sides must still agree on every coordinate.
static void diff_add_affine_incomplete(void) {
    uint8_t coordinate[5][P256_FE_LEN];
    for (size_t i = 0; i < 5; i++) {
        draw_element(coordinate[i]);
    }
    diff_point_row("p256_add_affine_incomplete", coordinate, 5, run_add_affine_incomplete);
    memset(coordinate[2], 0, P256_FE_LEN);
    diff_point_row("p256_add_affine_incomplete", coordinate, 5, run_add_affine_incomplete);
    coordinate[2][P256_FE_LEN - 1] = 1;
    memcpy(coordinate[3], coordinate[0], P256_FE_LEN);
    diff_point_row("p256_add_affine_incomplete", coordinate, 5, run_add_affine_incomplete);
}

// Both conversions and the doubling on random coordinates, on the curve or not, and then on the
// inputs where a value they compute is zero: Z = 0, where the conversion back moves 1 into Y,
// and with Y = 0 too, where nothing else would; and for the doubling Y = 0, where Z3 is zero,
// and X = Z^2 and X = -Z^2, where m is.
static void diff_jacobian_one_point(void) {
    uint8_t coordinate[COORDINATES][P256_FE_LEN];
    for (size_t i = 0; i < COORDINATES; i++) {
        draw_element(coordinate[i]);
    }
    diff_point_row("p256_to_jacobian", coordinate, COORDINATES, run_to_jacobian);
    diff_point_row("p256_from_jacobian", coordinate, COORDINATES, run_from_jacobian);
    diff_point_row("p256_double_jacobian", coordinate, COORDINATES, run_double_jacobian);
    memset(coordinate[2], 0, P256_FE_LEN);
    diff_point_row("p256_to_jacobian", coordinate, COORDINATES, run_to_jacobian);
    diff_point_row("p256_from_jacobian", coordinate, COORDINATES, run_from_jacobian);
    diff_point_row("p256_double_jacobian", coordinate, COORDINATES, run_double_jacobian);
    memset(coordinate[1], 0, P256_FE_LEN);
    diff_point_row("p256_from_jacobian", coordinate, COORDINATES, run_from_jacobian);
    draw_element(coordinate[2]);
    coordinate[2][P256_FE_LEN - 1] |= 1;
    diff_point_row("p256_double_jacobian", coordinate, COORDINATES, run_double_jacobian);
    draw_element(coordinate[1]);
    plain_square(coordinate[0], coordinate[2]);
    diff_point_row("p256_double_jacobian", coordinate, COORDINATES, run_double_jacobian);
    p256_wide_fe x;
    p256_wide_fe_from_bytes(&x, coordinate[0]);
    p256_wide_fe_neg(&x, &x);
    p256_wide_fe_to_bytes(coordinate[0], &x);
    diff_point_row("p256_double_jacobian", coordinate, COORDINATES, run_double_jacobian);
}

// The incomplete Jacobian addition on random coordinates, on the curve or not, and then on
// inputs outside its condition, where Z3 is zero: Z1 = 0, Z2 = 0, two points with the same x and
// Z, and one point twice.
static void diff_add_jacobian_incomplete(void) {
    uint8_t coordinate[MOST_COORDINATES][P256_FE_LEN];
    for (size_t i = 0; i < MOST_COORDINATES; i++) {
        draw_element(coordinate[i]);
    }
    diff_point_row("p256_add_jacobian_incomplete", coordinate, 6, run_add_jacobian_incomplete);
    memset(coordinate[2], 0, P256_FE_LEN);
    diff_point_row("p256_add_jacobian_incomplete", coordinate, 6, run_add_jacobian_incomplete);
    draw_element(coordinate[2]);
    memset(coordinate[5], 0, P256_FE_LEN);
    diff_point_row("p256_add_jacobian_incomplete", coordinate, 6, run_add_jacobian_incomplete);
    memcpy(coordinate[3], coordinate[0], P256_FE_LEN);
    memcpy(coordinate[5], coordinate[2], P256_FE_LEN);
    diff_point_row("p256_add_jacobian_incomplete", coordinate, 6, run_add_jacobian_incomplete);
    memcpy(coordinate[4], coordinate[1], P256_FE_LEN);
    diff_point_row("p256_add_jacobian_incomplete", coordinate, 6, run_add_jacobian_incomplete);
}

#define ROUNDS 25

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff p256 wide: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    static const uint8_t ANSWERS[2] = {WIDEMUL_CONSTANT_TIME, WIDEMUL_NOT_STATED};
    for (size_t i = 0; i < sizeof ANSWERS; i++) {
        for (int round = 0; round < ROUNDS; round++) {
            diff_keygen(ANSWERS[i]);
            diff_sign(ANSWERS[i]);
            diff_ecdh(ANSWERS[i]);
        }
    }
    for (int round = 0; round < ROUNDS; round++) {
        diff_add_affine_incomplete();
        diff_jacobian_one_point();
        diff_add_jacobian_incomplete();
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff p256 wide: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
