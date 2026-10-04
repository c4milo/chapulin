// The constant-time P-256 arm of the differential oracle: a key
// generation, a signature and a key exchange through p256_ecdh.h's and
// p256_sign.h's entries, against the same Lean spec process
// test/diff_test.c drives. The Makefile builds it as a host object's
// sources, with -DCH_CPU_RUNTIME, and every row runs under both answers:
// WIDEMUL_CONSTANT_TIME, which runs the wide files, four limbs of 64 bits
// (docs/decisions.md 94), and WIDEMUL_NOT_STATED, which runs p256_field.c,
// p256_scalar.c and p256_point.c on the decomposition.
//
// Its own main, as test/diff_x25519_test.c is: test/diff_test.c diffs the
// verifier in p256.c, which shares no arithmetic with these files, and no
// other row it runs reads them. spec/lean/Spec/P256.lean computes over Nat
// modulo p and n, so it states no limb representation and serves both
// copies unchanged.
//
// Three rows, each on fresh random inputs:
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
//   integers.
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

#define ROUNDS 100

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
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff p256 wide: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
