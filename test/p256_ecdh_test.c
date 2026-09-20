// P-256 ECDH against vectors Python computed (test/gen_p256_ecdh_vectors.py),
// plus the boundaries and the agreement property a generator cannot express.
// Its own binary, out of the packaged object like p256_field and p384:
// nothing links p256_ecdh.c until the server role does.
//
// The vectors are the independent answer. What this file adds: both sides
// of the scalar range (n-1 works, n does not), the points that must be
// refused and the check each one trips, the zeroed output every refusal
// owes its caller, and two key pairs that must agree on one secret.
#include <stdio.h>
#include <string.h>

#include "p256_ecdh.h"
#include "p256_ecdh_vectors.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

// The byte a refused call must not leave behind: every output buffer
// starts full of it, so a zeroed buffer afterwards is this file's doing.
#define POISON 0xaa

static int all_zero(const uint8_t *b, size_t n) {
    uint8_t bits = 0;
    for (size_t i = 0; i < n; i++) {
        bits |= b[i];
    }
    return bits == 0;
}

static void fill(uint8_t *b, size_t n) {
    memset(b, POISON, n);
}

static void run_keygen_cases(void) {
    for (size_t i = 0; i < COUNT(P256_ECDH_KEYGEN); i++) {
        const p256_ecdh_keygen_case *c = &P256_ECDH_KEYGEN[i];
        uint8_t priv[P256_SCALAR_LEN];
        uint8_t pub[P256_POINT_LEN];
        fill(priv, sizeof priv);
        fill(pub, sizeof pub);
        CHECK(p256_ecdh_keygen(c->scalar, priv, pub) == 1);
        CHECK(memcmp(priv, c->scalar, sizeof priv) == 0);
        CHECK(memcmp(pub, c->pub, sizeof pub) == 0);
        // A key this file just produced is a key it must accept.
        CHECK(p256_ecdh_point_valid(pub) == 1);
    }
}

static void run_shared_cases(void) {
    for (size_t i = 0; i < COUNT(P256_ECDH_SHARED); i++) {
        const p256_ecdh_shared_case *c = &P256_ECDH_SHARED[i];
        uint8_t out[P256_SECRET_LEN];
        fill(out, sizeof out);
        CHECK(p256_ecdh_point_valid(c->peer) == 1);
        CHECK(p256_ecdh(c->priv, c->peer, out) == 1);
        CHECK(memcmp(out, c->shared, sizeof out) == 0);
    }
}

static void run_bad_points(void) {
    // One private key for all of them: the point decides the verdict.
    for (size_t i = 0; i < COUNT(P256_ECDH_BAD_POINT); i++) {
        const uint8_t *point = P256_ECDH_BAD_POINT[i].point;
        uint8_t out[P256_SECRET_LEN];
        fill(out, sizeof out);
        CHECK(p256_ecdh_point_valid(point) == 0);
        CHECK(p256_ecdh(P256_ECDH_SCALAR_ONE, point, out) == 0);
        CHECK(all_zero(out, sizeof out));
    }
}

// The scalar range, both sides of both ends: 1 and n-1 are scalars, 0 and
// n are not. The peer point is the generator, which every case accepts.
static void run_scalar_boundary(void) {
    uint8_t pub[P256_POINT_LEN];
    uint8_t priv[P256_SCALAR_LEN];
    uint8_t out[P256_SECRET_LEN];

    CHECK(p256_ecdh_keygen(P256_ECDH_SCALAR_ONE, priv, pub) == 1);
    CHECK(p256_ecdh_keygen(P256_ECDH_SCALAR_LAST, priv, pub) == 1);

    fill(priv, sizeof priv);
    fill(pub, sizeof pub);
    CHECK(p256_ecdh_keygen(P256_ECDH_SCALAR_FIRST_BAD, priv, pub) == 0);
    CHECK(all_zero(priv, sizeof priv));
    CHECK(all_zero(pub, sizeof pub));

    fill(priv, sizeof priv);
    fill(pub, sizeof pub);
    CHECK(p256_ecdh_keygen(P256_ECDH_SCALAR_ZERO, priv, pub) == 0);
    CHECK(all_zero(priv, sizeof priv));
    CHECK(all_zero(pub, sizeof pub));

    // n itself is refused twice over: the range check rejects it, and
    // n*G is the point at infinity, which the affine mask rejects on its
    // own, so a build that dropped the range check would still answer 0
    // here. n+1 is what separates them: it is out of range, and
    // (n+1)*G is G, a finite point, so only the range check can refuse
    // it. test/violations/inv03-p256-ecdh-scalar-range.violation is the
    // mutant this case exists for.
    fill(priv, sizeof priv);
    fill(pub, sizeof pub);
    CHECK(p256_ecdh_keygen(P256_ECDH_SCALAR_ABOVE_ORDER, priv, pub) == 0);
    CHECK(all_zero(priv, sizeof priv));
    CHECK(all_zero(pub, sizeof pub));

    // The same two ends through the key exchange itself.
    const uint8_t *generator = P256_ECDH_KEYGEN[0].pub; // 1 * G
    fill(out, sizeof out);
    CHECK(p256_ecdh(P256_ECDH_SCALAR_LAST, generator, out) == 1);
    fill(out, sizeof out);
    CHECK(p256_ecdh(P256_ECDH_SCALAR_FIRST_BAD, generator, out) == 0);
    CHECK(all_zero(out, sizeof out));
    fill(out, sizeof out);
    CHECK(p256_ecdh(P256_ECDH_SCALAR_ZERO, generator, out) == 0);
    CHECK(all_zero(out, sizeof out));
    fill(out, sizeof out);
    CHECK(p256_ecdh(P256_ECDH_SCALAR_ABOVE_ORDER, generator, out) == 0);
    CHECK(all_zero(out, sizeof out));
}

// What a key exchange is for: two key pairs, two calls, one secret. The
// vectors cannot state this, because it holds whatever the scalars are.
static void run_agreement(void) {
    const uint8_t *a = P256_ECDH_KEYGEN[4].scalar;
    const uint8_t *b = P256_ECDH_KEYGEN[5].scalar;
    uint8_t priv_a[P256_SCALAR_LEN];
    uint8_t priv_b[P256_SCALAR_LEN];
    uint8_t pub_a[P256_POINT_LEN];
    uint8_t pub_b[P256_POINT_LEN];
    uint8_t secret_a[P256_SECRET_LEN];
    uint8_t secret_b[P256_SECRET_LEN];

    CHECK(p256_ecdh_keygen(a, priv_a, pub_a) == 1);
    CHECK(p256_ecdh_keygen(b, priv_b, pub_b) == 1);
    CHECK(p256_ecdh(priv_a, pub_b, secret_a) == 1);
    CHECK(p256_ecdh(priv_b, pub_a, secret_b) == 1);
    CHECK(memcmp(secret_a, secret_b, sizeof secret_a) == 0);
    // Different pairs, different secret: a routine that returned a
    // constant would pass every check above and fail this one.
    CHECK(memcmp(secret_a, P256_ECDH_SHARED[0].shared, sizeof secret_a) != 0);
}

int main(void) {
    run_keygen_cases();
    run_shared_cases();
    run_bad_points();
    run_scalar_boundary();
    run_agreement();
    if (failures) {
        printf("p256_ecdh_test: %d FAILURES\n", failures);
        return 1;
    }
    printf("p256_ecdh_test: %zu key pairs, %zu shared secrets, %zu refused points, "
           "boundaries and agreement passed\n",
           COUNT(P256_ECDH_KEYGEN), COUNT(P256_ECDH_SHARED), COUNT(P256_ECDH_BAD_POINT));
    return 0;
}
