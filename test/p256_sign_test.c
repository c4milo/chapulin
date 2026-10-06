// ECDSA P-256 signing: the scalar arithmetic mod the group order, whole
// signatures against the RFC 6979 deterministic answer, the key and
// buffer boundaries, and a cross-check against the independent verifier
// in p256.c.
//
// Its own binary for the reason test/p384_test.c gives: nothing in a
// client object calls the signer, and the module stays testable without
// the rest of the stack. test/gen_p256_sign_vectors.py wrote
// test/p256_sign_vectors.h; that script recomputes every constant
// p256_scalar.c and p256_point.c carry and reproduces RFC 6979 A.2.5
// before it prints a vector, so the answers here come from Python's
// integers and hashlib's HMAC rather than from the C under test.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "p256.h"
#include "p256_scalar.h"
#include "p256_sign.h"
#include "p256_sign_vectors.h"
#include "test_widemul.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "CH_ASSERT %s at %s:%d\n", cond, file, line);
    exit(2);
}

static int same_bytes(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

// a + b mod n, a * b mod n and a^-1 mod n against Python's answers, in
// both the aliased and the separate output shapes a caller uses. The two
// that multiply go through widemul.h's dispatchers, as p256_sign.c calls
// them, so a host binary's run with the multiply bit puts the vectors
// through p256_wide_scalar.c and its run without it through
// p256_scalar.c.
static void test_scalar_arithmetic(void) {
    for (size_t i = 0; i < sizeof p256_scalar_vectors / sizeof p256_scalar_vectors[0]; i++) {
        const p256_scalar_vector *v = &p256_scalar_vectors[i];
        p256_scalar a;
        p256_scalar b;
        p256_scalar got;
        uint8_t out[32];

        p256_scalar_from_bytes(&a, v->a);
        p256_scalar_from_bytes(&b, v->b);

        p256_scalar_add(&got, &a, &b);
        p256_scalar_to_bytes(out, &got);
        CHECK(same_bytes(out, v->sum, 32));

        widemul_p256_scalar_mul(TEST_WIDEMUL, &got, &a, &b);
        p256_scalar_to_bytes(out, &got);
        CHECK(same_bytes(out, v->product, 32));

        widemul_p256_scalar_inverse(TEST_WIDEMUL, &got, &a);
        p256_scalar_to_bytes(out, &got);
        CHECK(same_bytes(out, v->inverse, 32));

        // The same three with the output aliasing an input, which
        // p256_scalar.h allows and p256_sign.c relies on.
        got = a;
        p256_scalar_add(&got, &got, &b);
        p256_scalar_to_bytes(out, &got);
        CHECK(same_bytes(out, v->sum, 32));

        got = a;
        widemul_p256_scalar_mul(TEST_WIDEMUL, &got, &got, &b);
        p256_scalar_to_bytes(out, &got);
        CHECK(same_bytes(out, v->product, 32));

        got = a;
        widemul_p256_scalar_inverse(TEST_WIDEMUL, &got, &got);
        p256_scalar_to_bytes(out, &got);
        CHECK(same_bytes(out, v->inverse, 32));
    }
}

// The group order itself, its neighbours and zero, against the two
// predicates p256_sign.c gates the key and the nonce on.
static void test_scalar_predicates(void) {
    static const uint8_t ORDER[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                                      0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
    uint8_t value[32];
    uint8_t out[32];
    p256_scalar s;

    memset(value, 0, sizeof value);
    p256_scalar_from_bytes(&s, value);
    CHECK(p256_scalar_zero_mask(&s) == 0xffffffff);
    CHECK(p256_scalar_reduced_mask(&s) == 0xffffffff);

    // The exact boundary: n-1 is below the order, n is not, n+1 is not.
    memcpy(value, ORDER, sizeof value);
    value[31] = 0x50;
    p256_scalar_from_bytes(&s, value);
    CHECK(p256_scalar_reduced_mask(&s) == 0xffffffff);

    memcpy(value, ORDER, sizeof value);
    p256_scalar_from_bytes(&s, value);
    CHECK(p256_scalar_reduced_mask(&s) == 0);
    // n reduces to zero, and n+1 reduces to one.
    p256_scalar_reduce(&s, &s);
    CHECK(p256_scalar_zero_mask(&s) == 0xffffffff);

    value[31] = 0x52;
    p256_scalar_from_bytes(&s, value);
    CHECK(p256_scalar_reduced_mask(&s) == 0);
    p256_scalar_reduce(&s, &s);
    p256_scalar_to_bytes(out, &s);
    CHECK(out[31] == 1);
    CHECK(p256_scalar_zero_mask(&s) == 0);

    // The largest 256-bit value still reduces with one subtraction.
    memset(value, 0xff, sizeof value);
    p256_scalar_from_bytes(&s, value);
    p256_scalar_reduce(&s, &s);
    CHECK(p256_scalar_reduced_mask(&s) == 0xffffffff);
}

// Whole signatures, byte for byte, and the same bytes accepted by the
// verifier in p256.c, which shares no arithmetic with the signer.
static void test_signatures(void) {
    for (size_t i = 0; i < sizeof p256_sign_vectors / sizeof p256_sign_vectors[0]; i++) {
        const p256_sign_vector *v = &p256_sign_vectors[i];
        uint8_t sig[P256_SIG_MAX];
        uint8_t again[P256_SIG_MAX];
        size_t sig_len = 0;
        size_t again_len = 0;

        CHECK(p256_sign(TEST_WIDEMUL, v->priv, v->msg_hash, sig, sizeof sig, &sig_len) == 1);
        CHECK(sig_len == v->sig_len);
        CHECK(same_bytes(sig, v->sig, sig_len));
        CHECK(p256_ecdsa_verify(v->pub, v->msg_hash, sig, sig_len) == 1);

        // A deterministic nonce means the same message signs the same
        // way every time. A signer that drew entropy would fail here.
        CHECK(p256_sign(TEST_WIDEMUL, v->priv, v->msg_hash, again, sizeof again, &again_len) == 1);
        CHECK(again_len == sig_len);
        CHECK(same_bytes(again, sig, sig_len));
    }
}

// A changed message hash changes the signature, and the old signature
// stops verifying against the new hash.
static void test_message_binding(void) {
    const p256_sign_vector *v = &p256_sign_vectors[0];
    uint8_t hash[32];
    uint8_t sig[P256_SIG_MAX];
    uint8_t other[P256_SIG_MAX];
    size_t sig_len = 0;
    size_t other_len = 0;

    memcpy(hash, v->msg_hash, sizeof hash);
    CHECK(p256_sign(TEST_WIDEMUL, v->priv, hash, sig, sizeof sig, &sig_len) == 1);
    hash[31] ^= 0x01;
    CHECK(p256_sign(TEST_WIDEMUL, v->priv, hash, other, sizeof other, &other_len) == 1);
    CHECK(!(other_len == sig_len && same_bytes(other, sig, sig_len)));
    CHECK(p256_ecdsa_verify(v->pub, hash, sig, sig_len) == 0);
    CHECK(p256_ecdsa_verify(v->pub, hash, other, other_len) == 1);
}

// The key range, at the exact boundary: 1 and n-1 sign, 0 and n do not,
// and p256_sign_key_ok, the test a server runs on its configuration,
// gives the same answer as the signer at each.
static void test_key_boundary(void) {
    static const uint8_t ORDER[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                                      0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
    const uint8_t *hash = p256_sign_vectors[0].msg_hash;
    uint8_t priv[32];
    uint8_t sig[P256_SIG_MAX];
    size_t sig_len = 0;

    memset(priv, 0, sizeof priv);
    CHECK(p256_sign(TEST_WIDEMUL, priv, hash, sig, sizeof sig, &sig_len) == 0);
    CHECK(p256_sign_key_ok(priv) == 0);

    priv[31] = 1;
    CHECK(p256_sign(TEST_WIDEMUL, priv, hash, sig, sizeof sig, &sig_len) == 1);
    CHECK(p256_sign_key_ok(priv) == 1);

    memcpy(priv, ORDER, sizeof priv);
    priv[31] = 0x50; // n - 1
    CHECK(p256_sign(TEST_WIDEMUL, priv, hash, sig, sizeof sig, &sig_len) == 1);
    CHECK(p256_sign_key_ok(priv) == 1);

    memcpy(priv, ORDER, sizeof priv); // n
    CHECK(p256_sign(TEST_WIDEMUL, priv, hash, sig, sizeof sig, &sig_len) == 0);
    CHECK(p256_sign_key_ok(priv) == 0);

    memset(priv, 0xff, sizeof priv); // above n
    CHECK(p256_sign(TEST_WIDEMUL, priv, hash, sig, sizeof sig, &sig_len) == 0);
    CHECK(p256_sign_key_ok(priv) == 0);
}

// The output buffer boundary: the exact length works and one byte less
// fails, with nothing written past cap.
static void test_buffer_boundary(void) {
    const p256_sign_vector *v = &p256_sign_vectors[0];
    uint8_t sig[P256_SIG_MAX + 1];
    size_t sig_len = 0;

    memset(sig, 0xaa, sizeof sig);
    CHECK(p256_sign(TEST_WIDEMUL, v->priv, v->msg_hash, sig, v->sig_len, &sig_len) == 1);
    CHECK(sig_len == v->sig_len);
    CHECK(sig[v->sig_len] == 0xaa);

    memset(sig, 0xaa, sizeof sig);
    sig_len = 0;
    CHECK(p256_sign(TEST_WIDEMUL, v->priv, v->msg_hash, sig, (size_t)v->sig_len - 1, &sig_len) ==
          0);
    CHECK(sig[v->sig_len - 1] == 0xaa);
    CHECK(p256_sign(TEST_WIDEMUL, v->priv, v->msg_hash, sig, 0, &sig_len) == 0);
}

// Every vector's DER is minimal: no INTEGER carries a leading zero it
// does not need, and every one whose top bit is set carries one.
static void test_der_shape(void) {
    for (size_t i = 0; i < sizeof p256_sign_vectors / sizeof p256_sign_vectors[0]; i++) {
        const p256_sign_vector *v = &p256_sign_vectors[i];
        const uint8_t *p = v->sig;
        CHECK(p[0] == 0x30);
        CHECK(p[1] == v->sig_len - 2);
        size_t off = 2;
        for (int half = 0; half < 2; half++) {
            CHECK(p[off] == 0x02);
            size_t len = p[off + 1];
            const uint8_t *body = p + off + 2;
            CHECK(len >= 1 && len <= 33);
            // Minimal form (X.690 8.3.2): a leading zero is present only
            // to clear the top bit of the byte after it.
            if (len > 1) {
                CHECK(!(body[0] == 0x00 && (body[1] & 0x80) == 0));
            }
            CHECK((body[0] & 0x80) == 0);
            off += 2 + len;
        }
        CHECK(off == v->sig_len);
    }
}

#ifdef CH_CPU_RUNTIME
// p256_sign_cpu, the entry a host object's server signs through, writes
// every vector's bytes under the value this binary runs under, once with
// the SHA-256 bit, so the nonce's HMACs run on the instructions, and once
// without it. A CPU without the instructions runs the first only where the
// environment does not require them (test_cpu_hash_bits); the row then
// says so. A key out of range is refused on either path.
static void test_signatures_cpu(void) {
    uint32_t with_sha256 = test_cpu | (test_cpu_hash_bits() & CH_CPU_CONSTANT_TIME_SHA256);
    uint32_t without_sha256 = test_cpu & ~(uint32_t)CH_CPU_CONSTANT_TIME_SHA256;
    const uint32_t values[] = {with_sha256, without_sha256};
    if ((with_sha256 & CH_CPU_CONSTANT_TIME_SHA256) == 0) {
        (void)printf("p256_sign: SKIP p256_sign_cpu on the SHA-256 instructions: this CPU "
                     "lacks them\n");
    }
    for (size_t c = 0; c < sizeof values / sizeof values[0]; c++) {
        for (size_t i = 0; i < sizeof p256_sign_vectors / sizeof p256_sign_vectors[0]; i++) {
            const p256_sign_vector *v = &p256_sign_vectors[i];
            uint8_t sig[P256_SIG_MAX];
            size_t sig_len = 0;
            CHECK(p256_sign_cpu(values[c], v->priv, v->msg_hash, sig, sizeof sig, &sig_len) == 1);
            CHECK(sig_len == v->sig_len);
            CHECK(same_bytes(sig, v->sig, sig_len));
        }
        uint8_t priv[32];
        uint8_t sig[P256_SIG_MAX];
        size_t sig_len = 0;
        memset(priv, 0, sizeof priv);
        CHECK(p256_sign_cpu(values[c], priv, p256_sign_vectors[0].msg_hash, sig, sizeof sig,
                            &sig_len) == 0);
    }
}
#endif

// A host binary takes the ch_cfg.cpu value it runs under as its one
// argument (test/test_cpu.h); every other binary takes none.
int main(int argc, char **argv) {
    test_take_cpu(argc, argv);
    test_scalar_arithmetic();
    test_scalar_predicates();
    test_signatures();
#ifdef CH_CPU_RUNTIME
    test_signatures_cpu();
#endif
    test_message_binding();
    test_key_boundary();
    test_buffer_boundary();
    test_der_shape();
    if (failures == 0) {
        (void)printf("p256_sign: all tests passed\n");
    }
    return failures != 0;
}
